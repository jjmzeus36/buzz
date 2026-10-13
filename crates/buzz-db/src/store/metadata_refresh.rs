//! Durable, coalesced recovery of canonical channel metadata projections.

use buzz_core::CommunityId;
use buzz_datastore_tracing::datastore_span;
use sqlx::Row;
use uuid::Uuid;

use crate::{Db, Result};

/// A short leased refresh of current canonical state, not a historical command.
pub struct MetadataRefresh {
    /// Server-owned tenant for this channel.
    pub community_id: CommunityId,
    /// Host resolved from the same tenant row as the claim.
    pub host: String,
    /// Channel whose current metadata needs publication.
    pub channel_id: Uuid,
    /// Fences release against a worker that reclaimed an expired lease.
    pub lease_token: Uuid,
}

impl Db {
    /// Claim at most eight pending active-community channels for two minutes.
    /// Claims commit before any channel/source lock is acquired. A crashed
    /// worker therefore retains no lock and its work becomes available again.
    #[datastore_span(name = "claim_metadata_refreshes", system = "postgresql")]
    pub async fn claim_metadata_refreshes(&self) -> Result<Vec<MetadataRefresh>> {
        let mut tx = self.begin_event_write_transaction().await?;
        // Deletion takes its lifecycle fence before purging queue rows. Take
        // the same order, including when the queue UPDATE trigger rechecks it.
        // This initial bounded read grants no claim; predicates below recheck
        // eligibility after all lifecycle fences have been acquired.
        let mut communities: Vec<Uuid> = sqlx::query_scalar(
            "SELECT q.community_id FROM channel_metadata_refresh q \
             JOIN communities t ON t.id = q.community_id \
             JOIN channels c ON c.community_id = q.community_id AND c.id = q.channel_id \
             WHERE q.completed_version < q.requested_version \
               AND (q.lease_until IS NULL OR q.lease_until <= clock_timestamp()) \
               AND t.archived_at IS NULL AND t.deletion_state = 'active' AND c.deleted_at IS NULL \
             ORDER BY q.requested_at, q.community_id, q.channel_id LIMIT 8",
        )
        .fetch_all(&mut *tx)
        .await?;
        communities.sort_unstable();
        communities.dedup();
        for community in &communities {
            sqlx::query("SELECT assert_community_write_allowed($1)")
                .bind(community)
                .execute(&mut *tx)
                .await?;
        }
        let rows = sqlx::query(
            "WITH candidates AS ( \
               SELECT q.community_id, q.channel_id FROM channel_metadata_refresh q \
               JOIN communities t ON t.id = q.community_id \
               JOIN channels c ON c.community_id = q.community_id AND c.id = q.channel_id \
               WHERE q.community_id = ANY($1::uuid[]) AND q.completed_version < q.requested_version \
                 AND (q.lease_until IS NULL OR q.lease_until <= clock_timestamp()) \
                 AND t.archived_at IS NULL AND t.deletion_state = 'active' AND c.deleted_at IS NULL \
               ORDER BY q.requested_at, q.community_id, q.channel_id \
               LIMIT 8 FOR UPDATE OF q SKIP LOCKED \
             ) UPDATE channel_metadata_refresh q \
             SET lease_token = gen_random_uuid(), lease_until = clock_timestamp() + INTERVAL '2 minutes' \
             FROM candidates c, communities t \
             WHERE q.community_id = c.community_id AND q.channel_id = c.channel_id AND t.id = q.community_id \
             RETURNING q.community_id, q.channel_id, q.lease_token, t.host",
        )
        .bind(&communities)
        .fetch_all(&mut *tx)
        .await?;
        let claims = rows
            .into_iter()
            .map(|row| {
                Ok(MetadataRefresh {
                    community_id: CommunityId::from_uuid(row.try_get("community_id")?),
                    host: row.try_get("host")?,
                    channel_id: row.try_get("channel_id")?,
                    lease_token: row.try_get("lease_token")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        tx.commit().await?;
        Ok(claims)
    }

    /// Release only this claim after successful publication. Failures keep the
    /// lease as bounded retry backoff; a later source change stays pending.
    #[datastore_span(name = "release_metadata_refresh", system = "postgresql")]
    pub async fn release_metadata_refresh(&self, claim: &MetadataRefresh) -> Result<()> {
        let mut tx = self.begin_event_write_transaction().await?;
        sqlx::query("SELECT assert_community_write_allowed($1)")
            .bind(claim.community_id.as_uuid())
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE channel_metadata_refresh SET lease_token = NULL, lease_until = NULL \
             WHERE community_id = $1 AND channel_id = $2 AND lease_token = $3",
        )
        .bind(claim.community_id.as_uuid())
        .bind(claim.channel_id)
        .bind(claim.lease_token)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
}
