//! Locked snapshots for relay-authored channel metadata publication.
//!
//! Metadata must be captured after obtaining its canonical replacement lock.
//! Holding the channel row through replacement prevents an older capture from
//! acquiring a newer event timestamp after a concurrent metadata update.

use buzz_core::{CommunityId, StoredEvent};
use buzz_datastore_tracing::datastore_span;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::channel::{row_to_channel_record, ChannelRecord};
use crate::{Db, DbError, Result};

/// Canonical channel metadata held stable until its discovery event commits.
pub struct LockedMetadataSnapshot {
    /// Channel fields captured after the canonical replacement lock was granted.
    pub channel: ChannelRecord,
    /// Active DM participant public keys included in metadata discovery tags.
    pub participant_pubkeys: Vec<Vec<u8>>,
    community_id: CommunityId,
    channel_id: Uuid,
    relay_pubkey: Vec<u8>,
    refresh_version: Option<i64>,
    replacement_persisted: bool,
    tx: Transaction<'static, Postgres>,
}

impl LockedMetadataSnapshot {
    /// Read the current metadata head timestamp on the snapshot's connection.
    pub async fn latest_metadata_event_timestamp(&mut self) -> Result<Option<u64>> {
        let value: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT created_at FROM events \
             WHERE community_id = $1 AND kind = $2 AND pubkey = $3 \
             AND channel_id = $4 AND deleted_at IS NULL \
             ORDER BY created_at DESC, id ASC LIMIT 1",
        )
        .bind(self.community_id.as_uuid())
        .bind(buzz_core::kind::KIND_NIP29_GROUP_METADATA as i32)
        .bind(&self.relay_pubkey)
        .bind(self.channel_id)
        .fetch_optional(&mut *self.tx)
        .await?;
        value
            .map(|timestamp| {
                u64::try_from(timestamp.timestamp())
                    .map_err(|_| DbError::InvalidTimestamp(timestamp.timestamp()))
            })
            .transpose()
    }

    /// Replace this coordinate's metadata while retaining the channel share lock.
    /// A failure leaves the transaction uncommitted so dropping the guard restores
    /// the previous metadata head.
    pub async fn replace_metadata_event(
        &mut self,
        event: &nostr::Event,
    ) -> Result<(StoredEvent, bool)> {
        let kind = buzz_core::kind::event_kind_i32(event);
        let group_id = self.channel_id.to_string();
        let d_tags: Vec<_> = event
            .tags
            .iter()
            .filter(|tag| tag.as_slice().first().is_some_and(|part| part == "d"))
            .collect();
        if kind != buzz_core::kind::KIND_NIP29_GROUP_METADATA as i32
            || event.pubkey.to_bytes().as_slice() != self.relay_pubkey.as_slice()
            || d_tags.len() != 1
            || d_tags[0].as_slice().get(1) != Some(&group_id)
        {
            return Err(DbError::InvalidData(
                "metadata replacement does not match its locked coordinate".into(),
            ));
        }
        let created_at_secs = event.created_at.as_secs() as i64;
        let created_at = DateTime::from_timestamp(created_at_secs, 0)
            .ok_or(DbError::InvalidTimestamp(created_at_secs))?;
        let existing: Option<(DateTime<Utc>, Vec<u8>)> = sqlx::query_as(
            "SELECT created_at, id FROM events \
             WHERE community_id = $1 AND kind = $2 AND pubkey = $3 \
             AND channel_id = $4 AND deleted_at IS NULL \
             ORDER BY created_at DESC, id ASC LIMIT 1",
        )
        .bind(self.community_id.as_uuid())
        .bind(kind)
        .bind(&self.relay_pubkey)
        .bind(self.channel_id)
        .fetch_optional(&mut *self.tx)
        .await?;
        let incoming_id = event.id.as_bytes().as_slice();
        if let Some((existing_ts, existing_id)) = existing {
            if created_at < existing_ts
                || (created_at == existing_ts && incoming_id >= existing_id.as_slice())
            {
                return Ok((
                    StoredEvent::with_received_at(
                        event.clone(),
                        Utc::now(),
                        Some(self.channel_id),
                        false,
                    ),
                    false,
                ));
            }
        }
        sqlx::query(
            "UPDATE events SET deleted_at = NOW() \
             WHERE community_id = $1 AND kind = $2 AND pubkey = $3 \
             AND channel_id = $4 AND deleted_at IS NULL",
        )
        .bind(self.community_id.as_uuid())
        .bind(kind)
        .bind(&self.relay_pubkey)
        .bind(self.channel_id)
        .execute(&mut *self.tx)
        .await?;
        let received_at = Utc::now();
        let tags = serde_json::to_value(&event.tags)?;
        let sig = event.sig.serialize();
        let inserted = sqlx::query(
            "INSERT INTO events \
             (community_id, id, pubkey, created_at, kind, tags, content, sig, received_at, channel_id, d_tag) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING",
        )
        .bind(self.community_id.as_uuid())
        .bind(event.id.as_bytes().as_slice())
        .bind(&self.relay_pubkey)
        .bind(created_at)
        .bind(kind)
        .bind(tags)
        .bind(&event.content)
        .bind(sig.as_slice())
        .bind(received_at)
        .bind(self.channel_id)
        .bind(group_id)
        .execute(&mut *self.tx)
        .await?;
        if inserted.rows_affected() == 0 {
            return Err(DbError::InvalidData(
                "metadata snapshot event id already exists".into(),
            ));
        }
        crate::insert_mentions_in_transaction(
            &mut self.tx,
            self.community_id,
            event,
            Some(self.channel_id),
        )
        .await?;
        self.replacement_persisted = true;
        Ok((
            StoredEvent::with_received_at(event.clone(), received_at, Some(self.channel_id), true),
            true,
        ))
    }

    /// Commit the discovery replacement and release all snapshot locks.
    pub async fn release(self) -> Result<()> {
        let mut tx = self.tx;
        if let Some(version) = self.refresh_version.filter(|_| self.replacement_persisted) {
            // The generation was captured BEFORE source reads. A mutation
            // committed afterwards cannot be acknowledged by this snapshot.
            sqlx::query(
                "UPDATE channel_metadata_refresh \
                 SET completed_version = GREATEST(completed_version, $3) \
                 WHERE community_id = $1 AND channel_id = $2",
            )
            .bind(self.community_id.as_uuid())
            .bind(self.channel_id)
            .bind(version)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}

/// Capture channel metadata after acquiring its canonical replacement lock.
///
/// Community deletion and TTL advisory fences precede the channel share lock.
/// The returned guard retains those locks through event replacement and commit,
/// with no nested pool acquisition.
pub async fn lock_metadata_snapshot(
    pool: &PgPool,
    community_id: CommunityId,
    channel_id: Uuid,
    relay_pubkey: &[u8],
) -> Result<LockedMetadataSnapshot> {
    let connection = crate::observability::acquire_writer(
        pool,
        crate::observability::WriterOperation::EventWrite,
    )
    .await?;
    let mut tx = Transaction::begin(connection, None).await?;
    // Never read this after capturing participants: a concurrent member write
    // could then advance the generation beyond the captured source snapshot.
    let refresh_version: Option<i64> = sqlx::query_scalar(
        "SELECT requested_version FROM channel_metadata_refresh \
         WHERE community_id = $1 AND channel_id = $2",
    )
    .bind(community_id.as_uuid())
    .bind(channel_id)
    .fetch_optional(&mut *tx)
    .await?;
    let replacement_lock = crate::replaceable::event_replacement_lock_key(
        community_id,
        buzz_core::kind::KIND_NIP29_GROUP_METADATA as i32,
        relay_pubkey,
        Some(channel_id.as_bytes()),
    );
    crate::observability::observe_advisory_lock(
        crate::observability::LockType::Replacement,
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(replacement_lock)
            .execute(&mut *tx),
    )
    .await?;
    sqlx::query("SELECT assert_community_write_allowed($1)")
        .bind(community_id.as_uuid())
        .execute(&mut *tx)
        .await?;
    let active: Option<bool> = sqlx::query_scalar(
        "SELECT TRUE FROM communities WHERE id = $1 AND archived_at IS NULL \
         AND deleted_at IS NULL AND deletion_state = 'active' FOR SHARE",
    )
    .bind(community_id.as_uuid())
    .fetch_optional(&mut *tx)
    .await?;
    if active != Some(true) {
        return Err(DbError::AccessDenied(
            "metadata publication requires an active community".into(),
        ));
    }
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))")
        .bind(format!(
            "buzz_channel_ttl:{}:{}",
            community_id.as_uuid(),
            channel_id
        ))
        .execute(&mut *tx)
        .await?;
    let row = sqlx::query(
        r#"
        SELECT id, name, channel_type::text AS channel_type, visibility::text AS visibility,
               description, canvas, created_by, created_at, updated_at, archived_at, deleted_at,
               nip29_group_id, topic_required, max_members,
               topic, topic_set_by, topic_set_at, purpose, purpose_set_by, purpose_set_at,
               ttl_seconds, ttl_deadline
        FROM channels
        WHERE community_id = $1 AND id = $2 AND deleted_at IS NULL
        FOR SHARE
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(channel_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(DbError::ChannelNotFound(channel_id))?;
    let channel = row_to_channel_record(row)?;
    let participant_pubkeys = if channel.channel_type == "dm" {
        sqlx::query_scalar(
            "SELECT pubkey FROM channel_members \
             WHERE community_id = $1 AND channel_id = $2 AND removed_at IS NULL \
             ORDER BY joined_at ASC, pubkey ASC",
        )
        .bind(community_id.as_uuid())
        .bind(channel_id)
        .fetch_all(&mut *tx)
        .await?
    } else {
        Vec::new()
    };
    Ok(LockedMetadataSnapshot {
        channel,
        participant_pubkeys,
        community_id,
        channel_id,
        relay_pubkey: relay_pubkey.to_vec(),
        refresh_version,
        replacement_persisted: false,
        tx,
    })
}

impl Db {
    /// Capture channel metadata behind its replacement and channel share locks.
    #[datastore_span(name = "lock_metadata_snapshot", system = "postgresql")]
    pub async fn lock_metadata_snapshot(
        &self,
        community_id: CommunityId,
        channel_id: Uuid,
        relay_pubkey: &[u8],
    ) -> Result<LockedMetadataSnapshot> {
        lock_metadata_snapshot(&self.pool, community_id, channel_id, relay_pubkey).await
    }
}
