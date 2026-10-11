//! Fail-closed logical original-byte quotas. Pending rows never expire or refund.
//! Each transaction locks the owner account before reading its ledger, including
//! baseline enrollment. No transaction spans object-store I/O.

use crate::Db;
use buzz_core::CommunityId;
use sqlx::Row;
use uuid::Uuid;

/// Admission failures are intentionally distinct from capacity exhaustion.
#[derive(Debug, thiserror::Error)]
pub enum QuotaError {
    /// Historical ownership has not been verified for this policy epoch.
    #[error("media quota baseline requires operator verification")]
    UnknownBaseline,
    /// Unique original bytes would exceed the operator's limit.
    #[error("media storage quota exceeded")]
    Exceeded,
    /// An earlier operation needs conservative reconciliation.
    #[error("media quota operation requires reconciliation")]
    Pending,
    /// Invalid or inconsistent accounting input.
    #[error("invalid media quota accounting input")]
    Invalid,
    /// Database failure; never fail open.
    #[error("media quota ledger unavailable")]
    Database(#[from] sqlx::Error),
    /// The community or admitted serving lease no longer permits writes.
    #[error("media quota write fence unavailable")]
    WriteFence(#[from] crate::DbError),
}

/// Validated policy. An epoch must be freshly verified after any enforcement gap.
#[derive(Clone, Copy, Debug)]
pub struct QuotaPolicy {
    /// Per-owner logical original-byte ceiling, positive and BIGINT-bounded.
    pub limit: i64,
    /// Operator-selected epoch tied to a complete historical manifest.
    pub baseline_id: Uuid,
}

/// A verified historical owner/hash claim.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineObject {
    /// Lowercase SHA-256 of original bytes.
    pub sha256: String,
    /// Actual original size.
    pub size_bytes: u64,
}

fn valid_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn size_i64(size: u64) -> Result<i64, QuotaError> {
    i64::try_from(size).ok().ok_or(QuotaError::Invalid)
}

impl Db {
    /// Reserve actual validated bytes before *any* durable media write.
    /// Returns a new operation token, or None for an already charged hash.
    /// A pending same-hash request fails closed, including after a restart.
    pub async fn reserve_media_quota(
        &self,
        community: CommunityId,
        pubkey: &[u8; 32],
        hash: &str,
        size: u64,
        policy: QuotaPolicy,
    ) -> Result<Option<Uuid>, QuotaError> {
        self.reserve_media_quota_with_lease(community, pubkey, hash, size, policy, None)
            .await
    }

    /// Reserve under an existing serving lease, allowing admitted uploads to
    /// finish while deletion quiesces. The lease must belong to this community.
    pub async fn reserve_media_quota_with_lease(
        &self,
        community: CommunityId,
        pubkey: &[u8; 32],
        hash: &str,
        size: u64,
        policy: QuotaPolicy,
        lease: Option<&crate::deletion::ServingWriteLease>,
    ) -> Result<Option<Uuid>, QuotaError> {
        let size = size_i64(size)?;
        if policy.limit <= 0 || policy.baseline_id.is_nil() || !valid_hash(hash) {
            return Err(QuotaError::Invalid);
        }
        let mut tx = self.pool.begin().await?;
        self.guard_media_quota_transaction(&mut tx, community, lease)
            .await?;
        let epoch: Option<(Uuid, i64)> = sqlx::query_as(
            "SELECT baseline_id,limit_bytes FROM media_quota_accounts WHERE community_id=$1 AND pubkey=$2 FOR UPDATE")
            .bind(community.as_uuid()).bind(pubkey.as_slice()).fetch_optional(&mut *tx).await?;
        if epoch != Some((policy.baseline_id, policy.limit)) {
            return Err(QuotaError::UnknownBaseline);
        }
        if let Some(row) = sqlx::query(
            "SELECT size_bytes, state FROM media_quota_objects WHERE community_id=$1 AND pubkey=$2 AND sha256=$3")
            .bind(community.as_uuid()).bind(pubkey.as_slice()).bind(hash).fetch_optional(&mut *tx).await? {
            if row.try_get::<i64,_>("size_bytes")? != size { return Err(QuotaError::Invalid); }
            if row.try_get::<String,_>("state")? != "charged" { return Err(QuotaError::Pending); }
            tx.commit().await?;
            return Ok(None);
        }
        // NUMERIC SUM avoids BIGINT overflow even for an imported over-limit baseline.
        let fits: bool = sqlx::query_scalar(
            "SELECT COALESCE(SUM(size_bytes),0) + $3::bigint <= $4::bigint FROM media_quota_objects WHERE community_id=$1 AND pubkey=$2")
            .bind(community.as_uuid()).bind(pubkey.as_slice()).bind(size).bind(policy.limit)
            .fetch_one(&mut *tx).await?;
        if !fits {
            return Err(QuotaError::Exceeded);
        }
        let operation = Uuid::new_v4();
        sqlx::query("INSERT INTO media_quota_objects (community_id,pubkey,sha256,size_bytes,operation_id,state) VALUES ($1,$2,$3,$4,$5,'pending')")
            .bind(community.as_uuid()).bind(pubkey.as_slice()).bind(hash).bind(size).bind(operation)
            .execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(Some(operation))
    }

    /// Mark a successfully published operation charged. The exact token fences
    /// stale completions; an uncertain/failed completion stays capacity-consuming.
    pub async fn finish_media_quota(
        &self,
        community: CommunityId,
        pubkey: &[u8; 32],
        hash: &str,
        operation: Uuid,
    ) -> Result<(), QuotaError> {
        self.finish_media_quota_with_lease(community, pubkey, hash, operation, None)
            .await
    }

    /// Complete the exact token under the upload's original durable serving lease.
    pub async fn finish_media_quota_with_lease(
        &self,
        community: CommunityId,
        pubkey: &[u8; 32],
        hash: &str,
        operation: Uuid,
        lease: Option<&crate::deletion::ServingWriteLease>,
    ) -> Result<(), QuotaError> {
        let mut tx = self.pool.begin().await?;
        self.guard_media_quota_transaction(&mut tx, community, lease)
            .await?;
        let result = sqlx::query("UPDATE media_quota_objects SET state='charged' WHERE community_id=$1 AND pubkey=$2 AND sha256=$3 AND operation_id=$4")
            .bind(community.as_uuid()).bind(pubkey.as_slice()).bind(hash).bind(operation)
            .execute(&mut *tx).await?;
        if result.rows_affected() != 1 {
            return Err(QuotaError::Invalid);
        }
        tx.commit().await?;
        Ok(())
    }

    /// Enroll a complete operator-verified baseline with all upload writers stopped.
    /// Renewal preserves every previous charge, including pending operations.
    /// This API does not discover historical attribution or attest completeness.
    pub async fn enroll_media_quota(
        &self,
        community: CommunityId,
        pubkey: &[u8; 32],
        policy: QuotaPolicy,
        evidence: &str,
        objects: &[BaselineObject],
    ) -> Result<(), QuotaError> {
        if policy.baseline_id.is_nil()
            || policy.limit <= 0
            || evidence.trim().is_empty()
            || evidence.len() > 4096
        {
            return Err(QuotaError::Invalid);
        }
        let mut hashes = std::collections::HashSet::new();
        for object in objects {
            size_i64(object.size_bytes)?;
            if !valid_hash(&object.sha256) || !hashes.insert(&object.sha256) {
                return Err(QuotaError::Invalid);
            }
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO media_quota_accounts (community_id,pubkey,baseline_id,evidence,limit_bytes) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (community_id,pubkey) DO NOTHING")
            .bind(community.as_uuid()).bind(pubkey.as_slice()).bind(policy.baseline_id).bind(evidence).bind(policy.limit).execute(&mut *tx).await?;
        sqlx::query("SELECT baseline_id FROM media_quota_accounts WHERE community_id=$1 AND pubkey=$2 FOR UPDATE")
            .bind(community.as_uuid()).bind(pubkey.as_slice()).fetch_one(&mut *tx).await?;
        let previous = sqlx::query(
            "SELECT sha256,size_bytes FROM media_quota_objects WHERE community_id=$1 AND pubkey=$2",
        )
        .bind(community.as_uuid())
        .bind(pubkey.as_slice())
        .fetch_all(&mut *tx)
        .await?;
        // A renewed manifest must include every previous liability at the same size.
        // Historical imports can add charges, but can never erase uncertainty.
        let supplied: std::collections::HashMap<_, _> = objects
            .iter()
            .map(|o| (o.sha256.as_str(), o.size_bytes))
            .collect();
        for row in previous {
            let hash: String = row.try_get("sha256")?;
            let size: i64 = row.try_get("size_bytes")?;
            if supplied.get(hash.as_str()).copied() != Some(size as u64) {
                return Err(QuotaError::Invalid);
            }
        }
        sqlx::query("UPDATE media_quota_accounts SET baseline_id=$3,evidence=$4,limit_bytes=$5,enrolled_at=now() WHERE community_id=$1 AND pubkey=$2")
            .bind(community.as_uuid()).bind(pubkey.as_slice()).bind(policy.baseline_id).bind(evidence).bind(policy.limit).execute(&mut *tx).await?;
        // Bound each statement without turning one enrollment into many commits.
        for chunk in objects.chunks(500) {
            let hashes: Vec<&str> = chunk.iter().map(|object| object.sha256.as_str()).collect();
            let sizes: Vec<i64> = chunk
                .iter()
                .map(|object| size_i64(object.size_bytes))
                .collect::<Result<_, _>>()?;
            let operations: Vec<Uuid> = chunk.iter().map(|_| Uuid::new_v4()).collect();
            sqlx::query("INSERT INTO media_quota_objects (community_id,pubkey,sha256,size_bytes,operation_id,state) SELECT $1,$2,sha256,size_bytes,operation_id,'charged' FROM UNNEST($3::text[],$4::bigint[],$5::uuid[]) AS item(sha256,size_bytes,operation_id) ON CONFLICT (community_id,pubkey,sha256) DO NOTHING")
                .bind(community.as_uuid()).bind(pubkey.as_slice()).bind(hashes)
                .bind(sizes).bind(operations).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Conservative recovery: retain the full charge and permit same-hash retry.
    /// Requires the observed operation UUID; never deletes/refunds storage liability.
    pub async fn recover_media_quota(
        &self,
        community: CommunityId,
        pubkey: &[u8; 32],
        hash: &str,
        operation: Uuid,
        evidence: &str,
    ) -> Result<(), QuotaError> {
        if evidence.trim().is_empty() || evidence.len() > 4096 {
            return Err(QuotaError::Invalid);
        }
        let result = sqlx::query("UPDATE media_quota_objects SET state='charged', recovery_evidence=$5 WHERE community_id=$1 AND pubkey=$2 AND sha256=$3 AND operation_id=$4 AND (state='pending' OR (state='charged' AND recovery_evidence=$5))")
            .bind(community.as_uuid()).bind(pubkey.as_slice()).bind(hash).bind(operation).bind(evidence).execute(&self.pool).await?;
        if result.rows_affected() != 1 {
            return Err(QuotaError::Invalid);
        }
        Ok(())
    }

    async fn guard_media_quota_transaction(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        community: CommunityId,
        lease: Option<&crate::deletion::ServingWriteLease>,
    ) -> Result<(), QuotaError> {
        if let Some(lease) = lease {
            if lease.community_id != community {
                return Err(QuotaError::Invalid);
            }
            self.deletion_store()
                .guard_transaction_with_serving_lease(tx, lease)
                .await?;
        }
        sqlx::query("SELECT assert_community_write_allowed($1)")
            .bind(community.as_uuid())
            .execute(&mut **tx)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "media_quota_regressions.rs"]
mod additional_postgres_tests;

#[cfg(test)]
mod postgres_tests {
    use super::*;
    pub(super) fn database_url() -> String {
        assert!(
            matches!(
                std::env::var("BUZZ_TEST_SCHEMA_MODE").as_deref(),
                Ok("desired" | "migration")
            ),
            "use the isolated PostgreSQL runner"
        );
        std::env::var("BUZZ_TEST_DATABASE_URL").expect("isolated test URL required")
    }
    pub(super) async fn fixture() -> (Db, CommunityId, QuotaPolicy) {
        let pool = sqlx::PgPool::connect(&database_url()).await.unwrap();
        let db = Db::from_pool(pool);
        if std::env::var("BUZZ_TEST_SCHEMA_MODE").as_deref() != Ok("desired") {
            db.migrate().await.unwrap();
        }
        let community = db
            .ensure_configured_community(&format!("quota-{}.test", Uuid::new_v4()))
            .await
            .unwrap()
            .id;
        let policy = QuotaPolicy {
            limit: 10,
            baseline_id: Uuid::new_v4(),
        };
        (db, community, policy)
    }
    pub(super) async fn enroll(db: &Db, c: CommunityId, p: QuotaPolicy, key: &[u8; 32]) {
        db.enroll_media_quota(c, key, p, "synthetic verified empty history", &[])
            .await
            .unwrap();
    }
    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn quota_race_restart_duplicate_and_recovery() {
        let (db, c, p) = fixture().await;
        let key = [1; 32];
        enroll(&db, c, p, &key).await;
        let h1 = "a".repeat(64);
        let h2 = "b".repeat(64);
        let (r1, r2) = tokio::join!(
            db.reserve_media_quota(c, &key, &h1, 6, p),
            db.reserve_media_quota(c, &key, &h2, 6, p)
        );
        assert_eq!(usize::from(r1.is_ok()) + usize::from(r2.is_ok()), 1);
        let (hash, token) = if let Ok(token) = r1 {
            (h1, token.unwrap())
        } else {
            (h2, r2.unwrap().unwrap())
        };
        let restarted = Db::from_pool(sqlx::PgPool::connect(&database_url()).await.unwrap());
        assert!(matches!(
            restarted.reserve_media_quota(c, &key, &hash, 6, p).await,
            Err(QuotaError::Pending)
        ));
        assert!(restarted
            .recover_media_quota(c, &key, &hash, Uuid::new_v4(), "wrong operation")
            .await
            .is_err());
        restarted
            .recover_media_quota(c, &key, &hash, token, "retain full uncertain charge")
            .await
            .unwrap();
        assert!(restarted
            .reserve_media_quota(c, &key, &hash, 6, p)
            .await
            .unwrap()
            .is_none());
        assert!(matches!(
            restarted
                .reserve_media_quota(c, &key, &"c".repeat(64), 5, p)
                .await,
            Err(QuotaError::Exceeded)
        ));
        assert!(matches!(
            restarted.reserve_media_quota(c, &key, &hash, 7, p).await,
            Err(QuotaError::Invalid)
        ));
        restarted
            .finish_media_quota(c, &key, &hash, token)
            .await
            .unwrap();
    }
    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn quota_unknown_baseline_epoch_tenant_owner_and_overflow() {
        let (db, c, p) = fixture().await;
        let key = [2; 32];
        let hash = "d".repeat(64);
        assert!(matches!(
            db.reserve_media_quota(c, &key, &hash, 1, p).await,
            Err(QuotaError::UnknownBaseline)
        ));
        enroll(&db, c, p, &key).await;
        assert!(matches!(
            db.reserve_media_quota(c, &key, &hash, u64::MAX, p).await,
            Err(QuotaError::Invalid)
        ));
        let token = db
            .reserve_media_quota(c, &key, &hash, 10, p)
            .await
            .unwrap()
            .unwrap();
        db.finish_media_quota(c, &key, &hash, token).await.unwrap();
        let other = [3; 32];
        enroll(&db, c, p, &other).await;
        assert!(db
            .reserve_media_quota(c, &other, &hash, 10, p)
            .await
            .unwrap()
            .is_some());
        let (_, c2, _) = fixture().await;
        enroll(&db, c2, p, &key).await;
        assert!(db
            .reserve_media_quota(c2, &key, &hash, 10, p)
            .await
            .unwrap()
            .is_some());
        let fresh = QuotaPolicy {
            baseline_id: Uuid::new_v4(),
            ..p
        };
        assert!(matches!(
            db.reserve_media_quota(c, &key, &hash, 10, fresh).await,
            Err(QuotaError::UnknownBaseline)
        ));
        assert!(db
            .enroll_media_quota(c, &key, fresh, "incomplete manifest", &[])
            .await
            .is_err());
        db.enroll_media_quota(
            c,
            &key,
            fresh,
            "complete renewed manifest",
            &[BaselineObject {
                sha256: hash.clone(),
                size_bytes: 10,
            }],
        )
        .await
        .unwrap();
        assert!(db
            .reserve_media_quota(c, &key, &hash, 10, fresh)
            .await
            .unwrap()
            .is_none());
    }
}
