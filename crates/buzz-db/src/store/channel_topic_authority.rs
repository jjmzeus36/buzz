//! Transaction-held moderation authority for workflow topic source writes.

use buzz_core::CommunityId;
use sqlx::{Postgres, Transaction};

use crate::{DbError, Result};

/// Stabilize persisted owner mapping and restriction rows through source commit.
/// The caller has already obtained lifecycle, TTL, channel, and member fences.
/// Missing users use the same canonical minimal row as `ensure_user`; missing
/// restriction rows become unrestricted sentinels, so even a first ban INSERT
/// must serialize with this transaction. Existing moderation and operator
/// UPSERT/UPDATE writers use the same row locks without a separate protocol.
pub(super) async fn lock_unrestricted_principal(
    tx: &mut Transaction<'_, Postgres>,
    community: CommunityId,
    principal: &[u8],
) -> Result<()> {
    sqlx::query("INSERT INTO users (community_id, pubkey) VALUES ($1, $2) ON CONFLICT DO NOTHING")
        .bind(community.as_uuid())
        .bind(principal)
        .execute(&mut **tx)
        .await?;
    let owner: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT agent_owner_pubkey FROM users WHERE community_id = $1 AND pubkey = $2 FOR SHARE",
    )
    .bind(community.as_uuid())
    .bind(principal)
    .fetch_one(&mut **tx)
    .await?;
    let mut keys = vec![principal.to_vec()];
    if let Some(owner) = owner {
        keys.push(owner);
    }
    // Both creation and share locking use the same order; agents can share an
    // owner or refer to another principal, so unordered inserts can deadlock.
    keys.sort();
    keys.dedup();
    for key in &keys {
        sqlx::query(
            "INSERT INTO community_bans (community_id, pubkey, banned, actor_pubkey) \
             VALUES ($1, $2, false, $3) ON CONFLICT (community_id, pubkey) DO NOTHING",
        )
        .bind(community.as_uuid())
        .bind(key)
        .bind(principal)
        .execute(&mut **tx)
        .await?;
    }
    for key in &keys {
        sqlx::query(
            "SELECT pubkey FROM community_bans WHERE community_id = $1 AND pubkey = $2 FOR SHARE",
        )
        .bind(community.as_uuid())
        .bind(key)
        .fetch_one(&mut **tx)
        .await?;
    }
    let restricted: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM community_bans WHERE community_id = $1 \
         AND pubkey = ANY($2::bytea[]) AND banned \
         AND (ban_expires_at IS NULL OR ban_expires_at > clock_timestamp())) \
         OR EXISTS(SELECT 1 FROM community_bans WHERE community_id = $1 \
         AND pubkey = $3 AND muted_until > clock_timestamp())",
    )
    .bind(community.as_uuid())
    .bind(&keys)
    .bind(principal)
    .fetch_one(&mut **tx)
    .await?;
    if restricted {
        return Err(DbError::AccessDenied(
            "topic principal is currently banned or timed out".into(),
        ));
    }
    Ok(())
}
