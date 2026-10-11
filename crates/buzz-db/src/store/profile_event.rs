//! Profile projection persisted under the replaceable-event transaction.

use buzz_core::CommunityId;
use sqlx::{Acquire, Postgres, Transaction};

use crate::{DbError, Result};

/// Validated profile fields. Missing fields clear the previous absolute state.
#[derive(Clone, Debug, Default)]
pub struct ProfileMetadata {
    /// Display name, limited to the database's 255-character column.
    pub display_name: Option<String>,
    /// Profile image URL.
    pub avatar_url: Option<String>,
    /// Profile biography.
    pub about: Option<String>,
    /// Canonical NIP-05 identifier, validated against the bound community host.
    pub nip05_handle: Option<String>,
}

impl ProfileMetadata {
    /// Validate database constraints before accepting the signed event.
    pub fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("display_name", &self.display_name),
            ("nip05", &self.nip05_handle),
        ] {
            if value
                .as_ref()
                .is_some_and(|value| value.chars().count() > 255)
            {
                return Err(DbError::InvalidData(format!(
                    "profile {name} exceeds 255 characters"
                )));
            }
        }
        Ok(())
    }
}

pub(crate) async fn project(
    tx: &mut Transaction<'_, Postgres>,
    community: CommunityId,
    event: &nostr::Event,
    profile: &ProfileMetadata,
) -> Result<bool> {
    profile.validate()?;
    let pubkey = event.pubkey.to_bytes();
    let user_insert = sqlx::query(
        "INSERT INTO users (community_id, pubkey) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(community.as_uuid())
    .bind(pubkey.as_slice())
    .execute(&mut **tx)
    .await?;

    // A contested local NIP-05 handle must not discard unrelated profile fields.
    // The savepoint recovers from the unique violation without losing atomicity.
    let mut savepoint = tx.begin().await?;
    match update(&mut savepoint, community, event, profile, true).await {
        Ok(()) => savepoint.commit().await?,
        Err(DbError::Sqlx(sqlx::Error::Database(error)))
            if error.constraint() == Some("idx_users_nip05") =>
        {
            savepoint.rollback().await?;
            update(tx, community, event, profile, false).await?;
        }
        Err(error) => return Err(error),
    }
    Ok(user_insert.rows_affected() == 1)
}

async fn update(
    tx: &mut Transaction<'_, Postgres>,
    community: CommunityId,
    event: &nostr::Event,
    profile: &ProfileMetadata,
    update_nip05: bool,
) -> Result<()> {
    let pubkey = event.pubkey.to_bytes();
    sqlx::query(
        "UPDATE users SET display_name = $3, avatar_url = $4, about = $5, \
        nip05_handle = CASE WHEN $6 THEN $7 ELSE nip05_handle END, \
        metadata_event_id = $8, updated_at = NOW() WHERE community_id = $1 AND pubkey = $2",
    )
    .bind(community.as_uuid())
    .bind(pubkey.as_slice())
    .bind(
        profile
            .display_name
            .as_deref()
            .filter(|value| !value.is_empty()),
    )
    .bind(
        profile
            .avatar_url
            .as_deref()
            .filter(|value| !value.is_empty()),
    )
    .bind(profile.about.as_deref().filter(|value| !value.is_empty()))
    .bind(update_nip05)
    .bind(
        profile
            .nip05_handle
            .as_deref()
            .filter(|value| !value.is_empty()),
    )
    .bind(event.id.as_bytes().as_slice())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[cfg(test)]
mod postgres_tests;
