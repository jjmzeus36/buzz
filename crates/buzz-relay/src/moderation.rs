//! Durable moderation identity checks shared by transport seams.

use crate::state::AppState;
use buzz_core::CommunityId;

pub(crate) const BANNED: &str = "blocked: you are banned from this community";
pub(crate) const UNAVAILABLE: &str = "error: internal error checking restriction state";

pub(crate) async fn check_read(
    state: &AppState,
    community: CommunityId,
    pubkey: &nostr::PublicKey,
    proven_owner: Option<&nostr::PublicKey>,
) -> Result<(), &'static str> {
    match state
        .db
        .moderation_principal_restriction_state(
            community,
            pubkey.as_bytes(),
            proven_owner.map(|owner| owner.as_bytes().as_slice()),
        )
        .await
    {
        Ok(restriction) if restriction.banned => Err(BANNED),
        Ok(_) => Ok(()),
        Err(error) => {
            tracing::warn!(%error, "moderation authority read failed");
            Err(UNAVAILABLE)
        }
    }
}

#[cfg(test)]
mod postgres_tests;
