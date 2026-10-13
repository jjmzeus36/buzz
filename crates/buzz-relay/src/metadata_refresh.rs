//! Bounded restart recovery of relay-signed canonical channel metadata.

use std::sync::Arc;
use std::time::Duration;

use buzz_core::TenantContext;
use tokio_util::sync::CancellationToken;

use crate::state::AppState;

/// Process one bounded batch. Source mutations and their refresh intent commit
/// together; only a committed metadata replacement advances completion. Retry
/// reconstructs current state and never replays a user's old channel command.
pub async fn refresh_pending_metadata(state: &Arc<AppState>) -> anyhow::Result<()> {
    for claim in state.db.claim_metadata_refreshes().await? {
        let tenant = TenantContext::resolved(claim.community_id, claim.host.clone());
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            crate::handlers::side_effects::emit_group_metadata_event(
                &tenant,
                state,
                claim.channel_id,
            ),
        )
        .await;
        match result {
            Ok(Ok(())) => state.db.release_metadata_refresh(&claim).await?,
            Ok(Err(error)) => {
                tracing::warn!(community = %claim.community_id, channel = %claim.channel_id, %error,
                    "Canonical metadata refresh failed; durable intent retained");
            }
            Err(error) => {
                tracing::warn!(community = %claim.community_id, channel = %claim.channel_id, %error,
                    "Canonical metadata refresh timed out; durable intent retained");
            }
        }
    }
    Ok(())
}

/// Recover pending work until shutdown. Cancellation drops an in-flight
/// transaction safely; its short claim lease allows another relay to recover.
pub async fn run(state: Arc<AppState>, cancel: CancellationToken) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            _ = interval.tick() => {}
        }
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            result = refresh_pending_metadata(&state) => {
                if let Err(error) = result {
                    tracing::warn!(%error, "Canonical metadata recovery tick failed; pending work retained");
                }
            }
        }
    }
}
