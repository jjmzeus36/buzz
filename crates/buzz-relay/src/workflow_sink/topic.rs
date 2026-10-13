//! Authorized workflow topic changes with the existing NIP-29 publication path.

use super::*;
use buzz_core::kind::KIND_SYSTEM_MESSAGE;
use buzz_core::TenantContext;

#[cfg(test)]
mod authority_postgres_tests;
#[cfg(test)]
mod governance_postgres_tests;
#[cfg(test)]
mod persistence_postgres_tests;
#[cfg(test)]
mod postgres_tests;
#[cfg(test)]
mod race_postgres_tests;
#[cfg(test)]
mod recovery_postgres_tests;
#[cfg(test)]
mod restriction_race_postgres_tests;

impl RelayActionSink {
    pub(super) async fn set_channel_topic_impl(
        &self,
        community: CommunityId,
        channel_id: String,
        topic: String,
        owner_pubkey: String,
    ) -> Result<(), ActionSinkError> {
        let state = self
            .state
            .upgrade()
            .ok_or_else(|| ActionSinkError::Database("relay is shutting down".into()))?;
        let channel = Uuid::parse_str(&channel_id)
            .map_err(|e| ActionSinkError::InvalidInput(format!("invalid channel: {e}")))?;
        let owner = nostr::PublicKey::from_hex(&owner_pubkey)
            .map_err(|e| ActionSinkError::InvalidInput(format!("invalid owner: {e}")))?;
        let host = state
            .db
            .lookup_community_host(community)
            .await
            .map_err(|e| ActionSinkError::Database(e.to_string()))?
            .ok_or_else(|| ActionSinkError::Database("workflow community is unavailable".into()))?;
        let tenant = TenantContext::resolved(community, host);
        // A workflow may be delayed after its initial authority check. Apply
        // current principal and persisted-owner bans, and principal-only
        // timeouts, at the topic side-effect boundary.
        let restrictions = state
            .db
            .moderation_principal_restriction_state(community, &owner.to_bytes(), None)
            .await
            .map_err(|e| ActionSinkError::Database(e.to_string()))?;
        if restrictions.banned || restrictions.muted_until.is_some() {
            return Err(ActionSinkError::Authorization(
                "workflow owner is currently banned or timed out".into(),
            ));
        }
        let payload =
            serde_json::json!({"type": "topic_changed", "actor": owner.to_hex(), "topic": topic});
        let event = EventBuilder::new(
            Kind::Custom(KIND_SYSTEM_MESSAGE as u16),
            payload.to_string(),
        )
        .tags([
            Tag::parse(["h", &channel.to_string()])
                .map_err(|e| ActionSinkError::EventBuild(e.to_string()))?,
            Tag::parse(["buzz:workflow", "true"])
                .map_err(|e| ActionSinkError::EventBuild(e.to_string()))?,
            Tag::parse(["buzz:workflow-owner", &owner.to_hex()])
                .map_err(|e| ActionSinkError::EventBuild(e.to_string()))?,
        ])
        .sign_with_keys(&state.relay_keypair)
        .map_err(|e| ActionSinkError::EventBuild(e.to_string()))?;
        let (stored, inserted) = state
            .db
            .set_topic_with_member_event(community, channel, &topic, &owner.to_bytes(), &event)
            .await
            .map_err(|e| ActionSinkError::Database(e.to_string()))?;
        // Persist fresh metadata before the notice can cause clients to
        // refetch it. Database failures remain failed workflow steps.
        crate::handlers::side_effects::emit_group_metadata_event(&tenant, &state, channel)
            .await
            .map_err(|e| ActionSinkError::Database(e.to_string()))?;
        if inserted {
            dispatch_persistent_event(
                &tenant,
                &state,
                &stored,
                KIND_SYSTEM_MESSAGE,
                &owner.to_hex(),
                None,
            )
            .await;
        }
        Ok(())
    }
}
