use super::postgres_tests::{events, execute_topic, fixture};
use super::*;
use buzz_core::channel::MemberRole;
use buzz_core::kind::KIND_NIP29_GROUP_METADATA;
use buzz_db::workflow::RunStatus;

#[tokio::test]
#[ignore = "requires Postgres"]
async fn workflow_topic_roles_preserve_owner_authority_and_exact_template_output() {
    let (state, community, channel, owner) = fixture().await;
    for role in [
        MemberRole::Owner,
        MemberRole::Admin,
        MemberRole::Member,
        MemberRole::Bot,
    ] {
        let principal = nostr::Keys::generate();
        state
            .db
            .ensure_user(community, &principal.public_key().to_bytes())
            .await
            .unwrap();
        state
            .db
            .add_member(
                community,
                channel,
                &principal.public_key().to_bytes(),
                role,
                Some(&owner.public_key().to_bytes()),
            )
            .await
            .unwrap();
        let topic = format!("{:?}: Cafe\u{301} \u{1f680}\n  ", role);
        let run = execute_topic(
            &state,
            community,
            channel,
            &principal,
            "{{trigger.text}}",
            &topic,
        )
        .await;
        assert_eq!(run.status, RunStatus::Completed, "{:?}", run.error_message);
        let saved = state.db.get_channel(community, channel).await.unwrap();
        assert_eq!(saved.topic.as_deref(), Some(topic.as_str()));
        assert_eq!(
            saved.topic_set_by,
            Some(principal.public_key().to_bytes().to_vec())
        );
        let notices = events(&state, community, channel, KIND_SYSTEM_MESSAGE).await;
        let payload: serde_json::Value = serde_json::from_str(
            &notices
                .iter()
                .find(|notice| {
                    serde_json::from_str::<serde_json::Value>(&notice.event.content).unwrap()
                        ["topic"]
                        == topic
                })
                .unwrap()
                .event
                .content,
        )
        .unwrap();
        assert_eq!(payload["actor"], principal.public_key().to_hex());
        let metadata = events(&state, community, channel, KIND_NIP29_GROUP_METADATA).await;
        assert!(metadata[0]
            .event
            .tags
            .iter()
            .any(|tag| tag.as_slice() == ["topic", topic.as_str()]));
    }
    let blank = execute_topic(&state, community, channel, &owner, "{{trigger.text}}", "  ").await;
    assert_eq!(blank.status, RunStatus::Completed);
    assert_eq!(
        state
            .db
            .get_channel(community, channel)
            .await
            .unwrap()
            .topic
            .as_deref(),
        Some("  ")
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn workflow_topic_enforces_current_principal_and_persisted_owner_moderation() {
    let (state, community, channel, owner) = fixture().await;
    let owner_bytes = owner.public_key().to_bytes();
    let future = chrono::Utc::now() + chrono::Duration::minutes(10);
    let past = chrono::Utc::now() - chrono::Duration::minutes(10);
    state
        .db
        .ban_community_member(community, &owner_bytes, &owner_bytes, None, None)
        .await
        .unwrap();
    let banned = execute_topic(&state, community, channel, &owner, "forbidden", "").await;
    assert_eq!(banned.status, RunStatus::Failed);
    assert!(state
        .db
        .is_member(community, channel, &owner_bytes)
        .await
        .unwrap());
    assert!(state
        .db
        .get_channel(community, channel)
        .await
        .unwrap()
        .topic
        .is_none());
    assert!(events(&state, community, channel, KIND_SYSTEM_MESSAGE)
        .await
        .is_empty());
    assert!(
        events(&state, community, channel, KIND_NIP29_GROUP_METADATA)
            .await
            .is_empty()
    );
    state
        .db
        .unban_community_member(community, &owner_bytes, &owner_bytes)
        .await
        .unwrap();
    state
        .db
        .timeout_community_member(community, &owner_bytes, &owner_bytes, future, None)
        .await
        .unwrap();
    assert_eq!(
        execute_topic(&state, community, channel, &owner, "forbidden", "")
            .await
            .status,
        RunStatus::Failed
    );
    state
        .db
        .untimeout_community_member(community, &owner_bytes, &owner_bytes)
        .await
        .unwrap();

    let agent = nostr::Keys::generate();
    let agent_bytes = agent.public_key().to_bytes();
    state.db.ensure_user(community, &agent_bytes).await.unwrap();
    state
        .db
        .set_agent_owner(community, &agent_bytes, &owner_bytes)
        .await
        .unwrap();
    state
        .db
        .add_member(community, channel, &agent_bytes, MemberRole::Bot, None)
        .await
        .unwrap();
    state
        .db
        .ban_community_member(community, &owner_bytes, &owner_bytes, None, None)
        .await
        .unwrap();
    assert_eq!(
        execute_topic(&state, community, channel, &agent, "inherited ban", "")
            .await
            .status,
        RunStatus::Failed
    );
    assert!(events(&state, community, channel, KIND_SYSTEM_MESSAGE)
        .await
        .is_empty());
    state
        .db
        .unban_community_member(community, &owner_bytes, &owner_bytes)
        .await
        .unwrap();
    // Human-owner timeouts do not transfer to an agent; only bans do.
    state
        .db
        .timeout_community_member(community, &owner_bytes, &owner_bytes, future, None)
        .await
        .unwrap();
    assert_eq!(
        execute_topic(&state, community, channel, &agent, "agent allowed", "")
            .await
            .status,
        RunStatus::Completed
    );
    state
        .db
        .timeout_community_member(community, &agent_bytes, &owner_bytes, future, None)
        .await
        .unwrap();
    assert_eq!(
        execute_topic(&state, community, channel, &agent, "agent timeout", "")
            .await
            .status,
        RunStatus::Failed
    );
    assert_eq!(
        state
            .db
            .get_channel(community, channel)
            .await
            .unwrap()
            .topic
            .as_deref(),
        Some("agent allowed")
    );
    assert_eq!(
        events(&state, community, channel, KIND_SYSTEM_MESSAGE)
            .await
            .len(),
        1
    );
    state
        .db
        .timeout_community_member(community, &agent_bytes, &owner_bytes, past, None)
        .await
        .unwrap();
    state
        .db
        .ban_community_member(community, &agent_bytes, &owner_bytes, None, Some(past))
        .await
        .unwrap();
    assert_eq!(
        execute_topic(&state, community, channel, &agent, "expired allowed", "")
            .await
            .status,
        RunStatus::Completed
    );
}
