use super::*;
use buzz_core::channel::{ChannelType, ChannelVisibility, MemberRole};
use buzz_core::kind::KIND_NIP29_GROUP_METADATA;
use buzz_db::workflow::RunStatus;
use serde_json::json;

pub(super) async fn fixture() -> (Arc<AppState>, CommunityId, Uuid, nostr::Keys) {
    let state = super::super::postgres_tests::test_state().await;
    let owner = nostr::Keys::generate();
    let community = state
        .db
        .ensure_configured_community(&format!("topic-{}.test", Uuid::new_v4()))
        .await
        .unwrap()
        .id;
    state
        .db
        .ensure_user(community, &owner.public_key().to_bytes())
        .await
        .unwrap();
    let channel = state
        .db
        .create_channel(
            community,
            "topic-test",
            ChannelType::Stream,
            ChannelVisibility::Open,
            None,
            &owner.public_key().to_bytes(),
            None,
        )
        .await
        .unwrap()
        .id;
    state
        .workflow_engine
        .set_action_sink(Arc::new(RelayActionSink::new(&state)));
    (state, community, channel, owner)
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn workflow_topic_uses_stored_channel_and_publishes_attributed_nip29_metadata() {
    let (state, community, channel, owner) = fixture().await;
    let (def, canonical) = buzz_workflow::WorkflowEngine::parse_yaml(
        "name: topic\ntrigger:\n  on: webhook\nsteps:\n  - id: topic\n    action: set_channel_topic\n    topic: 'Status: {{trigger.text}}'\n",
    ).unwrap();
    let workflow = state
        .db
        .create_workflow(
            community,
            Some(channel),
            &owner.public_key().to_bytes(),
            "topic",
            &canonical,
            &[1; 32],
        )
        .await
        .unwrap();
    let context = buzz_workflow::executor::TriggerContext {
        text: "approved".into(),
        channel_id: Uuid::new_v4().to_string(),
        ..Default::default()
    };
    let run = state
        .db
        .create_workflow_run(
            community,
            workflow,
            None,
            Some(&serde_json::to_value(&context).unwrap()),
        )
        .await
        .unwrap();
    let result = buzz_workflow::executor::execute_run(
        &state.workflow_engine,
        community,
        run,
        &def,
        &context,
    )
    .await;
    state
        .workflow_engine
        .finalize_run(community, run, result, None)
        .await;
    let saved_run = state.db.get_workflow_run(community, run).await.unwrap();
    assert_eq!(
        saved_run.status,
        RunStatus::Completed,
        "{:?}",
        saved_run.error_message
    );
    let saved_channel = state.db.get_channel(community, channel).await.unwrap();
    assert_eq!(saved_channel.topic.as_deref(), Some("Status: approved"));
    assert_eq!(
        saved_channel.topic_set_by,
        Some(owner.public_key().to_bytes().to_vec())
    );
    let metadata = state
        .db
        .query_events_for_event_write(&buzz_db::event::EventQuery {
            kinds: Some(vec![KIND_NIP29_GROUP_METADATA as i32]),
            channel_id: Some(channel),
            limit: Some(10),
            ..buzz_db::event::EventQuery::for_community(community)
        })
        .await
        .unwrap();
    assert_eq!(metadata.len(), 1);
    assert_eq!(metadata[0].event.pubkey, state.relay_keypair.public_key());
    metadata[0].event.verify().unwrap();
    assert!(metadata[0]
        .event
        .tags
        .iter()
        .any(|tag| tag.as_slice() == ["topic", "Status: approved"]));
    let notices = state
        .db
        .query_events_for_event_write(&buzz_db::event::EventQuery {
            kinds: Some(vec![KIND_SYSTEM_MESSAGE as i32]),
            channel_id: Some(channel),
            limit: Some(10),
            ..buzz_db::event::EventQuery::for_community(community)
        })
        .await
        .unwrap();
    assert_eq!(notices.len(), 1);
    let notice = &notices[0].event;
    assert_eq!(notice.pubkey, state.relay_keypair.public_key());
    notice.verify().unwrap();
    for expected in [
        vec!["h".to_string(), channel.to_string()],
        vec!["buzz:workflow".to_string(), "true".to_string()],
        vec![
            "buzz:workflow-owner".to_string(),
            owner.public_key().to_hex(),
        ],
    ] {
        assert!(notice.tags.iter().any(|tag| tag.as_slice() == expected));
    }
    let payload: serde_json::Value = serde_json::from_str(&notice.content).unwrap();
    assert_eq!(
        payload,
        json!({"type":"topic_changed", "actor":owner.public_key().to_hex(), "topic":"Status: approved"})
    );

    // Empty topics explicitly clear the channel header and NIP-29 topic tag.
    let cleared = execute_topic(&state, community, channel, &owner, "{{trigger.text}}", "").await;
    assert_eq!(cleared.status, RunStatus::Completed);
    assert_eq!(
        state
            .db
            .get_channel(community, channel)
            .await
            .unwrap()
            .topic
            .as_deref(),
        Some("")
    );
    let metadata = state
        .db
        .query_events_for_event_write(&buzz_db::event::EventQuery {
            kinds: Some(vec![KIND_NIP29_GROUP_METADATA as i32]),
            channel_id: Some(channel),
            limit: Some(10),
            ..buzz_db::event::EventQuery::for_community(community)
        })
        .await
        .unwrap();
    assert_eq!(metadata.len(), 1);
    assert!(!metadata[0]
        .event
        .tags
        .iter()
        .any(|tag| tag.as_slice().first().map(String::as_str) == Some("topic")));
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn workflow_topic_rejects_nonmembers_revocation_archival_and_colliding_tenants() {
    let (state, community, channel, owner) = fixture().await;
    let sink = RelayActionSink::new(&state);
    let other = nostr::Keys::generate();
    state
        .db
        .ensure_user(community, &other.public_key().to_bytes())
        .await
        .unwrap();
    assert!(sink
        .set_channel_topic(
            community,
            &channel.to_string(),
            "outsider",
            &other.public_key().to_hex()
        )
        .await
        .is_err());
    let neighbor = state
        .db
        .ensure_configured_community(&format!("neighbor-{}.test", Uuid::new_v4()))
        .await
        .unwrap()
        .id;
    state
        .db
        .ensure_user(neighbor, &other.public_key().to_bytes())
        .await
        .unwrap();
    state
        .db
        .create_channel_with_id(
            neighbor,
            channel,
            "colliding",
            ChannelType::Stream,
            ChannelVisibility::Open,
            None,
            &other.public_key().to_bytes(),
            None,
        )
        .await
        .unwrap();
    assert!(sink
        .set_channel_topic(
            neighbor,
            &channel.to_string(),
            "cross tenant",
            &owner.public_key().to_hex()
        )
        .await
        .is_err());
    assert!(state
        .db
        .get_channel(neighbor, channel)
        .await
        .unwrap()
        .topic
        .is_none());
    assert!(state
        .db
        .get_channel(community, channel)
        .await
        .unwrap()
        .topic
        .is_none());

    state
        .db
        .add_member(
            community,
            channel,
            &other.public_key().to_bytes(),
            MemberRole::Owner,
            Some(&owner.public_key().to_bytes()),
        )
        .await
        .unwrap();
    state
        .db
        .remove_member(
            community,
            channel,
            &owner.public_key().to_bytes(),
            &other.public_key().to_bytes(),
        )
        .await
        .unwrap();
    assert!(sink
        .set_channel_topic(
            community,
            &channel.to_string(),
            "revoked",
            &owner.public_key().to_hex()
        )
        .await
        .is_err());
    state.db.archive_channel(community, channel).await.unwrap();
    assert!(sink
        .set_channel_topic(
            community,
            &channel.to_string(),
            "archived",
            &other.public_key().to_hex()
        )
        .await
        .is_err());
    assert!(state
        .db
        .get_channel(community, channel)
        .await
        .unwrap()
        .topic
        .is_none());
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn workflow_topic_event_failure_rolls_back_metadata_change() {
    let (state, community, channel, owner) = fixture().await;
    let forbidden = EventBuilder::new(Kind::Custom(22242), "AUTH events cannot be persisted")
        .tags([Tag::parse(["h", &channel.to_string()]).unwrap()])
        .sign_with_keys(&owner)
        .unwrap();
    assert!(state
        .db
        .set_topic_with_member_event(
            community,
            channel,
            "must roll back",
            &owner.public_key().to_bytes(),
            &forbidden
        )
        .await
        .is_err());
    assert!(state
        .db
        .get_channel(community, channel)
        .await
        .unwrap()
        .topic
        .is_none());
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn workflow_topic_allows_ordinary_members_and_rejects_unscoped_workflows() {
    let (state, community, channel, owner) = fixture().await;
    let member = nostr::Keys::generate();
    state
        .db
        .ensure_user(community, &member.public_key().to_bytes())
        .await
        .unwrap();
    state
        .db
        .add_member(
            community,
            channel,
            &member.public_key().to_bytes(),
            MemberRole::Member,
            None,
        )
        .await
        .unwrap();
    let sink = RelayActionSink::new(&state);
    sink.set_channel_topic(
        community,
        &channel.to_string(),
        "member topic",
        &member.public_key().to_hex(),
    )
    .await
    .unwrap();
    let saved = state.db.get_channel(community, channel).await.unwrap();
    assert_eq!(saved.topic.as_deref(), Some("member topic"));
    assert_eq!(
        saved.topic_set_by,
        Some(member.public_key().to_bytes().to_vec())
    );
    assert!(saved.topic_set_at.is_some());

    let (definition, canonical) = buzz_workflow::WorkflowEngine::parse_yaml(
        "name: unscoped\ntrigger:\n  on: webhook\nsteps:\n  - id: topic\n    action: set_channel_topic\n    topic: forbidden\n",
    ).unwrap();
    let workflow = state
        .db
        .create_workflow(
            community,
            None,
            &owner.public_key().to_bytes(),
            "unscoped",
            &canonical,
            &[2; 32],
        )
        .await
        .unwrap();
    let run = state
        .db
        .create_workflow_run(community, workflow, None, None)
        .await
        .unwrap();
    let trigger = buzz_workflow::executor::TriggerContext {
        channel_id: channel.to_string(),
        ..Default::default()
    };
    let result = buzz_workflow::executor::execute_run(
        &state.workflow_engine,
        community,
        run,
        &definition,
        &trigger,
    )
    .await;
    assert!(matches!(
        &result,
        Err((buzz_workflow::WorkflowError::InvalidDefinition(_), _))
    ));
    state
        .workflow_engine
        .finalize_run(community, run, result, None)
        .await;
    assert_eq!(
        state
            .db
            .get_workflow_run(community, run)
            .await
            .unwrap()
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
        Some("member topic")
    );
}

pub(super) async fn execute_topic(
    state: &Arc<AppState>,
    community: CommunityId,
    channel: Uuid,
    owner: &nostr::Keys,
    template: &str,
    text: &str,
) -> buzz_db::workflow::WorkflowRunRecord {
    let yaml = format!("name: topic-fixture\ntrigger:\n  on: webhook\nsteps:\n  - id: topic\n    action: set_channel_topic\n    topic: {}\n", serde_json::to_string(template).unwrap());
    let (def, canonical) = buzz_workflow::WorkflowEngine::parse_yaml(&yaml).unwrap();
    let workflow = state
        .db
        .create_workflow(
            community,
            Some(channel),
            &owner.public_key().to_bytes(),
            "topic-fixture",
            &canonical,
            &[3; 32],
        )
        .await
        .unwrap();
    let trigger = buzz_workflow::executor::TriggerContext {
        text: text.to_string(),
        channel_id: Uuid::new_v4().to_string(),
        author: nostr::Keys::generate().public_key().to_hex(),
        ..Default::default()
    };
    let run = state
        .db
        .create_workflow_run(
            community,
            workflow,
            None,
            Some(&serde_json::to_value(&trigger).unwrap()),
        )
        .await
        .unwrap();
    let result = buzz_workflow::executor::execute_run(
        &state.workflow_engine,
        community,
        run,
        &def,
        &trigger,
    )
    .await;
    state
        .workflow_engine
        .finalize_run(community, run, result, None)
        .await;
    state.db.get_workflow_run(community, run).await.unwrap()
}

pub(super) async fn events(
    state: &AppState,
    community: CommunityId,
    channel: Uuid,
    kind: u32,
) -> Vec<buzz_core::StoredEvent> {
    state
        .db
        .query_events_for_event_write(&buzz_db::event::EventQuery {
            kinds: Some(vec![kind as i32]),
            channel_id: Some(channel),
            limit: Some(100),
            ..buzz_db::event::EventQuery::for_community(community)
        })
        .await
        .unwrap()
}
