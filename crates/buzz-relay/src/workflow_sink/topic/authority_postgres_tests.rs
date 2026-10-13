use super::postgres_tests::{events, fixture};
use super::*;
use buzz_core::channel::MemberRole;
use buzz_core::kind::KIND_NIP29_GROUP_METADATA;
use std::time::Duration;

async fn member_without_user(
    state: &AppState,
    community: CommunityId,
    channel: Uuid,
) -> nostr::Keys {
    let member = nostr::Keys::generate();
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
    assert!(state
        .db
        .get_user(community, &member.public_key().to_bytes())
        .await
        .unwrap()
        .is_none());
    assert!(state
        .db
        .get_community_ban(community, &member.public_key().to_bytes())
        .await
        .unwrap()
        .is_none());
    member
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn workflow_topic_preserves_ordinary_member_without_user_row() {
    let (state, community, channel, _) = fixture().await;
    let member = member_without_user(&state, community, channel).await;
    RelayActionSink::new(&state)
        .set_channel_topic(
            community,
            &channel.to_string(),
            "ordinary member",
            &member.public_key().to_hex(),
        )
        .await
        .unwrap();
    let saved = state.db.get_channel(community, channel).await.unwrap();
    assert_eq!(saved.topic.as_deref(), Some("ordinary member"));
    assert_eq!(
        saved.topic_set_by,
        Some(member.public_key().to_bytes().to_vec())
    );
    assert!(saved.topic_set_at.is_some());
    let user = state
        .db
        .get_user(community, &member.public_key().to_bytes())
        .await
        .unwrap()
        .unwrap();
    assert!(user.display_name.is_none());
    assert!(user.avatar_url.is_none());
    assert!(user.about.is_none());
    assert!(user.nip05_handle.is_none());
    let (_, persisted_owner) = state
        .db
        .get_agent_channel_policy(community, &member.public_key().to_bytes())
        .await
        .unwrap()
        .unwrap();
    assert!(persisted_owner.is_none());
    let restrictions = state
        .db
        .moderation_principal_restriction_state(community, &member.public_key().to_bytes(), None)
        .await
        .unwrap();
    assert!(!restrictions.banned);
    assert!(restrictions.muted_until.is_none());
    assert_eq!(
        events(&state, community, channel, KIND_SYSTEM_MESSAGE)
            .await
            .len(),
        1
    );
    let metadata = events(&state, community, channel, KIND_NIP29_GROUP_METADATA).await;
    assert_eq!(metadata.len(), 1);
    assert!(metadata[0]
        .event
        .tags
        .iter()
        .any(|tag| tag.as_slice() == ["topic", "ordinary member"]));
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn workflow_topic_notice_failure_rolls_back_provisional_authority_rows() {
    let (state, community, channel, _) = fixture().await;
    let member = member_without_user(&state, community, channel).await;
    let forbidden = EventBuilder::new(Kind::Custom(22242), "AUTH cannot be stored")
        .tags([Tag::parse(["h", &channel.to_string()]).unwrap()])
        .sign_with_keys(&member)
        .unwrap();
    let result = state
        .db
        .set_topic_with_member_event(
            community,
            channel,
            "rollback",
            &member.public_key().to_bytes(),
            &forbidden,
        )
        .await;
    assert!(
        matches!(result, Err(buzz_db::DbError::AuthEventRejected)),
        "must reach the event insertion after authority rows: {result:?}"
    );
    assert!(state
        .db
        .get_user(community, &member.public_key().to_bytes())
        .await
        .unwrap()
        .is_none());
    assert!(state
        .db
        .get_community_ban(community, &member.public_key().to_bytes())
        .await
        .unwrap()
        .is_none());
    let saved = state.db.get_channel(community, channel).await.unwrap();
    assert!(saved.topic.is_none());
    assert!(saved.topic_set_by.is_none());
    assert!(saved.topic_set_at.is_none());
    assert!(events(&state, community, channel, KIND_SYSTEM_MESSAGE)
        .await
        .is_empty());
    assert!(
        events(&state, community, channel, KIND_NIP29_GROUP_METADATA)
            .await
            .is_empty()
    );
}

// Identify the real production statement and its particular blocker. A sleep
// or an unrelated Lock wait cannot satisfy this barrier.
async fn blocked_pid<T>(
    state: &AppState,
    blocker: i32,
    query_pattern: &str,
    task: &tokio::task::JoinHandle<T>,
) -> i32 {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            assert!(!task.is_finished(), "production writer bypassed the retained authority fence");
            let mut probe = state.db.begin_event_write_transaction().await.unwrap();
            let pid: Option<i32> = sqlx::query_scalar(
                "SELECT pid FROM pg_stat_activity WHERE datname = current_database() AND query LIKE $2 AND $1 = ANY(pg_blocking_pids(pid)) LIMIT 1",
            ).bind(blocker).bind(query_pattern).fetch_optional(&mut *probe).await.unwrap();
            if let Some(pid) = pid { return pid; }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }).await.expect("specific production writer reached its competing lock")
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn workflow_topic_holds_moderation_and_mapping_fences_through_notice_commit() {
    for restriction in [
        "first ban",
        "existing ban",
        "existing timeout",
        "inherited ban",
        "owner mapping",
    ] {
        let (state, community, channel, human) = fixture().await;
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
                MemberRole::Member,
                None,
            )
            .await
            .unwrap();
        if restriction.starts_with("existing") {
            state
                .db
                .timeout_community_member(
                    community,
                    &principal.public_key().to_bytes(),
                    &human.public_key().to_bytes(),
                    chrono::Utc::now() - chrono::Duration::minutes(1),
                    None,
                )
                .await
                .unwrap();
        }
        if restriction == "inherited ban" {
            state
                .db
                .set_agent_owner(
                    community,
                    &principal.public_key().to_bytes(),
                    &human.public_key().to_bytes(),
                )
                .await
                .unwrap();
            state
                .db
                .timeout_community_member(
                    community,
                    &human.public_key().to_bytes(),
                    &human.public_key().to_bytes(),
                    chrono::Utc::now() - chrono::Duration::minutes(1),
                    None,
                )
                .await
                .unwrap();
        }
        if restriction == "owner mapping" {
            state
                .db
                .ban_community_member(
                    community,
                    &human.public_key().to_bytes(),
                    &human.public_key().to_bytes(),
                    None,
                    None,
                )
                .await
                .unwrap();
        }
        let notice = EventBuilder::new(Kind::Custom(KIND_SYSTEM_MESSAGE as u16), "retained fence")
            .tags([Tag::parse(["h", &channel.to_string()]).unwrap()])
            .sign_with_keys(&state.relay_keypair)
            .unwrap();
        let notice_id = notice.id;
        // Stop the actual notice INSERT after all source authorization locks
        // have been acquired. Reads remain possible for precise lock probes.
        let mut notice_guard = state.db.begin_event_write_transaction().await.unwrap();
        sqlx::query("LOCK TABLE events IN SHARE MODE")
            .execute(&mut *notice_guard)
            .await
            .unwrap();
        let guard_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *notice_guard)
            .await
            .unwrap();
        let contender = Arc::clone(&state);
        let actor = principal.public_key().to_bytes();
        let source = tokio::spawn(async move {
            contender
                .db
                .set_topic_with_member_event(
                    community,
                    channel,
                    "serialized before restriction",
                    &actor,
                    &notice,
                )
                .await
        });
        let source_pid = blocked_pid(&state, guard_pid, "%INSERT INTO events%", &source).await;
        let writer = Arc::clone(&state);
        let target = if restriction == "inherited ban" {
            human.public_key().to_bytes()
        } else {
            principal.public_key().to_bytes()
        };
        let human_key = human.public_key().to_bytes();
        let restriction_write = tokio::spawn(async move {
            match restriction {
                "owner mapping" => writer
                    .db
                    .set_agent_owner(community, &target, &human_key)
                    .await
                    .map(|_| ()),
                "existing timeout" => writer
                    .db
                    .timeout_community_member(
                        community,
                        &target,
                        &human_key,
                        chrono::Utc::now() + chrono::Duration::minutes(10),
                        None,
                    )
                    .await
                    .map(|_| ()),
                _ => writer
                    .db
                    .ban_community_member(community, &target, &human_key, None, None)
                    .await
                    .map(|_| ()),
            }
        });
        let pattern = if restriction == "owner mapping" {
            "%UPDATE users%"
        } else {
            "%INSERT INTO community_bans%"
        };
        blocked_pid(&state, source_pid, pattern, &restriction_write).await;
        assert!(state
            .db
            .get_channel(community, channel)
            .await
            .unwrap()
            .topic
            .is_none());
        notice_guard.commit().await.unwrap();
        let (stored, inserted) = tokio::time::timeout(Duration::from_secs(5), source)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(inserted);
        assert_eq!(stored.event.id, notice_id);
        tokio::time::timeout(Duration::from_secs(5), restriction_write)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let saved = state.db.get_channel(community, channel).await.unwrap();
        assert_eq!(
            saved.topic.as_deref(),
            Some("serialized before restriction")
        );
        assert_eq!(
            events(&state, community, channel, KIND_SYSTEM_MESSAGE)
                .await
                .len(),
            1
        );
        let state_after = state
            .db
            .moderation_principal_restriction_state(
                community,
                &principal.public_key().to_bytes(),
                None,
            )
            .await
            .unwrap();
        if restriction == "existing timeout" {
            assert!(state_after.muted_until.is_some());
        } else {
            assert!(state_after.banned);
        }
    }
}
