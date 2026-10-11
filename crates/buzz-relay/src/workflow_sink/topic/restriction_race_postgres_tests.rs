use super::*;
use std::time::Duration;

async fn wait_for_topic_blocker<T>(
    state: &AppState,
    guard_pid: i32,
    task: &tokio::task::JoinHandle<T>,
) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            assert!(!task.is_finished(), "topic action bypassed its held TTL fence");
            let mut probe = state.db.begin_event_write_transaction().await.unwrap();
            let blocked: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname = current_database() \
                 AND query LIKE '%pg_advisory_xact_lock_shared(hashtextextended%' AND $1 = ANY(pg_blocking_pids(pid)))",
            ).bind(guard_pid).fetch_one(&mut *probe).await.unwrap();
            if blocked { break; }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }).await.expect("real topic action must wait on the specific TTL guard");
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn workflow_topic_rechecks_moderation_committed_while_waiting_for_ttl() {
    use super::postgres_tests::{events, execute_topic, fixture};
    use buzz_core::{channel::MemberRole, kind::KIND_NIP29_GROUP_METADATA};
    use buzz_db::workflow::RunStatus;
    for restriction in [
        "direct ban",
        "direct timeout",
        "inherited ban",
        "inherited timeout",
        "new owner ban",
    ] {
        let (state, community, channel, owner) = fixture().await;
        let principal = if restriction.starts_with("inherited") || restriction == "new owner ban" {
            let agent = nostr::Keys::generate();
            state
                .db
                .ensure_user(community, &agent.public_key().to_bytes())
                .await
                .unwrap();
            state
                .db
                .set_agent_owner(
                    community,
                    &agent.public_key().to_bytes(),
                    &owner.public_key().to_bytes(),
                )
                .await
                .unwrap();
            state
                .db
                .add_member(
                    community,
                    channel,
                    &agent.public_key().to_bytes(),
                    MemberRole::Bot,
                    None,
                )
                .await
                .unwrap();
            if restriction == "new owner ban" {
                let mut cleanup = state.db.begin_event_write_transaction().await.unwrap();
                sqlx::query("UPDATE users SET agent_owner_pubkey = NULL WHERE community_id = $1 AND pubkey = $2")
                    .bind(community.as_uuid()).bind(agent.public_key().to_bytes().as_slice())
                    .execute(&mut *cleanup).await.unwrap();
                cleanup.commit().await.unwrap();
            }
            agent
        } else {
            owner.clone()
        };
        let mut ttl_guard = state.db.begin_event_write_transaction().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!(
                "buzz_channel_ttl:{}:{}",
                community.as_uuid(),
                channel
            ))
            .execute(&mut *ttl_guard)
            .await
            .unwrap();
        let guard_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *ttl_guard)
            .await
            .unwrap();
        let contender = Arc::clone(&state);
        let principal_for_run = principal.clone();
        let task = tokio::spawn(async move {
            execute_topic(
                &contender,
                community,
                channel,
                &principal_for_run,
                "late write",
                "",
            )
            .await
        });
        wait_for_topic_blocker(&state, guard_pid, &task).await;
        if restriction == "new owner ban" {
            state
                .db
                .ensure_user(community, &principal.public_key().to_bytes())
                .await
                .unwrap();
            state
                .db
                .set_agent_owner(
                    community,
                    &principal.public_key().to_bytes(),
                    &owner.public_key().to_bytes(),
                )
                .await
                .unwrap();
        }
        if restriction.ends_with("timeout") {
            state
                .db
                .timeout_community_member(
                    community,
                    &owner.public_key().to_bytes(),
                    &owner.public_key().to_bytes(),
                    chrono::Utc::now() + chrono::Duration::minutes(10),
                    None,
                )
                .await
                .unwrap();
        } else {
            state
                .db
                .ban_community_member(
                    community,
                    &owner.public_key().to_bytes(),
                    &owner.public_key().to_bytes(),
                    None,
                    None,
                )
                .await
                .unwrap();
        }
        assert!(state
            .db
            .is_member(community, channel, &principal.public_key().to_bytes())
            .await
            .unwrap());
        ttl_guard.commit().await.unwrap();
        let run = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        if restriction == "inherited timeout" {
            assert_eq!(
                run.status,
                RunStatus::Completed,
                "human-owner timeout must not block its agent"
            );
            assert_eq!(run.current_step, 1);
            assert_eq!(
                run.execution_trace,
                serde_json::json!([{"step_id": "topic", "status": "completed", "output": {"updated": true, "topic": "late write"}}])
            );
            assert!(run.error_code.is_none());
            assert!(run.error_message.is_none());
            assert_eq!(
                state
                    .db
                    .get_channel(community, channel)
                    .await
                    .unwrap()
                    .topic
                    .as_deref(),
                Some("late write")
            );
            continue;
        }
        assert_eq!(
            run.status,
            RunStatus::Failed,
            "restriction committed during the TTL wait: {restriction}"
        );
        assert_eq!(run.current_step, 0);
        assert_eq!(run.execution_trace, serde_json::json!([]));
        assert_eq!(run.error_code.as_deref(), Some("webhook_failed"));
        assert!(run
            .error_message
            .as_deref()
            .unwrap()
            .contains("topic principal is currently banned or timed out"));
        assert!(run.started_at.is_some());
        assert!(run.completed_at.is_some());
        if restriction == "inherited ban" || restriction == "new owner ban" {
            assert!(
                state
                    .db
                    .get_community_ban(community, &principal.public_key().to_bytes())
                    .await
                    .unwrap()
                    .is_none(),
                "denied authorization must roll back a provisional principal fence"
            );
        }
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
}
