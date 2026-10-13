use super::postgres_tests::{events, execute_topic, fixture};
use super::*;
use buzz_core::kind::KIND_NIP29_GROUP_METADATA;
use buzz_db::workflow::RunStatus;

// A fixture-scoped real INSERT failure exercises the production sink and SQL
// transaction, including committed metadata that must survive failed replaces.
#[tokio::test]
#[ignore = "requires Postgres"]
async fn workflow_topic_real_insert_failure_rolls_back_and_metadata_failure_fails_run() {
    for fail_kind in [KIND_SYSTEM_MESSAGE, KIND_NIP29_GROUP_METADATA] {
        let (state, community, channel, owner) = fixture().await;
        RelayActionSink::new(&state)
            .set_channel_topic(
                community,
                &channel.to_string(),
                "old",
                &owner.public_key().to_hex(),
            )
            .await
            .unwrap();
        let before = state.db.get_channel(community, channel).await.unwrap();
        let metadata_before = events(&state, community, channel, KIND_NIP29_GROUP_METADATA).await;
        let notices_before = events(&state, community, channel, KIND_SYSTEM_MESSAGE).await;
        let function = format!("topic_insert_failure_{}", Uuid::new_v4().simple());
        let trigger = format!("trg_{}", function);
        let mut fixture_tx = state.db.begin_event_write_transaction().await.unwrap();
        // All interpolated values are generated UUIDs/identifiers or kind
        // constants; no user-controlled strings enter this fixture DDL.
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN \
             IF NEW.community_id = '{community}'::uuid AND NEW.channel_id = '{channel}'::uuid AND NEW.kind = {fail_kind} THEN \
             RAISE EXCEPTION 'fixture topic insert rejected'; END IF; RETURN NEW; END $$; \
             CREATE TRIGGER {trigger} BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION {function}();"
        ))).execute(&mut *fixture_tx).await.unwrap();
        fixture_tx.commit().await.unwrap();
        let run = execute_topic(&state, community, channel, &owner, "new", "").await;
        let after = state.db.get_channel(community, channel).await.unwrap();
        let metadata_after = events(&state, community, channel, KIND_NIP29_GROUP_METADATA).await;
        let notices_after = events(&state, community, channel, KIND_SYSTEM_MESSAGE).await;
        let mut cleanup = state.db.begin_event_write_transaction().await.unwrap();
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "DROP TRIGGER {trigger} ON events; DROP FUNCTION {function}();"
        )))
        .execute(&mut *cleanup)
        .await
        .unwrap();
        cleanup.commit().await.unwrap();
        assert_eq!(run.status, RunStatus::Failed);
        assert!(run
            .error_message
            .unwrap()
            .contains("fixture topic insert rejected"));
        assert_eq!(
            metadata_after[0].event.id, metadata_before[0].event.id,
            "failed metadata replacement must retain old head"
        );
        if fail_kind == KIND_SYSTEM_MESSAGE {
            assert_eq!(after.topic, before.topic);
            assert_eq!(after.topic_set_by, before.topic_set_by);
            assert_eq!(after.topic_set_at, before.topic_set_at);
            assert_eq!(notices_after[0].event.id, notices_before[0].event.id);
            assert_eq!(notices_after.len(), notices_before.len());
        } else {
            // Source topic/notice transaction has committed; projection failure
            // is reported as failed execution, never a completed step.
            assert_eq!(after.topic.as_deref(), Some("new"));
            assert_eq!(notices_after.len(), notices_before.len() + 1);

            // A later source change must win recovery: never replay the failed
            // historical workflow action (or create another system notice).
            state
                .db
                .set_topic(community, channel, "newest", &owner.public_key().to_bytes())
                .await
                .unwrap();
            let claimed = state.db.claim_metadata_refreshes().await.unwrap();
            assert!(claimed
                .iter()
                .any(|claim| claim.community_id == community && claim.channel_id == channel));
            // Simulate a process exiting after its claim commits. Expiration
            // makes the durable work available to a fresh worker invocation.
            let mut expiry = state.db.begin_event_write_transaction().await.unwrap();
            sqlx::query("UPDATE channel_metadata_refresh SET lease_until = NOW() - INTERVAL '1 second' WHERE community_id = $1 AND channel_id = $2")
                .bind(community.as_uuid()).bind(channel).execute(&mut *expiry).await.unwrap();
            expiry.commit().await.unwrap();
            crate::metadata_refresh::refresh_pending_metadata(&state)
                .await
                .unwrap();
            let recovered = events(&state, community, channel, KIND_NIP29_GROUP_METADATA).await;
            assert_eq!(recovered.len(), 1);
            recovered[0].event.verify().unwrap();
            assert!(recovered[0]
                .event
                .tags
                .iter()
                .any(|tag| tag.as_slice() == ["topic", "newest"]));
            assert_eq!(
                events(&state, community, channel, KIND_SYSTEM_MESSAGE)
                    .await
                    .len(),
                notices_after.len()
            );
            assert!(state
                .db
                .claim_metadata_refreshes()
                .await
                .unwrap()
                .iter()
                .all(|claim| claim.community_id != community || claim.channel_id != channel));
        }
    }
}
