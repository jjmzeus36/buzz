use super::postgres_tests::{events, fixture};
use super::*;
use buzz_core::channel::MemberRole;
use buzz_core::kind::KIND_NIP29_GROUP_METADATA;

async fn versions(state: &AppState, community: CommunityId, channel: Uuid) -> (i64, i64) {
    let mut tx = state.db.begin_event_write_transaction().await.unwrap();
    sqlx::query_as("SELECT requested_version, completed_version FROM channel_metadata_refresh WHERE community_id = $1 AND channel_id = $2")
        .bind(community.as_uuid()).bind(channel).fetch_one(&mut *tx).await.unwrap()
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn metadata_snapshot_only_completes_its_captured_generation() {
    let (state, community, channel, _) = fixture().await;
    let relay = state.relay_keypair.public_key().to_bytes();
    let before = versions(&state, community, channel).await;
    let empty_snapshot = state
        .db
        .lock_metadata_snapshot(community, channel, &relay)
        .await
        .unwrap();
    empty_snapshot.release().await.unwrap();
    assert_eq!(
        versions(&state, community, channel).await,
        before,
        "releasing without persisting cannot acknowledge work"
    );

    let mut snapshot = state
        .db
        .lock_metadata_snapshot(community, channel, &relay)
        .await
        .unwrap();
    let member = nostr::Keys::generate();
    state
        .db
        .ensure_user(community, &member.public_key().to_bytes())
        .await
        .unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        state.db.add_member(
            community,
            channel,
            &member.public_key().to_bytes(),
            MemberRole::Member,
            None,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let newer = versions(&state, community, channel).await;
    assert!(newer.0 > before.0);
    let event = EventBuilder::new(Kind::Custom(KIND_NIP29_GROUP_METADATA as u16), "")
        .tags([Tag::parse(["d", &channel.to_string()]).unwrap()])
        .sign_with_keys(&state.relay_keypair)
        .unwrap();
    assert!(snapshot.replace_metadata_event(&event).await.unwrap().1);
    snapshot.release().await.unwrap();
    let after = versions(&state, community, channel).await;
    assert_eq!(after.0, newer.0);
    assert_eq!(
        after.1, before.0,
        "newer source generation must remain pending"
    );
    crate::metadata_refresh::refresh_pending_metadata(&state)
        .await
        .unwrap();
    let recovered = versions(&state, community, channel).await;
    assert_eq!(recovered.0, recovered.1);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn metadata_acknowledgement_failure_rolls_back_projection_and_remains_recoverable() {
    let (state, community, channel, owner) = fixture().await;
    let tenant = TenantContext::resolved(community, "unused.test");
    crate::handlers::side_effects::emit_group_metadata_event(&tenant, &state, channel)
        .await
        .unwrap();
    let old = events(&state, community, channel, KIND_NIP29_GROUP_METADATA).await;
    state
        .db
        .set_topic(
            community,
            channel,
            "recover me",
            &owner.public_key().to_bytes(),
        )
        .await
        .unwrap();
    let function = format!("reject_metadata_ack_{}", Uuid::new_v4().simple());
    let trigger = format!("trg_{function}");
    let mut tx = state.db.begin_event_write_transaction().await.unwrap();
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN \
         IF NEW.community_id = '{community}'::uuid AND NEW.channel_id = '{channel}'::uuid \
         AND NEW.completed_version > OLD.completed_version THEN RAISE EXCEPTION 'fixture ack rejected'; END IF; RETURN NEW; END $$; \
         CREATE TRIGGER {trigger} BEFORE UPDATE ON channel_metadata_refresh FOR EACH ROW EXECUTE FUNCTION {function}();"
    ))).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    let error = crate::handlers::side_effects::emit_group_metadata_event(&tenant, &state, channel)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("fixture ack rejected"));
    assert_eq!(
        events(&state, community, channel, KIND_NIP29_GROUP_METADATA).await[0]
            .event
            .id,
        old[0].event.id
    );
    let pending = versions(&state, community, channel).await;
    assert!(pending.0 > pending.1);
    let mut tx = state.db.begin_event_write_transaction().await.unwrap();
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "DROP TRIGGER {trigger} ON channel_metadata_refresh; DROP FUNCTION {function}();"
    )))
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    crate::metadata_refresh::refresh_pending_metadata(&state)
        .await
        .unwrap();
    assert!(
        events(&state, community, channel, KIND_NIP29_GROUP_METADATA).await[0]
            .event
            .tags
            .iter()
            .any(|tag| tag.as_slice() == ["topic", "recover me"])
    );
    let done = versions(&state, community, channel).await;
    assert_eq!(done.0, done.1);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn metadata_recovery_does_not_extend_ephemeral_channel_lifetime() {
    let (state, community, channel, _) = fixture().await;
    state
        .db
        .update_channel(
            community,
            channel,
            buzz_db::channel::ChannelUpdate {
                ttl_seconds: Some(Some(600)),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let deadline = state
        .db
        .get_channel(community, channel)
        .await
        .unwrap()
        .ttl_deadline;
    assert!(deadline.is_some());
    crate::metadata_refresh::refresh_pending_metadata(&state)
        .await
        .unwrap();
    assert_eq!(
        state
            .db
            .get_channel(community, channel)
            .await
            .unwrap()
            .ttl_deadline,
        deadline,
        "derived publication is not user activity"
    );
    let done = versions(&state, community, channel).await;
    assert_eq!(done.0, done.1, "metadata must not enqueue itself forever");
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn metadata_claims_are_bounded_tenant_scoped_and_old_workers_cannot_release_new_claims() {
    let (state, community, channel, owner) = fixture().await;
    let other = state
        .db
        .ensure_configured_community(&format!("refresh-other-{}.test", Uuid::new_v4()))
        .await
        .unwrap()
        .id;
    let mut tx = state.db.begin_event_write_transaction().await.unwrap();
    sqlx::query("INSERT INTO channels (community_id, id, name, created_by) VALUES ($1, $2, 'same UUID, different tenant', $3)")
        .bind(other.as_uuid()).bind(channel).bind(owner.public_key().to_bytes().as_slice()).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO channels (community_id, name, created_by) SELECT $1, 'bounded backlog', $2 FROM generate_series(1, 10)")
        .bind(community.as_uuid()).bind(owner.public_key().to_bytes().as_slice()).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    let first = state.db.claim_metadata_refreshes().await.unwrap();
    assert_eq!(first.len(), 8);
    let second = state.db.claim_metadata_refreshes().await.unwrap();
    assert!(second.len() <= 8);
    assert!(first.iter().all(|a| second
        .iter()
        .all(|b| (a.community_id, a.channel_id) != (b.community_id, b.channel_id))));
    let original = first
        .iter()
        .chain(&second)
        .find(|claim| claim.community_id == community && claim.channel_id == channel)
        .unwrap();
    let isolated = first
        .iter()
        .chain(&second)
        .find(|claim| claim.community_id == other && claim.channel_id == channel)
        .unwrap();
    let mut tx = state.db.begin_event_write_transaction().await.unwrap();
    sqlx::query("UPDATE channel_metadata_refresh SET lease_until = NOW() - INTERVAL '1 second' WHERE community_id = $1 AND channel_id = $2")
        .bind(community.as_uuid()).bind(channel).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    let reclaimed = state.db.claim_metadata_refreshes().await.unwrap();
    let replacement = reclaimed
        .iter()
        .find(|claim| claim.community_id == community && claim.channel_id == channel)
        .unwrap();
    assert_ne!(original.lease_token, replacement.lease_token);
    state.db.release_metadata_refresh(original).await.unwrap();
    let mut tx = state.db.begin_event_write_transaction().await.unwrap();
    for expected in [replacement, isolated] {
        let token: Uuid = sqlx::query_scalar("SELECT lease_token FROM channel_metadata_refresh WHERE community_id = $1 AND channel_id = $2")
            .bind(expected.community_id.as_uuid()).bind(expected.channel_id).fetch_one(&mut *tx).await.unwrap();
        assert_eq!(token, expected.lease_token);
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn metadata_worker_recovers_pending_state_and_joins_on_shutdown() {
    let (state, community, channel, _) = fixture().await;
    let cancel = tokio_util::sync::CancellationToken::new();
    let worker = tokio::spawn(crate::metadata_refresh::run(
        Arc::clone(&state),
        cancel.clone(),
    ));
    let recovered = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let (requested, completed) = versions(&state, community, channel).await;
            if requested == completed {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await;
    cancel.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(1), worker)
        .await
        .unwrap()
        .unwrap();
    recovered.unwrap();
    let metadata = events(&state, community, channel, KIND_NIP29_GROUP_METADATA).await;
    assert_eq!(metadata.len(), 1);
    metadata[0].event.verify().unwrap();
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn metadata_publication_rechecks_community_archive_after_claim() {
    let (state, community, channel, _) = fixture().await;
    let claims = state.db.claim_metadata_refreshes().await.unwrap();
    let claim = claims
        .iter()
        .find(|claim| claim.community_id == community && claim.channel_id == channel)
        .unwrap();
    let mut tx = state.db.begin_event_write_transaction().await.unwrap();
    sqlx::query("UPDATE communities SET archived_at = NOW() WHERE id = $1")
        .bind(community.as_uuid())
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let tenant = TenantContext::resolved(community, claim.host.clone());
    assert!(
        crate::handlers::side_effects::emit_group_metadata_event(&tenant, &state, channel)
            .await
            .is_err()
    );
    assert!(
        events(&state, community, channel, KIND_NIP29_GROUP_METADATA)
            .await
            .is_empty()
    );
    let pending = versions(&state, community, channel).await;
    assert!(pending.0 > pending.1);
    assert!(state
        .db
        .claim_metadata_refreshes()
        .await
        .unwrap()
        .iter()
        .all(|candidate| candidate.community_id != community));
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn metadata_queue_keeps_oldest_pending_time_until_completion() {
    let (state, community, channel, owner) = fixture().await;
    let mut tx = state.db.begin_event_write_transaction().await.unwrap();
    sqlx::query("UPDATE channel_metadata_refresh SET requested_at = '2000-01-01'::timestamptz WHERE community_id = $1 AND channel_id = $2")
        .bind(community.as_uuid()).bind(channel).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    async fn requested_at(
        state: &AppState,
        community: CommunityId,
        channel: Uuid,
    ) -> chrono::DateTime<chrono::Utc> {
        let mut tx = state.db.begin_event_write_transaction().await.unwrap();
        sqlx::query_scalar("SELECT requested_at FROM channel_metadata_refresh WHERE community_id = $1 AND channel_id = $2")
            .bind(community.as_uuid()).bind(channel).fetch_one(&mut *tx).await.unwrap()
    }
    let oldest = requested_at(&state, community, channel).await;
    state
        .db
        .set_topic(
            community,
            channel,
            "busy channel",
            &owner.public_key().to_bytes(),
        )
        .await
        .unwrap();
    assert_eq!(
        requested_at(&state, community, channel).await,
        oldest,
        "busy channels must not move behind newer pending work"
    );
    crate::metadata_refresh::refresh_pending_metadata(&state)
        .await
        .unwrap();
    let done = versions(&state, community, channel).await;
    assert_eq!(done.0, done.1);
    state
        .db
        .set_topic(
            community,
            channel,
            "new work",
            &owner.public_key().to_bytes(),
        )
        .await
        .unwrap();
    assert!(
        requested_at(&state, community, channel).await > oldest,
        "new pending work gets a fresh queue position"
    );
}
