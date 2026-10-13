use super::*;
use crate::handlers::ingest::{ingest_event, IngestAuth, IngestError};
use buzz_auth::Scope;
use buzz_core::{
    channel::{ChannelType, ChannelVisibility},
    CommunityId,
};
use nostr::Keys;

async fn fixture() -> (Arc<AppState>, TenantContext, Uuid, Keys, sqlx::PgPool) {
    let state = crate::workflow_sink::postgres_tests::test_state().await;
    let owner = Keys::generate();
    let host = format!("atomic-{}.test", Uuid::new_v4());
    let community = state
        .db
        .ensure_configured_community(&host)
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
            "atomic",
            ChannelType::Stream,
            ChannelVisibility::Open,
            None,
            &owner.public_key().to_bytes(),
            None,
        )
        .await
        .unwrap()
        .id;
    let pool = sqlx::PgPool::connect(&crate::test_support::database_url())
        .await
        .unwrap();
    (
        state,
        TenantContext::resolved(community, host),
        channel,
        owner,
        pool,
    )
}
fn command(keys: &Keys, channel: Uuid, kind: u16, tags: &[(&str, String)]) -> Event {
    let mut all = vec![
        Tag::parse(["h", &channel.to_string()]).unwrap(),
        Tag::parse(["nonce", &Uuid::new_v4().to_string()]).unwrap(),
    ];
    all.extend(
        tags.iter()
            .map(|(k, v)| Tag::parse([*k, v.as_str()]).unwrap()),
    );
    EventBuilder::new(Kind::Custom(kind), "")
        .tags(all)
        .allow_self_tagging()
        .sign_with_keys(keys)
        .unwrap()
}
fn auth(keys: &Keys) -> IngestAuth {
    IngestAuth::Nip42 {
        moderation_owner: None,
        pubkey: keys.public_key(),
        scopes: Scope::all_known(),
        channel_ids: None,
        conn_id: Uuid::new_v4(),
    }
}
async fn stored(pool: &sqlx::PgPool, community: CommunityId, event: &Event) -> bool {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM events WHERE community_id=$1 AND id=$2)")
        .bind(community.as_uuid())
        .bind(event.id.as_bytes().as_slice())
        .fetch_one(pool)
        .await
        .unwrap()
}
async fn notice_count(pool: &sqlx::PgPool, community: CommunityId) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM events WHERE community_id=$1 AND kind IN (40099,44100,44101)",
    )
    .bind(community.as_uuid())
    .fetch_one(pool)
    .await
    .unwrap()
}
async fn fault(pool: &sqlx::PgPool, kind: u32) {
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE FUNCTION reject_atomic_notice() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind={kind} THEN RAISE EXCEPTION 'mandatory notice unavailable'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_atomic_notice BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION reject_atomic_notice();")))
        .execute(pool).await.unwrap();
}
async fn recover(pool: &sqlx::PgPool) {
    sqlx::raw_sql(
        "DROP TRIGGER reject_atomic_notice ON events; DROP FUNCTION reject_atomic_notice();",
    )
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn ingest_membership_commands_rollback_required_notices_and_retry_once() {
    let (state, tenant, channel, owner, pool) = fixture().await;
    let target = Keys::generate();
    let add = command(
        &owner,
        channel,
        9000,
        &[("p", target.public_key().to_hex())],
    );
    fault(&pool, 44100).await;
    assert!(ingest_event(&state, &tenant, add.clone(), auth(&owner))
        .await
        .is_err());
    assert!(
        !stored(&pool, tenant.community(), &add).await,
        "failed add cannot leave source receipt"
    );
    assert!(!state
        .db
        .is_member(tenant.community(), channel, &target.public_key().to_bytes())
        .await
        .unwrap());
    assert_eq!(notice_count(&pool, tenant.community()).await, 0);
    recover(&pool).await;
    assert!(
        ingest_event(&state, &tenant, add.clone(), auth(&owner))
            .await
            .unwrap()
            .accepted
    );
    assert!(state
        .db
        .is_member(tenant.community(), channel, &target.public_key().to_bytes())
        .await
        .unwrap());
    assert_eq!(notice_count(&pool, tenant.community()).await, 2);
    let workflow = state
        .db
        .create_workflow(
            tenant.community(),
            Some(channel),
            &target.public_key().to_bytes(),
            "atomic-owned",
            r#"{"name":"atomic","trigger":{"on":"webhook"},"steps":[]}"#,
            &[9; 32],
        )
        .await
        .unwrap();
    let remove = command(
        &owner,
        channel,
        9001,
        &[("p", target.public_key().to_hex())],
    );
    fault(&pool, 44101).await;
    assert!(ingest_event(&state, &tenant, remove.clone(), auth(&owner))
        .await
        .is_err());
    assert!(!stored(&pool, tenant.community(), &remove).await);
    assert!(state
        .db
        .is_member(tenant.community(), channel, &target.public_key().to_bytes())
        .await
        .unwrap());
    assert!(
        state
            .db
            .get_workflow(tenant.community(), workflow)
            .await
            .unwrap()
            .enabled
    );
    assert_eq!(notice_count(&pool, tenant.community()).await, 2);
    recover(&pool).await;
    assert!(
        ingest_event(&state, &tenant, remove.clone(), auth(&owner))
            .await
            .unwrap()
            .accepted
    );
    assert!(!state
        .db
        .is_member(tenant.community(), channel, &target.public_key().to_bytes())
        .await
        .unwrap());
    assert!(
        !state
            .db
            .get_workflow(tenant.community(), workflow)
            .await
            .unwrap()
            .enabled
    );
    assert_eq!(notice_count(&pool, tenant.community()).await, 4);
    assert_eq!(
        ingest_event(&state, &tenant, add, auth(&owner))
            .await
            .unwrap()
            .message,
        "duplicate:"
    );
    assert!(
        !state
            .db
            .is_member(tenant.community(), channel, &target.public_key().to_bytes())
            .await
            .unwrap(),
        "old add must never reapply after removal"
    );
    assert_eq!(notice_count(&pool, tenant.community()).await, 4);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn ingest_metadata_rolls_back_every_tag_and_preserves_successful_receipt() {
    let (state, tenant, channel, owner, pool) = fixture().await;
    let edit = command(
        &owner,
        channel,
        9002,
        &[
            ("topic", "new topic".into()),
            ("purpose", "new purpose".into()),
            ("visibility", "private".into()),
        ],
    );
    fault(&pool, 40099).await;
    assert!(ingest_event(&state, &tenant, edit.clone(), auth(&owner))
        .await
        .is_err());
    let unchanged = state
        .db
        .get_channel(tenant.community(), channel)
        .await
        .unwrap();
    assert_eq!(unchanged.topic, None);
    assert_eq!(unchanged.purpose, None);
    assert_eq!(unchanged.visibility, "open");
    assert!(!stored(&pool, tenant.community(), &edit).await);
    recover(&pool).await;
    assert!(
        ingest_event(&state, &tenant, edit.clone(), auth(&owner))
            .await
            .unwrap()
            .accepted
    );
    assert_eq!(notice_count(&pool, tenant.community()).await, 3);
    let changed = state
        .db
        .get_channel(tenant.community(), channel)
        .await
        .unwrap();
    assert_eq!(changed.topic.as_deref(), Some("new topic"));
    assert_eq!(changed.visibility, "private");
    let invalid_late = command(
        &owner,
        channel,
        9002,
        &[
            ("topic", "must roll back".into()),
            ("archived", "true".into()),
            ("archived", "true".into()),
        ],
    );
    assert!(
        ingest_event(&state, &tenant, invalid_late.clone(), auth(&owner))
            .await
            .is_err()
    );
    let after = state
        .db
        .get_channel(tenant.community(), channel)
        .await
        .unwrap();
    assert_eq!(after.topic.as_deref(), Some("new topic"));
    assert!(after.archived_at.is_none());
    assert!(!stored(&pool, tenant.community(), &invalid_late).await);
    assert_eq!(notice_count(&pool, tenant.community()).await, 3);
    state
        .db
        .set_topic(
            tenant.community(),
            channel,
            "later",
            &owner.public_key().to_bytes(),
        )
        .await
        .unwrap();
    assert_eq!(
        ingest_event(&state, &tenant, edit, auth(&owner))
            .await
            .unwrap()
            .message,
        "duplicate:"
    );
    assert_eq!(
        state
            .db
            .get_channel(tenant.community(), channel)
            .await
            .unwrap()
            .topic
            .as_deref(),
        Some("later")
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn ingest_receipts_survive_self_removal_archive_but_not_tenant_or_token_changes() {
    let (state, tenant, channel, owner, pool) = fixture().await;
    let member = Keys::generate();
    state
        .db
        .add_member(
            tenant.community(),
            channel,
            &member.public_key().to_bytes(),
            MemberRole::Member,
            Some(&owner.public_key().to_bytes()),
        )
        .await
        .unwrap();
    state
        .db
        .update_channel(
            tenant.community(),
            channel,
            ChannelUpdate {
                visibility: Some("private".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let leave = command(
        &member,
        channel,
        9001,
        &[("p", member.public_key().to_hex())],
    );
    assert!(
        ingest_event(&state, &tenant, leave.clone(), auth(&member))
            .await
            .unwrap()
            .accepted
    );
    assert_eq!(
        ingest_event(&state, &tenant, leave.clone(), auth(&member))
            .await
            .unwrap()
            .message,
        "duplicate:"
    );
    let archive = command(&owner, channel, 9002, &[("archived", "true".into())]);
    assert!(
        ingest_event(&state, &tenant, archive.clone(), auth(&owner))
            .await
            .unwrap()
            .accepted
    );
    assert_eq!(
        ingest_event(&state, &tenant, archive.clone(), auth(&owner))
            .await
            .unwrap()
            .message,
        "duplicate:"
    );
    let other = state
        .db
        .ensure_configured_community(&format!("other-{}.test", Uuid::new_v4()))
        .await
        .unwrap()
        .id;
    assert!(matches!(
        ingest_event(
            &state,
            &TenantContext::resolved(other, "other.test"),
            archive.clone(),
            auth(&owner)
        )
        .await,
        Err(IngestError::Rejected(_))
    ));
    assert!(!stored(&pool, other, &archive).await);
    let mut restricted = auth(&owner);
    if let IngestAuth::Nip42 { channel_ids, .. } = &mut restricted {
        *channel_ids = Some(vec![Uuid::new_v4()]);
    }
    assert!(ingest_event(&state, &tenant, archive, restricted)
        .await
        .is_err());
    assert_eq!(notice_count(&pool, tenant.community()).await, 3);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn ingest_db_policy_denials_leave_no_receipt_and_absent_role_preserves_authority() {
    let (state, tenant, channel, owner, pool) = fixture().await;
    let outsider = Keys::generate();
    let elevated = command(
        &outsider,
        channel,
        9000,
        &[
            ("p", outsider.public_key().to_hex()),
            ("role", "owner".into()),
        ],
    );
    assert!(
        ingest_event(&state, &tenant, elevated.clone(), auth(&outsider))
            .await
            .is_err()
    );
    assert!(!stored(&pool, tenant.community(), &elevated).await);
    assert_eq!(notice_count(&pool, tenant.community()).await, 0);
    let preserve = command(&owner, channel, 9000, &[("p", owner.public_key().to_hex())]);
    assert!(
        ingest_event(&state, &tenant, preserve, auth(&owner))
            .await
            .unwrap()
            .accepted
    );
    let role:String=sqlx::query_scalar("SELECT role::text FROM channel_members WHERE community_id=$1 AND channel_id=$2 AND pubkey=$3")
        .bind(tenant.community().as_uuid()).bind(channel).bind(owner.public_key().to_bytes().as_slice()).fetch_one(&pool).await.unwrap();
    assert_eq!(role, "owner");
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn ingest_authority_is_rechecked_after_waiting_for_membership_writer() {
    let (state, tenant, channel, owner, pool) = fixture().await;
    let target = Keys::generate();
    state
        .db
        .ensure_user(tenant.community(), &target.public_key().to_bytes())
        .await
        .unwrap();
    let event = command(
        &owner,
        channel,
        9000,
        &[("p", target.public_key().to_hex())],
    );
    let mut writer = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!(
            "buzz_channel_membership:{}:{}",
            tenant.community(),
            channel
        ))
        .execute(&mut *writer)
        .await
        .unwrap();
    let task = tokio::spawn({
        let state = Arc::clone(&state);
        let tenant = tenant.clone();
        let event = event.clone();
        let auth = auth(&owner);
        async move { ingest_event(&state, &tenant, event, auth).await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(5),async {
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory')").fetch_one(&pool).await.unwrap();
            if waiting {break;}
            tokio::task::yield_now().await;
        }
    }).await.expect("command reached held membership fence");
    sqlx::query("UPDATE users SET channel_add_policy='nobody' WHERE community_id=$1 AND pubkey=$2")
        .bind(tenant.community().as_uuid())
        .bind(target.public_key().to_bytes().as_slice())
        .execute(&mut *writer)
        .await
        .unwrap();
    writer.commit().await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(!stored(&pool, tenant.community(), &event).await);
    assert!(!state
        .db
        .is_member(tenant.community(), channel, &target.public_key().to_bytes())
        .await
        .unwrap());
    assert_eq!(notice_count(&pool, tenant.community()).await, 0);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn ingest_notices_use_relay_time_and_distinct_signed_occurrences() {
    let (state, tenant, channel, owner, pool) = fixture().await;
    let before = nostr::Timestamp::now();
    let target = Keys::generate();
    let make = |kind, time| {
        EventBuilder::new(Kind::Custom(kind), "")
            .tags([
                Tag::parse(["h", &channel.to_string()]).unwrap(),
                Tag::parse(["p", &target.public_key().to_hex()]).unwrap(),
            ])
            .custom_created_at(nostr::Timestamp::from(time))
            .sign_with_keys(&owner)
            .unwrap()
    };
    let add = make(9000, before.as_secs() + 60);
    let remove = make(9001, before.as_secs() - 60);
    assert!(
        ingest_event(&state, &tenant, add, auth(&owner))
            .await
            .unwrap()
            .accepted
    );
    assert!(
        ingest_event(&state, &tenant, remove, auth(&owner))
            .await
            .unwrap()
            .accepted
    );
    let notices = state
        .db
        .query_events_for_event_write(&buzz_db::event::EventQuery {
            kinds: Some(vec![44100, 44101]),
            limit: Some(10),
            ..buzz_db::event::EventQuery::for_community(tenant.community())
        })
        .await
        .unwrap();
    assert_eq!(notices.len(), 2);
    for notice in notices {
        assert!(notice.event.created_at >= before);
        assert!(notice.event.created_at <= nostr::Timestamp::now());
        notice.event.verify().unwrap();
    }
    let repeat = command(
        &owner,
        channel,
        9002,
        &[
            ("topic", "A".into()),
            ("topic", "B".into()),
            ("topic", "A".into()),
        ],
    );
    assert!(
        ingest_event(&state, &tenant, repeat, auth(&owner))
            .await
            .unwrap()
            .accepted
    );
    assert_eq!(
        notice_count(&pool, tenant.community()).await,
        7,
        "each signed occurrence persists a distinct notice"
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn command_guard_uses_one_writer_connection_for_owned_agent_remove() {
    let (state, tenant, channel, owner, pool) = fixture().await;
    let agent = Keys::generate();
    state
        .db
        .ensure_user(tenant.community(), &agent.public_key().to_bytes())
        .await
        .unwrap();
    sqlx::query("UPDATE users SET agent_owner_pubkey=$3 WHERE community_id=$1 AND pubkey=$2")
        .bind(tenant.community().as_uuid())
        .bind(agent.public_key().to_bytes().as_slice())
        .bind(owner.public_key().to_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    state
        .db
        .add_member(
            tenant.community(),
            channel,
            &agent.public_key().to_bytes(),
            MemberRole::Member,
            Some(&owner.public_key().to_bytes()),
        )
        .await
        .unwrap();
    let one = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&crate::test_support::database_url())
        .await
        .unwrap();
    let db = buzz_db::Db::from_pool(one);
    let event = command(&owner, channel, 9001, &[("p", agent.public_key().to_hex())]);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        db.lock_channel_command(tenant.community(), channel, &event, None)
            .await
            .unwrap()
            .commit(ChannelCommandMutation::RemoveMember, Vec::new(), None)
            .await
            .unwrap();
    })
    .await
    .expect("caller-owned helpers cannot acquire a second connection");
    assert!(!state
        .db
        .is_member(tenant.community(), channel, &agent.public_key().to_bytes())
        .await
        .unwrap());
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn ingest_private_flip_rechecks_visibility_for_late_subscriber() {
    use std::{collections::HashMap, sync::atomic::AtomicU8};
    use tokio::sync::{mpsc, Mutex};
    use tokio_util::sync::CancellationToken;
    let (state, tenant, channel, owner, _) = fixture().await;
    let outsider = Keys::generate();
    let register = |key: &Keys| {
        let id = Uuid::new_v4();
        let (tx, rx) = mpsc::channel(16);
        let (ctrl, _) = mpsc::channel(4);
        state.conn_manager.register(
            id,
            tx,
            ctrl,
            None,
            CancellationToken::new(),
            tenant.community(),
            Arc::new(AtomicU8::new(0)),
            Arc::new(Mutex::new(HashMap::new())),
            3,
        );
        state
            .conn_manager
            .set_authenticated_pubkey(id, key.public_key().to_bytes().to_vec());
        (id, rx)
    };
    let (owner_id, mut owner_rx) = register(&owner);
    let (outsider_id, mut outsider_rx) = register(&outsider);
    let filter = nostr::Filter::new().kinds([Kind::Custom(9002), Kind::Custom(40099)]);
    state.sub_registry.register_scoped(
        tenant.community(),
        owner_id,
        "owner".into(),
        vec![filter.clone()],
        Some(channel),
    );
    let observer = tokio::spawn({
        let state = Arc::clone(&state);
        let community = tenant.community();
        async move {
            let frame = owner_rx.recv().await.unwrap();
            let axum::extract::ws::Message::Text(frame) = frame else {
                panic!("expected notice");
            };
            let value: serde_json::Value = serde_json::from_str(&frame).unwrap();
            assert_eq!(value[2]["kind"], 40099);
            // Model a subscription registration racing just after eviction.
            state.sub_registry.register_scoped(
                community,
                outsider_id,
                "late".into(),
                vec![filter],
                Some(channel),
            );
            let source = owner_rx.recv().await.unwrap();
            let axum::extract::ws::Message::Text(source) = source else {
                panic!("expected source");
            };
            let source: serde_json::Value = serde_json::from_str(&source).unwrap();
            assert_eq!(source[2]["kind"], 9002);
        }
    });
    let edit = command(&owner, channel, 9002, &[("visibility", "private".into())]);
    assert!(
        ingest_event(&state, &tenant, edit, auth(&owner))
            .await
            .unwrap()
            .accepted
    );
    tokio::time::timeout(std::time::Duration::from_secs(5), observer)
        .await
        .unwrap()
        .unwrap();
    assert!(
        outsider_rx.try_recv().is_err(),
        "pre-command Open must not authorize delivery after private flip"
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn ingest_receipt_requires_exact_stored_envelope_and_channel() {
    let (state, tenant, channel, owner, pool) = fixture().await;
    let event = command(&owner, channel, 9002, &[("topic", "accepted".into())]);
    assert!(
        ingest_event(&state, &tenant, event.clone(), auth(&owner))
            .await
            .unwrap()
            .accepted
    );
    sqlx::query("UPDATE events SET content='corrupt receipt' WHERE community_id=$1 AND id=$2")
        .bind(tenant.community().as_uuid())
        .bind(event.id.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        ingest_event(&state, &tenant, event.clone(), auth(&owner))
            .await
            .is_err(),
        "matching ID cannot mask a different stored signed envelope"
    );
    sqlx::query("UPDATE events SET content=$3, channel_id=NULL WHERE community_id=$1 AND id=$2")
        .bind(tenant.community().as_uuid())
        .bind(event.id.as_bytes().as_slice())
        .bind(&event.content)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        ingest_event(&state, &tenant, event, auth(&owner))
            .await
            .is_err(),
        "matching envelope cannot mask a different stored channel"
    );
    assert_eq!(notice_count(&pool, tenant.community()).await, 1);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn ingest_membership_history_and_mention_failure_share_command_transaction() {
    let (state, tenant, channel, owner, pool) = fixture().await;
    let target = Keys::generate();
    let add = command(
        &owner,
        channel,
        9000,
        &[("p", target.public_key().to_hex())],
    );
    sqlx::raw_sql("CREATE FUNCTION reject_atomic_mentions() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF EXISTS(SELECT 1 FROM events WHERE community_id=NEW.community_id AND id=NEW.event_id AND kind=44100) THEN RAISE EXCEPTION 'mention index unavailable'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_atomic_mentions BEFORE INSERT ON event_mentions FOR EACH ROW EXECUTE FUNCTION reject_atomic_mentions();").execute(&pool).await.unwrap();
    assert!(ingest_event(&state, &tenant, add.clone(), auth(&owner))
        .await
        .is_err());
    assert!(!stored(&pool, tenant.community(), &add).await);
    assert!(!state
        .db
        .is_member(tenant.community(), channel, &target.public_key().to_bytes())
        .await
        .unwrap());
    assert_eq!(notice_count(&pool, tenant.community()).await, 0);
    sqlx::raw_sql("DROP TRIGGER reject_atomic_mentions ON event_mentions; DROP FUNCTION reject_atomic_mentions();").execute(&pool).await.unwrap();
    assert!(
        ingest_event(&state, &tenant, add, auth(&owner))
            .await
            .unwrap()
            .accepted
    );
    let remove = command(
        &owner,
        channel,
        9001,
        &[("p", target.public_key().to_hex())],
    );
    assert!(
        ingest_event(&state, &tenant, remove, auth(&owner))
            .await
            .unwrap()
            .accepted
    );
    for (kind, scope) in [
        (9000, Some(channel)),
        (9001, Some(channel)),
        (44100, None),
        (44101, None),
    ] {
        let history = state
            .db
            .query_events_for_event_write(&buzz_db::event::EventQuery {
                kinds: Some(vec![kind]),
                p_tag_hex: Some(target.public_key().to_hex()),
                channel_id: scope,
                limit: Some(10),
                ..buzz_db::event::EventQuery::for_community(tenant.community())
            })
            .await
            .unwrap();
        assert_eq!(
            history.len(),
            1,
            "kind {kind} must be recoverable by authenticated #p history"
        );
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn ingest_held_authority_keeps_proven_owner_when_mapping_is_missing() {
    let (state, tenant, channel, owner, pool) = fixture().await;
    let agent = Keys::generate();
    state
        .db
        .ensure_user(tenant.community(), &agent.public_key().to_bytes())
        .await
        .unwrap();
    state
        .db
        .add_member(
            tenant.community(),
            channel,
            &agent.public_key().to_bytes(),
            MemberRole::Member,
            Some(&owner.public_key().to_bytes()),
        )
        .await
        .unwrap();
    let proven_auth = || {
        let mut value = auth(&agent);
        if let IngestAuth::Nip42 {
            moderation_owner, ..
        } = &mut value
        {
            *moderation_owner = Some(owner.public_key());
        }
        value
    };
    let event = command(
        &agent,
        channel,
        9002,
        &[("topic", "blocked after owner ban".into())],
    );
    let mut writer = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!(
            "buzz_channel_membership:{}:{}",
            tenant.community(),
            channel
        ))
        .execute(&mut *writer)
        .await
        .unwrap();
    let task = tokio::spawn({
        let state = Arc::clone(&state);
        let tenant = tenant.clone();
        let event = event.clone();
        let auth = proven_auth();
        async move { ingest_event(&state, &tenant, event, auth).await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(5),async {
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory')").fetch_one(&pool).await.unwrap();
            if waiting {break;} tokio::task::yield_now().await;
        }
    }).await.expect("outer owner check passed before held command fence");
    sqlx::query("INSERT INTO community_bans (community_id,pubkey,banned,actor_pubkey) VALUES ($1,$2,true,$2) ON CONFLICT (community_id,pubkey) DO UPDATE SET banned=true")
        .bind(tenant.community().as_uuid()).bind(owner.public_key().to_bytes().as_slice()).execute(&mut *writer).await.unwrap();
    writer.commit().await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap()
            .is_err(),
        "proven owner ban must be rechecked while held, even without persisted mapping"
    );
    assert!(!stored(&pool, tenant.community(), &event).await);
    assert_eq!(
        state
            .db
            .get_channel(tenant.community(), channel)
            .await
            .unwrap()
            .topic,
        None
    );
    assert_eq!(notice_count(&pool, tenant.community()).await, 0);
    sqlx::query("UPDATE community_bans SET banned=false, muted_until=NOW()+interval '1 hour' WHERE community_id=$1 AND pubkey=$2")
        .bind(tenant.community().as_uuid()).bind(owner.public_key().to_bytes().as_slice()).execute(&pool).await.unwrap();
    let allowed = command(
        &agent,
        channel,
        9002,
        &[("topic", "owner timeout does not cascade".into())],
    );
    assert!(
        ingest_event(&state, &tenant, allowed, proven_auth())
            .await
            .unwrap()
            .accepted
    );
    let mapping: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT agent_owner_pubkey FROM users WHERE community_id=$1 AND pubkey=$2",
    )
    .bind(tenant.community().as_uuid())
    .bind(agent.public_key().to_bytes().as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        mapping.is_none(),
        "trusted claim does not invent persisted ownership"
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn ingest_membership_commands_preserve_first_valid_target_selection() {
    let (state, tenant, channel, owner, _) = fixture().await;
    let target = Keys::generate();
    for kind in [9000, 9001] {
        let event = EventBuilder::new(Kind::Custom(kind), "")
            .tags([
                Tag::parse(["h", &channel.simple().to_string().to_uppercase()]).unwrap(),
                Tag::parse(["p", "bad-key"]).unwrap(),
                Tag::parse(["p", "aa"]).unwrap(),
                Tag::parse(["p", &target.public_key().to_hex().to_uppercase()]).unwrap(),
            ])
            .sign_with_keys(&owner)
            .unwrap();
        assert!(
            ingest_event(&state, &tenant, event, auth(&owner))
                .await
                .unwrap()
                .accepted
        );
        assert_eq!(
            state
                .db
                .is_member(tenant.community(), channel, &target.public_key().to_bytes())
                .await
                .unwrap(),
            kind == 9000
        );
        let notices = state
            .db
            .query_events_for_event_write(&buzz_db::event::EventQuery {
                kinds: Some(vec![if kind == 9000 { 44100 } else { 44101 }]),
                limit: Some(10),
                ..buzz_db::event::EventQuery::for_community(tenant.community())
            })
            .await
            .unwrap();
        assert_eq!(notices.len(), 1);
        assert!(
            notices[0]
                .event
                .tags
                .iter()
                .any(|tag| tag.as_slice() == ["p", target.public_key().to_hex().as_str()]),
            "membership notices normalize lowercase routing keys"
        );
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn ingest_concurrent_self_remove_and_archive_retries_return_exact_receipts() {
    for kind in [9001, 9002] {
        let (state, tenant, channel, owner, pool) = fixture().await;
        let member = Keys::generate();
        state
            .db
            .add_member(
                tenant.community(),
                channel,
                &member.public_key().to_bytes(),
                MemberRole::Member,
                Some(&owner.public_key().to_bytes()),
            )
            .await
            .unwrap();
        state
            .db
            .update_channel(
                tenant.community(),
                channel,
                ChannelUpdate {
                    visibility: Some("private".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let (actor, tags) = if kind == 9001 {
            (&member, vec![("p", member.public_key().to_hex())])
        } else {
            (&owner, vec![("archived", "true".into())])
        };
        let event = command(actor, channel, kind, &tags);
        let mut writer = pool.begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!(
                "buzz_channel_membership:{}:{}",
                tenant.community(),
                channel
            ))
            .execute(&mut *writer)
            .await
            .unwrap();
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let state = Arc::clone(&state);
            let tenant = tenant.clone();
            let event = event.clone();
            let auth = auth(actor);
            tasks.push(tokio::spawn(async move {
                ingest_event(&state, &tenant, event, auth).await
            }));
        }
        tokio::time::timeout(std::time::Duration::from_secs(5),async {
            loop {
                let waiting:i64=sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory'").fetch_one(&pool).await.unwrap();
                if waiting==2 {break;} tokio::task::yield_now().await;
            }
        }).await.expect("both exact requests missed the early receipt before either commits");
        writer.commit().await.unwrap();
        let mut duplicate_count = 0;
        for task in tasks {
            let result = tokio::time::timeout(std::time::Duration::from_secs(5), task)
                .await
                .unwrap()
                .unwrap()
                .expect("concurrent committed source is a receipt, not a new policy decision");
            assert!(result.accepted);
            if result.message == "duplicate:" {
                duplicate_count += 1;
            }
        }
        assert_eq!(duplicate_count, 1);
        assert!(stored(&pool, tenant.community(), &event).await);
        assert_eq!(
            notice_count(&pool, tenant.community()).await,
            if kind == 9001 { 2 } else { 1 }
        );
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn ingest_atomic_metadata_keeps_all_immutable_shape_checks() {
    let (state, tenant, channel, owner, pool) = fixture().await;
    let invalid = vec![
        Tag::parse(["unknown", "value"]).unwrap(),
        Tag::parse(["name"]).unwrap(),
        Tag::parse(["name", " ### "]).unwrap(),
        Tag::parse(["archived"]).unwrap(),
        Tag::parse(["archived", "maybe"]).unwrap(),
        Tag::parse(["visibility"]).unwrap(),
        Tag::parse(["visibility", "public"]).unwrap(),
        Tag::parse(["ttl"]).unwrap(),
        Tag::parse(["ttl", "0"]).unwrap(),
        Tag::parse(["ttl", "-2"]).unwrap(),
    ];
    for tag in invalid {
        let event = EventBuilder::new(Kind::Custom(9002), "")
            .tags([Tag::parse(["h", &channel.to_string()]).unwrap(), tag])
            .sign_with_keys(&owner)
            .unwrap();
        assert!(
            matches!(
                ingest_event(&state, &tenant, event.clone(), auth(&owner)).await,
                Err(IngestError::Rejected(_))
            ),
            "invalid immutable tags must reject even when unguarded mutable preflight is skipped"
        );
        assert!(!stored(&pool, tenant.community(), &event).await);
    }
    let bare_topic = EventBuilder::new(Kind::Custom(9002), "")
        .tags([
            Tag::parse(["h", &channel.to_string()]).unwrap(),
            Tag::parse(["topic"]).unwrap(),
        ])
        .sign_with_keys(&owner)
        .unwrap();
    assert!(
        ingest_event(&state, &tenant, bare_topic, auth(&owner))
            .await
            .unwrap()
            .accepted,
        "legacy authorized bare topic remains a no-op"
    );
    assert_eq!(notice_count(&pool, tenant.community()).await, 0);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn ingest_command_thread_ancestry_counters_and_notices_commit_together() {
    let (state, tenant, channel, owner, pool) = fixture().await;
    let root = EventBuilder::new(Kind::Custom(9), "thread root")
        .tags([Tag::parse(["h", &channel.to_string()]).unwrap()])
        .sign_with_keys(&owner)
        .unwrap();
    assert!(
        ingest_event(&state, &tenant, root.clone(), auth(&owner))
            .await
            .unwrap()
            .accepted
    );
    let event = EventBuilder::new(Kind::Custom(9002), "")
        .tags([
            Tag::parse(["h", &channel.to_string()]).unwrap(),
            Tag::parse(["topic", "threaded command"]).unwrap(),
            Tag::parse(["e", &root.id.to_hex(), "", "reply"]).unwrap(),
        ])
        .sign_with_keys(&owner)
        .unwrap();
    fault(&pool, 40099).await;
    assert!(ingest_event(&state, &tenant, event.clone(), auth(&owner))
        .await
        .is_err());
    assert!(!stored(&pool, tenant.community(), &event).await);
    assert!(state
        .db
        .get_thread_metadata_by_event(tenant.community(), event.id.as_bytes())
        .await
        .unwrap()
        .is_none());
    let count: i64 = sqlx::query_scalar(
        "SELECT COALESCE(sum(reply_count),0)::bigint FROM thread_metadata WHERE community_id=$1",
    )
    .bind(tenant.community().as_uuid())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 0, "late notice failure rolls back parent counters");
    recover(&pool).await;
    assert!(
        ingest_event(&state, &tenant, event.clone(), auth(&owner))
            .await
            .unwrap()
            .accepted
    );
    let meta = state
        .db
        .get_thread_metadata_by_event(tenant.community(), event.id.as_bytes())
        .await
        .unwrap()
        .expect("accepted command keeps thread ancestry");
    assert_eq!(
        meta.parent_event_id.as_deref(),
        Some(root.id.as_bytes().as_slice())
    );
    assert_eq!(
        meta.root_event_id.as_deref(),
        Some(root.id.as_bytes().as_slice())
    );
    assert_eq!(meta.depth, 1);
    assert_eq!(
        ingest_event(&state, &tenant, event.clone(), auth(&owner))
            .await
            .unwrap()
            .message,
        "duplicate:"
    );
    let parent = state
        .db
        .get_thread_metadata_by_event(tenant.community(), root.id.as_bytes())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(parent.reply_count, 1);
    assert_eq!(parent.descendant_count, 1);
    let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM thread_metadata tm INNER JOIN events e ON e.community_id=tm.community_id AND e.id=tm.event_id AND e.created_at=tm.event_created_at WHERE tm.community_id=$1 AND tm.parent_event_id=$2 AND e.id=$3")
        .bind(tenant.community().as_uuid()).bind(root.id.as_bytes().as_slice()).bind(event.id.as_bytes().as_slice()).fetch_one(&pool).await.unwrap();
    assert_eq!(visible, 1, "thread history join sees the command");
    assert_eq!(notice_count(&pool, tenant.community()).await, 1);
}
