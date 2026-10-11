use crate::{
    connection::{AuthState, ConnectionState},
    state::AppState,
};
use axum::{
    extract::{ws::Message, State},
    http::{HeaderMap, StatusCode},
};
use base64::Engine;
use buzz_core::{CommunityId, StoredEvent, TenantContext};
use nostr::{EventBuilder, Filter, Keys, Kind, Tag};
use std::{
    collections::HashMap,
    sync::{atomic::AtomicU8, Arc},
};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

async fn fixture() -> (Arc<AppState>, sqlx::PgPool, TenantContext) {
    let state =
        crate::test_support::app_state(&std::env::var("REDIS_URL").expect("isolated Redis")).await;
    let pool = sqlx::PgPool::connect(&crate::test_support::database_url())
        .await
        .expect("database");
    let tenant = community(&pool).await;
    (state, pool, tenant)
}

async fn community(pool: &sqlx::PgPool) -> TenantContext {
    let id = CommunityId::from_uuid(Uuid::new_v4());
    let host = format!("ban-{}.example", id);
    sqlx::query("INSERT INTO communities (id,host) VALUES ($1,$2)")
        .bind(id.as_uuid())
        .bind(&host)
        .execute(pool)
        .await
        .expect("community");
    TenantContext::resolved(id, &host)
}

async fn restriction(
    pool: &sqlx::PgPool,
    tenant: &TenantContext,
    keys: &Keys,
    banned: bool,
    expired: bool,
    timeout: bool,
) {
    sqlx::query("INSERT INTO community_bans (community_id,pubkey,banned,ban_expires_at,muted_until,actor_pubkey) VALUES ($1,$2,$3,CASE WHEN $4 THEN now()-interval '1 second' ELSE NULL END,CASE WHEN $5 THEN now()+interval '1 hour' ELSE NULL END,$2) ON CONFLICT (community_id,pubkey) DO UPDATE SET banned=EXCLUDED.banned,ban_expires_at=EXCLUDED.ban_expires_at,muted_until=EXCLUDED.muted_until")
        .bind(tenant.community().as_uuid()).bind(keys.public_key().to_bytes().as_slice())
        .bind(banned).bind(expired).bind(timeout).execute(pool).await.expect("restriction");
}

async fn authenticate(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    keys: &Keys,
    owner: Option<&Keys>,
) -> (
    Arc<ConnectionState>,
    mpsc::Receiver<Message>,
    mpsc::Receiver<Message>,
) {
    let challenge = Uuid::new_v4().to_string();
    let (send_tx, send_rx) = mpsc::channel(64);
    let (ctrl_tx, ctrl_rx) = mpsc::channel(64);
    let conn = Arc::new(ConnectionState {
        conn_id: Uuid::new_v4(),
        tenant: tenant.clone(),
        remote_addr: "127.0.0.1:1234".parse().expect("address"),
        auth_state: RwLock::new(AuthState::Pending {
            challenge: challenge.clone(),
        }),
        subscriptions: Arc::new(Mutex::new(HashMap::new())),
        send_tx,
        ctrl_tx,
        cancel: CancellationToken::new(),
        backpressure_count: Arc::new(AtomicU8::new(0)),
        grace_limit: 3,
    });
    state.conn_manager.register(
        conn.conn_id,
        conn.send_tx.clone(),
        conn.ctrl_tx.clone(),
        None,
        conn.cancel.clone(),
        tenant.community(),
        Arc::clone(&conn.backpressure_count),
        Arc::clone(&conn.subscriptions),
        3,
    );
    let relay = crate::api::bridge::nip42_expected_relay_url(&state.config.relay_url, tenant);
    let mut tags = vec![
        Tag::parse(["relay", &relay]).expect("relay"),
        Tag::parse(["challenge", &challenge]).expect("challenge"),
    ];
    if let Some(owner) = owner {
        let proof =
            buzz_sdk::nip_oa::compute_auth_tag(owner, &keys.public_key(), "").expect("proof");
        tags.push(
            Tag::parse(serde_json::from_str::<Vec<String>>(&proof).expect("tag"))
                .expect("auth tag"),
        );
    }
    let auth = EventBuilder::new(Kind::Authentication, "")
        .tags(tags)
        .sign_with_keys(keys)
        .expect("signed auth");
    crate::handlers::auth::handle_auth(auth, Arc::clone(&conn), Arc::clone(state)).await;
    (conn, send_rx, ctrl_rx)
}

fn headers(
    state: &AppState,
    tenant: &TenantContext,
    keys: &Keys,
    owner: Option<&Keys>,
    route: &str,
) -> HeaderMap {
    let url = crate::api::bridge::nip98_expected_url(&state.config.relay_url, tenant, route);
    let event = EventBuilder::new(Kind::HttpAuth, Uuid::new_v4().to_string())
        .tags([
            Tag::parse(["u", &url]).expect("url"),
            Tag::parse(["method", "POST"]).expect("method"),
        ])
        .sign_with_keys(keys)
        .expect("NIP98");
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&event).expect("json"));
    let mut headers = HeaderMap::new();
    headers.insert("host", tenant.host().parse().expect("host"));
    headers.insert(
        "authorization",
        format!("Nostr {encoded}").parse().expect("authorization"),
    );
    if let Some(owner) = owner {
        headers.insert(
            "x-auth-tag",
            buzz_sdk::nip_oa::compute_auth_tag(owner, &keys.public_key(), "")
                .expect("proof")
                .parse()
                .expect("header"),
        );
    }
    headers
}

fn drain(rx: &mut mpsc::Receiver<Message>) -> Vec<String> {
    let mut frames = Vec::new();
    while let Ok(message) = rx.try_recv() {
        if let Message::Text(text) = message {
            frames.push(text.to_string());
        }
    }
    frames
}

async fn ws_reads(
    state: &Arc<AppState>,
    conn: &Arc<ConnectionState>,
    rx: &mut mpsc::Receiver<Message>,
    denial: Option<&str>,
) {
    drain(rx);
    for search in [false, true] {
        let filter = if search {
            Filter::new().kind(Kind::TextNote).search("needle")
        } else {
            Filter::new().kind(Kind::TextNote)
        };
        crate::handlers::req::handle_req(
            format!("req-{search}"),
            vec![filter],
            vec![None],
            Arc::clone(conn),
            Arc::clone(state),
        )
        .await;
        let frames = drain(rx);
        if let Some(reason) = denial {
            assert!(
                frames.iter().any(|frame| frame.contains(reason)),
                "REQ: {frames:?}"
            );
            assert!(
                !frames.iter().any(|frame| frame.starts_with("[\"EVENT\"")),
                "no historical events"
            );
        } else {
            assert!(
                frames.iter().any(|frame| frame.contains("EOSE")),
                "REQ allowed: {frames:?}"
            );
        }
    }
    crate::handlers::count::handle_count(
        "count".into(),
        vec![Filter::new().kind(Kind::TextNote)],
        Arc::clone(conn),
        Arc::clone(state),
    )
    .await;
    let frames = drain(rx);
    assert!(
        frames
            .iter()
            .any(|frame| frame.contains(denial.unwrap_or("COUNT"))),
        "COUNT: {frames:?}"
    );
}

async fn http_reads(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    keys: &Keys,
    owner: Option<&Keys>,
    status: StatusCode,
) {
    for route in ["/query", "/count"] {
        let headers = headers(state, tenant, keys, owner, route);
        let body = axum::body::Bytes::from_static(br#"[{"kinds":[1]}]"#);
        let result = if route == "/query" {
            crate::api::bridge::query_events(State(Arc::clone(state)), headers, body).await
        } else {
            crate::api::bridge::count_events(State(Arc::clone(state)), headers, body).await
        };
        let actual = result
            .as_ref()
            .map(|_| StatusCode::OK)
            .unwrap_or_else(|e| e.0);
        assert_eq!(actual, status, "{route}: {result:?}");
    }
}

async fn fanout(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    conn: &Arc<ConnectionState>,
    allowed: bool,
    rx: &mut mpsc::Receiver<Message>,
) {
    let pool = sqlx::PgPool::connect(&crate::test_support::database_url())
        .await
        .expect("database");
    for visibility in [None, Some("open"), Some("private")] {
        let channel = visibility.map(|_| Uuid::new_v4());
        if let Some(id) = channel {
            let pubkey = match &*conn.auth_state.read().await {
                AuthState::Authenticated(ctx) => ctx.pubkey,
                _ => panic!("authenticated"),
            };
            sqlx::query("INSERT INTO channels (community_id,id,name,channel_type,visibility,created_by) VALUES ($1,$2,'test','stream',$3::channel_visibility,$4)")
                .bind(tenant.community().as_uuid()).bind(id).bind(visibility).bind(pubkey.to_bytes().as_slice()).execute(&pool).await.expect("channel");
            sqlx::query("INSERT INTO channel_members (community_id,channel_id,pubkey,role) VALUES ($1,$2,$3,'member')")
                .bind(tenant.community().as_uuid()).bind(id).bind(pubkey.to_bytes().as_slice()).execute(&pool).await.expect("membership");
        }
        let event = StoredEvent::new(
            EventBuilder::new(Kind::TextNote, "live")
                .sign_with_keys(&Keys::generate())
                .expect("event"),
            channel,
        );
        let out = crate::handlers::event::filter_fanout_by_access(
            state,
            tenant.community(),
            &event,
            vec![(conn.conn_id, "live".into())],
            None,
        )
        .await;
        assert_eq!(!out.is_empty(), allowed, "fanout {visibility:?}");
        // Exercise actual local and cross-pod delivery through the shared gate.
        state.sub_registry.register_scoped(
            tenant.community(),
            conn.conn_id,
            "live".into(),
            vec![Filter::new().kind(Kind::TextNote)],
            channel,
        );
        for remote in [false, true] {
            drain(rx);
            if remote {
                crate::handlers::event::fan_out_pubsub_event(
                    state,
                    buzz_pubsub::ChannelEvent {
                        community_id: tenant.community(),
                        topic: channel
                            .map(buzz_pubsub::EventTopic::Channel)
                            .unwrap_or(buzz_pubsub::EventTopic::Global),
                        event: event.event.clone(),
                    },
                )
                .await;
            } else {
                crate::handlers::event::fan_out_event_to_local_subscribers(
                    state,
                    tenant.community(),
                    &event,
                )
                .await;
            }
            let frames = drain(rx);
            assert_eq!(
                frames.iter().any(|frame| frame.starts_with("[\"EVENT\"")),
                allowed,
                "delivery remote={remote} visibility={visibility:?}: {frames:?}"
            );
        }
    }
}

#[derive(Clone, Copy)]
enum WriteExpectation {
    Allowed,
    Restricted,
    Unavailable,
}

async fn writes(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    keys: &Keys,
    owner: Option<&Keys>,
    conn: &Arc<ConnectionState>,
    rx: &mut mpsc::Receiver<Message>,
    expectation: WriteExpectation,
) {
    let denied = !matches!(expectation, WriteExpectation::Allowed);
    let pool = sqlx::PgPool::connect(&crate::test_support::database_url())
        .await
        .expect("database");
    let channel = Uuid::new_v4();
    sqlx::query("INSERT INTO channels (community_id,id,name,channel_type,visibility,created_by) VALUES ($1,$2,'writes','stream','open',$3)")
        .bind(tenant.community().as_uuid()).bind(channel).bind(keys.public_key().to_bytes().as_slice()).execute(&pool).await.expect("channel");
    sqlx::query("INSERT INTO channel_members (community_id,channel_id,pubkey,role) VALUES ($1,$2,$3,'member')")
        .bind(tenant.community().as_uuid()).bind(channel).bind(keys.public_key().to_bytes().as_slice()).execute(&pool).await.expect("membership");
    let event = EventBuilder::new(Kind::Custom(9), "probe")
        .tags([Tag::parse(["h", &channel.to_string()]).expect("channel")])
        .sign_with_keys(keys)
        .expect("message");
    for keyed in [false, true] {
        let mut headers = headers(state, tenant, keys, owner, "/events");
        if keyed {
            headers.insert(
                "idempotency-key",
                hex::encode([9u8; 32]).parse().expect("key"),
            );
        }
        let result = crate::api::bridge::submit_event(
            State(Arc::clone(state)),
            headers,
            serde_json::to_vec(&event).expect("json").into(),
        )
        .await;
        if denied {
            let response = result.expect_err("HTTP write must deny");
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), 16384)
                .await
                .expect("body");
            let text = String::from_utf8_lossy(&body);
            match expectation {
                WriteExpectation::Unavailable => {
                    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
                    assert!(
                        text.contains("internal server error"),
                        "redacted authority failure: {text}"
                    );
                }
                WriteExpectation::Restricted => assert!(
                    text.contains("banned") || text.contains("timed out"),
                    "HTTP write (keyed={keyed}) correct denial: {text}"
                ),
                WriteExpectation::Allowed => unreachable!("denied branch"),
            }
        } else {
            assert!(
                result.is_ok(),
                "HTTP write (keyed={keyed}) allowed: {result:?}"
            );
        }
    }
    drain(rx);
    crate::handlers::event::handle_event(event, Arc::clone(conn), Arc::clone(state)).await;
    let frames = drain(rx);
    assert!(
        frames
            .iter()
            .any(|frame| frame.contains(if denied { "false" } else { "true" })),
        "WS write: {frames:?}"
    );
    let ephemeral = EventBuilder::new(Kind::Custom(24134), "ephemeral")
        .tags([Tag::parse(["p", &Keys::generate().public_key().to_hex()]).expect("recipient")])
        .sign_with_keys(keys)
        .expect("ephemeral");
    let ephemeral_id = ephemeral.id.to_hex();
    crate::handlers::event::handle_event(ephemeral, Arc::clone(conn), Arc::clone(state)).await;
    let frames = drain(rx);
    let ack = frames
        .iter()
        .filter_map(|frame| serde_json::from_str::<serde_json::Value>(frame).ok())
        .find(|frame| frame[0] == "OK" && frame[1] == ephemeral_id)
        .expect("ephemeral acknowledgement");
    assert_eq!(ack[2], !denied, "ephemeral disposition: {ack}");
    let reason = ack[3].as_str().expect("reason");
    match expectation {
        WriteExpectation::Restricted => assert!(
            reason.contains("banned") || reason.contains("timed out"),
            "ephemeral rejection: {reason}"
        ),
        WriteExpectation::Unavailable => assert!(
            reason.contains("restriction state"),
            "ephemeral authority failure: {reason}"
        ),
        WriteExpectation::Allowed => {}
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn missed_disconnect_direct_and_proven_owner_bans_gate_all_transports() {
    let (state, pool, tenant) = fixture().await;
    for owned in [false, true] {
        let keys = Keys::generate();
        let owner = Keys::generate();
        // Backfill fails but authentication/provenance remain valid.
        if owned {
            sqlx::raw_sql("CREATE FUNCTION ban_test_materialize_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected owner materialization failure'; END $$; CREATE TRIGGER ban_test_materialize_fail BEFORE UPDATE OF agent_owner_pubkey ON users FOR EACH ROW EXECUTE FUNCTION ban_test_materialize_fail();").execute(&pool).await.expect("inject failure");
        }
        let (conn, mut rx, _ctrl) =
            authenticate(&state, &tenant, &keys, owned.then_some(&owner)).await;
        match &*conn.auth_state.read().await {
            AuthState::Authenticated(ctx) => {
                assert_eq!(
                    ctx.moderation_owner_pubkey,
                    owned.then_some(owner.public_key())
                );
                assert_eq!(
                    ctx.agent_owner_pubkey, None,
                    "failed backfill must not grant observer ownership"
                );
            }
            _ => panic!("auth must succeed despite optional backfill failure"),
        }
        ws_reads(&state, &conn, &mut rx, None).await;
        fanout(&state, &tenant, &conn, true, &mut rx).await;
        let target = if owned { &owner } else { &keys };
        restriction(&pool, &tenant, target, true, false, false).await;
        assert!(
            !conn.cancel.is_cancelled(),
            "test intentionally omits disconnect delivery"
        );
        ws_reads(&state, &conn, &mut rx, Some(super::BANNED)).await;
        http_reads(
            &state,
            &tenant,
            &keys,
            owned.then_some(&owner),
            StatusCode::FORBIDDEN,
        )
        .await;
        fanout(&state, &tenant, &conn, false, &mut rx).await;
        writes(
            &state,
            &tenant,
            &keys,
            owned.then_some(&owner),
            &conn,
            &mut rx,
            WriteExpectation::Restricted,
        )
        .await;
        restriction(&pool, &tenant, target, true, true, true).await;
        ws_reads(&state, &conn, &mut rx, None).await;
        http_reads(
            &state,
            &tenant,
            &keys,
            owned.then_some(&owner),
            StatusCode::OK,
        )
        .await;
        fanout(&state, &tenant, &conn, true, &mut rx).await;
        // An owner's timeout never cascades; an identity's own timeout blocks its writes.
        writes(
            &state,
            &tenant,
            &keys,
            owned.then_some(&owner),
            &conn,
            &mut rx,
            if owned {
                WriteExpectation::Allowed
            } else {
                WriteExpectation::Restricted
            },
        )
        .await;
        if owned {
            let mappings: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE community_id=$1 AND pubkey=$2 AND agent_owner_pubkey IS NOT NULL")
                .bind(tenant.community().as_uuid()).bind(keys.public_key().to_bytes().as_slice())
                .fetch_one(&pool).await.expect("mapping count");
            assert_eq!(
                mappings, 0,
                "all transport gates must survive failed backfill"
            );
            sqlx::raw_sql("DROP TRIGGER ban_test_materialize_fail ON users; DROP FUNCTION ban_test_materialize_fail();").execute(&pool).await.expect("restore");
        }
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn stored_owner_cannot_be_rebound_or_omitted_to_escape_ban_and_is_tenant_scoped() {
    let (state, pool, tenant) = fixture().await;
    let keys = Keys::generate();
    let original = Keys::generate();
    let replacement = Keys::generate();
    let (old_conn, _rx, _ctrl) = authenticate(&state, &tenant, &keys, Some(&original)).await;
    assert!(matches!(
        &*old_conn.auth_state.read().await,
        AuthState::Authenticated(_)
    ));
    restriction(&pool, &tenant, &original, true, false, false).await;
    for proof in [None, Some(&replacement)] {
        let (conn, _rx, mut ctrl) = authenticate(&state, &tenant, &keys, proof).await;
        assert!(conn.cancel.is_cancelled());
        assert!(drain(&mut ctrl)
            .iter()
            .any(|frame| frame.contains(super::BANNED)));
        http_reads(&state, &tenant, &keys, proof, StatusCode::FORBIDDEN).await;
    }
    let other = community(&pool).await;
    let (conn, mut rx, _ctrl) = authenticate(&state, &other, &keys, Some(&original)).await;
    assert!(matches!(
        &*conn.auth_state.read().await,
        AuthState::Authenticated(_)
    ));
    ws_reads(&state, &conn, &mut rx, None).await;
    http_reads(&state, &other, &keys, Some(&original), StatusCode::OK).await;
    fanout(&state, &other, &conn, true, &mut rx).await;
    // Invalid or unrelated proof never becomes a trusted moderation owner.
    let unrelated = Keys::generate();
    let invalid =
        buzz_sdk::nip_oa::compute_auth_tag(&original, &unrelated.public_key(), "").expect("proof");
    assert!(crate::api::relay_members::extract_nip_oa_owner(
        keys.public_key().as_bytes(),
        Some(&invalid),
        Some(nostr::Timestamp::now().as_secs())
    )
    .is_none());
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn closed_relay_owner_proof_restricts_without_granting_membership() {
    let (mut state, pool, tenant) = fixture().await;
    let config = Arc::make_mut(&mut Arc::get_mut(&mut state).expect("unshared fixture").config);
    config.require_relay_membership = true;
    config.allow_nip_oa_auth = false;
    let member = Keys::generate();
    let owner = Keys::generate();
    sqlx::query("INSERT INTO relay_members (community_id,pubkey,role) VALUES ($1,$2,'member')")
        .bind(tenant.community().as_uuid())
        .bind(member.public_key().to_hex())
        .execute(&pool)
        .await
        .expect("direct membership");
    let (conn, mut rx, _ctrl) = authenticate(&state, &tenant, &member, Some(&owner)).await;
    {
        let auth = conn.auth_state.read().await;
        let AuthState::Authenticated(context) = &*auth else {
            panic!("direct member denied")
        };
        assert_eq!(context.moderation_owner_pubkey, Some(owner.public_key()));
        assert_eq!(
            context.agent_owner_pubkey, None,
            "proof must not grant observer rights"
        );
    }
    ws_reads(&state, &conn, &mut rx, None).await;
    restriction(&pool, &tenant, &owner, true, false, false).await;
    ws_reads(&state, &conn, &mut rx, Some(super::BANNED)).await;
    writes(
        &state,
        &tenant,
        &member,
        Some(&owner),
        &conn,
        &mut rx,
        WriteExpectation::Restricted,
    )
    .await;
    http_reads(
        &state,
        &tenant,
        &member,
        Some(&owner),
        StatusCode::FORBIDDEN,
    )
    .await;
    let (denied, _rx, mut ctrl) = authenticate(&state, &tenant, &member, Some(&owner)).await;
    assert!(denied.cancel.is_cancelled());
    assert!(drain(&mut ctrl)
        .iter()
        .any(|frame| frame.contains(super::BANNED)));

    let stranger = Keys::generate();
    let clear_owner = Keys::generate();
    let (denied, mut rx, _ctrl) =
        authenticate(&state, &tenant, &stranger, Some(&clear_owner)).await;
    assert!(matches!(
        &*denied.auth_state.read().await,
        AuthState::Failed
    ));
    assert!(drain(&mut rx)
        .iter()
        .any(|frame| frame.contains("not a relay member")));
    http_reads(
        &state,
        &tenant,
        &stranger,
        Some(&clear_owner),
        StatusCode::FORBIDDEN,
    )
    .await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn moderation_authority_failure_denies_reads_fanout_and_writes() {
    let (state, pool, tenant) = fixture().await;
    let keys = Keys::generate();
    let (conn, mut rx, _ctrl) = authenticate(&state, &tenant, &keys, None).await;
    sqlx::query("ALTER TABLE community_bans RENAME TO unavailable_ban_probe")
        .execute(&pool)
        .await
        .expect("inject authority failure");
    ws_reads(&state, &conn, &mut rx, Some(super::UNAVAILABLE)).await;
    http_reads(
        &state,
        &tenant,
        &keys,
        None,
        StatusCode::INTERNAL_SERVER_ERROR,
    )
    .await;
    fanout(&state, &tenant, &conn, false, &mut rx).await;
    writes(
        &state,
        &tenant,
        &keys,
        None,
        &conn,
        &mut rx,
        WriteExpectation::Unavailable,
    )
    .await;
    let (fresh, _rx, mut ctrl) = authenticate(&state, &tenant, &keys, None).await;
    assert!(fresh.cancel.is_cancelled());
    assert!(drain(&mut ctrl)
        .iter()
        .any(|frame| frame.contains(super::UNAVAILABLE)));
    sqlx::query("ALTER TABLE unavailable_ban_probe RENAME TO community_bans")
        .execute(&pool)
        .await
        .expect("restore");
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn batched_restrictions_keep_recipient_order_and_timeout_identity() {
    use buzz_db::moderation::ModerationPrincipal;
    let (state, pool, tenant) = fixture().await;
    let clear = Keys::generate();
    let banned = Keys::generate();
    let expired = Keys::generate();
    let owner = Keys::generate();
    let agent = Keys::generate();
    restriction(&pool, &tenant, &banned, true, false, false).await;
    restriction(&pool, &tenant, &expired, true, true, false).await;
    restriction(&pool, &tenant, &owner, false, false, true).await;
    let principal = |keys: &Keys, owner: Option<&Keys>| ModerationPrincipal {
        pubkey: keys.public_key().to_bytes().to_vec(),
        proven_owner: owner.map(|key| key.public_key().to_bytes().to_vec()),
    };
    let inputs = vec![
        principal(&clear, None),
        principal(&agent, Some(&banned)),
        principal(&expired, None),
        principal(&banned, None),
        principal(&agent, Some(&owner)),
        principal(&owner, None),
        principal(&agent, None),
    ];
    let states = state
        .db
        .moderation_principal_restrictions(tenant.community(), &inputs)
        .await
        .expect("batch");
    assert_eq!(
        states.iter().map(|s| s.banned).collect::<Vec<_>>(),
        vec![false, true, false, true, false, false, false]
    );
    assert_eq!(
        states
            .iter()
            .map(|s| s.muted_until.is_some())
            .collect::<Vec<_>>(),
        vec![false, false, false, false, false, true, false]
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn private_report_and_admin_timeout_exceptions_are_preserved() {
    use crate::handlers::ingest::{ingest_event, IngestAuth};
    let (state, pool, tenant) = fixture().await;
    let admin = Keys::generate();
    let target = Keys::generate();
    let auth = || IngestAuth::Nip42 {
        pubkey: admin.public_key(),
        moderation_owner: None,
        scopes: buzz_auth::Scope::all_known(),
        channel_ids: None,
        conn_id: Uuid::new_v4(),
    };
    sqlx::query("INSERT INTO relay_members (community_id,pubkey,role) VALUES ($1,$2,'owner')")
        .bind(tenant.community().as_uuid())
        .bind(admin.public_key().to_hex())
        .execute(&pool)
        .await
        .expect("role");
    restriction(&pool, &tenant, &admin, false, false, true).await;
    restriction(&pool, &tenant, &target, false, false, true).await;
    let untimeout = EventBuilder::new(Kind::Custom(9043), "")
        .tags([Tag::parse(["p", &target.public_key().to_hex()]).expect("target")])
        .sign_with_keys(&admin)
        .expect("command");
    assert!(
        ingest_event(&state, &tenant, untimeout.clone(), auth())
            .await
            .expect("timed-out admin may untimeout")
            .accepted
    );
    assert!(state
        .db
        .moderation_restriction_state(tenant.community(), target.public_key().as_bytes())
        .await
        .expect("target restriction")
        .muted_until
        .is_none());
    restriction(&pool, &tenant, &admin, true, false, true).await;
    assert!(
        ingest_event(&state, &tenant, untimeout, auth())
            .await
            .is_err(),
        "banned admin must not mutate"
    );
    let report = EventBuilder::new(Kind::Custom(1984), "private signal")
        .tags([Tag::parse(["p", &target.public_key().to_hex(), "spam"]).expect("report")])
        .sign_with_keys(&admin)
        .expect("report");
    assert!(
        ingest_event(&state, &tenant, report.clone(), auth())
            .await
            .expect("report exception")
            .accepted
    );
    let stored: i64 =
        sqlx::query_scalar("SELECT count(*) FROM events WHERE community_id=$1 AND id=$2")
            .bind(tenant.community().as_uuid())
            .bind(report.id.to_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .expect("event count");
    let private: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM moderation_reports WHERE community_id=$1 AND report_event_id=$2",
    )
    .bind(tenant.community().as_uuid())
    .bind(report.id.to_bytes().as_slice())
    .fetch_one(&pool)
    .await
    .expect("report count");
    assert_eq!((stored, private), (0, 1));
}
