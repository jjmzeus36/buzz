//! Real upload handler, durable ledger, and loopback S3 acceptance tests.
use super::*;
use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{Method, Request},
    Router,
};
use buzz_db::media_quota::{BaselineObject, QuotaPolicy};
use nostr::{EventBuilder, JsonUtil, Keys, Kind, Tag, Timestamp};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use tower::ServiceExt;

#[derive(Default)]
struct Objects {
    values: HashMap<String, Vec<u8>>,
    calls: Vec<(Method, String)>,
    fail_sidecar: bool,
}
type SharedObjects = Arc<Mutex<Objects>>;

async fn s3(State(objects): State<SharedObjects>, request: Request<Body>) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let mut objects = objects.lock().unwrap();
    objects.calls.push((method.clone(), path.clone()));
    let (status, body) =
        if method == Method::PUT && objects.fail_sidecar && path.contains("/_meta/") {
            (StatusCode::INTERNAL_SERVER_ERROR, Vec::new())
        } else if method == Method::PUT {
            objects.values.insert(path, bytes.to_vec());
            (StatusCode::OK, Vec::new())
        } else if let Some(bytes) = objects.values.get(&path) {
            (
                StatusCode::OK,
                if method == Method::GET {
                    bytes.clone()
                } else {
                    Vec::new()
                },
            )
        } else {
            (StatusCode::NOT_FOUND, Vec::new())
        };
    Response::builder()
        .status(status)
        .header("content-length", body.len())
        .body(Body::from(body))
        .unwrap()
}

struct Fixture {
    state: Arc<AppState>,
    pool: sqlx::PgPool,
    objects: SharedObjects,
    server: tokio::task::JoinHandle<()>,
    community: buzz_core::CommunityId,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Fixture {
    async fn new(policy: Option<QuotaPolicy>) -> Self {
        assert_eq!(
            std::env::var("BUZZ_TEST_SCHEMA_MODE").as_deref(),
            Ok("desired"),
            "use isolated PostgreSQL runner"
        );
        let url = std::env::var("BUZZ_TEST_DATABASE_URL").unwrap();
        let objects = Arc::new(Mutex::new(Objects::default()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let router = Router::new().fallback(s3).with_state(objects.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let mut config = crate::config::Config::from_env().unwrap();
        config.database_url = url;
        config.redis_url = "redis://127.0.0.1:1".into();
        config.require_relay_membership = false;
        config.audit_enabled = false;
        config.media_uploads_per_minute = 100;
        config.media_quota = policy;
        config.media.s3_endpoint = endpoint;
        config.media.s3_access_key = "synthetic".into();
        config.media.s3_secret_key = "synthetic".into();
        config.media.s3_bucket = "quota-test".into();
        config.media.s3_addressing_style = buzz_media::config::S3AddressingStyle::Path;
        config.media.upload_records_enabled = false;
        let pool = sqlx::PgPool::connect(&config.database_url).await.unwrap();
        let db = buzz_db::Db::from_pool(pool.clone());
        let community = db
            .ensure_configured_community("quota.test")
            .await
            .unwrap()
            .id;
        let redis_pool = deadpool_redis::Config::from_url(&config.redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .unwrap();
        let pubsub = Arc::new(
            buzz_pubsub::PubSubManager::new(&config.redis_url, redis_pool.clone())
                .await
                .unwrap(),
        );
        let audit = buzz_audit::AuditService::new(pool.clone());
        let auth = buzz_auth::AuthService::new(config.auth.clone());
        let search = buzz_search::SearchService::new(pool.clone());
        let workflow = Arc::new(buzz_workflow::WorkflowEngine::new(
            db.clone(),
            buzz_workflow::WorkflowConfig::default(),
        ));
        let media = buzz_media::MediaStorage::new(&config.media).unwrap();
        let (state, _shutdown) = AppState::new(
            config,
            db,
            redis_pool,
            audit,
            pubsub,
            auth,
            search,
            workflow,
            Keys::generate(),
            media,
        );
        Self {
            state: Arc::new(state),
            pool,
            objects,
            server,
            community,
        }
    }
    async fn upload(&self, keys: &Keys, bytes: &[u8], route: &str) -> Response {
        let hash = hex::encode(Sha256::digest(bytes));
        let event = EventBuilder::new(Kind::from(24242), "synthetic quota upload")
            .tags([
                Tag::parse(["t", "upload"]).unwrap(),
                Tag::parse(["x", &hash]).unwrap(),
                Tag::parse(["server", "quota.test"]).unwrap(),
                Tag::parse([
                    "expiration",
                    &(Timestamp::now().as_secs() + 300).to_string(),
                ])
                .unwrap(),
            ])
            .sign_with_keys(keys)
            .unwrap();
        let auth = format!(
            "Nostr {}",
            base64::engine::general_purpose::STANDARD.encode(event.as_json())
        );
        let chunks = bytes
            .chunks(37)
            .map(|bytes| Ok::<_, std::io::Error>(Bytes::copy_from_slice(bytes)))
            .collect::<Vec<_>>();
        Router::new()
            .route(route, axum::routing::put(upload_blob))
            .with_state(self.state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(route)
                    .header("host", "quota.test")
                    .header("authorization", auth)
                    .header("x-sha-256", hash)
                    .header("content-type", "text/plain")
                    .body(Body::from_stream(futures_util::stream::iter(chunks)))
                    .unwrap(),
            )
            .await
            .unwrap()
    }
    async fn enroll(&self, keys: &Keys, policy: QuotaPolicy, objects: &[BaselineObject]) {
        self.state
            .db
            .enroll_media_quota(
                self.community,
                &keys.public_key().to_bytes(),
                policy,
                "verified synthetic complete history",
                objects,
            )
            .await
            .unwrap();
    }
    async fn rows(&self, keys: &Keys) -> Vec<(String, i64, String)> {
        sqlx::query_as("SELECT sha256,size_bytes,state FROM media_quota_objects WHERE community_id=$1 AND pubkey=$2 ORDER BY sha256")
            .bind(self.community.as_uuid()).bind(keys.public_key().to_bytes().as_slice()).fetch_all(&self.pool).await.unwrap()
    }
}
const IMAGE: &[u8] = include_bytes!("../../../buzz-media/tests/fixtures/ios/uikit-sanitized.png");
const VIDEO: &[u8] = include_bytes!("../../../buzz-media/tests/fixtures/quota/minimal.mp4");

#[tokio::test]
#[ignore = "requires Postgres"]
async fn quota_handler_finish_failure_retains_published_original_and_pending_charge() {
    let policy = QuotaPolicy {
        limit: 10,
        baseline_id: uuid::Uuid::new_v4(),
    };
    let f = Fixture::new(Some(policy)).await;
    let keys = Keys::generate();
    f.enroll(&keys, policy, &[]).await;
    sqlx::query("CREATE FUNCTION quota_fail_finish() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.state='pending' AND NEW.state='charged' THEN RAISE EXCEPTION 'synthetic finalization failure'; END IF; RETURN NEW; END $$").execute(&f.pool).await.unwrap();
    sqlx::query("CREATE TRIGGER quota_fail_finish BEFORE UPDATE ON media_quota_objects FOR EACH ROW EXECUTE FUNCTION quota_fail_finish()").execute(&f.pool).await.unwrap();
    assert_eq!(
        f.upload(&keys, b"hello\n", "/upload").await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let row = f.rows(&keys).await;
    assert_eq!(row[0].1, 6);
    assert_eq!(row[0].2, "pending");
    assert!(
        f.objects
            .lock()
            .unwrap()
            .values
            .keys()
            .any(|path| path.contains("/_meta/")),
        "publication precedes attempted ledger finalization"
    );
    let calls = f.objects.lock().unwrap().calls.len();
    assert_eq!(
        f.upload(&keys, b"hello\n", "/upload").await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        f.upload(&keys, b"world", "/upload").await.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(f.objects.lock().unwrap().calls.len(), calls);
    sqlx::query("DROP TRIGGER quota_fail_finish ON media_quota_objects")
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION quota_fail_finish()")
        .execute(&f.pool)
        .await
        .unwrap();
    let operation: uuid::Uuid = sqlx::query_scalar(
        "SELECT operation_id FROM media_quota_objects WHERE community_id=$1 AND pubkey=$2",
    )
    .bind(f.community.as_uuid())
    .bind(keys.public_key().to_bytes().as_slice())
    .fetch_one(&f.pool)
    .await
    .unwrap();
    f.state
        .db
        .recover_media_quota(
            f.community,
            &keys.public_key().to_bytes(),
            &row[0].0,
            operation,
            "old writer stopped; retain full charge",
        )
        .await
        .unwrap();
    let puts = f
        .objects
        .lock()
        .unwrap()
        .calls
        .iter()
        .filter(|(method, _)| method == Method::PUT)
        .count();
    assert_eq!(
        f.upload(&keys, b"hello\n", "/upload").await.status(),
        StatusCode::OK
    );
    assert_eq!(f.rows(&keys).await[0].2, "charged");
    assert_eq!(
        f.objects
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|(method, _)| method == Method::PUT)
            .count(),
        puts
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn quota_handler_unknown_baseline_guards_every_dispatch_branch() {
    let policy = QuotaPolicy {
        limit: 1024 * 1024,
        baseline_id: uuid::Uuid::new_v4(),
    };
    let f = Fixture::new(Some(policy)).await;
    for (bytes, route) in [
        (IMAGE, "/upload"),
        (&b"hello\n"[..], "/upload"),
        (VIDEO, "/upload"),
        (IMAGE, "/media/upload"),
    ] {
        let keys = Keys::generate();
        let response = f.upload(&keys, bytes, route).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(f.rows(&keys).await.is_empty());
        assert!(
            f.objects.lock().unwrap().calls.is_empty(),
            "unknown history must fail before S3 even with valid bytes"
        );
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn quota_handler_charges_signer_before_storage_idempotency_and_retains_failures() {
    let policy = QuotaPolicy {
        limit: 6,
        baseline_id: uuid::Uuid::new_v4(),
    };
    let f = Fixture::new(Some(policy)).await;
    let first = Keys::generate();
    let second = Keys::generate();
    f.enroll(&first, policy, &[]).await;
    f.enroll(&second, policy, &[]).await;
    assert_eq!(
        f.upload(&first, b"hello\n", "/upload").await.status(),
        StatusCode::OK
    );
    let calls = f.objects.lock().unwrap().calls.len();
    let puts = f
        .objects
        .lock()
        .unwrap()
        .calls
        .iter()
        .filter(|(method, _)| method == Method::PUT)
        .count();
    assert_eq!(
        f.upload(&second, b"hello\n", "/upload").await.status(),
        StatusCode::OK
    );
    assert_eq!(f.rows(&first).await[0].1, 6);
    assert_eq!(f.rows(&second).await[0].1, 6);
    assert_eq!(f.rows(&second).await[0].2, "charged");
    assert!(f.objects.lock().unwrap().calls.len() > calls);
    assert_eq!(
        f.objects
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|(method, _)| method == Method::PUT)
            .count(),
        puts
    );
    let calls = f.objects.lock().unwrap().calls.len();
    assert_eq!(
        f.upload(&second, b"world", "/upload").await.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(f.objects.lock().unwrap().calls.len(), calls);
    let third = Keys::generate();
    f.enroll(&third, policy, &[]).await;
    f.objects.lock().unwrap().fail_sidecar = true;
    assert_eq!(
        f.upload(&third, b"test", "/upload").await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(f.rows(&third).await[0].1, 4);
    assert_eq!(f.rows(&third).await[0].2, "pending");
    let calls = f.objects.lock().unwrap().calls.len();
    assert_eq!(
        f.upload(&third, b"test", "/upload").await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        f.upload(&third, b"world", "/upload").await.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(f.objects.lock().unwrap().calls.len(), calls);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn quota_handler_disabled_uploads_do_not_touch_existing_or_unknown_ledger() {
    let f = Fixture::new(None).await;
    let keys = Keys::generate();
    let stale = QuotaPolicy {
        limit: 1,
        baseline_id: uuid::Uuid::new_v4(),
    };
    f.enroll(
        &keys,
        stale,
        &[BaselineObject {
            sha256: "a".repeat(64),
            size_bytes: 10,
        }],
    )
    .await;
    let before = f.rows(&keys).await;
    for bytes in [IMAGE, &b"hello\n"[..], VIDEO, &b""[..]] {
        assert_eq!(
            f.upload(&keys, bytes, "/upload").await.status(),
            StatusCode::OK
        );
        assert_eq!(
            f.rows(&keys).await,
            before,
            "disabled uploads never consult/update quota ledger"
        );
    }
    let unknown = Keys::generate();
    assert_eq!(
        f.upload(&unknown, b"hello\n", "/upload").await.status(),
        StatusCode::OK
    );
    assert!(f.rows(&unknown).await.is_empty());
}
