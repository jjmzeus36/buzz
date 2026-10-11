//! Exercise quota callbacks through production uploads with a loopback S3 fixture.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{
    body::Body,
    extract::State,
    http::{Method, Request, StatusCode},
    response::Response,
    Router,
};
use buzz_core::{tenant::TenantContext, CommunityId};
use buzz_media::{
    config::{MediaConfig, S3AddressingStyle},
    error::MediaError,
    storage::MediaStorage,
    upload::{
        process_file_upload_admitted, process_upload_admitted, process_video_upload_admitted,
        AdmissionFuture, UploadAdmission,
    },
    upload_record::UploadAttribution,
};
use bytes::Bytes;
use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp};
use sha2::{Digest, Sha256};

#[derive(Default)]
struct Objects {
    bytes: HashMap<String, Vec<u8>>,
    requests: Vec<(Method, String)>,
    fail_suffix: Option<String>,
}
type SharedObjects = Arc<Mutex<Objects>>;

async fn s3(State(objects): State<SharedObjects>, request: Request<Body>) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let body = axum::body::to_bytes(request.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let mut objects = objects.lock().unwrap();
    objects.requests.push((method.clone(), path.clone()));
    let fail = objects
        .fail_suffix
        .as_ref()
        .is_some_and(|suffix| path.ends_with(suffix));
    let (status, bytes) = if fail && method == Method::PUT {
        (StatusCode::INTERNAL_SERVER_ERROR, vec![])
    } else if method == Method::PUT {
        objects.bytes.insert(path, body.to_vec());
        (StatusCode::OK, vec![])
    } else if let Some(bytes) = objects.bytes.get(&path) {
        (
            StatusCode::OK,
            if method == Method::GET {
                bytes.clone()
            } else {
                vec![]
            },
        )
    } else {
        (StatusCode::NOT_FOUND, vec![])
    };
    Response::builder()
        .status(status)
        .header("content-length", bytes.len())
        .body(Body::from(bytes))
        .unwrap()
}

struct Fixture {
    config: MediaConfig,
    storage: MediaStorage,
    tenant: TenantContext,
    objects: SharedObjects,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Fixture {
    async fn new() -> Self {
        let objects = Arc::new(Mutex::new(Objects::default()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let router = Router::new().fallback(s3).with_state(objects.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let config = MediaConfig {
            s3_endpoint: endpoint,
            s3_access_key: "synthetic".into(),
            s3_secret_key: "synthetic".into(),
            s3_bucket: "quota-test".into(),
            s3_region: "us-east-1".into(),
            s3_addressing_style: S3AddressingStyle::Path,
            max_image_bytes: 1024 * 1024,
            max_gif_bytes: 1024 * 1024,
            max_video_bytes: 1024 * 1024,
            max_file_bytes: 1024 * 1024,
            public_base_url: "http://media.test/media".into(),
            upload_records_enabled: false,
            upload_ip_header: None,
            upload_port_header: None,
        };
        let storage = MediaStorage::new(&config).unwrap();
        Self {
            config,
            storage,
            tenant: TenantContext::resolved(
                CommunityId::from_uuid(uuid::Uuid::new_v4()),
                "media.test",
            ),
            objects,
            server,
        }
    }
}

#[derive(Default)]
struct Admission {
    reject: bool,
    fail_completion: bool,
    existing: bool,
    reserved: Mutex<Vec<(String, u64)>>,
    completed: Mutex<Vec<(String, String)>>,
}
impl UploadAdmission for Admission {
    fn reserve<'a>(&'a self, hash: &'a str, size: u64) -> AdmissionFuture<'a, Option<String>> {
        Box::pin(async move {
            self.reserved.lock().unwrap().push((hash.into(), size));
            if self.reject {
                return Err(MediaError::QuotaExceeded);
            }
            Ok((!self.existing).then(|| "exact-operation".into()))
        })
    }
    fn complete<'a>(&'a self, hash: &'a str, token: String) -> AdmissionFuture<'a, ()> {
        Box::pin(async move {
            self.completed.lock().unwrap().push((hash.into(), token));
            if self.fail_completion {
                return Err(MediaError::QuotaUnavailable);
            }
            Ok(())
        })
    }
}

fn auth(bytes: &[u8]) -> nostr::Event {
    let hash = hex::encode(Sha256::digest(bytes));
    EventBuilder::new(Kind::from(24242), "synthetic quota upload")
        .tags([
            Tag::parse(["t", "upload"]).unwrap(),
            Tag::parse(["x", &hash]).unwrap(),
            Tag::parse([
                "expiration",
                &(Timestamp::now().as_secs() + 300).to_string(),
            ])
            .unwrap(),
        ])
        .sign_with_keys(&Keys::generate())
        .unwrap()
}
const IMAGE: &[u8] = include_bytes!("fixtures/ios/uikit-sanitized.png");
const VIDEO: &[u8] = include_bytes!("fixtures/quota/minimal.mp4");

#[tokio::test]
async fn quota_buffered_rejection_precedes_all_storage_and_follows_validation() {
    let f = Fixture::new().await;
    let a = Admission {
        reject: true,
        ..Admission::default()
    };
    for image in [false, true] {
        let bytes = if image {
            IMAGE
        } else {
            b"plain text attachment"
        };
        let result = if image {
            process_upload_admitted(
                &f.storage,
                &f.config,
                &f.tenant,
                &auth(bytes),
                Bytes::copy_from_slice(bytes),
                None,
                Some(&a),
            )
            .await
        } else {
            process_file_upload_admitted(
                &f.storage,
                &f.config,
                &f.tenant,
                &auth(bytes),
                Bytes::copy_from_slice(bytes),
                None,
                Some(&a),
            )
            .await
        };
        assert!(matches!(result, Err(MediaError::QuotaExceeded)));
        assert_eq!(
            a.reserved.lock().unwrap().last().unwrap().1,
            bytes.len() as u64
        );
    }
    assert!(f.objects.lock().unwrap().requests.is_empty());
    assert!(a.completed.lock().unwrap().is_empty());
    let result = process_upload_admitted(
        &f.storage,
        &f.config,
        &f.tenant,
        &auth(b"not an image"),
        Bytes::from_static(b"not an image"),
        None,
        Some(&a),
    )
    .await;
    assert!(result.is_err());
    assert_eq!(a.reserved.lock().unwrap().len(), 2);
    let result = process_file_upload_admitted(
        &f.storage,
        &f.config,
        &f.tenant,
        &auth(b"wrong hash"),
        Bytes::from_static(b"attachment"),
        None,
        Some(&a),
    )
    .await;
    assert!(result.is_err());
    assert_eq!(a.reserved.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn quota_buffered_failures_keep_reservation_and_completion_is_after_publication() {
    for suffix in [".bin", ".thumb.jpg", ".json"] {
        let f = Fixture::new().await;
        f.objects.lock().unwrap().fail_suffix = Some(suffix.into());
        let a = Admission::default();
        let result = if suffix == ".thumb.jpg" {
            process_upload_admitted(
                &f.storage,
                &f.config,
                &f.tenant,
                &auth(IMAGE),
                Bytes::from_static(IMAGE),
                None,
                Some(&a),
            )
            .await
        } else {
            let bytes = b"plain text attachment";
            process_file_upload_admitted(
                &f.storage,
                &f.config,
                &f.tenant,
                &auth(bytes),
                Bytes::from_static(bytes),
                None,
                Some(&a),
            )
            .await
        };
        assert!(result.is_err(), "failure at {suffix} must propagate");
        assert_eq!(a.reserved.lock().unwrap().len(), 1);
        assert!(
            a.completed.lock().unwrap().is_empty(),
            "failed write at {suffix} cannot finalize"
        );
    }
    let f = Fixture::new().await;
    let a = Admission {
        fail_completion: true,
        ..Admission::default()
    };
    let bytes = b"plain text attachment";
    let result = process_file_upload_admitted(
        &f.storage,
        &f.config,
        &f.tenant,
        &auth(bytes),
        Bytes::from_static(bytes),
        None,
        Some(&a),
    )
    .await;
    assert!(matches!(result, Err(MediaError::QuotaUnavailable)));
    assert_eq!(a.completed.lock().unwrap()[0].1, "exact-operation");
    let hash = hex::encode(Sha256::digest(bytes));
    assert!(f
        .objects
        .lock()
        .unwrap()
        .bytes
        .keys()
        .any(|key| key.ends_with(&format!("/{hash}.json"))));
}

#[tokio::test]
async fn quota_idempotent_storage_path_admits_owner_and_disabled_path_works() {
    let f = Fixture::new().await;
    let bytes = b"plain text attachment";
    // The compatibility API's disabled admission still publishes normally.
    buzz_media::process_file_upload(
        &f.storage,
        &f.config,
        &f.tenant,
        &auth(bytes),
        Bytes::from_static(bytes),
        None,
    )
    .await
    .unwrap();
    let puts = f
        .objects
        .lock()
        .unwrap()
        .requests
        .iter()
        .filter(|(method, _)| method == Method::PUT)
        .count();
    for existing in [false, true] {
        let a = Admission {
            existing,
            ..Admission::default()
        };
        process_file_upload_admitted(
            &f.storage,
            &f.config,
            &f.tenant,
            &auth(bytes),
            Bytes::from_static(bytes),
            None,
            Some(&a),
        )
        .await
        .unwrap();
        assert_eq!(
            a.reserved.lock().unwrap().len(),
            1,
            "another owner claiming stored bytes must be admitted"
        );
        assert_eq!(a.completed.lock().unwrap().len(), usize::from(!existing));
    }
    assert_eq!(
        f.objects
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|(method, _)| method == Method::PUT)
            .count(),
        puts
    );
}

#[tokio::test]
async fn quota_video_uses_actual_stream_bytes_and_never_publishes_rejection() {
    for claimed in [None, Some(1), Some(VIDEO.len() as u64 + 10)] {
        let f = Fixture::new().await;
        let a = Admission {
            reject: true,
            ..Admission::default()
        };
        let chunks = VIDEO
            .chunks(37)
            .map(|chunk| Ok::<_, axum::Error>(Bytes::copy_from_slice(chunk)))
            .collect::<Vec<_>>();
        let result = process_video_upload_admitted(
            &f.storage,
            &f.config,
            &f.tenant,
            &auth(VIDEO),
            futures_util::stream::iter(chunks),
            claimed,
            None,
            Some(&a),
        )
        .await;
        assert!(
            matches!(result, Err(MediaError::QuotaExceeded)),
            "valid video should reach quota: {result:?}"
        );
        assert_eq!(
            a.reserved.lock().unwrap()[0],
            (hex::encode(Sha256::digest(VIDEO)), VIDEO.len() as u64)
        );
        assert!(f.objects.lock().unwrap().requests.is_empty());
    }
}

#[tokio::test]
async fn quota_video_storage_failure_and_upload_record_failure_never_finalize() {
    for suffix in [".mp4", ".json"] {
        let f = Fixture::new().await;
        f.objects.lock().unwrap().fail_suffix = Some(suffix.into());
        let a = Admission::default();
        let result = process_video_upload_admitted(
            &f.storage,
            &f.config,
            &f.tenant,
            &auth(VIDEO),
            futures_util::stream::iter([Ok::<_, axum::Error>(Bytes::from_static(VIDEO))]),
            None,
            None,
            Some(&a),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(a.reserved.lock().unwrap().len(), 1);
        assert!(a.completed.lock().unwrap().is_empty());
    }
    let f = Fixture::new().await;
    let mut config = f.config.clone();
    config.upload_records_enabled = true;
    // Upload records and the sidecar both end in JSON; distinguish them by
    // checking that the failing write is the event record, before the sidecar.
    f.objects.lock().unwrap().fail_suffix = Some(".json".into());
    let a = Admission::default();
    let result = process_file_upload_admitted(
        &f.storage,
        &config,
        &f.tenant,
        &auth(b"attachment"),
        Bytes::from_static(b"attachment"),
        Some(UploadAttribution::default()),
        Some(&a),
    )
    .await;
    assert!(result.is_err());
    assert!(f
        .objects
        .lock()
        .unwrap()
        .requests
        .iter()
        .any(|(method, path)| method == Method::PUT && path.contains("/_uploads/")));
    assert!(!f
        .objects
        .lock()
        .unwrap()
        .requests
        .iter()
        .any(|(method, path)| method == Method::PUT && path.contains("/_meta/")));
    assert!(a.completed.lock().unwrap().is_empty());
}
