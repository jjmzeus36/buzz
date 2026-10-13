//! Fake-S3 regression tests for the production streamed-download storage seam.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{header, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use buzz_media::config::{MediaConfig, S3AddressingStyle};
use buzz_media::storage::MediaStorage;
use buzz_media::MediaError;
use futures_util::StreamExt;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const KEY: &str = "disappeared.mp4";
const OBJECT_BYTES: &[u8] = b"video bytes";
const PRIVATE_ERROR_BODY: &str = "<Error><Code>PrivateBackendDetail</Code></Error>";

#[derive(Clone)]
struct FakeS3State {
    get_status: StatusCode,
    get_body: &'static [u8],
    requests: Arc<Mutex<Vec<Method>>>,
}

struct FakeS3 {
    endpoint: String,
    requests: Arc<Mutex<Vec<Method>>>,
    task: JoinHandle<()>,
}

impl FakeS3 {
    async fn start(get_status: StatusCode, get_body: &'static [u8]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake S3 listener");
        let endpoint = format!(
            "http://{}",
            listener.local_addr().expect("listener address")
        );
        let requests = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route(
                "/buzz-media/disappeared.mp4",
                axum::routing::any(fake_s3_request),
            )
            .with_state(FakeS3State {
                get_status,
                get_body,
                requests: requests.clone(),
            });
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve fake S3");
        });
        Self {
            endpoint,
            requests,
            task,
        }
    }

    fn storage(&self) -> MediaStorage {
        MediaStorage::new(&MediaConfig {
            s3_endpoint: self.endpoint.clone(),
            s3_access_key: "fake-access".to_string(),
            s3_secret_key: "fake-secret".to_string(),
            s3_bucket: "buzz-media".to_string(),
            s3_region: "us-east-1".to_string(),
            s3_addressing_style: S3AddressingStyle::Path,
            max_image_bytes: 50 * 1024 * 1024,
            max_gif_bytes: 10 * 1024 * 1024,
            max_video_bytes: 524_288_000,
            max_file_bytes: 104_857_600,
            public_base_url: "http://localhost/media".to_string(),
            upload_records_enabled: false,
            upload_ip_header: None,
            upload_port_header: None,
        })
        .expect("build real storage client with fake static credentials")
    }
}

impl Drop for FakeS3 {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn fake_s3_request(State(state): State<FakeS3State>, request: Request<Body>) -> Response {
    state
        .requests
        .lock()
        .expect("request log")
        .push(request.method().clone());
    match *request.method() {
        Method::HEAD => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_LENGTH, OBJECT_BYTES.len())
            .header(header::CONNECTION, "close")
            .body(Body::empty())
            .expect("HEAD response"),
        Method::GET => Response::builder()
            .status(state.get_status)
            .header(header::CONNECTION, "close")
            .body(Body::from(state.get_body))
            .expect("GET response"),
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

#[tokio::test]
async fn stream_get_404_after_successful_head_is_not_found() {
    let fake_s3 = FakeS3::start(StatusCode::NOT_FOUND, PRIVATE_ERROR_BODY.as_bytes()).await;
    let storage = fake_s3.storage();
    let metadata = storage
        .head_with_metadata(KEY)
        .await
        .expect("successful HEAD")
        .expect("object existed at HEAD");
    assert_eq!(metadata.size, OBJECT_BYTES.len() as u64);

    // This uses the real rust-s3 fail-on-err path, which returns an error
    // rather than a stream response carrying a 404 status.
    let error = match storage.get_stream(KEY).await {
        Ok(_) => panic!("GET after disappearance must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, MediaError::NotFound), "{error:?}");
    let response = error.into_response();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        to_bytes(response.into_body(), 4096)
            .await
            .expect("error body"),
        r#"{"error":"not found"}"#
    );
    assert_eq!(
        *fake_s3.requests.lock().expect("request log"),
        [Method::HEAD, Method::GET]
    );
}

#[tokio::test]
async fn stream_get_other_s3_failures_preserve_internal_details_and_safe_http_errors() {
    for status in [
        StatusCode::BAD_REQUEST,
        StatusCode::FORBIDDEN,
        StatusCode::INTERNAL_SERVER_ERROR,
    ] {
        let fake_s3 = FakeS3::start(status, PRIVATE_ERROR_BODY.as_bytes()).await;
        let storage = fake_s3.storage();
        let result = tokio::time::timeout(Duration::from_secs(15), storage.get_stream(KEY))
            .await
            .expect("bounded S3 failure response");
        let error = match result {
            Ok(_) => panic!("unsuccessful S3 GET must fail"),
            Err(error) => error,
        };
        match &error {
            MediaError::StorageError(detail) => {
                assert!(
                    detail.contains(&format!("Got HTTP {}", status.as_u16())),
                    "{detail}"
                );
                assert!(detail.contains(PRIVATE_ERROR_BODY), "{detail}");
            }
            error => panic!("S3 {status} must stay a storage error: {error:?}"),
        }
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            to_bytes(response.into_body(), 4096)
                .await
                .expect("error body"),
            r#"{"error":"internal error"}"#
        );
    }
}

#[tokio::test]
async fn successful_stream_get_still_returns_object_bytes() {
    let fake_s3 = FakeS3::start(StatusCode::OK, OBJECT_BYTES).await;
    let storage = fake_s3.storage();
    let mut stream = storage.get_stream(KEY).await.expect("successful GET");
    let mut actual = Vec::new();
    while let Some(chunk) = stream.next().await {
        actual.extend_from_slice(&chunk.expect("stream chunk"));
    }
    assert_eq!(actual, OBJECT_BYTES);
    assert_eq!(
        *fake_s3.requests.lock().expect("request log"),
        [Method::GET]
    );
}
