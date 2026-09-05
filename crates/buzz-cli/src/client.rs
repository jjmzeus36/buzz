use std::future::Future;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, NaiveDateTime, Utc};
use nostr::{EventBuilder, JsonUtil, Keys, Kind, Tag};
use sha2::{Digest, Sha256};

use crate::error::CliError;

/// Descriptor returned by the relay after a successful upload.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlobDescriptor {
    /// Public URL of the uploaded blob.
    pub url: String,
    /// Hex-encoded SHA-256 of the file content.
    pub sha256: String,
    /// File size in bytes.
    pub size: u64,
    /// MIME type (e.g. `image/jpeg`).
    #[serde(rename = "type")]
    pub mime_type: String,
    /// Unix timestamp when the file was uploaded.
    pub uploaded: i64,
    /// Image dimensions as `<width>x<height>` (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dim: Option<String>,
    /// Blurhash placeholder string (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blurhash: Option<String>,
    /// Thumbnail URL (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb: Option<String>,
    /// Duration in seconds for video/audio (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<f64>,
}

/// Build an `imeta` tag array from a BlobDescriptor (NIP-92 media metadata).
pub fn build_imeta_tag(d: &BlobDescriptor) -> Vec<String> {
    let mut tag = vec![
        "imeta".to_string(),
        format!("url {}", d.url),
        format!("m {}", d.mime_type),
        format!("x {}", d.sha256),
        format!("size {}", d.size),
    ];
    if let Some(ref dim) = d.dim {
        tag.push(format!("dim {dim}"));
    }
    if let Some(ref bh) = d.blurhash {
        tag.push(format!("blurhash {bh}"));
    }
    if let Some(ref th) = d.thumb {
        tag.push(format!("thumb {th}"));
    }
    if let Some(dur) = d.duration {
        tag.push(format!("duration {dur}"));
    }
    tag
}

/// MIME types accepted for upload.
const ALLOWED_MIMES: &[&str] = &[
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "video/mp4",
];

/// Maximum file size for image uploads (50 MB).
const MAX_IMAGE_BYTES: u64 = 50 * 1024 * 1024;

/// Maximum file size for video uploads (500 MB).
const MAX_VIDEO_BYTES: u64 = 500 * 1024 * 1024;

/// Inclusive byte ceiling for NIP-11 public-metadata reads.
///
/// A document of exactly this size is accepted. A declared `Content-Length`
/// greater than this value is rejected before any body bytes are read. When
/// length is missing, chunked, or dishonest, reads stop at the first chunk
/// that would pass this ceiling.
pub const NIP11_PUBLIC_METADATA_MAX_BYTES: usize = 64 * 1024;

/// Inclusive byte ceiling for keyed POST /events response bodies.
///
/// A body of exactly this size is accepted. A declared `Content-Length`
/// greater than this value is rejected before any body bytes are read. When
/// length is missing, chunked, or dishonest, reads stop at the first chunk
/// that would pass this ceiling. Used only by keyed POST /events responses.
pub const KEYED_RESPONSE_MAX_BYTES: usize = 64 * 1024;

/// Fixed non-success text for the keyed NIP-11 preflight.
///
/// In-bound error bodies are discarded so a hostile relay cannot echo
/// attacker-controlled text through [`CliError`] Display, Debug, or
/// structured JSON.
const BOUNDED_PUBLIC_METADATA_ERROR: &str = "public metadata request failed";

fn public_metadata_oversize(limit: usize) -> CliError {
    CliError::PublicMetadataTooLarge { limit }
}

fn declared_public_metadata_too_large(content_length: Option<u64>, limit: usize) -> bool {
    content_length.is_some_and(|len| len > limit as u64)
}

fn public_metadata_chunk_exceeds_limit(current: usize, chunk_len: usize, limit: usize) -> bool {
    current.saturating_add(chunk_len) > limit
}

fn keyed_response_oversize(limit: usize) -> CliError {
    CliError::KeyedResponseTooLarge { limit }
}

fn declared_keyed_response_too_large(content_length: Option<u64>, limit: usize) -> bool {
    content_length.is_some_and(|len| len > limit as u64)
}

fn keyed_response_chunk_exceeds_limit(current: usize, chunk_len: usize, limit: usize) -> bool {
    current.saturating_add(chunk_len) > limit
}

/// Sign a NIP-98 HTTP auth event (kind:27235) and return the Authorization header value.
///
/// The event includes:
/// - `u` tag: the full request URL
/// - `method` tag: HTTP method (GET, POST, PUT, DELETE)
/// - `payload` tag: SHA-256 hex of the request body (if present)
fn sign_nip98(
    keys: &Keys,
    method: &str,
    url: &str,
    body: Option<&[u8]>,
) -> Result<String, CliError> {
    let mut tags = vec![
        Tag::parse(["u", url]).map_err(|e| CliError::Other(format!("tag error: {e}")))?,
        Tag::parse(["method", method]).map_err(|e| CliError::Other(format!("tag error: {e}")))?,
        // Nonce prevents replay rejection for rapid-fire requests with identical bodies.
        Tag::parse(["nonce", &uuid::Uuid::new_v4().to_string()])
            .map_err(|e| CliError::Other(format!("tag error: {e}")))?,
    ];
    if let Some(b) = body {
        let hash = hex::encode(Sha256::digest(b));
        tags.push(
            Tag::parse(["payload", &hash])
                .map_err(|e| CliError::Other(format!("tag error: {e}")))?,
        );
    }
    let event = EventBuilder::new(Kind::Custom(27235), "")
        .tags(tags)
        .sign_with_keys(keys)
        .map_err(|e| CliError::Other(format!("NIP-98 signing failed: {e}")))?;
    let json = event.as_json();
    Ok(format!("Nostr {}", B64.encode(json.as_bytes())))
}

fn relay_server_tag(relay_url: &str) -> Option<String> {
    let authority = buzz_core::tenant::relay_url_authority(relay_url);
    if authority.is_empty() {
        None
    } else {
        Some(authority)
    }
}

/// Maximum number of attempts per request (initial attempt + two retries).
const RETRY_MAX_ATTEMPTS: u32 = 3;

/// Keyed stored-event POST attempts (initial attempt + three retries).
///
/// Three consecutive `Retry-After: 5` responses reach the 15-second legal
/// writer-capacity window on the fourth attempt, still inside the 90-second
/// keyed operation deadline. Generic (non-keyed) operations keep
/// [`RETRY_MAX_ATTEMPTS`].
const KEYED_RETRY_MAX_ATTEMPTS: u32 = 4;

/// Base sleep durations for full-jitter exponential backoff.
/// `RETRY_BASE_SECS[i]` is the ceiling for attempt `i` before attempt `i+1`.
const RETRY_BASE_SECS: [f64; 2] = [0.5, 1.5];

/// Maximum seconds to honour a relay-provided `retry in Ns` hint from a 429.
/// Defensive cap against pathological hints; real relay hints observed up to ~24 s.
const RETRY_IN_MAX_SECS: u64 = 30;

/// Outer bound for a keyed POST /events operation, including Retry-After waits.
const KEYED_OPERATION_DEADLINE_SECS: u64 = 90;

/// HTTP `Retry-After` classification for keyed 503 retries.
///
/// `Representable` is a nonnegative whole-second wait floor from either
/// delay-seconds or a GMT HTTP-date converted relative to header-receipt time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetryAfterHint {
    MissingOrMalformed,
    Representable(u64),
    Overflow,
}

/// Returns a full-jitter delay for attempt `i`: a random duration in `[0, RETRY_BASE_SECS[i])`.
fn jitter_delay(attempt: u32) -> Duration {
    Duration::from_secs_f64(RETRY_BASE_SECS[attempt as usize] * rand::random::<f64>())
}

/// Full-jitter delay for keyed retries.
///
/// Extra keyed attempts reuse the last generic jitter ceiling so they never
/// index past [`RETRY_BASE_SECS`].
fn keyed_jitter_delay(attempt: u32) -> Duration {
    let max_idx = RETRY_BASE_SECS.len().saturating_sub(1);
    let idx = (attempt as usize).min(max_idx);
    Duration::from_secs_f64(RETRY_BASE_SECS[idx] * rand::random::<f64>())
}

/// Read an env var as a `u64` of seconds and return the corresponding `Duration`.
/// Falls back to `default` if the var is unset, unparseable, or zero (zero is treated
/// as invalid to prevent accidentally disabling all timeouts).
fn env_duration_secs(name: &str, default: u64) -> Duration {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(default))
}

/// Unauthenticated public-read client. Redirects are refused in place so a
/// NIP-11 preflight cannot be steered at loopback or a private target.
fn public_no_redirect_client() -> Result<reqwest::Client, CliError> {
    reqwest::Client::builder()
        .timeout(env_duration_secs("BUZZ_TIMEOUT_SECS", 30))
        .connect_timeout(env_duration_secs("BUZZ_CONNECT_TIMEOUT_SECS", 15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| CliError::Other(e.to_string()))
}

/// Parse an HTTP `Retry-After` value as delay-seconds or HTTP-date.
///
/// All-digit delay-seconds are honoured exactly, including values larger
/// than `u64` ([`RetryAfterHint::Overflow`]). The three HTTP-date forms
/// clients must understand (IMF-fixdate, obsolete RFC 850, and obsolete
/// asctime) are interpreted as GMT and converted to a nonnegative
/// whole-second delay relative to the time the response headers are
/// received, rounding any positive fractional remainder up so a retry
/// cannot start before the absolute time. A date at or before now is
/// [`RetryAfterHint::Representable`] `0`. Empty values and any other
/// malformed text are [`RetryAfterHint::MissingOrMalformed`] so the caller
/// can fall back to keyed jitter. Unrepresentable date conversions are
/// [`RetryAfterHint::Overflow`] and must not retry early.
fn parse_retry_after_hint(headers: &reqwest::header::HeaderMap) -> RetryAfterHint {
    parse_retry_after_hint_at(headers, Utc::now())
}

/// Deterministic `Retry-After` parser against a supplied UTC `now`.
fn parse_retry_after_hint_at(
    headers: &reqwest::header::HeaderMap,
    now: DateTime<Utc>,
) -> RetryAfterHint {
    let Some(value) = headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
    else {
        return RetryAfterHint::MissingOrMalformed;
    };
    parse_retry_after_value(value, now)
}

fn parse_retry_after_value(value: &str, now: DateTime<Utc>) -> RetryAfterHint {
    if value.is_empty() {
        return RetryAfterHint::MissingOrMalformed;
    }
    if value.bytes().all(|b| b.is_ascii_digit()) {
        return match value.parse::<u64>() {
            Ok(secs) => RetryAfterHint::Representable(secs),
            Err(_) => RetryAfterHint::Overflow,
        };
    }
    match parse_http_date_gmt(value) {
        Some(when) => http_date_to_retry_after_hint(when, now),
        None => RetryAfterHint::MissingOrMalformed,
    }
}

/// IMF-fixdate, obsolete RFC 850, and obsolete asctime, with GMT semantics.
fn parse_http_date_gmt(value: &str) -> Option<DateTime<Utc>> {
    const FORMATS: &[&str] = &[
        "%a, %d %b %Y %H:%M:%S GMT",
        "%A, %d-%b-%y %H:%M:%S GMT",
        "%a %b %e %H:%M:%S %Y",
        "%a %b %_d %H:%M:%S %Y",
    ];
    for fmt in FORMATS {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(value, fmt) {
            return Some(ndt.and_utc());
        }
    }
    None
}

/// Convert a future HTTP-date to a whole-second delay, ceiling any positive
/// fraction so the client never retries before the absolute time.
fn http_date_to_retry_after_hint(when: DateTime<Utc>, now: DateTime<Utc>) -> RetryAfterHint {
    if when <= now {
        return RetryAfterHint::Representable(0);
    }
    let Ok(delta) = when.signed_duration_since(now).to_std() else {
        return RetryAfterHint::Overflow;
    };
    let mut secs = delta.as_secs();
    if delta.subsec_nanos() > 0 {
        match secs.checked_add(1) {
            Some(ceiled) => secs = ceiled,
            None => return RetryAfterHint::Overflow,
        }
    }
    RetryAfterHint::Representable(secs)
}

#[cfg(test)]
fn parse_retry_after_delta_seconds(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    match parse_retry_after_hint(headers) {
        RetryAfterHint::Representable(secs) => Some(secs),
        RetryAfterHint::MissingOrMalformed | RetryAfterHint::Overflow => None,
    }
}

/// Retry sleeps must strictly fit inside the remaining bound so a deadline
/// tie cannot start another in-flight request.
fn delay_strictly_fits(delay: Duration, remaining: Duration) -> bool {
    delay < remaining
}

fn keyed_503_retry_delay(
    hint: RetryAfterHint,
    jitter: Duration,
    remaining: Duration,
) -> Option<Duration> {
    match hint {
        RetryAfterHint::MissingOrMalformed => {
            let delay = delay_from_retry_after_and_jitter(None, jitter)?;
            delay_strictly_fits(delay, remaining).then_some(delay)
        }
        RetryAfterHint::Overflow => None,
        RetryAfterHint::Representable(secs) => {
            let delay = delay_from_retry_after_and_jitter(Some(secs), jitter)?;
            delay_strictly_fits(delay, remaining).then_some(delay)
        }
    }
}

/// Map a keyed 503 after the retry loop cannot start another attempt.
///
/// A valid positive representable Retry-After — delay-seconds or a
/// date-derived whole-second floor — is preserved as
/// [`CliError::RelayDeferred`] so an outer caller cannot undercut the relay
/// wait floor, including on the last attempt when no internal delay remains.
/// `Retry-After: 0` (including an HTTP-date at or before now) has no wait
/// floor and stays ordinary retryable [`CliError::Relay`]. Missing and
/// malformed Retry-After keep the original [`CliError::Relay`]. Overflow
/// Retry-After — an all-digit delay above `u64` or an unrepresentable
/// HTTP-date conversion — is [`CliError::RelayRetryAfterOverflow`]:
/// explicitly nonretryable, same relay-error status/body, and no invented
/// finite wait.
fn keyed_exhausted_error(error: CliError, retry_after: RetryAfterHint) -> CliError {
    match (&error, retry_after) {
        (CliError::Relay { status: 503, body }, RetryAfterHint::Representable(secs))
            if secs > 0 =>
        {
            CliError::RelayDeferred {
                status: 503,
                body: body.clone(),
                retry_after_seconds: secs,
            }
        }
        (CliError::Relay { status: 503, body }, RetryAfterHint::Overflow) => {
            CliError::RelayRetryAfterOverflow {
                status: 503,
                body: body.clone(),
            }
        }
        _ => error,
    }
}

/// Classify an already-known keyed error after the operation deadline has
/// been crossed. In-flight request/body expiry is [`keyed_deadline_unknown`].
/// A retry-sleep (or remaining-bound) crossing must not invent ambiguity:
/// keyed 503 with a positive representable Retry-After stays deferred with
/// that exact floor; keyed 503 with a zero or missing/malformed hint stays
/// [`CliError::Relay`]; keyed 503 with overflow is
/// [`CliError::RelayRetryAfterOverflow`]; a definitive connect failure stays
/// the network error; a transport-uncertain timeout/request/body/decode
/// outcome is [`CliError::DeliveryUnknown`].
fn keyed_deadline_after_known_error(
    error: CliError,
    retry_after: RetryAfterHint,
    kind_u16: u16,
) -> CliError {
    match &error {
        CliError::Network(net_err)
            if !net_err.is_connect()
                && (net_err.is_timeout()
                    || net_err.is_request()
                    || net_err.is_body()
                    || net_err.is_decode()) =>
        {
            keyed_deadline_unknown(kind_u16)
        }
        _ => keyed_exhausted_error(error, retry_after),
    }
}

fn keyed_deadline_unknown(kind_u16: u16) -> CliError {
    CliError::DeliveryUnknown(format!(
        "stored event (kind {kind_u16}) outcome unknown: keyed operation deadline exceeded"
    ))
}

/// 301–303/307/308 are returned in place. They are not 503 and must not enter
/// the keyed retry loop. The message is fixed so a hostile 3xx body is not echoed.
fn keyed_redirect_refused(status: reqwest::StatusCode) -> Option<CliError> {
    match status.as_u16() {
        301 | 302 | 303 | 307 | 308 => Some(CliError::Relay {
            status: status.as_u16(),
            body: "redirect refused".into(),
        }),
        _ => None,
    }
}

/// Combine a valid HTTP `Retry-After` delta with full jitter.
///
/// A parsed hint is a floor: the delay is never shorter than that delta.
/// Bounded nonnegative jitter for the retry attempt is then added. A valid
/// representable hint is never clipped. If hint + jitter cannot be represented
/// as a [`Duration`], returns `None` so the caller can surface the 503 without
/// retrying early. Missing or malformed headers pass `None` for the hint and
/// keep the jitter-only fallback.
fn delay_from_retry_after_and_jitter(
    retry_after: Option<u64>,
    jitter: Duration,
) -> Option<Duration> {
    let max_jitter = Duration::from_secs_f64(RETRY_BASE_SECS.into_iter().fold(0.0_f64, f64::max));
    let jitter = jitter.min(max_jitter);
    match retry_after {
        Some(secs) => Duration::from_secs(secs).checked_add(jitter),
        None => Some(jitter),
    }
}

/// Scan a plain-text string for a `retry in <N>s` pattern and return `N`.
///
/// Matches the literal substring `retry in ` followed by one or more ASCII digits
/// and the character `s`. Works on both extracted field values (`rate-limited:
/// quota exceeded; retry in 4s`) and substrings of raw relay JSON bodies.
/// Returns `None` when the pattern is absent or the digit sequence is empty.
fn parse_retry_hint_text(text: &str) -> Option<u64> {
    const PREFIX: &str = "retry in ";
    let after = text.find(PREFIX).map(|i| &text[i + PREFIX.len()..])?;
    let end = after
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(after.len());
    if end == 0 || after.as_bytes().get(end) != Some(&b's') {
        return None;
    }
    after[..end].parse::<u64>().ok()
}

/// Parse a `retry in Ns` hint from a relay 429 JSON body.
///
/// Extracts the `error` or `message` field and delegates to
/// `parse_retry_hint_text`. Returns `None` when the body is not valid JSON or
/// the extracted field does not contain the pattern.
#[cfg(test)]
fn parse_retry_in_secs(body: &str) -> Option<u64> {
    let text = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("error")
                .or_else(|| v.get("message"))
                .and_then(|m| m.as_str().map(str::to_string))
        })?;
    parse_retry_hint_text(&text)
}

/// Extract the `error` or `message` field from a relay JSON error body.
///
/// Production relay error bodies are shaped as `{"error":"..."}` (via `api_error()`).
/// Returns the extracted field value, or `None` if the body is not valid JSON or
/// neither field is present.  The raw body should be retained for diagnostics when
/// `None` is returned.
fn extract_relay_message_field(body: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("error")
                .or_else(|| v.get("message"))
                .and_then(|m| m.as_str().map(str::to_string))
        })
}

fn should_retry_legacy_upload(status: reqwest::StatusCode) -> bool {
    matches!(
        status,
        reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::METHOD_NOT_ALLOWED
    )
}

/// Returns `true` for moderation command kinds (9040–9044).
///
/// These events execute immediately at the relay without dedup, so they must
/// not be blindly retried on ambiguous outcomes.
fn is_moderation_kind(kind: u16) -> bool {
    matches!(kind, 9040..=9044)
}

/// Returns `true` for HTTP status codes that indicate a successful response
/// (equivalent to `reqwest::StatusCode::is_success()` for u16).
fn resp_was_success(status: u16) -> bool {
    (200..300).contains(&status)
}

/// Returns `true` if a stored-event exhaustion error is ambiguous (the relay
/// may have executed the command) and should be converted to `DeliveryUnknown`.
///
/// Connect failures are definitively pre-relay (never executed) so they remain
/// retryable. Canonical pre-ingest 429 (`Relay{status:429}`) was provably
/// rejected before storage — also retryable. Everything else (timeout, body
/// loss, decode error, proxy 502-504) may have crossed the relay's storage
/// boundary and must not invite an outer re-sign.
fn is_stored_event_exhaustion_ambiguous(e: &CliError) -> bool {
    match e {
        CliError::Network(net_err) => {
            // Connect is definitively pre-relay.
            if net_err.is_connect() {
                return false;
            }
            // Timeout, body, decode, request — ambiguous.
            net_err.is_timeout() || net_err.is_body() || net_err.is_decode() || net_err.is_request()
        }
        // Canonical pre-ingest 429 — relay did not store.
        CliError::Relay { status: 429, .. } => false,
        // Proxy 502-504 — relay may have accepted before the proxy failed.
        CliError::Relay {
            status: 502..=504, ..
        } => true,
        // All other variants are not retried by with_retry_body; not ambiguous.
        _ => false,
    }
}

fn is_safe_media_path_segment(sha256_ext: &str) -> bool {
    let segments: Vec<&str> = sha256_ext.split('.').collect();
    match segments.as_slice() {
        [hash] => is_lower_hex_sha256(hash),
        [hash, ext] => is_lower_hex_sha256(hash) && is_safe_media_ext(ext),
        [hash, "thumb", "jpg"] => is_lower_hex_sha256(hash),
        _ => false,
    }
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

fn is_safe_media_ext(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 8
        && value.chars().all(|c| matches!(c, 'a'..='z' | '0'..='9'))
}

fn media_url_from_input(relay_url: &str, input: &str) -> Result<String, CliError> {
    let input = input.trim();
    if input.starts_with("http://") || input.starts_with("https://") {
        let parsed = url::Url::parse(input)
            .map_err(|e| CliError::Usage(format!("invalid media URL: {e}")))?;
        if !parsed.path().starts_with("/media/") {
            return Err(CliError::Usage(
                "media URL must point at a /media/ path".to_string(),
            ));
        }
        let Some(sha256_ext) = parsed.path().strip_prefix("/media/") else {
            return Err(CliError::Usage(
                "media URL must point at a /media/ path".to_string(),
            ));
        };
        if !is_safe_media_path_segment(sha256_ext) {
            return Err(CliError::Usage(
                "media path must be sha256, sha256.ext, or sha256.thumb.jpg".to_string(),
            ));
        }
        let relay = url::Url::parse(relay_url)
            .map_err(|e| CliError::Usage(format!("invalid relay URL: {e}")))?;
        if parsed.scheme() != relay.scheme()
            || parsed.host_str() != relay.host_str()
            || parsed.port_or_known_default() != relay.port_or_known_default()
        {
            return Err(CliError::Usage(
                "refusing to sign media GET for a non-relay origin".to_string(),
            ));
        }
        return Ok(input.to_string());
    }
    if input.contains("://") {
        return Err(CliError::Usage(
            "media URL must use http:// or https://".to_string(),
        ));
    }

    let sha256_ext = input.trim_start_matches("/media/");
    if sha256_ext.is_empty() {
        return Err(CliError::Usage(
            "media input must be a URL or sha256[.ext]".to_string(),
        ));
    }
    if !is_safe_media_path_segment(sha256_ext) {
        return Err(CliError::Usage(
            "media input must be sha256, sha256.ext, or sha256.thumb.jpg".to_string(),
        ));
    }
    Ok(format!(
        "{}/media/{sha256_ext}",
        relay_url.trim_end_matches('/')
    ))
}

fn sign_blossom_get(keys: &Keys, media_url: &str) -> Result<String, CliError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use nostr::Timestamp;

    let now = Timestamp::now().as_secs();
    let exp_str = (now + 600).to_string();
    let domain = relay_server_tag(media_url)
        .ok_or_else(|| CliError::Usage(format!("invalid media URL: {media_url}")))?;
    let tags = vec![
        Tag::parse(["t", "get"]).map_err(|e| CliError::Other(e.to_string()))?,
        Tag::parse(["expiration", &exp_str]).map_err(|e| CliError::Other(e.to_string()))?,
        Tag::parse(["server", &domain]).map_err(|e| CliError::Other(e.to_string()))?,
    ];

    let auth_event = EventBuilder::new(Kind::from(24242), "Get media")
        .tags(tags)
        .sign_with_keys(keys)
        .map_err(|e| CliError::Other(format!("signing failed: {e}")))?;

    Ok(format!(
        "Nostr {}",
        URL_SAFE_NO_PAD.encode(auth_event.as_json().as_bytes())
    ))
}

fn sign_blossom_upload(
    keys: &Keys,
    sha256: &str,
    mime: &str,
    relay_url: &str,
) -> Result<String, CliError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use nostr::Timestamp;

    let now = Timestamp::now().as_secs();
    let expiry: u64 = if mime.starts_with("video/") {
        3600
    } else {
        600
    };
    let exp_str = (now + expiry).to_string();

    let mut tags = vec![
        Tag::parse(["t", "upload"]).map_err(|e| CliError::Other(e.to_string()))?,
        Tag::parse(["x", sha256]).map_err(|e| CliError::Other(e.to_string()))?,
        Tag::parse(["expiration", &exp_str]).map_err(|e| CliError::Other(e.to_string()))?,
    ];
    if let Some(domain) = relay_server_tag(relay_url) {
        tags.push(Tag::parse(["server", &domain]).map_err(|e| CliError::Other(e.to_string()))?);
    }

    let auth_event = EventBuilder::new(Kind::from(24242), "Upload file")
        .tags(tags)
        .sign_with_keys(keys)
        .map_err(|e| CliError::Other(format!("signing failed: {e}")))?;

    Ok(format!(
        "Nostr {}",
        URL_SAFE_NO_PAD.encode(auth_event.as_json().as_bytes())
    ))
}

#[cfg(test)]
mod media_download_tests {
    use super::*;

    #[test]
    fn media_url_from_sha_uses_relay_media_path() {
        let hash = "a".repeat(64);
        assert_eq!(
            media_url_from_input("https://relay.example", &format!("{hash}.jpg")).unwrap(),
            format!("https://relay.example/media/{hash}.jpg")
        );
        assert_eq!(
            media_url_from_input("https://relay.example/", &format!("/media/{hash}.jpg")).unwrap(),
            format!("https://relay.example/media/{hash}.jpg")
        );
    }

    #[test]
    fn media_url_accepts_only_same_relay_media_urls() {
        let hash = "a".repeat(64);
        assert!(media_url_from_input(
            "https://relay.example:443",
            &format!("https://relay.example/media/{hash}.jpg")
        )
        .is_ok());
        assert!(media_url_from_input(
            "https://relay.example",
            &format!("http://relay.example/media/{hash}.jpg")
        )
        .is_err());
        assert!(media_url_from_input(
            "https://relay.example",
            &format!("https://evil.example/media/{hash}.jpg")
        )
        .is_err());
        assert!(media_url_from_input(
            "https://relay.example",
            &format!("https://relay.example/media-evil/{hash}.jpg")
        )
        .is_err());
        assert!(media_url_from_input(
            "https://relay.example",
            &format!("ftp://relay.example/media/{hash}.jpg")
        )
        .is_err());
    }

    #[test]
    fn media_url_rejects_path_confusion_and_non_hash_inputs() {
        for input in [
            "abc123.jpg",
            "../evil",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/evil.jpg",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.JPG",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.eviltoolong",
            "https://relay.example/media/abc123.jpg",
            "https://relay.example/media/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.JPG",
        ] {
            assert!(
                media_url_from_input("https://relay.example", input).is_err(),
                "input should be rejected: {input}"
            );
        }
    }

    #[test]
    fn media_get_auth_header_is_server_scoped() {
        let keys = Keys::generate();
        let hash = "a".repeat(64);
        let header = sign_blossom_get(
            &keys,
            &format!("https://relay.example:443/media/{hash}.jpg"),
        )
        .unwrap();
        let encoded = header.strip_prefix("Nostr ").unwrap();
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .unwrap();
        let event = nostr::Event::from_json(std::str::from_utf8(&json).unwrap()).unwrap();
        event.verify().unwrap();
        assert_eq!(event.kind, Kind::from(24242));

        let tags: Vec<Vec<String>> = event
            .tags
            .iter()
            .map(|tag| tag.as_slice().to_vec())
            .collect();
        assert!(tags.iter().any(|tag| tag.as_slice() == ["t", "get"]));
        assert!(tags
            .iter()
            .any(|tag| tag.as_slice() == ["server", "relay.example"]));
        assert!(!tags
            .iter()
            .any(|tag| tag.first().map(String::as_str) == Some("x")));
    }

    #[test]
    fn legacy_upload_retry_statuses_are_narrow() {
        assert!(should_retry_legacy_upload(reqwest::StatusCode::NOT_FOUND));
        assert!(should_retry_legacy_upload(
            reqwest::StatusCode::METHOD_NOT_ALLOWED
        ));
        assert!(!should_retry_legacy_upload(
            reqwest::StatusCode::UNPROCESSABLE_ENTITY
        ));
        assert!(!should_retry_legacy_upload(
            reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE
        ));
    }
}

const QUERY_PAGE_SIZE: u32 = 500;

fn advance_query_cursor(
    filter: &mut serde_json::Value,
    page: &[serde_json::Value],
) -> Result<(), CliError> {
    let last = page
        .last()
        .expect("a full query page always has a last event");
    let created_at = last
        .get("created_at")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| CliError::Other("query event missing created_at".into()))?;
    let id = last
        .get("id")
        .and_then(serde_json::Value::as_str)
        .filter(|id| id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| CliError::Other("query event missing valid id".into()))?;
    filter["until"] = serde_json::json!(created_at);
    filter["before_id"] = serde_json::json!(id);
    Ok(())
}

async fn read_bounded_public_metadata_body(
    mut resp: reqwest::Response,
    limit: usize,
) -> Result<String, CliError> {
    if declared_public_metadata_too_large(resp.content_length(), limit) {
        return Err(public_metadata_oversize(limit));
    }

    let mut collected = Vec::new();
    if let Some(declared) = resp.content_length() {
        collected.reserve(declared as usize);
    }

    while let Some(chunk) = resp.chunk().await? {
        if public_metadata_chunk_exceeds_limit(collected.len(), chunk.len(), limit) {
            return Err(public_metadata_oversize(limit));
        }
        collected.extend_from_slice(&chunk);
    }

    String::from_utf8(collected).map_err(|_| CliError::Other("public metadata is not UTF-8".into()))
}

/// Typed non-success mapping for the keyed NIP-11 preflight.
///
/// Preserves HTTP status and the caller-facing family (`Conflict` for 409,
/// otherwise `Relay`). The message is always [`BOUNDED_PUBLIC_METADATA_ERROR`].
fn bounded_public_metadata_status_error(status: reqwest::StatusCode) -> CliError {
    let message = BOUNDED_PUBLIC_METADATA_ERROR.to_string();
    if status.as_u16() == 409 {
        CliError::Conflict(message)
    } else {
        CliError::Relay {
            status: status.as_u16(),
            body: message,
        }
    }
}

/// Read a bounded NIP-11 body, then map status without echoing that body
/// on non-success. Oversize is rejected by
/// [`read_bounded_public_metadata_body`] before this mapping.
async fn handle_bounded_public_metadata(
    resp: reqwest::Response,
    limit: usize,
) -> Result<String, CliError> {
    let status = resp.status();
    let body = read_bounded_public_metadata_body(resp, limit).await?;
    if status.is_success() {
        Ok(body)
    } else {
        Err(bounded_public_metadata_status_error(status))
    }
}

async fn read_bounded_keyed_response_body(
    mut resp: reqwest::Response,
    limit: usize,
) -> Result<String, CliError> {
    if declared_keyed_response_too_large(resp.content_length(), limit) {
        return Err(keyed_response_oversize(limit));
    }

    let mut collected = Vec::new();
    if let Some(declared) = resp.content_length() {
        collected.reserve((declared as usize).min(limit));
    }

    while let Some(chunk) = resp.chunk().await? {
        if keyed_response_chunk_exceeds_limit(collected.len(), chunk.len(), limit) {
            return Err(keyed_response_oversize(limit));
        }
        collected.extend_from_slice(&chunk);
    }

    Ok(String::from_utf8_lossy(&collected).into_owned())
}

/// Shared status/body mapper for unbounded `handle_response` and bounded keyed
/// POST /events responses.
///
/// Success returns the body. Non-success extracts JSON `error`/`message` when
/// present, maps 409 to [`CliError::Conflict`], annotates 403 when
/// `BUZZ_AUTH_TAG` is set, and otherwise returns [`CliError::Relay`].
fn map_response_status_and_body(
    status: reqwest::StatusCode,
    body: String,
) -> Result<String, CliError> {
    if !status.is_success() {
        let status = status.as_u16();
        let message = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| {
                v.get("error")
                    .or_else(|| v.get("message"))
                    .and_then(|m| m.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or(body);
        if status == 409 {
            return Err(CliError::Conflict(message));
        }
        if status == 403 && std::env::var("BUZZ_AUTH_TAG").is_ok() {
            let message = format!(
                "{message} (BUZZ_AUTH_TAG is set — it may be stale or revoked; try unsetting it)"
            );
            return Err(CliError::Relay {
                status,
                body: message,
            });
        }
        return Err(CliError::Relay {
            status,
            body: message,
        });
    }
    Ok(body)
}

/// Capture status before consuming a keyed POST /events body, enforce
/// [`KEYED_RESPONSE_MAX_BYTES`], then map through `map_response_status_and_body`.
///
/// Oversize is always [`CliError::KeyedResponseTooLarge`]. On non-success,
/// non-oversize body-read failures keep the empty-body fallback. On success,
/// body-read failures remain [`CliError::Network`].
async fn handle_keyed_response(resp: reqwest::Response) -> Result<String, CliError> {
    let status = resp.status();
    let body = match read_bounded_keyed_response_body(resp, KEYED_RESPONSE_MAX_BYTES).await {
        Ok(body) => body,
        Err(CliError::KeyedResponseTooLarge { limit }) => {
            return Err(CliError::KeyedResponseTooLarge { limit });
        }
        Err(e) if status.is_success() => return Err(e),
        Err(_) => String::new(),
    };
    map_response_status_and_body(status, body)
}

pub struct BuzzClient {
    http: reqwest::Client,
    /// Never follows redirects. The only client used for keyed stored-event POSTs,
    /// so a 307/308 cannot receive the signed body or `Idempotency-Key`.
    http_keyed: reqwest::Client,
    relay_url: String, // base URL, no trailing slash, e.g. "https://relay.buzz.place"
    keys: Keys,
    /// Optional NIP-OA auth tag injected into every signed event.
    auth_tag: Option<Tag>,
    /// Raw JSON of the auth tag for the `x-auth-tag` HTTP header.
    auth_tag_json: Option<String>,
}

impl BuzzClient {
    /// Create a new client pointing at `relay_url`.
    ///
    /// Timeout defaults are tuned for degraded WAN links and can be overridden
    /// via environment variables:
    ///
    /// - `BUZZ_CONNECT_TIMEOUT_SECS` — TCP connect timeout (default 15 s)
    /// - `BUZZ_TIMEOUT_SECS` — per-request total timeout (default 30 s)
    ///
    /// A value of zero for either variable is treated as invalid and falls back to the default.
    pub fn new(
        relay_url: String,
        keys: Keys,
        auth_tag: Option<Tag>,
        auth_tag_json: Option<String>,
    ) -> Result<Self, CliError> {
        let timeout = env_duration_secs("BUZZ_TIMEOUT_SECS", 30);
        let connect_timeout = env_duration_secs("BUZZ_CONNECT_TIMEOUT_SECS", 15);
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(connect_timeout)
            .build()
            .map_err(|e| CliError::Other(e.to_string()))?;
        let http_keyed = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(connect_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| CliError::Other(e.to_string()))?;
        Ok(Self {
            http,
            http_keyed,
            relay_url,
            keys,
            auth_tag,
            auth_tag_json,
        })
    }

    /// Get the keypair.
    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    /// Get the relay base URL.
    #[allow(dead_code)]
    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }

    /// Return the owner pubkey carried by the NIP-OA auth tag, if any.
    ///
    /// The auth tag is `["auth", owner_pubkey, conditions, sig]`; the
    /// owner pubkey lives at index 1.
    pub fn auth_tag_owner_hex(&self) -> Option<String> {
        self.auth_tag
            .as_ref()
            .map(|t| t.as_slice())
            .and_then(|slice| slice.get(1).cloned())
    }

    /// Sign an event builder, injecting the NIP-OA auth tag if configured.
    ///
    /// All event creation should go through this method to ensure consistent
    /// auth tag injection. Callers MUST NOT add `auth` tags to the builder
    /// before calling this method.
    pub fn sign_event(&self, builder: EventBuilder) -> Result<nostr::Event, CliError> {
        let builder = if let Some(ref tag) = self.auth_tag {
            builder.tags([tag.clone()])
        } else {
            builder
        };
        let event = builder
            .sign_with_keys(&self.keys)
            .map_err(|e| CliError::Other(format!("signing failed: {e}")))?;

        // Enforce: auth tags may only come from self.auth_tag injection.
        let auth_count = event
            .tags
            .iter()
            .filter(|t| t.as_slice().first().map(|s| s.as_str()) == Some("auth"))
            .count();
        let expected = if self.auth_tag.is_some() { 1 } else { 0 };
        if auth_count != expected {
            return Err(CliError::Other(format!(
                "event has {auth_count} auth tags — expected {expected}; \
                 callers must not add auth tags manually"
            )));
        }

        Ok(event)
    }

    /// Attach the `x-auth-tag` header if configured (NIP-OA relay membership delegation).
    fn with_auth_tag(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self.auth_tag_json {
            Some(ref json) => req.header("x-auth-tag", json),
            None => req,
        }
    }

    /// Keyed stored-event POST. Always uses [`Self::http_keyed`] so the signed
    /// body and `Idempotency-Key` cannot be forwarded through a redirect.
    fn keyed_stored_event_post(
        &self,
        url: &str,
        body: bytes::Bytes,
        key_hex: &str,
        auth: String,
    ) -> reqwest::RequestBuilder {
        self.with_auth_tag(
            self.http_keyed
                .post(url)
                .header("Authorization", auth)
                .header("Content-Type", "application/json")
                .header(buzz_core::idempotency::HEADER_NAME, key_hex)
                .body(body),
        )
    }

    /// Execute `op` up to `RETRY_MAX_ATTEMPTS` times, including body-transfer failures
    /// and transient relay error statuses.
    ///
    /// The closure is expected to consume the response body and return the parsed result
    /// as `T`. Retries on non-last attempts when `op` returns:
    ///
    /// - `Err(CliError::Network(e))` where `e.is_connect() || e.is_timeout() ||
    ///   e.is_request() || e.is_body() || e.is_decode()` — covers both connection
    ///   failures and mid-body TCP drops.
    /// - `Err(CliError::Relay { status: 429 | 502 | 503 | 504, .. })` — transient
    ///   relay or proxy errors on read-semantic operations. For 429 the `retry in Ns`
    ///   hint from the body is used as the delay (capped at `RETRY_IN_MAX_SECS`);
    ///   502, 503, and 504 use exponential jitter. Unkeyed stored-event writes use
    ///   [`Self::with_retry_unkeyed_write`] and do not retry HTTP 503.
    ///
    /// Use this variant for all operations (reads, writes, uploads); the retry boundary
    /// covers the entire operation including response body transfer.
    async fn with_retry_body<'a, T, F, Fut>(&'a self, op: F) -> Result<T, CliError>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T, CliError>> + 'a,
        T: 'a,
    {
        self.with_retry_classified(true, op).await
    }

    async fn with_retry_unkeyed_write<'a, T, F, Fut>(&'a self, op: F) -> Result<T, CliError>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T, CliError>> + 'a,
        T: 'a,
    {
        self.with_retry_classified(false, op).await
    }

    async fn with_retry_classified<'a, T, F, Fut>(
        &'a self,
        retry_503: bool,
        op: F,
    ) -> Result<T, CliError>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T, CliError>> + 'a,
        T: 'a,
    {
        for attempt in 0..RETRY_MAX_ATTEMPTS {
            let is_last = attempt == RETRY_MAX_ATTEMPTS - 1;
            match op().await {
                Ok(value) => return Ok(value),
                Err(e) => {
                    if !is_last {
                        let delay = match &e {
                            CliError::Network(net_err)
                                if net_err.is_connect()
                                    || net_err.is_timeout()
                                    || net_err.is_request()
                                    || net_err.is_body()
                                    || net_err.is_decode() =>
                            {
                                Some(jitter_delay(attempt))
                            }
                            CliError::Relay { status: 429, body } => {
                                let d = parse_retry_hint_text(body)
                                    .map(|s| Duration::from_secs(s.min(RETRY_IN_MAX_SECS)))
                                    .unwrap_or_else(|| jitter_delay(attempt));
                                Some(d)
                            }
                            CliError::Relay {
                                status: 502 | 504, ..
                            } => Some(jitter_delay(attempt)),
                            CliError::Relay { status: 503, .. } if retry_503 => {
                                Some(jitter_delay(attempt))
                            }
                            _ => None,
                        };
                        if let Some(d) = delay {
                            tokio::time::sleep(d).await;
                            continue;
                        }
                    }
                    return Err(e);
                }
            }
        }
        unreachable!("loop exhausts all RETRY_MAX_ATTEMPTS")
    }

    async fn query_pages(
        &self,
        mut filter: serde_json::Value,
        limit: Option<u32>,
    ) -> Result<Vec<serde_json::Value>, CliError> {
        let mut events = Vec::new();

        while limit.is_none_or(|limit| events.len() < limit as usize) {
            let page_limit = limit
                .map(|limit| (limit as usize - events.len()).min(QUERY_PAGE_SIZE as usize))
                .unwrap_or(QUERY_PAGE_SIZE as usize);
            filter["limit"] = serde_json::json!(page_limit);

            let raw = self.query(&filter).await?;
            let page: Vec<serde_json::Value> = serde_json::from_str(&raw)
                .map_err(|e| CliError::Other(format!("failed to parse query response: {e}")))?;
            let done = page.len() < page_limit;

            if !done {
                advance_query_cursor(&mut filter, &page)?;
            }
            events.extend(page);
            if done {
                break;
            }
        }

        Ok(events)
    }

    /// Query up to `limit` historical events, following the relay bridge's
    /// composite `(until, before_id)` cursor across bounded result pages.
    pub async fn query_paginated(
        &self,
        filter: serde_json::Value,
        limit: u32,
    ) -> Result<Vec<serde_json::Value>, CliError> {
        self.query_pages(filter, Some(limit)).await
    }

    /// Query every historical event matching a filter across bounded pages.
    pub async fn query_all(
        &self,
        filter: serde_json::Value,
    ) -> Result<Vec<serde_json::Value>, CliError> {
        self.query_pages(filter, None).await
    }

    /// Query a filter exhaustively up to `max_events`.
    ///
    /// One extra event is requested so reaching the bound is reported as
    /// truncation instead of being mistaken for authoritative absence.
    pub async fn query_all_bounded(
        &self,
        filter: serde_json::Value,
        max_events: u32,
    ) -> Result<Vec<serde_json::Value>, CliError> {
        let probe_limit = max_events
            .checked_add(1)
            .ok_or_else(|| CliError::Other("query bound is too large".into()))?;
        let events = self.query_pages(filter, Some(probe_limit)).await?;
        if events.len() > max_events as usize {
            return Err(CliError::Other(format!(
                "query exceeded the exhaustive {max_events}-event bound; narrow the query or retry"
            )));
        }
        Ok(events)
    }

    /// Sign an event builder verbatim: no NIP-OA auth-tag injection, and none
    /// of [`sign_event`]'s "callers must not add auth tags" enforcement.
    ///
    /// Used only for NIP-IA identity archive/unarchive requests (kind
    /// 9035/9036), whose optional `auth` tag is a *content-level*
    /// owner-of-agent attestation about the *target* identity — unrelated to
    /// this client's own NIP-OA membership delegation (`self.auth_tag`,
    /// which [`sign_event`] injects into every other event and which
    /// `submit_event` separately attaches via the `x-auth-tag` HTTP header).
    /// Routing an identity archive request through `sign_event` would either
    /// silently drop the caller's owner attestation or double up an
    /// unrelated tag.
    pub fn sign_event_unchecked(&self, builder: EventBuilder) -> Result<nostr::Event, CliError> {
        builder
            .sign_with_keys(&self.keys)
            .map_err(|e| CliError::Other(format!("signing failed: {e}")))
    }

    /// GET a public, unauthenticated relay endpoint (e.g. the NIP-11 `/info`
    /// document), returning the raw JSON body. No NIP-98 Authorization and no
    /// `x-auth-tag` header — the endpoint is public relay metadata, not a
    /// membership-scoped resource.
    pub async fn get_public(&self, path: &str) -> Result<String, CliError> {
        let url = format!("{}{path}", self.relay_url);
        let http = public_no_redirect_client()?;
        let resp = http
            .get(&url)
            .header("Accept", "application/nostr+json")
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// GET public relay metadata (NIP-11) with a fixed body ceiling.
    ///
    /// Used only for the keyed kind-9 send preflight. Does not follow
    /// redirects. A declared `Content-Length` above
    /// [`NIP11_PUBLIC_METADATA_MAX_BYTES`] is rejected before reading body
    /// bytes. Missing, dishonest, or chunked lengths are consumed
    /// incrementally and stop at the first over-limit chunk. Oversize
    /// success and error responses map to
    /// [`CliError::PublicMetadataTooLarge`] and never echo the body.
    /// In-bound non-success responses keep their HTTP status and typed
    /// error family (`Conflict` for 409, otherwise `Relay`) but replace
    /// any relay-controlled body with a fixed client message.
    pub async fn get_public_metadata(&self, path: &str) -> Result<String, CliError> {
        let url = format!("{}{path}", self.relay_url);
        let http = public_no_redirect_client()?;
        let resp = http
            .get(&url)
            .header("Accept", "application/nostr+json")
            .send()
            .await?;
        handle_bounded_public_metadata(resp, NIP11_PUBLIC_METADATA_MAX_BYTES).await
    }

    /// Execute a one-shot query via the HTTP bridge.
    /// `filter` is a Nostr filter object (will be wrapped in an array).
    /// Returns the raw JSON response (array of events).
    pub async fn query(&self, filter: &serde_json::Value) -> Result<String, CliError> {
        self.query_multi(std::slice::from_ref(filter)).await
    }

    /// Execute a one-shot query with multiple filters via the HTTP bridge.
    /// Each filter is ORed by the relay (standard Nostr REQ behavior).
    pub async fn query_multi(&self, filters: &[serde_json::Value]) -> Result<String, CliError> {
        let url = format!("{}/query", self.relay_url);
        let body = bytes::Bytes::from(
            serde_json::to_vec(filters)
                .map_err(|e| CliError::Other(format!("filter serialization failed: {e}")))?,
        );
        self.with_retry_body(|| {
            let body = body.clone();
            let url = url.clone();
            async move {
                let auth = sign_nip98(&self.keys, "POST", &url, Some(&body))?;
                let resp = self
                    .with_auth_tag(
                        self.http
                            .post(&url)
                            .header("Authorization", auth)
                            .header("Content-Type", "application/json")
                            .body(body),
                    )
                    .send()
                    .await?;
                self.handle_response(resp).await
            }
        })
        .await
    }

    /// Execute a one-shot count via the HTTP bridge.
    /// Returns the count as a JSON string.
    #[allow(dead_code)]
    pub async fn count(&self, filter: &serde_json::Value) -> Result<String, CliError> {
        let url = format!("{}/count", self.relay_url);
        let body = bytes::Bytes::from(
            serde_json::to_vec(&[filter])
                .map_err(|e| CliError::Other(format!("filter serialization failed: {e}")))?,
        );
        self.with_retry_body(|| {
            let body = body.clone();
            let url = url.clone();
            async move {
                let auth = sign_nip98(&self.keys, "POST", &url, Some(&body))?;
                let resp = self
                    .with_auth_tag(
                        self.http
                            .post(&url)
                            .header("Authorization", auth)
                            .header("Content-Type", "application/json")
                            .body(body),
                    )
                    .send()
                    .await?;
                self.handle_response(resp).await
            }
        })
        .await
    }

    /// GET an authed relay endpoint (NIP-98), returning the raw JSON body.
    ///
    /// `path` is a root-relative path incl. any query string, e.g.
    /// `/moderation/reports?status=open&limit=20`. Used by the moderation
    /// read commands, which read structured queue/audit rows rather than
    /// stored events.
    pub async fn get_authed(&self, path: &str) -> Result<String, CliError> {
        let url = format!("{}{path}", self.relay_url);
        self.with_retry_body(|| {
            let url = url.clone();
            async move {
                let auth = sign_nip98(&self.keys, "GET", &url, None)?;
                let resp = self
                    .with_auth_tag(self.http.get(&url).header("Authorization", auth))
                    .send()
                    .await?;
                self.handle_response(resp).await
            }
        })
        .await
    }

    /// POST a JSON body to a relay-relative path with NIP-98 authentication.
    ///
    /// Used by `buzz gifs search` and `buzz gifs share` to reach the relay's
    /// KLIPY proxy endpoints.  Returns the raw response body as a string (may
    /// be empty for 204 No Content responses).
    pub async fn post_json_authed(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<String, CliError> {
        let url = format!("{}{path}", self.relay_url);
        let body_bytes = bytes::Bytes::from(
            serde_json::to_vec(body)
                .map_err(|e| CliError::Other(format!("request serialization failed: {e}")))?,
        );
        self.with_retry_body(|| {
            let body_bytes = body_bytes.clone();
            let url = url.clone();
            async move {
                let auth = sign_nip98(&self.keys, "POST", &url, Some(&body_bytes))?;
                let resp = self
                    .with_auth_tag(
                        self.http
                            .post(&url)
                            .header("Authorization", auth)
                            .header("Content-Type", "application/json")
                            .body(body_bytes),
                    )
                    .send()
                    .await?;
                // 204 No Content: return empty string rather than failing on
                // an empty body that cannot be parsed as JSON.
                if resp.status() == reqwest::StatusCode::NO_CONTENT {
                    return Ok(String::new());
                }
                self.handle_response(resp).await
            }
        })
        .await
    }

    /// Submit a signed Nostr event via POST /events.
    ///
    /// For non-idempotent moderation command kinds (9040–9044), an ambiguous
    /// outcome (mid-request error, body loss, non-ingest 429, or 502/503/504)
    /// surfaces as `CliError::DeliveryUnknown` instead of being retried.  These
    /// events execute at the relay *before* any dedup check, so a blind re-send
    /// can duplicate the mutation.  Only confirmed-unreceived failures (TCP
    /// connect error or a pre-ingest 429 carrying a `rate-limited:` body) are
    /// safe to retry.
    ///
    /// All other event kinds retain the standard retry policy.
    pub async fn submit_event(&self, event: nostr::Event) -> Result<String, CliError> {
        self.submit_event_with_idempotency_key(event, None).await
    }

    /// Submit a stored event, optionally with a request-scoped idempotency key.
    ///
    /// When `key` is `Some`, the same serialized body and `Idempotency-Key`
    /// header are reused on 503/network retries; NIP-98 is re-signed each
    /// attempt. Unkeyed submits never retry HTTP 503 as if they were keyed.
    pub async fn submit_event_with_idempotency_key(
        &self,
        event: nostr::Event,
        key: Option<[u8; 32]>,
    ) -> Result<String, CliError> {
        let kind = event.kind.as_u16();
        if let Some(key) = key {
            if is_moderation_kind(kind)
                || !buzz_core::idempotency::supports_keyed_kind(u32::from(kind))
            {
                return Err(CliError::Usage(
                    "--idempotency-key is only supported for kind 9".into(),
                ));
            }
            self.submit_keyed_stored_event(event, key).await
        } else if is_moderation_kind(kind) {
            self.submit_moderation_event(event).await
        } else {
            self.submit_stored_event(event).await
        }
    }

    /// Submit a moderation command (kinds 9040–9044) with non-idempotent retry policy.
    async fn submit_moderation_event(&self, event: nostr::Event) -> Result<String, CliError> {
        let url = format!("{}/events", self.relay_url);
        let body = bytes::Bytes::from(
            serde_json::to_vec(&event)
                .map_err(|e| CliError::Other(format!("event serialization failed: {e}")))?,
        );

        for attempt in 0..RETRY_MAX_ATTEMPTS {
            let is_last = attempt == RETRY_MAX_ATTEMPTS - 1;

            // Re-sign NIP-98 each attempt: the nonce tag generates a fresh
            // event ID, keeping retries safe against the relay's replay guard.
            let auth = sign_nip98(&self.keys, "POST", &url, Some(&body))?;
            let send_result: Result<reqwest::Response, CliError> = self
                .with_auth_tag(
                    self.http
                        .post(&url)
                        .header("Authorization", auth)
                        .header("Content-Type", "application/json")
                        .body(body.clone()),
                )
                .send()
                .await
                .map_err(CliError::from);

            match send_result {
                Err(e) => {
                    if let CliError::Network(ref net_err) = e {
                        // Only connect-failure is safe to retry: the relay never saw
                        // the request. Timeout and mid-request errors are ambiguous.
                        if !is_last && net_err.is_connect() {
                            tokio::time::sleep(jitter_delay(attempt)).await;
                            continue;
                        }
                        if net_err.is_connect() {
                            // Final attempt: definitively never reached the relay — retryable.
                            return Err(e);
                        }
                        if net_err.is_timeout()
                            || net_err.is_request()
                            || net_err.is_body()
                            || net_err.is_decode()
                        {
                            // Ambiguous: the relay may have executed this command.
                            return Err(CliError::DeliveryUnknown(format!(
                                "moderation command (kind {}) outcome unknown: {}",
                                event.kind.as_u16(),
                                net_err
                            )));
                        }
                    }
                    return Err(e);
                }
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if status == 429 {
                        // Only retry if the relay's own ingest layer rejected it:
                        // the extracted error/message field must start with
                        // "rate-limited:". A proxy-level 429 (or JSON-wrapped body
                        // whose field does not start with "rate-limited:") leaves
                        // relay execution state ambiguous.
                        let body_text = resp.text().await.unwrap_or_default();
                        let extracted = extract_relay_message_field(&body_text);
                        let msg = extracted.as_deref().unwrap_or(&body_text);
                        if msg.starts_with("rate-limited:") {
                            // Canonical pre-ingest 429: the relay provably did not execute
                            // the command. Retry while budget remains; on exhaustion return
                            // Relay(429) (retryable:true) — the caller may retry the exact
                            // same command. DeliveryUnknown is reserved for outcomes where
                            // relay execution is genuinely ambiguous (proxy 429, 502-504,
                            // timeout/body-loss after the relay may have acted).
                            if !is_last {
                                let delay = parse_retry_hint_text(msg)
                                    .map(|s| Duration::from_secs(s.min(RETRY_IN_MAX_SECS)))
                                    .unwrap_or_else(|| jitter_delay(attempt));
                                tokio::time::sleep(delay).await;
                                continue;
                            }
                            // Budget exhausted — still pre-ingest, still safe to retry.
                            return Err(CliError::Relay {
                                status: 429,
                                body: body_text,
                            });
                        }
                        // Non-canonical 429 (proxy-level or unrecognised body): outcome unknown.
                        return Err(CliError::DeliveryUnknown(format!(
                            "moderation command (kind {}) outcome unknown: HTTP 429",
                            event.kind.as_u16()
                        )));
                    }
                    if matches!(status, 502..=504) {
                        // Proxy-level error: the relay may have received and executed
                        // the command before the proxy failed.
                        return Err(CliError::DeliveryUnknown(format!(
                            "moderation command (kind {}) outcome unknown: HTTP {status}",
                            event.kind.as_u16()
                        )));
                    }
                    // 2xx or definitive error (4xx other than 429): read body normally.
                    let body_text = resp.text().await.map_err(|e| {
                        // Body loss after relay confirmed receipt is ambiguous for
                        // non-idempotent commands.
                        CliError::DeliveryUnknown(format!(
                            "moderation command (kind {}) outcome unknown: response body lost: {e}",
                            event.kind.as_u16()
                        ))
                    })?;
                    // Map the body through handle_response's error logic inline.
                    if !resp_was_success(status) {
                        let message = serde_json::from_str::<serde_json::Value>(&body_text)
                            .ok()
                            .and_then(|v| {
                                v.get("error")
                                    .or_else(|| v.get("message"))
                                    .and_then(|m| m.as_str())
                                    .map(str::to_string)
                            })
                            .unwrap_or(body_text);
                        let message = if status == 403 && std::env::var("BUZZ_AUTH_TAG").is_ok() {
                            format!(
                                "{message} (BUZZ_AUTH_TAG is set — it may be stale or revoked; try unsetting it)"
                            )
                        } else {
                            message
                        };
                        return Err(CliError::Relay {
                            status,
                            body: message,
                        });
                    }
                    return Ok(body_text);
                }
            }
        }
        unreachable!("loop exhausts all RETRY_MAX_ATTEMPTS")
    }

    /// Submit a stored event (all non-moderation kinds) with the standard retry policy.
    ///
    /// The full operation — network send AND response body read — is inside the retry
    /// boundary so that a dropped body after a 200 header is retried with the same
    /// serialized event bytes (and a fresh per-attempt NIP-98 auth event).
    ///
    /// **Exhaustion policy:** after all attempts, connect failures and canonical
    /// pre-ingest 429 remain retryable (`CliError::Network`/`CliError::Relay{429}`)
    /// because the relay provably never executed them. Any other final failure
    /// (timeout, request, body loss, decode, proxy 502-504) is ambiguous — the
    /// relay may have stored the event — so we surface `DeliveryUnknown`
    /// (retryable:false) to prevent an outer re-sign creating a duplicate write.
    /// Content-addressed uploads are exempt: same bytes ⇒ same hash, so outer
    /// re-run is safe regardless of the failure kind.
    async fn submit_stored_event(&self, event: nostr::Event) -> Result<String, CliError> {
        let url = format!("{}/events", self.relay_url);
        let body = bytes::Bytes::from(
            serde_json::to_vec(&event)
                .map_err(|e| CliError::Other(format!("event serialization failed: {e}")))?,
        );
        let result = self
            .with_retry_unkeyed_write(|| {
                let body = body.clone();
                let url = url.clone();
                async move {
                    // Re-sign NIP-98 each attempt: the nonce tag generates a fresh
                    // event ID, keeping retries safe against the relay's replay guard.
                    let auth = sign_nip98(&self.keys, "POST", &url, Some(&body))?;
                    let resp = self
                        .with_auth_tag(
                            self.http
                                .post(&url)
                                .header("Authorization", auth)
                                .header("Content-Type", "application/json")
                                .body(body),
                        )
                        .send()
                        .await?;
                    self.handle_response(resp).await
                }
            })
            .await;

        // Translate ambiguous final errors to DeliveryUnknown so an outer agent
        // following retryable:true does not re-sign and risk a duplicate write.
        // Connect failures stay Network (retryable:true) — definitively never received.
        // Canonical pre-ingest 429 (Relay{429}) stays retryable — definitively not stored.
        if let Err(ref e) = result {
            if is_stored_event_exhaustion_ambiguous(e) {
                let kind_u16 = event.kind.as_u16();
                return Err(CliError::DeliveryUnknown(format!(
                    "stored event (kind {kind_u16}) outcome unknown after all attempts: {e}"
                )));
            }
        }
        result
    }

    /// Keyed stored-event POST. Retries only HTTP 503 and transport-uncertain
    /// network failures, up to [`KEYED_RETRY_MAX_ATTEMPTS`] (initial plus three
    /// retries). Each retry reuses the same signed event, serialized body, and
    /// `Idempotency-Key`, and generates a fresh NIP-98 Authorization. Extra
    /// keyed retries reuse the last generic jitter ceiling.
    ///
    /// One Tokio-clock deadline covers send, response-body read, and retry
    /// sleeps for the whole operation. A valid positive Retry-After that does
    /// not fit the remaining bound, or a final-attempt positive representable
    /// Retry-After (delay-seconds or HTTP-date floor), returns
    /// [`CliError::RelayDeferred`] without another request. `Retry-After: 0`
    /// and missing/malformed Retry-After return the original 503. Numeric
    /// overflow returns [`CliError::RelayRetryAfterOverflow`] without another
    /// request and without inventing a finite wait.
    ///
    /// Deadline expiry while an HTTP request or response body is still in
    /// flight is [`CliError::DeliveryUnknown`]. A scheduler overrun that
    /// crosses the deadline during a retry sleep does not invent that
    /// ambiguity: the already-known error is classified. Keyed 503 with a
    /// positive representable Retry-After is [`CliError::RelayDeferred`] with
    /// that exact floor; keyed 503 with a zero or missing/malformed hint
    /// stays [`CliError::Relay`]; overflow is
    /// [`CliError::RelayRetryAfterOverflow`]; a definitive connect failure
    /// stays the network error; a transport-uncertain timeout, request, body,
    /// or decode outcome is [`CliError::DeliveryUnknown`].
    async fn submit_keyed_stored_event(
        &self,
        event: nostr::Event,
        key: [u8; 32],
    ) -> Result<String, CliError> {
        let url = format!("{}/events", self.relay_url);
        let body = bytes::Bytes::from(
            serde_json::to_vec(&event)
                .map_err(|e| CliError::Other(format!("event serialization failed: {e}")))?,
        );
        let key_hex = hex::encode(key);
        let kind_u16 = event.kind.as_u16();
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(KEYED_OPERATION_DEADLINE_SECS);
        self.submit_keyed_within_deadline(url, body, key_hex, kind_u16, deadline)
            .await
    }

    async fn submit_keyed_within_deadline(
        &self,
        url: String,
        body: bytes::Bytes,
        key_hex: String,
        kind_u16: u16,
        deadline: tokio::time::Instant,
    ) -> Result<String, CliError> {
        for attempt in 0..KEYED_RETRY_MAX_ATTEMPTS {
            let is_last = attempt == KEYED_RETRY_MAX_ATTEMPTS - 1;
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(keyed_deadline_unknown(kind_u16));
            }
            let body = body.clone();
            let url = url.clone();
            let key_hex = key_hex.clone();
            let attempt_fut = async {
                let auth = sign_nip98(&self.keys, "POST", &url, Some(&body))?;
                let send_result = self
                    .keyed_stored_event_post(&url, body, &key_hex, auth)
                    .send()
                    .await;
                match send_result {
                    Err(e) => Ok::<_, CliError>((
                        Err(CliError::from(e)),
                        RetryAfterHint::MissingOrMalformed,
                    )),
                    Ok(resp) => {
                        if let Some(err) = keyed_redirect_refused(resp.status()) {
                            Ok((Err(err), RetryAfterHint::MissingOrMalformed))
                        } else {
                            let retry_after =
                                if resp.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE {
                                    parse_retry_after_hint(resp.headers())
                                } else {
                                    RetryAfterHint::MissingOrMalformed
                                };
                            Ok((handle_keyed_response(resp).await, retry_after))
                        }
                    }
                }
            };
            let (result, retry_after) = match tokio::time::timeout_at(deadline, attempt_fut).await {
                Ok(Ok(pair)) => pair,
                Ok(Err(e)) => return Err(e),
                Err(_elapsed) => return Err(keyed_deadline_unknown(kind_u16)),
            };
            match result {
                Ok(value) => return Ok(value),
                Err(e) => {
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    if remaining.is_zero() {
                        return Err(keyed_deadline_after_known_error(e, retry_after, kind_u16));
                    }
                    // Last attempt must not compute retry-only delay state.
                    // Extra keyed retries reuse the last RETRY_BASE_SECS
                    // ceiling via keyed_jitter_delay rather than indexing past
                    // the generic table.
                    if is_last {
                        return Err(keyed_exhausted_error(e, retry_after));
                    }
                    let delay = match &e {
                        CliError::Network(net_err)
                            if net_err.is_connect()
                                || net_err.is_timeout()
                                || net_err.is_request()
                                || net_err.is_body()
                                || net_err.is_decode() =>
                        {
                            let delay = keyed_jitter_delay(attempt);
                            delay_strictly_fits(delay, remaining).then_some(delay)
                        }
                        CliError::Relay { status: 503, .. } => keyed_503_retry_delay(
                            retry_after,
                            keyed_jitter_delay(attempt),
                            remaining,
                        ),
                        _ => None,
                    };
                    if let Some(d) = delay {
                        tokio::time::sleep(d).await;
                        if deadline
                            .saturating_duration_since(tokio::time::Instant::now())
                            .is_zero()
                        {
                            return Err(keyed_deadline_after_known_error(e, retry_after, kind_u16));
                        }
                        continue;
                    }
                    return Err(keyed_exhausted_error(e, retry_after));
                }
            }
        }
        Err(CliError::Other("keyed submit exhausted retries".into()))
    }

    /// Publish an ephemeral event via WebSocket with NIP-42 authentication.
    ///
    /// The relay rejects ephemeral kinds (20000–29999) over HTTP. Delegates to
    /// `buzz_ws_client::publish_event` which handles connect, NIP-42 auth,
    /// EVENT send, OK wait, and graceful close.
    pub async fn publish_ephemeral_event(&self, event: nostr::Event) -> Result<String, CliError> {
        let ws_url = to_ws_url(&self.relay_url);
        // Hard cap — inner wait ceilings sum to 70 s; connect time and network RTT are
        // additional overhead absorbed by this budget.
        // See buzz_ws_client::{AUTH_CHALLENGE_TIMEOUT_SECS, AUTH_OK_TIMEOUT_SECS,
        // PUBLISH_OK_TIMEOUT_SECS} for the inner ceilings.
        let ok =
            buzz_ws_client::publish_event(&ws_url, event, &self.keys, self.auth_tag.as_ref(), 75)
                .await
                .map_err(|e| CliError::Other(e.to_string()))?;

        if !ok.accepted {
            return Err(CliError::Relay {
                status: 400,
                body: ok.message,
            });
        }
        Ok(serde_json::json!({
            "event_id": ok.event_id,
            "accepted": true,
            "message": ok.message,
        })
        .to_string())
    }

    /// Upload a file to the relay's Blossom endpoint.
    /// Returns a BlobDescriptor on success.
    pub async fn upload_file(&self, file_path: &str) -> Result<BlobDescriptor, CliError> {
        // 1. Read file — validate it exists and is a regular file
        let metadata = std::fs::metadata(file_path)
            .map_err(|e| CliError::Other(format!("cannot access {file_path}: {e}")))?;
        if !metadata.is_file() {
            return Err(CliError::Usage(format!("{file_path} is not a file")));
        }

        let bytes = std::fs::read(file_path)
            .map_err(|e| CliError::Other(format!("failed to read {file_path}: {e}")))?;

        // 2. Detect MIME from magic bytes
        let mime = infer::get(&bytes)
            .map(|t| t.mime_type().to_string())
            .unwrap_or_else(|| "application/octet-stream".to_string());

        if !ALLOWED_MIMES.contains(&mime.as_str()) {
            return Err(CliError::Usage(format!("unsupported file type: {mime}")));
        }

        // 3. Size check
        let max = if mime.starts_with("video/") {
            MAX_VIDEO_BYTES
        } else {
            MAX_IMAGE_BYTES
        };
        if bytes.len() as u64 > max {
            return Err(CliError::Usage(format!(
                "file too large: {} bytes (max {})",
                bytes.len(),
                max
            )));
        }

        // 4. SHA-256
        let sha256 = hex::encode(Sha256::digest(&bytes));

        // 5. PUT request to the BUD-02 /upload endpoint with a generous timeout.
        // Auth is signed per attempt — matches the per-attempt signing pattern in download_media.
        let upload_timeout = if mime.starts_with("video/") {
            Duration::from_secs(600)
        } else {
            Duration::from_secs(120)
        };
        let url = format!("{}/upload", self.relay_url);
        let upload_body = bytes::Bytes::from(bytes);

        // The full upload operation — network send AND response body read — lives inside
        // with_retry_body so that a dropped body after 200 headers is retried with the
        // same file bytes and a fresh Blossom auth per attempt.
        let result: Result<BlobDescriptor, CliError> = self
            .with_retry_body(|| {
                let upload_body = upload_body.clone();
                let url = url.clone();
                let mime = mime.clone();
                let sha256 = sha256.clone();
                async move {
                    let auth_header =
                        sign_blossom_upload(&self.keys, &sha256, &mime, &self.relay_url)?;
                    let resp = self
                        .with_auth_tag(
                            self.http
                                .put(&url)
                                .timeout(upload_timeout)
                                .header("Authorization", auth_header)
                                .header("Content-Type", &mime)
                                .header("X-SHA-256", &sha256)
                                .body(upload_body),
                        )
                        .send()
                        .await?;
                    let status = resp.status();
                    if !status.is_success() {
                        let s = status.as_u16();
                        let body = resp.text().await.unwrap_or_default();
                        return Err(CliError::Relay { status: s, body });
                    }
                    resp.json::<BlobDescriptor>().await.map_err(CliError::from)
                }
            })
            .await;

        // If the primary /upload endpoint definitively doesn't exist on this relay version
        // (404 or 405), fall back to the legacy /media/upload endpoint.  The 404/405 switch
        // itself is not retried; only transient failures on the selected legacy endpoint are.
        match result {
            Ok(desc) => return Ok(desc),
            Err(CliError::Relay { status: s, body: _ })
                if should_retry_legacy_upload(
                    reqwest::StatusCode::from_u16(s).unwrap_or(reqwest::StatusCode::NOT_FOUND),
                ) =>
            {
                // Fall through to legacy endpoint below.
            }
            Err(e) => return Err(e),
        }

        let legacy_url = format!("{}/media/upload", self.relay_url);
        self.with_retry_body(|| {
            let upload_body = upload_body.clone();
            let legacy_url = legacy_url.clone();
            let mime = mime.clone();
            let sha256 = sha256.clone();
            async move {
                let auth_header = sign_blossom_upload(&self.keys, &sha256, &mime, &self.relay_url)?;
                let resp = self
                    .with_auth_tag(
                        self.http
                            .put(&legacy_url)
                            .timeout(upload_timeout)
                            .header("Authorization", auth_header)
                            .header("Content-Type", &mime)
                            .header("X-SHA-256", &sha256)
                            .body(upload_body),
                    )
                    .send()
                    .await?;
                if !resp.status().is_success() {
                    let status = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default();
                    return Err(CliError::Relay { status, body });
                }
                resp.json::<BlobDescriptor>().await.map_err(CliError::from)
            }
        })
        .await
    }

    /// Download a Blossom media blob using BUD-01 `t=get` auth.
    pub async fn download_media(&self, input: &str) -> Result<bytes::Bytes, CliError> {
        let url = media_url_from_input(&self.relay_url, input)?;
        // Use a dedicated client: 120 s timeout, no redirect forwarding.
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            // Do not forward Authorization or x-auth-tag to redirect targets.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| CliError::Other(format!("http client init failed: {e}")))?;
        self.with_retry_body(|| {
            let url = url.clone();
            let client = client.clone();
            async move {
                let auth_header = sign_blossom_get(&self.keys, &url)?;
                let resp = self
                    .with_auth_tag(client.get(&url).header("Authorization", auth_header))
                    .send()
                    .await?;
                if !resp.status().is_success() {
                    let status = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default();
                    return Err(CliError::Relay { status, body });
                }
                resp.bytes().await.map_err(CliError::Network)
            }
        })
        .await
    }

    async fn handle_response(&self, resp: reqwest::Response) -> Result<String, CliError> {
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            map_response_status_and_body(status, body)
        } else {
            let body = resp.text().await?;
            map_response_status_and_body(status, body)
        }
    }
}

/// Normalize a relay URL: ws:// → http://, wss:// → https://, strip trailing slash.
/// BUZZ_RELAY_URL may be ws/wss (copied from MCP config).
pub fn normalize_relay_url(url: &str) -> String {
    url.replace("wss://", "https://")
        .replace("ws://", "http://")
        .trim_end_matches('/')
        .to_string()
}

/// Convert an HTTP(S) relay base URL back to a WebSocket URL for NIP-01 connections.
fn to_ws_url(http_url: &str) -> String {
    http_url
        .replace("https://", "wss://")
        .replace("http://", "ws://")
}

/// Normalize raw event JSON array into the canonical Nostr event shape.
/// String signatures are preserved; absent or non-string signatures remain absent.
pub fn normalize_events(events: &[serde_json::Value]) -> String {
    let normalized: Vec<serde_json::Value> = events
        .iter()
        .map(|e| {
            let mut event = serde_json::json!({
                "id": e.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                "pubkey": e.get("pubkey").and_then(|v| v.as_str()).unwrap_or(""),
                "kind": e.get("kind").and_then(|v| v.as_u64()).unwrap_or(0),
                "content": e.get("content").and_then(|v| v.as_str()).unwrap_or(""),
                "created_at": e.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0),
                "tags": e.get("tags").cloned().unwrap_or(serde_json::json!([])),
            });
            if let Some(sig) = e.get("sig").and_then(|v| v.as_str()) {
                event["sig"] = serde_json::json!(sig);
            }
            event
        })
        .collect();
    serde_json::to_string(&normalized).unwrap_or_default()
}

/// Extract the d-tag value from a Nostr event JSON object.
pub fn extract_d_tag(event: &serde_json::Value) -> String {
    event
        .get("tags")
        .and_then(|t| t.as_array())
        .and_then(|tags| {
            tags.iter().find(|t| {
                t.as_array()
                    .and_then(|a| a.first())
                    .and_then(|v| v.as_str())
                    == Some("d")
            })
        })
        .and_then(|t| t.as_array())
        .and_then(|a| a.get(1))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Extract a named tag's value from a Nostr event JSON object.
/// Finds the first tag whose first element matches `key` and returns the second element.
pub fn extract_tag_value(event: &serde_json::Value, key: &str) -> String {
    event
        .get("tags")
        .and_then(|t| t.as_array())
        .and_then(|tags| {
            tags.iter().find(|t| {
                t.as_array()
                    .and_then(|a| a.first())
                    .and_then(|v| v.as_str())
                    == Some(key)
            })
        })
        .and_then(|t| t.as_array())
        .and_then(|a| a.get(1))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Extract all p-tags into [{pubkey, role}] from a Nostr event JSON object.
pub fn extract_p_tags(event: &serde_json::Value) -> Vec<serde_json::Value> {
    event
        .get("tags")
        .and_then(|t| t.as_array())
        .map(|tags| {
            tags.iter()
                .filter(|t| {
                    t.as_array()
                        .and_then(|a| a.first())
                        .and_then(|v| v.as_str())
                        == Some("p")
                })
                .map(|t| {
                    let a = t.as_array().unwrap();
                    serde_json::json!({
                        "pubkey": a.get(1).and_then(|v| v.as_str()).unwrap_or(""),
                        "role": a.get(3).and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("member"),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Return a create-command response, injecting the entity ID **only** when the
/// relay accepted the event (`"accepted": true`). When the relay rejected the
/// event, emitting the locally-computed link would be misleading — callers
/// that copy or share the link would reference an event that was never stored.
pub fn create_response_with_id_if_accepted(resp: &str, id_key: &str, id_val: &str) -> String {
    let mut v: serde_json::Value = serde_json::from_str(resp).unwrap_or(serde_json::json!({}));
    let accepted = v.get("accepted").and_then(|a| a.as_bool()).unwrap_or(false);
    if accepted {
        v[id_key] = serde_json::json!(id_val);
    }
    v.to_string()
}

/// Print a create-command response, injecting the generated entity ID.
pub fn print_create_response(resp: &str, id_key: &str, id_val: &str) {
    println!(
        "{}",
        create_response_with_id_if_accepted(resp, id_key, id_val)
    );
}

/// Extract a JSON field from relay write response messages shaped as
/// `response:{...}`.
pub fn extract_relay_response_field(resp: &str, field: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(resp)
        .ok()?
        .get("message")?
        .as_str()?
        .strip_prefix("response:")
        .and_then(|json| serde_json::from_str::<serde_json::Value>(json).ok())
        .and_then(|v| v.get(field)?.as_str().map(str::to_string))
}

/// Normalize a relay write-response into a consistent JSON object.
/// Relay returns: {"event_id": "...", "accepted": true, "message": "..."}
/// Falls back to raw text if parsing fails.
pub fn normalize_write_response(raw: &str) -> String {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
        if v.get("event_id").is_some() || v.get("accepted").is_some() {
            return serde_json::json!({
                "event_id": v.get("event_id").and_then(|v| v.as_str()).unwrap_or(""),
                "accepted": v.get("accepted").and_then(|v| v.as_bool()).unwrap_or(false),
                "message": v.get("message").and_then(|v| v.as_str()).unwrap_or(""),
            })
            .to_string();
        }
    }
    raw.to_string()
}

#[cfg(test)]
mod retry_tests {
    use std::time::Duration;

    use crate::error::CliError;

    use chrono::{DateTime, NaiveDate, Utc};

    use super::{
        delay_from_retry_after_and_jitter, env_duration_secs, http_date_to_retry_after_hint,
        is_moderation_kind, jitter_delay, keyed_503_retry_delay, keyed_exhausted_error,
        keyed_jitter_delay, parse_retry_after_delta_seconds, parse_retry_after_hint,
        parse_retry_after_hint_at, parse_retry_after_value, parse_retry_hint_text,
        parse_retry_in_secs, RetryAfterHint, KEYED_OPERATION_DEADLINE_SECS,
        KEYED_RETRY_MAX_ATTEMPTS, RETRY_BASE_SECS, RETRY_IN_MAX_SECS, RETRY_MAX_ATTEMPTS,
    };

    fn utc_hms(year: i32, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> DateTime<Utc> {
        NaiveDate::from_ymd_opt(year, month, day)
            .unwrap()
            .and_hms_opt(hour, min, sec)
            .unwrap()
            .and_utc()
    }

    fn utc_hms_nano(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        min: u32,
        sec: u32,
        nano: u32,
    ) -> DateTime<Utc> {
        NaiveDate::from_ymd_opt(year, month, day)
            .unwrap()
            .and_hms_nano_opt(hour, min, sec, nano)
            .unwrap()
            .and_utc()
    }

    fn retry_after_headers(value: &str) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::RETRY_AFTER, value.parse().unwrap());
        headers
    }

    // ---- parse_retry_in_secs ----

    #[test]
    fn parse_relay_json_with_error_field() {
        let body = r#"{"error":"rate-limited: quota exceeded; retry in 5s"}"#;
        assert_eq!(parse_retry_in_secs(body), Some(5));
    }

    #[test]
    fn parse_relay_json_with_message_field() {
        let body = r#"{"message":"back off; retry in 3s please"}"#;
        assert_eq!(parse_retry_in_secs(body), Some(3));
    }

    #[test]
    fn parse_retry_in_zero_seconds() {
        let body = r#"{"error":"retry in 0s"}"#;
        assert_eq!(parse_retry_in_secs(body), Some(0));
    }

    #[test]
    fn parse_garbled_body_returns_none() {
        assert_eq!(parse_retry_in_secs("not json at all"), None);
    }

    #[test]
    fn parse_missing_retry_pattern_returns_none() {
        let body = r#"{"error":"rate-limited, please slow down"}"#;
        assert_eq!(parse_retry_in_secs(body), None);
    }

    #[test]
    fn parse_empty_body_returns_none() {
        assert_eq!(parse_retry_in_secs(""), None);
    }

    // ---- parse_retry_hint_text ----

    #[test]
    fn hint_text_plain_extracted_field_returns_secs() {
        // Shape produced by handle_response: JSON extracted, plain text arrives.
        assert_eq!(
            parse_retry_hint_text("rate-limited: quota exceeded; retry in 4s"),
            Some(4)
        );
    }

    #[test]
    fn hint_text_raw_json_body_returns_secs() {
        // Shape from download_media's inline error path: raw JSON body preserved.
        assert_eq!(
            parse_retry_hint_text(r#"{"error":"rate-limited: retry in 7s"}"#),
            Some(7)
        );
    }

    #[test]
    fn hint_text_plain_no_pattern_returns_none() {
        assert_eq!(parse_retry_hint_text("rate-limited: slow down"), None);
    }

    #[test]
    fn hint_text_empty_returns_none() {
        assert_eq!(parse_retry_hint_text(""), None);
    }

    // ---- is_moderation_kind ----

    #[test]
    fn moderation_kind_covers_9040_through_9044() {
        for kind in 9040u16..=9044 {
            assert!(is_moderation_kind(kind), "kind {kind} should be moderation");
        }
    }

    #[test]
    fn non_moderation_kinds_are_not_moderation() {
        for kind in [1u16, 9039, 9045, 39000, 20000, 30023] {
            assert!(
                !is_moderation_kind(kind),
                "kind {kind} should not be moderation"
            );
        }
    }

    // ---- Retry-After floor + jitter (keyed 503) ----

    #[test]
    fn keyed_retry_after_sixty_is_a_floor_plus_bounded_jitter() {
        let hint_secs = 60u64;
        let jitter = Duration::from_millis(250);
        let delay = delay_from_retry_after_and_jitter(Some(hint_secs), jitter)
            .expect("60s Retry-After must be representable");
        let hint = Duration::from_secs(hint_secs);
        assert!(
            delay >= hint,
            "valid Retry-After must never be undercut; got {delay:?} < {hint:?}"
        );
        assert_eq!(delay, hint + jitter);
        let no_jitter = delay_from_retry_after_and_jitter(Some(hint_secs), Duration::ZERO)
            .expect("60s Retry-After must be representable");
        assert_eq!(no_jitter, hint);
        assert!(delay >= no_jitter);
    }

    #[test]
    fn keyed_retry_after_missing_or_malformed_uses_jitter_fallback() {
        let jitter = Duration::from_millis(400);
        assert_eq!(
            delay_from_retry_after_and_jitter(None, jitter),
            Some(jitter)
        );

        let mut headers = reqwest::header::HeaderMap::new();
        assert_eq!(parse_retry_after_delta_seconds(&headers), None);
        headers.insert(reqwest::header::RETRY_AFTER, "5".parse().unwrap());
        assert_eq!(parse_retry_after_delta_seconds(&headers), Some(5));
        headers.insert(reqwest::header::RETRY_AFTER, "5s".parse().unwrap());
        assert_eq!(parse_retry_after_delta_seconds(&headers), None);
        headers.insert(reqwest::header::RETRY_AFTER, "not-a-date".parse().unwrap());
        assert_eq!(parse_retry_after_delta_seconds(&headers), None);
    }

    #[test]
    fn http_date_retry_after_future_exact_now_and_past() {
        let now = utc_hms(1994, 11, 6, 8, 49, 37);
        let future = retry_after_headers("Sun, 06 Nov 1994 08:50:37 GMT");
        assert_eq!(
            parse_retry_after_hint_at(&future, now),
            RetryAfterHint::Representable(60)
        );
        let exact = retry_after_headers("Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(
            parse_retry_after_hint_at(&exact, now),
            RetryAfterHint::Representable(0)
        );
        let past = retry_after_headers("Sun, 06 Nov 1994 08:48:37 GMT");
        assert_eq!(
            parse_retry_after_hint_at(&past, now),
            RetryAfterHint::Representable(0)
        );
    }

    #[test]
    fn http_date_retry_after_ceils_positive_fractional_remainder() {
        let now = utc_hms_nano(1994, 11, 6, 8, 49, 37, 500_000_000);
        let when = utc_hms(1994, 11, 6, 8, 49, 38);
        assert_eq!(
            http_date_to_retry_after_hint(when, now),
            RetryAfterHint::Representable(1),
            "0.5s remaining must ceil so the retry cannot start before the absolute time"
        );
        let headers = retry_after_headers("Sun, 06 Nov 1994 08:49:38 GMT");
        assert_eq!(
            parse_retry_after_hint_at(&headers, now),
            RetryAfterHint::Representable(1)
        );
        let exact_second = utc_hms(1994, 11, 6, 8, 49, 37);
        assert_eq!(
            parse_retry_after_hint_at(&headers, exact_second),
            RetryAfterHint::Representable(1)
        );
    }

    #[test]
    fn http_date_retry_after_accepts_imf_rfc850_and_asctime() {
        let now = utc_hms(1994, 11, 6, 7, 49, 37);
        for value in [
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
        ] {
            assert_eq!(
                parse_retry_after_hint_at(&retry_after_headers(value), now),
                RetryAfterHint::Representable(3600),
                "accepted HTTP-date form must parse with GMT semantics: {value}"
            );
        }
    }

    #[test]
    fn http_date_retry_after_malformed_keeps_jitter_fallback() {
        let now = utc_hms(1994, 11, 6, 8, 49, 37);
        for value in [
            "5s",
            "not-a-date",
            "Wed, 21 Oct 2015 07:28:00 UTC",
            "Sun, 06 Nov 1994 08:49:37 GMT trailing",
        ] {
            let hint = parse_retry_after_hint_at(&retry_after_headers(value), now);
            assert_eq!(
                hint,
                RetryAfterHint::MissingOrMalformed,
                "malformed Retry-After must keep the jitter fallback, got {hint:?} for {value:?}"
            );
        }
        assert_eq!(
            parse_retry_after_hint(&reqwest::header::HeaderMap::new()),
            RetryAfterHint::MissingOrMalformed
        );
        assert_eq!(
            parse_retry_after_value("", now),
            RetryAfterHint::MissingOrMalformed
        );
    }

    #[test]
    fn date_derived_retry_after_floor_is_not_undercut() {
        let now = utc_hms(2026, 9, 2, 12, 0, 0);
        let headers = retry_after_headers("Wed, 02 Sep 2026 12:01:00 GMT");
        let hint = parse_retry_after_hint_at(&headers, now);
        assert_eq!(hint, RetryAfterHint::Representable(60));
        let RetryAfterHint::Representable(secs) = hint else {
            panic!("date-derived hint must be representable seconds");
        };
        let jitter = Duration::from_millis(250);
        let delay = delay_from_retry_after_and_jitter(Some(secs), jitter)
            .expect("date-derived 60s floor must be representable");
        assert!(
            delay >= Duration::from_secs(60),
            "date-derived Retry-After must never be undercut; got {delay:?}"
        );
        let remaining = Duration::from_secs(KEYED_OPERATION_DEADLINE_SECS);
        let retry = keyed_503_retry_delay(hint, jitter, remaining)
            .expect("in-bound date-derived floor must retry");
        assert!(retry >= Duration::from_secs(60));
        let deferred = keyed_exhausted_error(
            CliError::Relay {
                status: 503,
                body: "idempotency unavailable".into(),
            },
            hint,
        );
        assert!(
            matches!(
                deferred,
                CliError::RelayDeferred {
                    status: 503,
                    retry_after_seconds: 60,
                    ..
                }
            ),
            "positive date-derived floor must be RelayDeferred, got {deferred:?}"
        );
        let digits = retry_after_headers("60");
        assert_eq!(
            parse_retry_after_hint(&digits),
            RetryAfterHint::Representable(60),
            "production wrapper must still honour delay-seconds"
        );
    }

    #[test]
    fn keyed_retry_after_pathological_does_not_retry_early() {
        let jitter = Duration::from_millis(500);
        match delay_from_retry_after_and_jitter(Some(u64::MAX), jitter) {
            None => {}
            Some(delay) => {
                assert!(
                    delay >= Duration::from_secs(u64::MAX),
                    "pathological Retry-After must not collapse to an early retry; got {delay:?}"
                );
            }
        }
        let remaining = Duration::from_secs(KEYED_OPERATION_DEADLINE_SECS);
        assert_eq!(
            keyed_503_retry_delay(RetryAfterHint::Overflow, jitter, remaining),
            None,
            "numeric-overflow Retry-After must not fall back to jitter"
        );
        assert_eq!(
            keyed_503_retry_delay(RetryAfterHint::Representable(3_600), jitter, remaining),
            None,
            "representable over-bound Retry-After must not retry inside the operation deadline"
        );
        let in_bound =
            keyed_503_retry_delay(RetryAfterHint::Representable(60), Duration::ZERO, remaining)
                .expect("in-bound 60s hint must retry");
        assert_eq!(in_bound, Duration::from_secs(60));
        assert_eq!(
            keyed_503_retry_delay(
                RetryAfterHint::Representable(KEYED_OPERATION_DEADLINE_SECS),
                Duration::ZERO,
                remaining,
            ),
            None,
            "a hint that consumes the entire remaining bound must not start another request"
        );
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::RETRY_AFTER,
            "9".repeat(40).parse().unwrap(),
        );
        assert_eq!(parse_retry_after_hint(&headers), RetryAfterHint::Overflow);
        headers.insert(reqwest::header::RETRY_AFTER, "3600".parse().unwrap());
        assert_eq!(
            parse_retry_after_hint(&headers),
            RetryAfterHint::Representable(3600)
        );
    }

    #[test]
    fn keyed_exhausted_preserves_in_bound_representable_retry_after() {
        let err = CliError::Relay {
            status: 503,
            body: "idempotency unavailable".into(),
        };
        let out = keyed_exhausted_error(err, RetryAfterHint::Representable(1));
        assert!(
            matches!(
                out,
                CliError::RelayDeferred {
                    status: 503,
                    retry_after_seconds: 1,
                    ..
                }
            ),
            "final-attempt in-bound Retry-After must stay a deferred floor, got {out:?}"
        );
        let missing = keyed_exhausted_error(
            CliError::Relay {
                status: 503,
                body: "idempotency unavailable".into(),
            },
            RetryAfterHint::MissingOrMalformed,
        );
        assert!(
            matches!(missing, CliError::Relay { status: 503, .. }),
            "missing Retry-After must remain Relay(503), got {missing:?}"
        );
        let overflow = keyed_exhausted_error(
            CliError::Relay {
                status: 503,
                body: "idempotency unavailable".into(),
            },
            RetryAfterHint::Overflow,
        );
        assert!(
            matches!(
                overflow,
                CliError::RelayRetryAfterOverflow { status: 503, .. }
            ),
            "overflow Retry-After must be RelayRetryAfterOverflow, got {overflow:?}"
        );
        assert!(
            !matches!(overflow, CliError::Relay { .. }),
            "overflow must not stay ordinary retryable Relay(503), got {overflow:?}"
        );
    }

    #[test]
    fn keyed_exhausted_retry_after_zero_stays_ordinary_relay_503() {
        let zero = keyed_exhausted_error(
            CliError::Relay {
                status: 503,
                body: "idempotency unavailable".into(),
            },
            RetryAfterHint::Representable(0),
        );
        assert!(
            matches!(zero, CliError::Relay { status: 503, .. }),
            "Retry-After 0 has no wait floor and must stay Relay(503), got {zero:?}"
        );
        assert!(
            !matches!(zero, CliError::RelayDeferred { .. }),
            "Retry-After 0 must not become permanently nonretryable deferred output, got {zero:?}"
        );
        assert!(
            crate::error::is_retryable_error(&zero),
            "Retry-After 0 must remain ordinary retryable Relay(503), got {zero:?}"
        );
    }

    #[test]
    fn keyed_retry_after_overflow_parser_to_exhausted_public_json() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::RETRY_AFTER,
            "9".repeat(40).parse().unwrap(),
        );
        assert_eq!(parse_retry_after_hint(&headers), RetryAfterHint::Overflow);

        let overflow = keyed_exhausted_error(
            CliError::Relay {
                status: 503,
                body: "idempotency unavailable".into(),
            },
            RetryAfterHint::Overflow,
        );
        assert!(
            matches!(
                overflow,
                CliError::RelayRetryAfterOverflow { status: 503, .. }
            ),
            "overflow must not stay ordinary Relay(503), got {overflow:?}"
        );
        assert!(!matches!(overflow, CliError::Relay { .. }));
        assert!(!matches!(overflow, CliError::RelayDeferred { .. }));
        assert!(!matches!(overflow, CliError::DeliveryUnknown(_)));
        assert_eq!(
            overflow.to_string(),
            "relay error 503: idempotency unavailable"
        );
        assert!(!crate::error::is_retryable_error(&overflow));
        assert_eq!(crate::error::exit_code(&overflow), 2);
        let overflow_json = crate::error::error_json(&overflow);
        assert_eq!(overflow_json["error"].as_str(), Some("relay_error"));
        assert_eq!(
            overflow_json["message"].as_str(),
            Some("relay error 503: idempotency unavailable")
        );
        assert_eq!(overflow_json["retryable"].as_bool(), Some(false));
        assert!(
            overflow_json.get("retry_after_seconds").is_none(),
            "overflow must not invent a finite retry_after_seconds, got {overflow_json}"
        );

        headers.insert(reqwest::header::RETRY_AFTER, "3600".parse().unwrap());
        let floor_hint = parse_retry_after_hint(&headers);
        assert_eq!(floor_hint, RetryAfterHint::Representable(3600));
        let deferred = keyed_exhausted_error(
            CliError::Relay {
                status: 503,
                body: "idempotency unavailable".into(),
            },
            floor_hint,
        );
        assert!(
            matches!(
                deferred,
                CliError::RelayDeferred {
                    status: 503,
                    retry_after_seconds: 3600,
                    ..
                }
            ),
            "positive representable floor must stay RelayDeferred, got {deferred:?}"
        );
        let deferred_json = crate::error::error_json(&deferred);
        assert_eq!(deferred_json["error"].as_str(), Some("relay_error"));
        assert_eq!(deferred_json["retryable"].as_bool(), Some(false));
        assert_eq!(deferred_json["retry_after_seconds"].as_u64(), Some(3600));

        headers.insert(reqwest::header::RETRY_AFTER, "0".parse().unwrap());
        let zero_hint = parse_retry_after_hint(&headers);
        assert_eq!(zero_hint, RetryAfterHint::Representable(0));
        let zero = keyed_exhausted_error(
            CliError::Relay {
                status: 503,
                body: "idempotency unavailable".into(),
            },
            zero_hint,
        );
        assert!(
            matches!(zero, CliError::Relay { status: 503, .. }),
            "Retry-After 0 must stay ordinary Relay(503), got {zero:?}"
        );
        assert!(crate::error::is_retryable_error(&zero));
        let zero_json = crate::error::error_json(&zero);
        assert_eq!(zero_json["error"].as_str(), Some("relay_error"));
        assert_eq!(zero_json["retryable"].as_bool(), Some(true));
        assert!(zero_json.get("retry_after_seconds").is_none());

        headers.insert(reqwest::header::RETRY_AFTER, "5s".parse().unwrap());
        assert_eq!(
            parse_retry_after_hint(&headers),
            RetryAfterHint::MissingOrMalformed
        );
        let malformed = keyed_exhausted_error(
            CliError::Relay {
                status: 503,
                body: "idempotency unavailable".into(),
            },
            parse_retry_after_hint(&headers),
        );
        assert!(
            matches!(malformed, CliError::Relay { status: 503, .. }),
            "malformed Retry-After must stay ordinary Relay(503), got {malformed:?}"
        );
        assert!(crate::error::is_retryable_error(&malformed));
        let malformed_json = crate::error::error_json(&malformed);
        assert_eq!(malformed_json["retryable"].as_bool(), Some(true));
        assert!(malformed_json.get("retry_after_seconds").is_none());

        let empty = reqwest::header::HeaderMap::new();
        assert_eq!(
            parse_retry_after_hint(&empty),
            RetryAfterHint::MissingOrMalformed
        );
        let missing = keyed_exhausted_error(
            CliError::Relay {
                status: 503,
                body: "idempotency unavailable".into(),
            },
            parse_retry_after_hint(&empty),
        );
        assert!(
            matches!(missing, CliError::Relay { status: 503, .. }),
            "missing Retry-After must stay ordinary Relay(503), got {missing:?}"
        );
        assert!(crate::error::is_retryable_error(&missing));
        let missing_json = crate::error::error_json(&missing);
        assert_eq!(missing_json["retryable"].as_bool(), Some(true));
        assert!(missing_json.get("retry_after_seconds").is_none());
    }

    // ---- jitter bounds ----

    #[test]
    fn jitter_stays_within_base() {
        for attempt in 0..RETRY_BASE_SECS.len() as u32 {
            let base = RETRY_BASE_SECS[attempt as usize];
            for _ in 0..100 {
                let delay = jitter_delay(attempt).as_secs_f64();
                assert!(
                    (0.0..=base).contains(&delay),
                    "jitter {delay} out of [0, {base}]"
                );
            }
        }
    }

    #[test]
    fn keyed_jitter_reuses_last_ceiling_past_generic_table() {
        let last_base = *RETRY_BASE_SECS
            .last()
            .expect("RETRY_BASE_SECS is non-empty");
        for attempt in 0..KEYED_RETRY_MAX_ATTEMPTS {
            let base = RETRY_BASE_SECS[(attempt as usize).min(RETRY_BASE_SECS.len() - 1)];
            for _ in 0..50 {
                let delay = keyed_jitter_delay(attempt).as_secs_f64();
                assert!(
                    (0.0..=base).contains(&delay),
                    "keyed jitter {delay} out of [0, {base}] on attempt {attempt}"
                );
            }
        }
        assert_eq!(last_base, 1.5);
    }

    // ---- constant sanity ----

    #[test]
    fn retry_constants_are_sensible() {
        assert_eq!(RETRY_MAX_ATTEMPTS, 3);
        assert_eq!(RETRY_BASE_SECS.len(), (RETRY_MAX_ATTEMPTS - 1) as usize);
        assert_eq!(KEYED_RETRY_MAX_ATTEMPTS, 4);
        const { assert!(RETRY_IN_MAX_SECS > 0) };
    }

    // ---- env_duration_secs ----

    #[test]
    fn env_duration_secs_parsing() {
        // All assertions share one env var key; sequential set/remove prevents races.
        const KEY: &str = "BUZZ_CLI_TEST_DURATION_SECS";

        // Valid numeric value is parsed.
        std::env::set_var(KEY, "42");
        assert_eq!(env_duration_secs(KEY, 30), Duration::from_secs(42));

        // Non-numeric falls back to default.
        std::env::set_var(KEY, "not-a-number");
        assert_eq!(env_duration_secs(KEY, 30), Duration::from_secs(30));

        // Zero is treated as invalid and falls back to default.
        std::env::set_var(KEY, "0");
        assert_eq!(env_duration_secs(KEY, 30), Duration::from_secs(30));

        // Unset uses the default.
        std::env::remove_var(KEY);
        assert_eq!(env_duration_secs(KEY, 30), Duration::from_secs(30));
    }
}

/// Integration tests for the kind-aware retry policy and body-boundary coverage.
///
/// These tests spin up a local HTTP server using axum and issue real HTTP requests
/// through `BuzzClient` to verify behavioural properties — not implementation details.
#[cfg(test)]
mod retry_policy_tests {
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{HeaderMap, Response, StatusCode};
    use axum::routing::post;
    use axum::Router;
    use nostr::{EventBuilder, Keys, Kind};
    use tokio::net::TcpListener;

    use super::super::error::CliError;
    use super::BuzzClient;

    /// Spawn a one-shot axum server on a random port.  The handler `f` receives the
    /// attempt counter (incremented before every call) and returns a `(StatusCode,
    /// String)`.  Returns the base URL and a join handle so the caller can assert
    /// attempt counts after the test.
    async fn test_server<F>(f: F) -> (String, Arc<AtomicU32>)
    where
        F: Fn(u32) -> (StatusCode, String) + Send + Sync + 'static,
    {
        let counter = Arc::new(AtomicU32::new(0));
        let handler: Arc<dyn Fn(u32) -> (StatusCode, String) + Send + Sync> = Arc::new(f);
        let state = (handler, counter.clone());

        type S = (
            Arc<dyn Fn(u32) -> (StatusCode, String) + Send + Sync>,
            Arc<AtomicU32>,
        );
        let app = Router::new()
            .route(
                "/events",
                post(
                    |State((handler, ctr)): State<S>, _headers: HeaderMap, _body: Body| async move {
                        let n = ctr.fetch_add(1, Ordering::SeqCst) + 1;
                        let (status, body) = handler(n);
                        Response::builder()
                            .status(status)
                            .header("content-type", "application/json")
                            .body(Body::from(body))
                            .unwrap()
                    },
                ),
            )
            .with_state(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), counter)
    }

    fn test_client(base_url: &str) -> BuzzClient {
        let keys = Keys::generate();
        BuzzClient::new(base_url.to_string(), keys, None, None).unwrap()
    }

    fn make_moderation_event(keys: &Keys, kind: u16) -> nostr::Event {
        EventBuilder::new(Kind::Custom(kind), "")
            .sign_with_keys(keys)
            .unwrap()
    }

    fn make_stored_event(keys: &Keys) -> nostr::Event {
        EventBuilder::new(Kind::TextNote, "hi")
            .sign_with_keys(keys)
            .unwrap()
    }

    /// A moderation command (kind 9040) that fails the first attempt with HTTP 429
    /// carrying a plain (non-relay-ingest) body is NOT retried — surfaces as
    /// `DeliveryUnknown`.
    #[tokio::test]
    async fn moderation_kind_non_ingest_429_returns_delivery_unknown() {
        let (url, attempts) = test_server(|_n| {
            (
                StatusCode::TOO_MANY_REQUESTS,
                r#"{"error":"slow down"}"#.to_string(),
            )
        })
        .await;
        let client = test_client(&url);
        let event = make_moderation_event(client.keys(), 9040);
        let err = client.submit_event(event).await.unwrap_err();
        assert!(
            matches!(err, CliError::DeliveryUnknown(_)),
            "expected DeliveryUnknown, got {err:?}"
        );
        // Non-ingest 429 must not be retried — exactly 1 attempt.
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "must not retry non-ingest 429"
        );
    }

    /// A moderation command (kind 9041) that gets a relay-ingest 429 (production JSON
    /// envelope `{"error":"rate-limited: ..."}`) IS retried, and the `retry in Ns` hint
    /// is honoured.
    ///
    /// Uses a 2s hint; jitter max for attempt 0 is 0.5s, so asserting elapsed ≥ 2s
    /// cleanly distinguishes hint-honoured from jitter-fallback.
    #[tokio::test]
    async fn moderation_kind_ingest_429_is_retried_until_success() {
        let (url, attempts) = test_server(|n| {
            if n < 2 {
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    // Exact production envelope: api_error() wraps every message as
                    // {"error":"..."}.  The extracted field starts with "rate-limited:"
                    // so the command is retried; the hint is honoured.
                    r#"{"error":"rate-limited: quota exceeded; retry in 2s"}"#.to_string(),
                )
            } else {
                (
                    StatusCode::OK,
                    r#"{"event_id":"abc","accepted":true,"message":""}"#.to_string(),
                )
            }
        })
        .await;
        let client = test_client(&url);
        let event = make_moderation_event(client.keys(), 9041);
        let t0 = std::time::Instant::now();
        let result = client.submit_event(event).await;
        let elapsed = t0.elapsed();
        assert!(
            result.is_ok(),
            "expected Ok after ingest-429 retry, got {result:?}"
        );
        assert!(
            attempts.load(Ordering::SeqCst) >= 2,
            "must have retried at least once"
        );
        assert!(
            elapsed.as_secs_f64() >= 2.0,
            "elapsed {:.2}s < 2s — hint was not honoured (fell back to jitter)",
            elapsed.as_secs_f64()
        );
    }

    /// A moderation command that receives the canonical pre-ingest 429 on EVERY
    /// attempt exhausts the retry budget and surfaces `CliError::Relay { status: 429 }` —
    /// NOT `DeliveryUnknown`. The relay provably never executed the command on any
    /// attempt, so the caller must be told it is safe to retry.
    #[tokio::test]
    async fn exhausted_ingest_429_returns_relay_429_retryable() {
        let (url, attempts) = test_server(|_n| {
            (
                StatusCode::TOO_MANY_REQUESTS,
                r#"{"error":"rate-limited: quota exceeded; retry in 0s"}"#.to_string(),
            )
        })
        .await;
        let client = test_client(&url);
        let event = make_moderation_event(client.keys(), 9040);
        let err = client.submit_event(event).await.unwrap_err();

        // Must be Relay(429), not DeliveryUnknown.
        assert!(
            matches!(err, CliError::Relay { status: 429, .. }),
            "exhausted ingest 429 must surface as Relay(429), got {err:?}"
        );
        // Must NOT be retryable:false.
        assert!(
            crate::error::is_retryable_error(&err),
            "Relay(429) must be retryable; got {err:?}"
        );
        // All RETRY_MAX_ATTEMPTS must have been tried.
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            3,
            "all retry attempts must fire for exhausted ingest 429"
        );
    }

    /// A moderation command (kind 9042) that gets HTTP 502 returns `DeliveryUnknown`
    /// immediately — proxy errors leave relay execution state ambiguous.
    #[tokio::test]
    async fn moderation_kind_502_returns_delivery_unknown() {
        let (url, attempts) =
            test_server(|_n| (StatusCode::BAD_GATEWAY, "bad gateway".to_string())).await;
        let client = test_client(&url);
        let event = make_moderation_event(client.keys(), 9042);
        let err = client.submit_event(event).await.unwrap_err();
        assert!(
            matches!(err, CliError::DeliveryUnknown(_)),
            "expected DeliveryUnknown for 502, got {err:?}"
        );
        // 502 must not be retried — exactly 1 attempt.
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "must not retry 502 for moderation kind"
        );
    }

    /// When all retry attempts are connect-failures (the relay definitively never saw
    /// the request), `submit_event` must return `CliError::Network` with
    /// `retryable:true` — not `DeliveryUnknown`.  Connect-failure is the one error
    /// condition the implementation itself identifies as confirmed-unreceived.
    #[tokio::test]
    async fn exhausted_connect_failures_return_network_retryable() {
        // Bind a port, capture the address, then drop the listener so every
        // subsequent connect attempt is refused immediately.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let base = format!("http://{addr}");
        let client = test_client(&base);
        let event = make_moderation_event(client.keys(), 9040);
        let err = client.submit_event(event).await.unwrap_err();
        // Must be Network (retryable), not DeliveryUnknown (retryable:false).
        assert!(
            matches!(err, super::super::error::CliError::Network(_)),
            "exhausted connect failures must surface as Network, got {err:?}"
        );
        // Confirm the error description does not suggest ambiguous delivery.
        let description = format!("{err:?}");
        assert!(
            !description.contains("outcome unknown"),
            "connect failure must not be labeled DeliveryUnknown; got: {description}"
        );
    }

    /// A stored (non-moderation) event submitted to a server that returns 502 on the
    /// first attempt and then succeeds is retried under the standard policy.
    #[tokio::test]
    async fn stored_event_502_is_retried_under_standard_policy() {
        let (url, attempts) = test_server(|n| {
            if n == 1 {
                (StatusCode::BAD_GATEWAY, "transient".to_string())
            } else {
                (
                    StatusCode::OK,
                    r#"{"event_id":"abc","accepted":true,"message":""}"#.to_string(),
                )
            }
        })
        .await;
        let client = test_client(&url);
        let event = make_stored_event(client.keys());
        let result = client.submit_event(event).await;
        assert!(
            result.is_ok(),
            "expected Ok after 502 retry for stored event, got {result:?}"
        );
        assert!(
            attempts.load(Ordering::SeqCst) >= 2,
            "must have retried at least once"
        );
    }

    /// Spin up a one-shot axum server that handles `GET /info` (and any other GET).
    /// Same contract as `test_server` — returns base URL and attempt counter.
    async fn get_server<F>(f: F) -> (String, Arc<AtomicU32>)
    where
        F: Fn(u32) -> (StatusCode, String) + Send + Sync + 'static,
    {
        let counter = Arc::new(AtomicU32::new(0));
        let handler: Arc<dyn Fn(u32) -> (StatusCode, String) + Send + Sync> = Arc::new(f);
        let state = (handler, counter.clone());

        type S = (
            Arc<dyn Fn(u32) -> (StatusCode, String) + Send + Sync>,
            Arc<AtomicU32>,
        );
        let app = Router::new()
            .route(
                "/{*path}",
                axum::routing::get(
                    |State((handler, ctr)): State<S>, _headers: HeaderMap| async move {
                        let n = ctr.fetch_add(1, Ordering::SeqCst) + 1;
                        let (status, body) = handler(n);
                        Response::builder()
                            .status(status)
                            .header("content-type", "application/json")
                            .body(Body::from(body))
                            .unwrap()
                    },
                ),
            )
            .with_state(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), counter)
    }

    /// Safe-read 503 is retried by `with_retry_body` (channels list / messages get /
    /// POST query-count) and succeeds on the next attempt.
    #[tokio::test]
    async fn query_503_is_retried_then_succeeds() {
        let (url, attempts) = get_server(|n| {
            if n == 1 {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "transient unavailable".to_string(),
                )
            } else {
                (StatusCode::OK, r#"{"ok":true}"#.to_string())
            }
        })
        .await;
        let client = test_client(&url);
        let result = client.get_authed("/info").await;
        assert!(
            result.is_ok(),
            "expected Ok after 503 retry, got {result:?}"
        );
        assert!(
            attempts.load(Ordering::SeqCst) >= 2,
            "must have retried at least once"
        );
    }

    /// POST /query is a read-only body and must retry HTTP 503 then succeed.
    #[tokio::test]
    async fn query_post_503_is_retried_then_succeeds() {
        let counter = Arc::new(AtomicU32::new(0));
        let handler_ctr = counter.clone();
        let app = Router::new().route(
            "/query",
            post(move || {
                let handler_ctr = handler_ctr.clone();
                async move {
                    let n = handler_ctr.fetch_add(1, Ordering::SeqCst) + 1;
                    if n == 1 {
                        Response::builder()
                            .status(StatusCode::SERVICE_UNAVAILABLE)
                            .body(Body::from("unavailable"))
                            .unwrap()
                    } else {
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Body::from("[]"))
                            .unwrap()
                    }
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = test_client(&format!("http://{addr}"));
        let result = client.query(&serde_json::json!({"limit": 1})).await;
        assert!(
            result.is_ok(),
            "expected Ok after POST /query 503 retry, got {result:?}"
        );
        assert!(
            counter.load(Ordering::SeqCst) >= 2,
            "POST /query must retry HTTP 503"
        );
    }

    /// Unkeyed stored-event writes must not retry ambiguous HTTP 503.
    #[tokio::test]
    async fn stored_event_503_is_not_retried() {
        let (url, attempts) = test_server(|_n| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"unavailable"}"#.to_string(),
            )
        })
        .await;
        let client = test_client(&url);
        let event = make_stored_event(client.keys());
        let err = client.submit_event(event).await.unwrap_err();
        assert!(
            matches!(err, CliError::DeliveryUnknown(_)),
            "unkeyed 503 must stay ambiguous, got {err:?}"
        );
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "unkeyed event writes must not retry HTTP 503"
        );
    }

    /// NIP-11 preflight must not follow a redirect to loopback or a private
    /// target, and must not forward authentication material.
    #[tokio::test]
    async fn nip11_preflight_does_not_follow_redirect_to_loopback() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let victim_hits = Arc::new(AtomicU32::new(0));
        let victim_hits2 = victim_hits.clone();
        let victim = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let victim_addr = victim.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = victim.accept().await else {
                    break;
                };
                victim_hits2.fetch_add(1, Ordering::SeqCst);
                let mut buf = vec![0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}")
                    .await;
            }
        });

        let redirector = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redirector_addr = redirector.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = redirector.accept().await else {
                    break;
                };
                let mut buf = vec![0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let location = format!("http://{victim_addr}/secret");
                let body = format!(
                    "HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\n\r\n"
                );
                let _ = stream.write_all(body.as_bytes()).await;
            }
        });

        let client = test_client(&format!("http://{redirector_addr}"));
        let result = client.get_public("/").await;
        assert!(
            matches!(result, Err(CliError::Relay { status: 302, .. })),
            "NIP-11 preflight must not follow the redirect, got {result:?}"
        );
        assert_eq!(
            victim_hits.load(Ordering::SeqCst),
            0,
            "loopback redirect target must never be contacted"
        );
    }

    /// `with_retry_body` retries transient HTTP 502 on a read path (`get_authed`)
    /// and succeeds on the next attempt.
    #[tokio::test]
    async fn query_502_is_retried_then_succeeds() {
        let (url, attempts) = get_server(|n| {
            if n == 1 {
                (
                    StatusCode::BAD_GATEWAY,
                    "transient gateway error".to_string(),
                )
            } else {
                (StatusCode::OK, r#"{"ok":true}"#.to_string())
            }
        })
        .await;
        let client = test_client(&url);
        let result = client.get_authed("/info").await;
        assert!(
            result.is_ok(),
            "expected Ok after 502 retry, got {result:?}"
        );
        assert!(
            attempts.load(Ordering::SeqCst) >= 2,
            "must have retried at least once"
        );
    }

    /// `with_retry_body` retries a 429 with a `retry in Ns` hint, honours the hint
    /// delay (not the shorter jitter fallback), and ultimately succeeds.
    ///
    /// Uses a 2s hint; jitter max for attempt 0 is 0.5s, so asserting elapsed ≥ 2s
    /// cleanly distinguishes hint-honoured from jitter-fallback.
    #[tokio::test]
    async fn query_429_with_hint_is_retried() {
        let (url, attempts) = get_server(|n| {
            if n < 2 {
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    // handle_response extracts the "error" field; the plain text
                    // "rate-limited: retry in 2s" then reaches parse_retry_hint_text.
                    r#"{"error":"rate-limited: retry in 2s"}"#.to_string(),
                )
            } else {
                (StatusCode::OK, r#"{"ok":true}"#.to_string())
            }
        })
        .await;
        let client = test_client(&url);
        let t0 = std::time::Instant::now();
        // Measure from just before attempt 1 fires so we capture the inter-attempt wait.
        let result = client.get_authed("/info").await;
        // Record elapsed after attempt 1 returns (inside the future) is not possible
        // directly, but the total includes the hint sleep; jitter max is 0.5s so ≥ 2s
        // proves the hint was honoured.
        let elapsed = t0.elapsed();
        assert!(
            result.is_ok(),
            "expected Ok after 429 retry, got {result:?}"
        );
        assert!(
            attempts.load(Ordering::SeqCst) >= 2,
            "must have retried at least once"
        );
        assert!(
            elapsed.as_secs_f64() >= 2.0,
            "elapsed {:.2}s < 2s — hint was not honoured (fell back to jitter)",
            elapsed.as_secs_f64()
        );
    }

    /// A definitive 4xx (403 Forbidden) is NOT retried — exactly 1 attempt.
    #[tokio::test]
    async fn query_403_is_not_retried() {
        let (url, attempts) = get_server(|_n| {
            (
                StatusCode::FORBIDDEN,
                r#"{"error":"not allowed"}"#.to_string(),
            )
        })
        .await;
        let client = test_client(&url);
        let result = client.get_authed("/info").await;
        assert!(
            matches!(result, Err(CliError::Relay { status: 403, .. })),
            "expected Relay 403 error, got {result:?}"
        );
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "403 must not be retried"
        );
    }

    /// `with_retry_body` retries on `is_body()` network errors (F2: body transfer inside
    /// the retry boundary).  Verified by confirming that a call through `get_authed`
    /// (which uses `with_retry_body`) retries when the server drops the connection after
    /// sending headers.  We simulate body loss by returning an intentionally truncated
    /// chunked response that reqwest will surface as an `is_body()` error.
    ///
    /// This test uses a raw TCP server to write partial HTTP responses; axum cannot
    /// easily simulate mid-body connection drops.
    #[tokio::test]
    async fn with_retry_body_retries_on_body_transfer_failure() {
        use tokio::io::AsyncWriteExt;

        let counter = Arc::new(AtomicU32::new(0));
        let counter2 = counter.clone();

        // Bind a raw TCP listener.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let n = counter2.fetch_add(1, Ordering::SeqCst) + 1;

                // Consume the request (required to avoid connection reset by server).
                let mut buf = vec![0u8; 4096];
                use tokio::io::AsyncReadExt;
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(100),
                    stream.read(&mut buf),
                )
                .await;

                if n < 3 {
                    // Attempts 1 & 2: send valid headers claiming a body, then drop.
                    let partial = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 100\r\n\r\n{\"partial\":";
                    let _ = stream.write_all(partial).await;
                    // Drop the stream without completing the body — causes is_body() on client.
                } else {
                    // Attempt 3: complete response.
                    let ok = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}";
                    let _ = stream.write_all(ok).await;
                }
            }
        });

        let base = format!("http://{addr}");
        // get_authed internally uses with_retry_body — the body read is inside the retry loop.
        let client = test_client(&base);
        // Stub path: the raw TCP server ignores the URL and always responds based on attempt count.
        let result = client.get_authed("/any-path").await;
        assert!(
            result.is_ok(),
            "expected Ok after body-loss retries, got {result:?}"
        );
        assert_eq!(
            counter.load(Ordering::SeqCst),
            3,
            "expected 3 attempts (2 body-loss + 1 success)"
        );
    }

    /// `submit_event` (non-moderation kind) uses `with_retry_body` — the full
    /// operation including response body read is inside the retry boundary.
    /// A partial-body drop after 200 headers must be retried with the same
    /// serialized event bytes (and a fresh NIP-98 auth per attempt).
    #[tokio::test]
    async fn stored_event_body_loss_is_retried_with_same_event_bytes() {
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;

        let counter = Arc::new(AtomicU32::new(0));
        let counter2 = counter.clone();
        let bodies: Arc<std::sync::Mutex<Vec<Vec<u8>>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let bodies2 = bodies.clone();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let n = counter2.fetch_add(1, Ordering::SeqCst) + 1;

                // Read the full HTTP request so we can capture the body.
                let mut buf = vec![0u8; 8192];
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(200),
                    stream.read(&mut buf),
                )
                .await;
                // Capture raw request bytes for assertion.
                let body_end = buf
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|i| i + 4)
                    .unwrap_or(0);
                let payload = buf[body_end..].to_vec();
                bodies2.lock().unwrap().push(payload);

                if n < 3 {
                    // Partial body drop.
                    let partial = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 100\r\n\r\n{\"partial\":";
                    let _ = stream.write_all(partial).await;
                } else {
                    let ok = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 41\r\n\r\n{\"event_id\":\"abc\",\"accepted\":true,\"message\":\"\"}";
                    let _ = stream.write_all(ok).await;
                }
            }
        });

        let base = format!("http://{addr}");
        let client = test_client(&base);
        let event = make_stored_event(client.keys());
        let result = client.submit_event(event).await;
        assert!(
            result.is_ok(),
            "expected Ok after body-loss retries, got {result:?}"
        );
        assert_eq!(
            counter.load(Ordering::SeqCst),
            3,
            "expected 3 attempts (2 body-loss + 1 success)"
        );
        // All three attempts must have sent the same serialized event bytes.
        let captured = bodies.lock().unwrap();
        assert_eq!(captured.len(), 3, "must have captured 3 request bodies");
        // Each attempt's payload must be identical (same signed event bytes).
        assert_eq!(
            captured[0], captured[1],
            "attempt 1 and 2 must use identical event bytes"
        );
        assert_eq!(
            captured[1], captured[2],
            "attempt 2 and 3 must use identical event bytes"
        );
    }

    /// `upload_file` uses `with_retry_body` — the full operation including response
    /// body read is inside the retry boundary.  A partial-body drop after 200 headers
    /// must be retried with identical file bytes and a fresh Blossom auth per attempt.
    #[tokio::test]
    async fn upload_body_loss_is_retried_with_same_file_bytes() {
        use std::io::Write;
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;

        // Write a minimal JPEG file so MIME detection works.
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        // JPEG magic + JFIF app0 marker: enough for `infer` to detect image/jpeg.
        let jpeg_header: &[u8] = &[
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
        ];
        tmp.write_all(jpeg_header).unwrap();
        let file_path = tmp.path().to_str().unwrap().to_string();

        let counter = Arc::new(AtomicU32::new(0));
        let counter2 = counter.clone();
        let auth_headers: Arc<std::sync::Mutex<Vec<String>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let auth_headers2 = auth_headers.clone();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let n = counter2.fetch_add(1, Ordering::SeqCst) + 1;

                // Read the request headers to extract the Authorization value.
                let mut buf = vec![0u8; 8192];
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(200),
                    stream.read(&mut buf),
                )
                .await;
                // Extract the Authorization header value.
                let req_str = String::from_utf8_lossy(&buf);
                let auth = req_str
                    .lines()
                    .find(|l| l.to_lowercase().starts_with("authorization:"))
                    .map(|l| l.to_string())
                    .unwrap_or_default();
                auth_headers2.lock().unwrap().push(auth);

                if n < 3 {
                    // Partial body drop.
                    let partial = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 100\r\n\r\n{\"partial\":";
                    let _ = stream.write_all(partial).await;
                } else {
                    // Valid BlobDescriptor response.
                    let ok_body = r#"{"url":"https://relay.test/media/aabbcc.jpg","sha256":"aabbcc","size":12,"type":"image/jpeg","uploaded":0}"#;
                    let ok = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                        ok_body.len(),
                        ok_body
                    );
                    let _ = stream.write_all(ok.as_bytes()).await;
                }
            }
        });

        let base = format!("http://{addr}");
        let client = test_client(&base);
        let result = client.upload_file(&file_path).await;
        assert!(
            result.is_ok(),
            "expected Ok after upload body-loss retries, got {result:?}"
        );
        assert_eq!(
            counter.load(Ordering::SeqCst),
            3,
            "expected 3 upload attempts (2 body-loss + 1 success)"
        );
        // Each attempt must carry a distinct Authorization header (fresh Blossom auth).
        let auths = auth_headers.lock().unwrap();
        assert_eq!(auths.len(), 3, "must have captured 3 auth headers");
        // All three must be non-empty (auth was signed).
        assert!(
            auths.iter().all(|a| a.contains("Nostr ")),
            "each attempt must carry Nostr auth"
        );
    }

    /// When all retry attempts for a stored event end with a partial body (200
    /// headers, dropped connection), the final error must be `DeliveryUnknown`
    /// (retryable:false) — the relay may have stored the event on any attempt, so
    /// an outer re-sign would risk a duplicate visible write.  All three attempts
    /// must fire with identical serialized event bytes.
    #[tokio::test]
    async fn stored_event_all_body_losses_return_delivery_unknown() {
        use tokio::io::AsyncWriteExt;

        let bodies: Arc<std::sync::Mutex<Vec<Vec<u8>>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let bodies2 = bodies.clone();
        let counter = Arc::new(AtomicU32::new(0));
        let counter2 = counter.clone();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                counter2.fetch_add(1, Ordering::SeqCst);
                let mut buf = vec![0u8; 8192];
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(200),
                    stream.read(&mut buf),
                )
                .await;
                // Extract the request body (after the blank line separating headers).
                let raw = buf.split(|&b| b == 0).next().unwrap_or(&buf).to_vec();
                if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                    bodies2.lock().unwrap().push(raw[pos + 4..].to_vec());
                }
                // Partial body: send headers + truncated body, then drop.
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 100\r\n\r\n{\"partial\":",
                    )
                    .await;
                // Drop stream — causes body-loss error on the client side.
            }
        });

        let base = format!("http://{addr}");
        let client = test_client(&base);
        let event = make_stored_event(client.keys());
        let err = client.submit_event(event).await.unwrap_err();

        // Final error must be DeliveryUnknown — relay may have accepted any attempt.
        assert!(
            matches!(err, CliError::DeliveryUnknown(_)),
            "all-body-loss exhaustion must return DeliveryUnknown, got {err:?}"
        );
        // All RETRY_MAX_ATTEMPTS must have fired.
        assert_eq!(
            counter.load(Ordering::SeqCst),
            3,
            "all 3 attempts must be made before surfacing DeliveryUnknown"
        );
        // All attempts must have sent identical serialized event bytes.
        let captured = bodies.lock().unwrap();
        if captured.len() >= 2 {
            assert_eq!(
                captured[0], captured[1],
                "all attempts must use identical event bytes"
            );
        }
    }

    /// When all retry attempts for a stored event return HTTP 502, the final error
    /// must be `DeliveryUnknown` (retryable:false) — a proxy 502 may occur after
    /// the relay accepted the event.
    #[tokio::test]
    async fn stored_event_all_502s_return_delivery_unknown() {
        let (url, attempts) =
            test_server(|_n| (StatusCode::BAD_GATEWAY, "bad gateway".to_string())).await;
        let client = test_client(&url);
        let event = make_stored_event(client.keys());
        let err = client.submit_event(event).await.unwrap_err();

        assert!(
            matches!(err, CliError::DeliveryUnknown(_)),
            "all-502 exhaustion must return DeliveryUnknown, got {err:?}"
        );
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            3,
            "all 3 attempts must fire before surfacing DeliveryUnknown"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{
        advance_query_cursor, create_response_with_id_if_accepted, extract_relay_response_field,
        normalize_events, BuzzClient,
    };
    use nostr::{EventBuilder, Keys, Kind, Tag};

    #[test]
    fn normalize_events_preserves_the_complete_signed_event_shape() {
        let signed_event = EventBuilder::new(Kind::TextNote, "signed content")
            .tags([Tag::parse(["h", "channel-id"]).unwrap()])
            .sign_with_keys(&Keys::generate())
            .unwrap();
        let mut event = serde_json::to_value(&signed_event).unwrap();
        event["relay_internal"] = serde_json::json!("excluded");

        let output: Vec<serde_json::Value> =
            serde_json::from_str(&normalize_events(&[event])).unwrap();
        let normalized = &output[0];
        let round_tripped: nostr::Event = serde_json::from_value(normalized.clone()).unwrap();

        assert_eq!(round_tripped, signed_event);
        round_tripped.verify().unwrap();
        assert!(normalized.get("sig").is_some());
        assert!(normalized.get("relay_internal").is_none());
    }

    #[test]
    fn normalize_events_omits_missing_or_non_string_signatures() {
        let output: Vec<serde_json::Value> = serde_json::from_str(&normalize_events(&[
            serde_json::json!({}),
            serde_json::json!({"sig": 42}),
        ]))
        .unwrap();

        assert!(output[0].get("sig").is_none());
        assert!(output[1].get("sig").is_none());
    }

    #[test]
    fn query_cursor_uses_last_events_composite_sort_key() {
        let mut filter = serde_json::json!({"kinds": [39000], "limit": 500});
        let page = vec![
            serde_json::json!({"id": "a".repeat(64), "created_at": 20}),
            serde_json::json!({"id": "b".repeat(64), "created_at": 10}),
        ];

        advance_query_cursor(&mut filter, &page).unwrap();

        assert_eq!(filter["until"], serde_json::json!(10));
        assert_eq!(filter["before_id"], serde_json::json!("b".repeat(64)));
    }

    #[test]
    fn query_cursor_rejects_missing_or_malformed_sort_key() {
        let mut filter = serde_json::json!({});
        assert!(
            advance_query_cursor(&mut filter, &[serde_json::json!({"id": "a".repeat(64)})])
                .is_err()
        );
        assert!(advance_query_cursor(
            &mut filter,
            &[serde_json::json!({"id": "not-an-event-id", "created_at": 10})]
        )
        .is_err());
    }

    #[test]
    fn extract_relay_response_field_reads_response_message_json() {
        let raw = r#"{"event_id":"abc","accepted":true,"message":"response:{\"workflow_id\":\"relay-id\",\"created\":true}"}"#;
        assert_eq!(
            extract_relay_response_field(raw, "workflow_id").as_deref(),
            Some("relay-id")
        );
    }

    #[test]
    fn extract_relay_response_field_returns_none_for_non_response_message() {
        let raw = r#"{"event_id":"abc","accepted":true,"message":""}"#;
        assert!(extract_relay_response_field(raw, "workflow_id").is_none());
    }

    #[test]
    fn create_response_with_id_if_accepted_injects_id_when_accepted() {
        let raw = r#"{"event_id":"abc","accepted":true,"message":"response:{\"workflow_id\":\"relay-id\"}"}"#;
        let out = create_response_with_id_if_accepted(raw, "workflow_id", "relay-id");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        // ID injected and original fields preserved when accepted.
        assert_eq!(v["workflow_id"].as_str(), Some("relay-id"));
        assert_eq!(v["event_id"].as_str(), Some("abc"));
        assert_eq!(v["accepted"].as_bool(), Some(true));
    }

    #[test]
    fn create_response_with_id_if_accepted_omits_id_when_rejected() {
        let raw = r#"{"event_id":"abc","accepted":false,"message":"duplicate"}"#;
        let out = create_response_with_id_if_accepted(raw, "workflow_id", "local-id");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        // ID must not be present when relay rejected the event; emitting a
        // link to an event that was never stored would mislead callers.
        assert!(
            v.get("workflow_id").is_none(),
            "link field must be absent on rejected create"
        );
        assert_eq!(v["accepted"].as_bool(), Some(false));
    }

    // --- (a) auth-suppression regression pair ---

    fn make_auth_tag() -> (Tag, String) {
        let owner_hex = "a".repeat(64);
        let sig_hex = "b".repeat(128);
        let tag_vec = vec![
            "auth".to_string(),
            owner_hex,
            "conditions".to_string(),
            sig_hex,
        ];
        let json = serde_json::to_string(&tag_vec).unwrap();
        let tag = Tag::parse(tag_vec).unwrap();
        (tag, json)
    }

    #[test]
    fn sign_event_unchecked_does_not_inject_ambient_auth_tag() {
        let keys = Keys::generate();
        let (auth_tag, auth_json) = make_auth_tag();
        let client = BuzzClient::new(
            "https://test.relay".into(),
            keys,
            Some(auth_tag),
            Some(auth_json),
        )
        .unwrap();

        let builder =
            EventBuilder::new(Kind::Custom(9035), "archive").tags([Tag::parse(["-"]).unwrap()]);
        let event = client.sign_event_unchecked(builder).unwrap();

        let auth_tags: Vec<_> = event
            .tags
            .iter()
            .filter(|t| t.as_slice().first().map(|s| s.as_str()) == Some("auth"))
            .collect();
        assert!(
            auth_tags.is_empty(),
            "sign_event_unchecked must not inject the ambient NIP-OA auth tag \
             into identity archive events; found {auth_tags:?}"
        );
    }

    #[test]
    fn sign_event_unchecked_preserves_callers_content_auth_tag() {
        let keys = Keys::generate();
        let (auth_tag, auth_json) = make_auth_tag();
        let client = BuzzClient::new(
            "https://test.relay".into(),
            keys,
            Some(auth_tag),
            Some(auth_json),
        )
        .unwrap();

        let content_auth = Tag::parse([
            "auth",
            &"c".repeat(64),
            "owner-attestation",
            &"d".repeat(128),
        ])
        .unwrap();

        let builder = EventBuilder::new(Kind::Custom(9035), "archive")
            .tags([Tag::parse(["-"]).unwrap(), content_auth]);
        let event = client.sign_event_unchecked(builder).unwrap();

        let auth_tags: Vec<_> = event
            .tags
            .iter()
            .filter(|t| t.as_slice().first().map(|s| s.as_str()) == Some("auth"))
            .collect();
        assert_eq!(
            auth_tags.len(),
            1,
            "content-level auth tag must survive sign_event_unchecked; found {auth_tags:?}"
        );
        assert_eq!(auth_tags[0].as_slice()[1], "c".repeat(64));
    }

    #[test]
    fn with_auth_tag_sets_header_when_configured() {
        let keys = Keys::generate();
        let (auth_tag, auth_json) = make_auth_tag();
        let client = BuzzClient::new(
            "https://test.relay".into(),
            keys,
            Some(auth_tag),
            Some(auth_json.clone()),
        )
        .unwrap();

        let req = client.http.post("https://test.relay/events");
        let req = client.with_auth_tag(req);
        let built = req.build().unwrap();
        let header = built
            .headers()
            .get("x-auth-tag")
            .expect("x-auth-tag header must be present");
        assert_eq!(
            header.to_str().unwrap(),
            &auth_json,
            "x-auth-tag header must carry the raw auth tag JSON"
        );
    }

    #[test]
    fn with_auth_tag_omits_header_when_not_configured() {
        let keys = Keys::generate();
        let client = BuzzClient::new("https://test.relay".into(), keys, None, None).unwrap();

        let req = client.http.post("https://test.relay/events");
        let req = client.with_auth_tag(req);
        let built = req.build().unwrap();
        assert!(
            built.headers().get("x-auth-tag").is_none(),
            "x-auth-tag header must not be present when no auth tag is configured"
        );
    }
}

#[cfg(test)]
mod keyed_submit_tests {
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use axum::extract::State;
    use axum::http::{HeaderMap, Response, StatusCode};
    use axum::routing::post;
    use axum::Router;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use nostr::{EventBuilder, JsonUtil, Keys, Kind};
    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::super::error::{error_json, is_retryable_error, CliError};
    use super::{
        BuzzClient, KEYED_OPERATION_DEADLINE_SECS, KEYED_RESPONSE_MAX_BYTES,
        KEYED_RETRY_MAX_ATTEMPTS,
    };

    struct KeyedCapture {
        attempts: AtomicU32,
        bodies: Mutex<Vec<Vec<u8>>>,
        keys: Mutex<Vec<String>>,
        auths: Mutex<Vec<String>>,
    }

    type KeyedHandlerResponse = (StatusCode, Vec<(&'static str, &'static str)>, String);
    type KeyedHandler = dyn Fn(u32) -> KeyedHandlerResponse + Send + Sync;

    async fn keyed_events_server<F>(f: F) -> (String, Arc<KeyedCapture>)
    where
        F: Fn(u32) -> KeyedHandlerResponse + Send + Sync + 'static,
    {
        let capture = Arc::new(KeyedCapture {
            attempts: AtomicU32::new(0),
            bodies: Mutex::new(Vec::new()),
            keys: Mutex::new(Vec::new()),
            auths: Mutex::new(Vec::new()),
        });
        let handler: Arc<KeyedHandler> = Arc::new(f);
        let state = (handler, capture.clone());

        type S = (Arc<KeyedHandler>, Arc<KeyedCapture>);
        let app = Router::new()
            .route(
                "/events",
                post(
                    |State((handler, cap)): State<S>,
                     headers: HeaderMap,
                     body: axum::body::Bytes| async move {
                        let n = cap.attempts.fetch_add(1, Ordering::SeqCst) + 1;
                        cap.bodies.lock().unwrap().push(body.to_vec());
                        let key = headers
                            .get("idempotency-key")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string();
                        cap.keys.lock().unwrap().push(key);
                        let auth = headers
                            .get(axum::http::header::AUTHORIZATION)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string();
                        cap.auths.lock().unwrap().push(auth);
                        let (status, extra_headers, body) = handler(n);
                        let mut builder = Response::builder()
                            .status(status)
                            .header("content-type", "application/json");
                        for (name, value) in extra_headers {
                            builder = builder.header(name, value);
                        }
                        builder.body(axum::body::Body::from(body)).unwrap()
                    },
                ),
            )
            .with_state(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), capture)
    }

    fn test_client(base_url: &str) -> BuzzClient {
        let keys = Keys::generate();
        BuzzClient::new(base_url.to_string(), keys, None, None).unwrap()
    }

    fn make_kind9_event(keys: &Keys) -> nostr::Event {
        EventBuilder::new(Kind::Custom(9), "hi")
            .sign_with_keys(keys)
            .unwrap()
    }

    fn nip98_event_from_authorization(value: &str) -> nostr::Event {
        let encoded = value.strip_prefix("Nostr ").expect("Nostr prefix");
        let json = B64.decode(encoded).expect("nip98 base64");
        nostr::Event::from_json(std::str::from_utf8(&json).unwrap()).unwrap()
    }

    fn payload_tag(event: &nostr::Event) -> String {
        event
            .tags
            .iter()
            .find_map(|tag| {
                let slice = tag.as_slice();
                (slice.first().map(String::as_str) == Some("payload"))
                    .then(|| slice.get(1).cloned())
                    .flatten()
            })
            .expect("payload tag")
    }

    #[tokio::test(start_paused = true)]
    async fn keyed_503_honors_retry_after_then_succeeds_with_same_body() {
        let (url, capture) = keyed_events_server(|n| {
            if n == 1 {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    vec![("retry-after", "60")],
                    r#"{"error":"idempotency unavailable"}"#.to_string(),
                )
            } else {
                (
                    StatusCode::OK,
                    Vec::new(),
                    r#"{"event_id":"abc","accepted":true,"message":""}"#.to_string(),
                )
            }
        })
        .await;
        let client = test_client(&url);
        let event = make_kind9_event(client.keys());
        let key = [0xab; 32];
        let submit = tokio::spawn(async move {
            client
                .submit_event_with_idempotency_key(event, Some(key))
                .await
        });

        let mut first_attempt_yields = 0u32;
        while capture.attempts.load(Ordering::SeqCst) < 1 {
            tokio::task::yield_now().await;
            first_attempt_yields += 1;
            assert!(
                first_attempt_yields < 10_000,
                "first keyed 503 never arrived"
            );
        }
        assert_eq!(capture.attempts.load(Ordering::SeqCst), 1);

        // The server increments `attempts` before returning the 503. Yield
        // until the client has consumed it and parked on Retry-After.
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        let retry_after_started = tokio::time::Instant::now();

        tokio::time::sleep(Duration::from_secs(59)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            capture.attempts.load(Ordering::SeqCst),
            1,
            "must not retry inside the advertised Retry-After window"
        );
        assert!(
            retry_after_started.elapsed() < Duration::from_secs(60),
            "must not retry before sixty seconds"
        );

        // Floor is 60s; attempt-0 full jitter is in [0, 0.5). Advance past the
        // combined ceiling so the second attempt is not timing-flaky.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let mut second_attempt_yields = 0u32;
        while capture.attempts.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
            second_attempt_yields += 1;
            assert!(
                second_attempt_yields < 10_000,
                "second keyed attempt did not run after Retry-After"
            );
        }
        assert!(
            retry_after_started.elapsed() >= Duration::from_secs(60),
            "attempt two must occur at or after sixty seconds"
        );
        let result = submit.await.expect("join keyed submit");
        assert!(
            result.is_ok(),
            "expected Ok after honoured Retry-After, got {result:?}"
        );
        assert_eq!(capture.attempts.load(Ordering::SeqCst), 2);

        let bodies = capture.bodies.lock().unwrap().clone();
        let keys = capture.keys.lock().unwrap().clone();
        let auths = capture.auths.lock().unwrap().clone();
        assert_eq!(bodies.len(), 2);
        assert_eq!(
            bodies[0], bodies[1],
            "retries must reuse the same event bytes"
        );
        let expected_key = hex::encode(key);
        assert_eq!(keys, vec![expected_key.clone(), expected_key]);

        let first_auth = nip98_event_from_authorization(&auths[0]);
        let second_auth = nip98_event_from_authorization(&auths[1]);
        first_auth.verify().unwrap();
        second_auth.verify().unwrap();
        assert_ne!(
            first_auth.id, second_auth.id,
            "each attempt must carry a freshly signed NIP-98 event"
        );
        let expected_payload = hex::encode(Sha256::digest(&bodies[0]));
        assert_eq!(payload_tag(&first_auth), expected_payload);
        assert_eq!(payload_tag(&second_auth), expected_payload);
    }

    #[tokio::test]
    async fn keyed_409_is_not_retried_and_returns_conflict() {
        let (url, capture) = keyed_events_server(|_n| {
            (
                StatusCode::CONFLICT,
                Vec::new(),
                r#"{"error":"idempotency-key conflict"}"#.to_string(),
            )
        })
        .await;
        let client = test_client(&url);
        let event = make_kind9_event(client.keys());
        let err = client
            .submit_event_with_idempotency_key(event, Some([0xcd; 32]))
            .await
            .unwrap_err();
        assert!(
            matches!(err, CliError::Conflict(_)),
            "keyed 409 must surface Conflict, got {err:?}"
        );
        assert_eq!(
            capture.attempts.load(Ordering::SeqCst),
            1,
            "keyed 409 must not be retried"
        );
    }

    #[tokio::test]
    async fn keyed_unsupported_kind_is_local_usage_without_network() {
        let (url, capture) = keyed_events_server(|_n| {
            panic!("unsupported keyed kind must not send a network request")
        })
        .await;
        let client = test_client(&url);
        let event = EventBuilder::new(Kind::TextNote, "hi")
            .sign_with_keys(client.keys())
            .unwrap();
        let err = client
            .submit_event_with_idempotency_key(event, Some([0x11; 32]))
            .await
            .unwrap_err();
        assert!(
            matches!(err, CliError::Usage(_)),
            "unsupported keyed kind must be local Usage, got {err:?}"
        );
        assert_eq!(capture.attempts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn keyed_over_bound_retry_after_returns_503_without_a_second_request() {
        let (url, capture) = keyed_events_server(|_n| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                vec![("retry-after", "3600")],
                r#"{"error":"idempotency unavailable"}"#.to_string(),
            )
        })
        .await;
        let client = test_client(&url);
        let event = make_kind9_event(client.keys());
        let submit = tokio::spawn(async move {
            client
                .submit_event_with_idempotency_key(event, Some([0x22; 32]))
                .await
        });
        let mut yields = 0u32;
        while capture.attempts.load(Ordering::SeqCst) < 1 {
            tokio::task::yield_now().await;
            yields += 1;
            assert!(yields < 10_000, "keyed over-bound 503 never arrived");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            capture.attempts.load(Ordering::SeqCst),
            1,
            "over-bound Retry-After must not issue another request"
        );
        let err = submit.await.expect("join").unwrap_err();
        assert!(
            matches!(
                err,
                CliError::RelayDeferred {
                    status: 503,
                    retry_after_seconds: 3_600,
                    ..
                }
            ),
            "over-bound hint must return deferred 503, got {err:?}"
        );
        assert!(!matches!(err, CliError::DeliveryUnknown(_)));
        assert!(!crate::error::is_retryable_error(&err));
        assert_eq!(capture.attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn keyed_deadline_bound_retry_after_is_deferred_without_a_second_request() {
        let (url, capture) = keyed_events_server(|_n| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                vec![("retry-after", "90")],
                r#"{"error":"idempotency unavailable"}"#.to_string(),
            )
        })
        .await;
        let client = test_client(&url);
        let event = make_kind9_event(client.keys());
        let submit = tokio::spawn(async move {
            client
                .submit_event_with_idempotency_key(event, Some([0x55; 32]))
                .await
        });
        let mut yields = 0u32;
        while capture.attempts.load(Ordering::SeqCst) < 1 {
            tokio::task::yield_now().await;
            yields += 1;
            assert!(yields < 10_000, "keyed bound 503 never arrived");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            capture.attempts.load(Ordering::SeqCst),
            1,
            "a hint equal to the remaining bound must not issue another request"
        );
        let err = submit.await.expect("join").unwrap_err();
        assert!(
            matches!(
                err,
                CliError::RelayDeferred {
                    status: 503,
                    retry_after_seconds: 90,
                    ..
                }
            ),
            "deadline-bound hint must return deferred 503, got {err:?}"
        );
        assert!(!matches!(err, CliError::DeliveryUnknown(_)));
        assert_eq!(capture.attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn keyed_overflow_retry_after_returns_503_without_early_retry() {
        let overflow: &'static str = "9999999999999999999999999999999999999999";
        let (url, capture) = keyed_events_server(move |_n| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                vec![("retry-after", overflow)],
                r#"{"error":"idempotency unavailable"}"#.to_string(),
            )
        })
        .await;
        let client = test_client(&url);
        let event = make_kind9_event(client.keys());
        let t0 = std::time::Instant::now();
        let err = client
            .submit_event_with_idempotency_key(event, Some([0x33; 32]))
            .await
            .unwrap_err();
        assert!(
            t0.elapsed() < Duration::from_secs(2),
            "overflow Retry-After must not fall back to a jitter sleep"
        );
        assert!(
            matches!(err, CliError::RelayRetryAfterOverflow { status: 503, .. }),
            "overflow hint must return nonretryable overflow 503, got {err:?}"
        );
        assert!(!matches!(err, CliError::Relay { .. }));
        assert!(!matches!(err, CliError::RelayDeferred { .. }));
        assert!(!matches!(err, CliError::DeliveryUnknown(_)));
        assert!(!crate::error::is_retryable_error(&err));
        let json = error_json(&err);
        assert_eq!(json["error"].as_str(), Some("relay_error"));
        assert_eq!(json["retryable"].as_bool(), Some(false));
        assert!(json.get("retry_after_seconds").is_none());
        assert_eq!(
            capture.attempts.load(Ordering::SeqCst),
            1,
            "overflow Retry-After must not issue another request"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn keyed_deadline_cancels_a_stalled_request_without_real_time_wait() {
        let accepted = Arc::new(AtomicU32::new(0));
        let accepted2 = accepted.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                accepted2.fetch_add(1, Ordering::SeqCst);
                let _held = stream;
                std::future::pending::<()>().await;
            }
        });
        let client = test_client(&format!("http://{addr}"));
        let event = make_kind9_event(client.keys());
        let started = tokio::time::Instant::now();
        let submit = tokio::spawn(async move {
            client
                .submit_event_with_idempotency_key(event, Some([0x44; 32]))
                .await
        });
        let mut yields = 0u32;
        while accepted.load(Ordering::SeqCst) < 1 {
            tokio::task::yield_now().await;
            yields += 1;
            assert!(yields < 10_000, "stalled keyed request never connected");
        }
        tokio::time::advance(Duration::from_secs(KEYED_OPERATION_DEADLINE_SECS)).await;
        let err = tokio::time::timeout(Duration::from_secs(1), submit)
            .await
            .expect("outer keyed deadline must fire on paused Tokio time")
            .expect("join")
            .unwrap_err();
        assert!(
            matches!(err, CliError::DeliveryUnknown(_)),
            "in-flight deadline expiry must be ambiguous, got {err:?}"
        );
        assert!(
            started.elapsed()
                <= Duration::from_secs(KEYED_OPERATION_DEADLINE_SECS) + Duration::from_secs(1),
            "stalled keyed submit must not outlive the outer Tokio deadline"
        );
    }

    /// A keyed 503 with a valid positive Retry-After is definitive. Parking in
    /// the retry sleep and jumping the whole remaining deadline must classify
    /// that known 503 as [`CliError::RelayDeferred`], never
    /// [`CliError::DeliveryUnknown`], and must not start another request.
    #[tokio::test(start_paused = true)]
    async fn keyed_retry_sleep_deadline_crossing_returns_deferred_floor() {
        let (url, capture) = keyed_events_server(|_n| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                vec![("retry-after", "60")],
                r#"{"error":"idempotency unavailable"}"#.to_string(),
            )
        })
        .await;
        let client = test_client(&url);
        let event = make_kind9_event(client.keys());
        let submit = tokio::spawn(async move {
            client
                .submit_event_with_idempotency_key(event, Some([0x66; 32]))
                .await
        });

        let mut first_attempt_yields = 0u32;
        while capture.attempts.load(Ordering::SeqCst) < 1 {
            tokio::task::yield_now().await;
            first_attempt_yields += 1;
            assert!(
                first_attempt_yields < 10_000,
                "first keyed 503 never arrived"
            );
        }
        assert_eq!(capture.attempts.load(Ordering::SeqCst), 1);

        // The server increments `attempts` before returning the 503. Yield
        // until the client has consumed it and parked on Retry-After.
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }

        tokio::time::advance(Duration::from_secs(KEYED_OPERATION_DEADLINE_SECS)).await;
        let err = tokio::time::timeout(Duration::from_secs(1), submit)
            .await
            .expect("retry-sleep deadline crossing must resolve on paused Tokio time")
            .expect("join")
            .unwrap_err();
        assert!(
            matches!(
                err,
                CliError::RelayDeferred {
                    status: 503,
                    retry_after_seconds: 60,
                    ..
                }
            ),
            "retry-sleep deadline crossing must preserve the Retry-After floor, got {err:?}"
        );
        assert!(
            !matches!(err, CliError::DeliveryUnknown(_)),
            "retry-sleep deadline crossing must not invent DeliveryUnknown, got {err:?}"
        );
        assert_eq!(
            capture.attempts.load(Ordering::SeqCst),
            1,
            "must not start another request after the deadline"
        );
    }

    async fn drive_keyed_attempts_on_paused_time(capture: &Arc<KeyedCapture>, expected: u32) {
        let mut yields = 0u32;
        while capture.attempts.load(Ordering::SeqCst) < expected {
            tokio::task::yield_now().await;
            yields += 1;
            if yields.is_multiple_of(16) {
                tokio::time::advance(Duration::from_secs(2)).await;
            }
            assert!(
                yields < 10_000,
                "keyed attempt {expected} never arrived (have {})",
                capture.attempts.load(Ordering::SeqCst)
            );
        }
    }

    async fn wait_for_keyed_attempt(capture: &Arc<KeyedCapture>, expected: u32) {
        let mut yields = 0u32;
        while capture.attempts.load(Ordering::SeqCst) < expected {
            tokio::task::yield_now().await;
            yields += 1;
            assert!(
                yields < 10_000,
                "keyed attempt {expected} did not run after Retry-After"
            );
        }
    }

    /// Four consecutive keyed HTTP 503s must exhaust the keyed attempt budget
    /// and return the original 503 without panicking on extra-attempt jitter.
    #[tokio::test(start_paused = true)]
    async fn keyed_three_503s_return_relay_error_without_panic() {
        let (url, capture) = keyed_events_server(|_n| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Vec::new(),
                r#"{"error":"idempotency unavailable"}"#.to_string(),
            )
        })
        .await;
        let client = test_client(&url);
        let event = make_kind9_event(client.keys());
        let submit = tokio::spawn(async move {
            client
                .submit_event_with_idempotency_key(event, Some([0x50; 32]))
                .await
        });
        drive_keyed_attempts_on_paused_time(&capture, KEYED_RETRY_MAX_ATTEMPTS).await;
        let err = submit.await.expect("join").unwrap_err();
        assert!(
            matches!(err, CliError::Relay { status: 503, .. }),
            "exhausted keyed 503 must surface Relay(503), got {err:?}"
        );
        assert!(
            crate::error::is_retryable_error(&err),
            "exhausted keyed 503 must remain retryable, got {err:?}"
        );
        assert!(!matches!(err, CliError::DeliveryUnknown(_)));
        assert_eq!(
            capture.attempts.load(Ordering::SeqCst),
            KEYED_RETRY_MAX_ATTEMPTS,
            "all four keyed attempts must fire"
        );
        let bodies = capture.bodies.lock().unwrap().clone();
        let keys = capture.keys.lock().unwrap().clone();
        let auths = capture.auths.lock().unwrap().clone();
        assert_eq!(bodies.len(), KEYED_RETRY_MAX_ATTEMPTS as usize);
        assert_eq!(bodies[0], bodies[1]);
        assert_eq!(bodies[1], bodies[2]);
        assert_eq!(bodies[2], bodies[3]);
        assert_eq!(keys[0], keys[1]);
        assert_eq!(keys[1], keys[2]);
        assert_eq!(keys[2], keys[3]);
        let first_auth = nip98_event_from_authorization(&auths[0]);
        let last_auth = nip98_event_from_authorization(&auths[3]);
        assert_ne!(first_auth.id, last_auth.id);
    }

    /// Four consecutive keyed HTTP 503s whose final response carries an
    /// in-bound representable Retry-After must exhaust attempts without panic
    /// and preserve that wait floor as structured deferred output.
    #[tokio::test(start_paused = true)]
    async fn keyed_three_503s_preserve_final_in_bound_retry_after_floor() {
        let (url, capture) = keyed_events_server(|n| {
            let headers = if n == KEYED_RETRY_MAX_ATTEMPTS {
                vec![("retry-after", "1")]
            } else {
                Vec::new()
            };
            (
                StatusCode::SERVICE_UNAVAILABLE,
                headers,
                r#"{"error":"idempotency unavailable"}"#.to_string(),
            )
        })
        .await;
        let client = test_client(&url);
        let event = make_kind9_event(client.keys());
        let submit = tokio::spawn(async move {
            client
                .submit_event_with_idempotency_key(event, Some([0x52; 32]))
                .await
        });
        drive_keyed_attempts_on_paused_time(&capture, KEYED_RETRY_MAX_ATTEMPTS).await;
        let err = submit.await.expect("join").unwrap_err();
        assert!(
            matches!(
                err,
                CliError::RelayDeferred {
                    status: 503,
                    retry_after_seconds: 1,
                    ..
                }
            ),
            "final in-bound Retry-After must surface RelayDeferred, got {err:?}"
        );
        assert!(
            !crate::error::is_retryable_error(&err),
            "deferred floor must not invite an immediate outer retry, got {err:?}"
        );
        assert!(!matches!(err, CliError::DeliveryUnknown(_)));
        assert_eq!(
            capture.attempts.load(Ordering::SeqCst),
            KEYED_RETRY_MAX_ATTEMPTS,
            "all four keyed attempts must fire"
        );
        let bodies = capture.bodies.lock().unwrap().clone();
        let keys = capture.keys.lock().unwrap().clone();
        let auths = capture.auths.lock().unwrap().clone();
        assert_eq!(bodies.len(), KEYED_RETRY_MAX_ATTEMPTS as usize);
        assert_eq!(bodies[0], bodies[1]);
        assert_eq!(bodies[1], bodies[2]);
        assert_eq!(bodies[2], bodies[3]);
        assert_eq!(keys[0], keys[1]);
        assert_eq!(keys[1], keys[2]);
        assert_eq!(keys[2], keys[3]);
        let first_auth = nip98_event_from_authorization(&auths[0]);
        let last_auth = nip98_event_from_authorization(&auths[3]);
        assert_ne!(first_auth.id, last_auth.id);
    }

    /// Three consecutive keyed 503s with `Retry-After: 5` must not start a
    /// fourth request before 15 seconds. The fourth attempt may then succeed
    /// with the same body/key and a fresh NIP-98 Authorization.
    #[tokio::test(start_paused = true)]
    async fn keyed_three_retry_after_5_succeeds_on_fourth_attempt_after_15s() {
        let (url, capture) = keyed_events_server(|n| {
            if n < KEYED_RETRY_MAX_ATTEMPTS {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    vec![("retry-after", "5")],
                    r#"{"error":"idempotency unavailable"}"#.to_string(),
                )
            } else {
                (
                    StatusCode::OK,
                    Vec::new(),
                    r#"{"event_id":"abc","accepted":true,"message":""}"#.to_string(),
                )
            }
        })
        .await;
        let client = test_client(&url);
        let event = make_kind9_event(client.keys());
        let key = [0x15; 32];
        let submit = tokio::spawn(async move {
            client
                .submit_event_with_idempotency_key(event, Some(key))
                .await
        });

        let mut first_attempt_yields = 0u32;
        while capture.attempts.load(Ordering::SeqCst) < 1 {
            tokio::task::yield_now().await;
            first_attempt_yields += 1;
            assert!(
                first_attempt_yields < 10_000,
                "first keyed 503 never arrived"
            );
        }
        assert_eq!(capture.attempts.load(Ordering::SeqCst), 1);
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        let retry_after_started = tokio::time::Instant::now();

        tokio::time::sleep(Duration::from_secs(4)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            capture.attempts.load(Ordering::SeqCst),
            1,
            "must not retry inside the first Retry-After: 5 window"
        );
        tokio::time::sleep(Duration::from_secs(3)).await;
        wait_for_keyed_attempt(&capture, 2).await;
        assert!(retry_after_started.elapsed() >= Duration::from_secs(5));

        tokio::time::sleep(Duration::from_secs(4)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            capture.attempts.load(Ordering::SeqCst),
            2,
            "must not start the third request inside the second Retry-After: 5 window"
        );
        tokio::time::sleep(Duration::from_secs(3)).await;
        wait_for_keyed_attempt(&capture, 3).await;
        assert!(retry_after_started.elapsed() >= Duration::from_secs(10));

        let elapsed = retry_after_started.elapsed();
        if elapsed < Duration::from_secs(14) {
            tokio::time::sleep(Duration::from_secs(14) - elapsed).await;
        }
        tokio::task::yield_now().await;
        assert_eq!(
            capture.attempts.load(Ordering::SeqCst),
            3,
            "must not start a fourth request before 15 seconds"
        );
        assert!(
            retry_after_started.elapsed() < Duration::from_secs(15),
            "pre-15s probe must remain before the legal capacity-release floor"
        );

        // Floor is 5s; extra keyed jitter is in [0, 1.5). Advance past the
        // combined ceiling so the fourth attempt is not timing-flaky.
        tokio::time::sleep(Duration::from_secs(7)).await;
        wait_for_keyed_attempt(&capture, KEYED_RETRY_MAX_ATTEMPTS).await;
        assert!(
            retry_after_started.elapsed() >= Duration::from_secs(15),
            "fourth attempt must start no earlier than 15 seconds"
        );

        let result = submit.await.expect("join keyed submit");
        assert!(
            result.is_ok(),
            "expected Ok on the fourth keyed attempt, got {result:?}"
        );
        assert_eq!(
            capture.attempts.load(Ordering::SeqCst),
            KEYED_RETRY_MAX_ATTEMPTS
        );

        let bodies = capture.bodies.lock().unwrap().clone();
        let keys = capture.keys.lock().unwrap().clone();
        let auths = capture.auths.lock().unwrap().clone();
        assert_eq!(bodies.len(), KEYED_RETRY_MAX_ATTEMPTS as usize);
        assert_eq!(bodies[0], bodies[1]);
        assert_eq!(bodies[1], bodies[2]);
        assert_eq!(bodies[2], bodies[3]);
        let expected_key = hex::encode(key);
        assert_eq!(
            keys,
            vec![
                expected_key.clone(),
                expected_key.clone(),
                expected_key.clone(),
                expected_key
            ]
        );
        let mut auth_ids = Vec::new();
        let expected_payload = hex::encode(Sha256::digest(&bodies[0]));
        for auth in &auths {
            let event = nip98_event_from_authorization(auth);
            event.verify().unwrap();
            assert_eq!(payload_tag(&event), expected_payload);
            auth_ids.push(event.id);
        }
        assert_eq!(auth_ids.len(), 4);
        for i in 1..auth_ids.len() {
            assert_ne!(
                auth_ids[i - 1],
                auth_ids[i],
                "each attempt must carry a freshly signed NIP-98 event"
            );
        }
    }

    /// Keyed connect-failure exhaustion must return the network error, never
    /// panic on last-attempt jitter indexing.
    #[tokio::test(start_paused = true)]
    async fn keyed_three_connect_failures_return_network_error_without_panic() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let client = test_client(&format!("http://{addr}"));
        let event = make_kind9_event(client.keys());
        let submit = tokio::spawn(async move {
            client
                .submit_event_with_idempotency_key(event, Some([0x51; 32]))
                .await
        });
        let mut steps = 0u32;
        while !submit.is_finished() {
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_secs(2)).await;
            steps += 1;
            assert!(
                steps < 10_000,
                "keyed connect exhaustion never finished on paused time"
            );
        }
        let err = submit.await.expect("join").unwrap_err();
        assert!(
            matches!(err, CliError::Network(_)),
            "exhausted keyed connect failures must surface Network, got {err:?}"
        );
        assert!(
            crate::error::is_retryable_error(&err),
            "keyed connect exhaustion must remain retryable, got {err:?}"
        );
        assert!(!matches!(err, CliError::DeliveryUnknown(_)));
        let description = format!("{err:?}");
        assert!(
            !description.contains("outcome unknown"),
            "keyed connect failure must not be labeled DeliveryUnknown; got: {description}"
        );
    }

    struct RedirectVictim {
        hits: AtomicU32,
        bodies: Mutex<Vec<Vec<u8>>>,
        keys: Mutex<Vec<Option<String>>>,
    }

    /// 307/308 must stop at the original `/events` POST. The redirect target
    /// must not receive the signed body or `Idempotency-Key`, and the client
    /// must not treat the 3xx as a 503/network retry.
    async fn keyed_redirect_does_not_forward(status: StatusCode) {
        const BODY_SENTINEL: &str = "keyed-redirect-body-must-not-surface";
        let expected_status = status.as_u16();

        let victim = Arc::new(RedirectVictim {
            hits: AtomicU32::new(0),
            bodies: Mutex::new(Vec::new()),
            keys: Mutex::new(Vec::new()),
        });
        let victim_state = victim.clone();
        let victim_app =
            Router::new().fallback(move |headers: HeaderMap, body: axum::body::Bytes| {
                let victim_state = victim_state.clone();
                async move {
                    victim_state.hits.fetch_add(1, Ordering::SeqCst);
                    victim_state.bodies.lock().unwrap().push(body.to_vec());
                    let key = headers
                        .get("idempotency-key")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_string);
                    victim_state.keys.lock().unwrap().push(key);
                    StatusCode::OK
                }
            });
        let victim_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let victim_addr: SocketAddr = victim_listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(victim_listener, victim_app).await.unwrap() });

        let origin_hits = Arc::new(AtomicU32::new(0));
        let origin_hits2 = origin_hits.clone();
        let location = format!("http://{victim_addr}/sink");
        let origin_app = Router::new().route(
            "/events",
            post(move || {
                let origin_hits2 = origin_hits2.clone();
                let location = location.clone();
                async move {
                    origin_hits2.fetch_add(1, Ordering::SeqCst);
                    Response::builder()
                        .status(status)
                        .header("location", location)
                        .header("content-type", "text/plain")
                        .body(axum::body::Body::from(BODY_SENTINEL))
                        .unwrap()
                }
            }),
        );
        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr: SocketAddr = origin_listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(origin_listener, origin_app).await.unwrap() });

        let client = test_client(&format!("http://{origin_addr}"));
        let event = make_kind9_event(client.keys());
        let err = client
            .submit_event_with_idempotency_key(event, Some([0x37; 32]))
            .await
            .unwrap_err();

        assert!(
            matches!(
                &err,
                CliError::Relay { status: s, body } if *s == expected_status && !body.contains(BODY_SENTINEL)
            ),
            "keyed {expected_status} must be a bounded Relay error without the 3xx body, got {err:?}"
        );
        assert!(
            !matches!(err, CliError::Network(_)),
            "keyed {expected_status} must not be retried as a network error, got {err:?}"
        );
        assert!(
            !matches!(err, CliError::DeliveryUnknown(_)),
            "keyed {expected_status} must not be DeliveryUnknown, got {err:?}"
        );
        assert!(
            !crate::error::is_retryable_error(&err),
            "keyed {expected_status} must not enter 503/network retry, got {err:?}"
        );
        assert_eq!(
            origin_hits.load(Ordering::SeqCst),
            1,
            "original keyed endpoint must be contacted only once"
        );
        assert_eq!(
            victim.hits.load(Ordering::SeqCst),
            0,
            "redirect target must not be contacted"
        );
        let victim_bodies = victim.bodies.lock().unwrap().clone();
        let victim_keys = victim.keys.lock().unwrap().clone();
        assert!(
            victim_bodies.iter().all(|b| b.is_empty()),
            "redirect target must not receive the signed body, got {victim_bodies:?}"
        );
        assert!(
            victim_keys.iter().all(|k| k.is_none()),
            "redirect target must not receive Idempotency-Key, got {victim_keys:?}"
        );
    }

    #[tokio::test]
    async fn keyed_307_does_not_forward_body_or_idempotency_key() {
        keyed_redirect_does_not_forward(StatusCode::TEMPORARY_REDIRECT).await;
    }

    #[tokio::test]
    async fn keyed_308_does_not_forward_body_or_idempotency_key() {
        keyed_redirect_does_not_forward(StatusCode::PERMANENT_REDIRECT).await;
    }

    fn assert_keyed_oversize(err: &CliError, hostile: &str) {
        match err {
            CliError::KeyedResponseTooLarge { limit } => {
                assert_eq!(*limit, KEYED_RESPONSE_MAX_BYTES);
            }
            other => panic!("expected KeyedResponseTooLarge, got {other:?}"),
        }
        assert!(
            !matches!(err, CliError::Network(_)),
            "oversize must not surface as Network, got {err:?}"
        );
        assert!(
            !matches!(err, CliError::Relay { .. }),
            "oversize must not surface as Relay, got {err:?}"
        );
        assert!(
            !matches!(err, CliError::DeliveryUnknown(_)),
            "oversize must not surface as DeliveryUnknown, got {err:?}"
        );
        assert!(
            !matches!(err, CliError::RelayDeferred { .. }),
            "oversize must not surface as RelayDeferred, got {err:?}"
        );
        let display = err.to_string();
        assert!(!display.contains(hostile));
        assert!(!format!("{err:?}").contains(hostile));
        assert!(!error_json(err).to_string().contains(hostile));
        assert!(!is_retryable_error(err));
    }

    async fn spawn_keyed_http_then_hold(response: Vec<u8>) -> (String, Arc<AtomicU32>) {
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts2 = attempts.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            attempts2.fetch_add(1, Ordering::SeqCst);
            let mut buf = vec![0u8; 8192];
            let _ = stream.read(&mut buf).await;
            let _ = stream.write_all(&response).await;
            // Keep the connection open so a client that waits for the rest of
            // the body cannot complete by seeing EOF.
            let mut unused = [0u8; 1];
            let _ = stream.read(&mut unused).await;
        });
        (format!("http://{addr}"), attempts)
    }

    async fn spawn_keyed_http_complete(response: Vec<u8>) -> (String, Arc<AtomicU32>) {
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts2 = attempts.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            attempts2.fetch_add(1, Ordering::SeqCst);
            let mut buf = vec![0u8; 8192];
            let _ = stream.read(&mut buf).await;
            let _ = stream.write_all(&response).await;
        });
        (format!("http://{addr}"), attempts)
    }

    #[tokio::test]
    async fn keyed_response_at_byte_ceiling_is_accepted() {
        let limit = KEYED_RESPONSE_MAX_BYTES;
        let body = "a".repeat(limit);
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {limit}\r\n\r\n"
        )
        .into_bytes();
        response.extend_from_slice(body.as_bytes());
        let (url, attempts) = spawn_keyed_http_complete(response).await;
        let client = test_client(&url);
        let event = make_kind9_event(client.keys());
        let got = client
            .submit_event_with_idempotency_key(event, Some([0x60; 32]))
            .await
            .unwrap();
        assert_eq!(got.len(), limit);
        assert_eq!(got, body);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn keyed_declared_oversize_response_is_rejected_before_body_collection() {
        const HOSTILE: &str = "hostile-keyed-response-body";
        let limit = KEYED_RESPONSE_MAX_BYTES;
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            limit + 1
        );
        let (url, attempts) = spawn_keyed_http_then_hold(headers.into_bytes()).await;
        let client = test_client(&url);
        let event = make_kind9_event(client.keys());
        let err = tokio::time::timeout(
            Duration::from_secs(5),
            client.submit_event_with_idempotency_key(event, Some([0x61; 32])),
        )
        .await
        .expect("declared oversize must not wait for an omitted body")
        .unwrap_err();
        assert_keyed_oversize(&err, HOSTILE);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn keyed_chunked_oversize_stops_at_first_cumulative_over_limit_chunk() {
        const HOSTILE: &str = "hostile-chunked-keyed-response";
        let limit = KEYED_RESPONSE_MAX_BYTES;
        let first = HOSTILE.len();
        let second = limit + 1 - first;
        assert_eq!(first + second, limit + 1);
        assert_ne!(second, limit + 1);
        let mut response =
            format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{first:x}\r\n")
                .into_bytes();
        response.extend_from_slice(HOSTILE.as_bytes());
        response.extend_from_slice(format!("\r\n{second:x}\r\n").as_bytes());
        response.extend(vec![b'x'; second]);
        response.extend_from_slice(b"\r\n");
        // No terminating 0-chunk. Waiting for the rest of the stream would hang.
        let (url, attempts) = spawn_keyed_http_then_hold(response).await;
        let client = test_client(&url);
        let event = make_kind9_event(client.keys());
        let err = tokio::time::timeout(
            Duration::from_secs(5),
            client.submit_event_with_idempotency_key(event, Some([0x62; 32])),
        )
        .await
        .expect("chunked oversize must not wait for a terminating chunk")
        .unwrap_err();
        assert_keyed_oversize(&err, HOSTILE);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn keyed_missing_length_oversize_is_rejected() {
        const HOSTILE: &str = "hostile-missing-length-keyed-response";
        let limit = KEYED_RESPONSE_MAX_BYTES;
        let mut body = HOSTILE.as_bytes().to_vec();
        body.extend(vec![b'x'; limit + 1 - HOSTILE.len()]);
        assert_eq!(body.len(), limit + 1);
        let mut response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n".to_vec();
        response.extend_from_slice(&body);
        let (url, attempts) = spawn_keyed_http_complete(response).await;
        let client = test_client(&url);
        let event = make_kind9_event(client.keys());
        let err = client
            .submit_event_with_idempotency_key(event, Some([0x63; 32]))
            .await
            .unwrap_err();
        assert_keyed_oversize(&err, HOSTILE);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn keyed_in_bound_json_400_maps_to_relay_with_extracted_message() {
        let (url, capture) = keyed_events_server(|_n| {
            (
                StatusCode::BAD_REQUEST,
                Vec::new(),
                r#"{"error":"event schema rejected"}"#.to_string(),
            )
        })
        .await;
        let client = test_client(&url);
        let event = make_kind9_event(client.keys());
        let err = client
            .submit_event_with_idempotency_key(event, Some([0x64; 32]))
            .await
            .unwrap_err();
        match &err {
            CliError::Relay { status: 400, body } => {
                assert_eq!(body, "event schema rejected");
            }
            other => panic!(
                "in-bound keyed 400 must map to Relay {{ status: 400 }} with extracted message, got {other:?}"
            ),
        }
        assert_eq!(
            capture.attempts.load(Ordering::SeqCst),
            1,
            "keyed 400 must not be retried"
        );
        assert!(!matches!(err, CliError::KeyedResponseTooLarge { .. }));
        assert!(!matches!(err, CliError::Network(_)));
        assert!(!matches!(err, CliError::DeliveryUnknown(_)));
        assert!(!matches!(err, CliError::RelayDeferred { .. }));
    }

    #[tokio::test]
    async fn keyed_503_retry_after_3600_is_deferred_after_one_attempt() {
        let (url, capture) = keyed_events_server(|_n| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                vec![("retry-after", "3600")],
                r#"{"error":"idempotency unavailable"}"#.to_string(),
            )
        })
        .await;
        let client = test_client(&url);
        let event = make_kind9_event(client.keys());
        let err = tokio::time::timeout(
            Duration::from_secs(5),
            client.submit_event_with_idempotency_key(event, Some([0x65; 32])),
        )
        .await
        .expect("Retry-After 3600 must not hang inside the keyed loop")
        .unwrap_err();
        assert!(
            matches!(
                err,
                CliError::RelayDeferred {
                    status: 503,
                    retry_after_seconds: 3600,
                    ..
                }
            ),
            "503 Retry-After 3600 must return RelayDeferred after one attempt, got {err:?}"
        );
        assert_eq!(
            capture.attempts.load(Ordering::SeqCst),
            1,
            "Retry-After 3600 must not issue another request"
        );
        assert!(!is_retryable_error(&err));
        assert!(!matches!(err, CliError::KeyedResponseTooLarge { .. }));
        assert!(!matches!(err, CliError::Network(_)));
        assert!(!matches!(err, CliError::DeliveryUnknown(_)));
        assert!(!matches!(err, CliError::Relay { .. }));
    }
}

#[cfg(test)]
mod public_metadata_tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    use nostr::Keys;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::{
        declared_public_metadata_too_large, public_metadata_chunk_exceeds_limit, BuzzClient,
        BOUNDED_PUBLIC_METADATA_ERROR, NIP11_PUBLIC_METADATA_MAX_BYTES,
    };
    use crate::error::{error_json, is_retryable_error, CliError};

    fn test_client(base_url: &str) -> BuzzClient {
        BuzzClient::new(base_url.to_string(), Keys::generate(), None, None).unwrap()
    }

    fn assert_oversize(err: &CliError, hostile: &str) {
        match err {
            CliError::PublicMetadataTooLarge { limit } => {
                assert_eq!(*limit, NIP11_PUBLIC_METADATA_MAX_BYTES);
            }
            other => panic!("expected PublicMetadataTooLarge, got {other:?}"),
        }
        let display = err.to_string();
        assert_eq!(
            display,
            format!("public metadata exceeds {NIP11_PUBLIC_METADATA_MAX_BYTES} bytes")
        );
        assert!(!display.contains(hostile));
        assert!(!format!("{err:?}").contains(hostile));
        assert!(!error_json(err).to_string().contains(hostile));
        assert!(!is_retryable_error(err));
    }

    async fn spawn_http_then_hold(response: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let _ = stream.write_all(&response).await;
            // Keep the connection open so a client that waits for the rest of
            // the body cannot complete by seeing EOF.
            let mut unused = [0u8; 1];
            let _ = stream.read(&mut unused).await;
        });
        format!("http://{addr}")
    }

    async fn spawn_http_complete(response: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let _ = stream.write_all(&response).await;
        });
        format!("http://{addr}")
    }

    fn json_of_size(size: usize) -> String {
        let mut doc = serde_json::json!({
            "supported_extensions": ["buzz-idempotency"],
            "idempotency": buzz_core::idempotency::canonical_nip11_descriptor(),
            "pad": ""
        });
        let base_len = serde_json::to_string(&doc).unwrap().len();
        assert!(size >= base_len);
        doc["pad"] = serde_json::json!("a".repeat(size - base_len));
        let body = serde_json::to_string(&doc).unwrap();
        assert_eq!(body.len(), size);
        body
    }

    #[test]
    fn declared_length_at_ceiling_is_accepted_by_the_predicate() {
        let limit = NIP11_PUBLIC_METADATA_MAX_BYTES;
        assert!(!declared_public_metadata_too_large(
            Some(limit as u64),
            limit
        ));
        assert!(declared_public_metadata_too_large(
            Some(limit as u64 + 1),
            limit
        ));
        assert!(!declared_public_metadata_too_large(None, limit));
    }

    #[test]
    fn incremental_chunk_predicate_trips_on_first_over_limit_chunk() {
        let limit = NIP11_PUBLIC_METADATA_MAX_BYTES;
        assert!(!public_metadata_chunk_exceeds_limit(0, limit, limit));
        assert!(public_metadata_chunk_exceeds_limit(0, limit + 1, limit));
        assert!(public_metadata_chunk_exceeds_limit(limit, 1, limit));
        assert!(!public_metadata_chunk_exceeds_limit(limit - 1, 1, limit));
    }

    #[tokio::test]
    async fn oversized_declared_length_is_rejected_before_body_collection() {
        const HOSTILE: &str = "hostile-nip11-body";
        let limit = NIP11_PUBLIC_METADATA_MAX_BYTES;
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            limit + 1
        );
        // Intentionally omit the body. Collecting by Content-Length would wait
        // for limit+1 bytes that never arrive.
        let url = spawn_http_then_hold(headers.into_bytes()).await;
        let err = test_client(&url)
            .get_public_metadata("/")
            .await
            .unwrap_err();
        assert_oversize(&err, HOSTILE);
    }

    #[tokio::test]
    async fn chunked_missing_length_overflow_stops_at_first_over_limit_chunk() {
        const HOSTILE: &str = "hostile-chunked-nip11";
        let limit = NIP11_PUBLIC_METADATA_MAX_BYTES;
        let over = limit + 1;
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nxxxxxxxx\r\n{over:x}\r\n"
        )
        .into_bytes();
        response.extend(vec![b'x'; over]);
        response.extend_from_slice(b"\r\n");
        // No terminating 0-chunk. Waiting for the rest of the stream would hang.
        let url = spawn_http_then_hold(response).await;
        let err = test_client(&url)
            .get_public_metadata("/")
            .await
            .unwrap_err();
        assert_oversize(&err, HOSTILE);
    }

    #[tokio::test]
    async fn valid_document_at_accepted_byte_boundary_is_returned() {
        let limit = NIP11_PUBLIC_METADATA_MAX_BYTES;
        let body = json_of_size(limit);
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {limit}\r\n\r\n"
        )
        .into_bytes();
        response.extend_from_slice(body.as_bytes());
        let url = spawn_http_complete(response).await;
        let got = test_client(&url).get_public_metadata("/").await.unwrap();
        assert_eq!(got.len(), limit);
        assert_eq!(got, body);
        let parsed: serde_json::Value = serde_json::from_str(&got).unwrap();
        assert!(buzz_core::idempotency::nip11_keyed_client_accepts(&parsed));
    }

    #[tokio::test]
    async fn oversized_error_response_is_not_echoed() {
        const HOSTILE: &str = "hostile-error-body";
        let limit = NIP11_PUBLIC_METADATA_MAX_BYTES;
        let headers = format!(
            "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{HOSTILE}",
            limit + 1
        );
        let url = spawn_http_then_hold(headers.into_bytes()).await;
        let err = test_client(&url)
            .get_public_metadata("/")
            .await
            .unwrap_err();
        assert_oversize(&err, HOSTILE);
        assert!(!matches!(err, CliError::Relay { status: 500, .. }));
        assert!(!matches!(err, CliError::Network(_)));
    }

    #[tokio::test]
    async fn in_bound_error_response_is_not_echoed() {
        const HOSTILE: &str = "hostile-in-bound-nip11-error";
        let body = format!(r#"{{"error":"{HOSTILE}","message":"{HOSTILE}"}}"#);
        let len = body.len();
        assert!(len <= NIP11_PUBLIC_METADATA_MAX_BYTES);
        let response = format!(
            "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {len}\r\n\r\n{body}"
        );
        let url = spawn_http_complete(response.into_bytes()).await;
        let err = test_client(&url)
            .get_public_metadata("/")
            .await
            .unwrap_err();
        match &err {
            CliError::Relay { status: 500, body } => {
                assert_eq!(body, BOUNDED_PUBLIC_METADATA_ERROR);
            }
            other => panic!(
                "in-bound NIP-11 error must keep HTTP status and Relay family, got {other:?}"
            ),
        }
        assert!(!matches!(err, CliError::PublicMetadataTooLarge { .. }));
        assert!(!matches!(err, CliError::Conflict(_)));
        let display = err.to_string();
        assert_eq!(
            display,
            format!("relay error 500: {BOUNDED_PUBLIC_METADATA_ERROR}")
        );
        assert!(!display.contains(HOSTILE));
        assert!(!format!("{err:?}").contains(HOSTILE));
        let json = error_json(&err);
        assert!(!json.to_string().contains(HOSTILE));
        assert_eq!(
            json.get("message").and_then(|m| m.as_str()),
            Some(display.as_str())
        );
    }

    #[tokio::test]
    async fn bounded_preflight_does_not_follow_redirect_to_loopback() {
        let victim_hits = Arc::new(AtomicU32::new(0));
        let victim_hits2 = victim_hits.clone();
        let victim = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let victim_addr = victim.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = victim.accept().await else {
                    break;
                };
                victim_hits2.fetch_add(1, Ordering::SeqCst);
                let mut buf = vec![0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}")
                    .await;
            }
        });

        let redirector = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redirector_addr = redirector.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = redirector.accept().await else {
                    break;
                };
                let mut buf = vec![0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let location = format!("http://{victim_addr}/secret");
                let body = format!(
                    "HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\n\r\n"
                );
                let _ = stream.write_all(body.as_bytes()).await;
            }
        });

        let result = test_client(&format!("http://{redirector_addr}"))
            .get_public_metadata("/")
            .await;
        assert!(
            matches!(result, Err(CliError::Relay { status: 302, .. })),
            "bounded NIP-11 preflight must not follow the redirect, got {result:?}"
        );
        assert_eq!(
            victim_hits.load(Ordering::SeqCst),
            0,
            "loopback redirect target must never be contacted"
        );
    }
}
