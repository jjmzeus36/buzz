//! Nostr HTTP bridge — POST /events, /query, /count with NIP-98 auth.
//!
//! These endpoints provide HTTP access to the relay's Nostr protocol,
//! authenticated via NIP-98 signed events.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::thread::{self, Thread};
use std::time::Duration;

use axum::{
    extract::{Path, Query, RawQuery, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use base64::Engine;
use dashmap::{DashMap, Entry as DashMapEntry};
use serde_json::Value;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, SemaphorePermit};
use uuid::Uuid;

use buzz_auth::{LimitType, Nip98ReplayGuard, RateLimiter, DEFAULT_REPLAY_TTL_SECS};
use buzz_core::TenantContext;

use crate::handlers::ingest::{
    ingest_keyed_http_event, try_acquire_keyed_ingress, IngestAuth, IngestError,
    KeyedEarlyDeadline, KeyedHttpEarlyContext, KeyedHttpError, KeyedHttpValidatedEvent,
    KeyedIngressGuard, KEYED_BUSY_RETRY_AFTER_SECS,
};
use crate::state::AppState;

use super::{api_error, internal_error, not_found};

pub(crate) async fn enforce_http_admission(
    state: &AppState,
    tenant: &TenantContext,
    pubkey: &nostr::PublicKey,
) -> Result<(), (StatusCode, Json<Value>)> {
    let limit = state.auth.config().rate_limits.human_api_calls_per_min;
    match crate::admission::check_principal(
        state.admission_rate_limiter.as_ref(),
        tenant,
        pubkey,
        LimitType::ApiCalls,
        60,
        limit,
    )
    .await
    {
        Ok(()) => Ok(()),
        Err(error) => Err(http_admission_error_response(error)),
    }
}

fn http_admission_error_response(
    error: crate::admission::AdmissionError,
) -> (StatusCode, Json<Value>) {
    match error {
        crate::admission::AdmissionError::Exceeded { reset_in_secs } => {
            metrics::counter!("buzz_admission_rejections_total", "transport" => "http", "reason" => "quota").increment(1);
            api_error(
                StatusCode::TOO_MANY_REQUESTS,
                &format!("rate-limited: quota exceeded; retry in {reset_in_secs}s"),
            )
        }
        crate::admission::AdmissionError::Unavailable => {
            metrics::counter!("buzz_admission_rejections_total", "transport" => "http", "reason" => "unavailable").increment(1);
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "rate-limited: shared admission unavailable",
            )
        }
    }
}

/// Values retained from an already-verified bridge authentication event.
#[derive(Debug)]
pub(crate) struct VerifiedBridgeAuth {
    pub(crate) pubkey: nostr::PublicKey,
    pub(crate) event_id_bytes: [u8; 32],
    pub(crate) signed_created_at: Option<u64>,
}

type BridgeAuthResult = Result<VerifiedBridgeAuth, (StatusCode, Json<Value>)>;

/// Verify bridge auth: NIP-98 (production) or X-Pubkey (dev mode).
///
/// Returns the authenticated public key, an event ID for replay detection, and
/// the verified signed auth timestamp. For X-Pubkey dev mode, the event ID is
/// a zero hash and the timestamp is absent.
pub(crate) fn verify_bridge_auth(
    headers: &HeaderMap,
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    require_auth_token: bool,
) -> BridgeAuthResult {
    verify_bridge_auth_with_options(headers, method, url, body, require_auth_token, false)
}

pub(crate) fn verify_bridge_auth_with_options(
    headers: &HeaderMap,
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    require_auth_token: bool,
    require_payload: bool,
) -> BridgeAuthResult {
    // Try NIP-98 first (Authorization: Nostr <base64>)
    if let Some(auth_str) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Nostr "))
    {
        let event_json = {
            use base64::engine::general_purpose::STANDARD as BASE64;
            let bytes = BASE64
                .decode(auth_str)
                .map_err(|_| api_error(StatusCode::UNAUTHORIZED, "invalid base64 in Nostr auth"))?;
            String::from_utf8(bytes)
                .map_err(|_| api_error(StatusCode::UNAUTHORIZED, "invalid UTF-8 in Nostr auth"))?
        };

        let event: nostr::Event = serde_json::from_str(&event_json)
            .map_err(|_| api_error(StatusCode::UNAUTHORIZED, "invalid NIP-98 event JSON"))?;
        let event_id_bytes = event.id.to_bytes();

        if require_payload
            && !event
                .tags
                .iter()
                .any(|tag| tag.kind() == nostr::TagKind::Payload)
        {
            return Err(api_error(
                StatusCode::UNAUTHORIZED,
                "NIP-98: missing payload tag",
            ));
        }

        let pubkey = buzz_auth::verify_nip98_event(&event_json, url, method, body)
            .map_err(|e| api_error(StatusCode::UNAUTHORIZED, &format!("NIP-98: {e}")))?;

        return Ok(VerifiedBridgeAuth {
            pubkey,
            event_id_bytes,
            signed_created_at: Some(event.created_at.as_secs()),
        });
    }

    // Dev-mode fallback: X-Pubkey header (only when require_auth_token is false)
    if !require_auth_token {
        if let Some(hex_val) = headers.get("x-pubkey").and_then(|v| v.to_str().ok()) {
            let pubkey = nostr::PublicKey::from_hex(hex_val)
                .map_err(|_| api_error(StatusCode::UNAUTHORIZED, "invalid X-Pubkey hex"))?;
            // Zero event ID — no replay detection needed for dev mode
            return Ok(VerifiedBridgeAuth {
                pubkey,
                event_id_bytes: [0u8; 32],
                signed_created_at: None,
            });
        }
    }

    Err(api_error(StatusCode::UNAUTHORIZED, "missing Nostr auth"))
}

/// Check NIP-98 replay and record the event ID atomically.
///
/// The correctness boundary is the shared, community-scoped Redis seen-set on
/// `AppState`, not process-local memory. Any Redis/guard error fails closed:
/// without the shared `SET NX EX` proof, a stateless worker cannot admit the
/// NIP-98 request safely.
pub(crate) async fn check_nip98_replay(
    state: &AppState,
    tenant: &TenantContext,
    event_id_bytes: [u8; 32],
) -> Result<(), (StatusCode, Json<Value>)> {
    check_nip98_replay_with_guard(state.nip98_replay.as_ref(), tenant, event_id_bytes).await
}

async fn check_nip98_replay_with_guard(
    replay_guard: &dyn Nip98ReplayGuard,
    tenant: &TenantContext,
    event_id_bytes: [u8; 32],
) -> Result<(), (StatusCode, Json<Value>)> {
    // Skip replay detection for dev-mode X-Pubkey auth (zero hash).
    if event_id_bytes == [0u8; 32] {
        return Ok(());
    }

    let event_id = nostr::EventId::from_byte_array(event_id_bytes);
    match replay_guard
        .try_mark(tenant, &event_id, DEFAULT_REPLAY_TTL_SECS)
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(api_error(
            StatusCode::UNAUTHORIZED,
            "NIP-98: replay detected",
        )),
        Err(e) => {
            tracing::warn!(
                community = %tenant.community(),
                error = %e,
                "NIP-98 replay guard failed; rejecting request fail-closed"
            );
            Err(api_error(
                StatusCode::UNAUTHORIZED,
                "NIP-98: replay check unavailable",
            ))
        }
    }
}

/// Construct the NIP-98 `u`-tag expected URL for a request bound to `tenant`.
///
/// Conformance row 44 obligation: "NIP-98 `u` URL host must match
/// `req.community`." Host comes from the resolved [`TenantContext`] — the
/// same host the row-zero seam already bound from the request `Host` header —
/// and the scheme comes from the deployment's configured relay URL so
/// `ws`/`wss` deployments map to `http`/`https` consistently with how the
/// client signs the URL it is actually hitting.
///
/// Critically, this does NOT use `config_relay_url`'s host. `config.relay_url`
/// is one static string per deployment; under multi-tenant a relay serves many
/// hosts, only one of which would match. Using it as the URL match key would
/// (a) accept a NIP-98 event signed for community A's host when the request
/// arrives at community B's host (host-binding side door — verify_nip98 would
/// pass and the relay would proceed against the wrong tenant's auth context),
/// and (b) reject every legitimate request whose community host isn't the
/// single configured one. Substituting `tenant.host()` closes both directions.
pub(crate) fn nip98_expected_url(
    config_relay_url: &str,
    tenant: &TenantContext,
    path: &str,
) -> String {
    let scheme = if config_relay_url.trim_start().starts_with("wss://") {
        "https"
    } else {
        "http"
    };
    format!("{scheme}://{}{path}", tenant.host())
}

/// Construct the NIP-42 expected `relay` URL for a connection bound to `tenant`.
///
/// NIP-42 (WebSocket AUTH) sibling of [`nip98_expected_url`]. Conformance row 44
/// obligation extends to the WS auth side: the AUTH event's `relay` tag must
/// match the per-tenant host the connection arrived on, not the deployment-wide
/// `config.relay_url`. Same hole the NIP-98 fix closed for HTTP — `config.relay_url`
/// is one static string per deployment, so verifying against it (a) admits an
/// AUTH event signed against community A's host on a connection bound to
/// community B (cross-host token reuse), and (b) rejects every legitimate AUTH
/// whose tenant host isn't the single configured one.
///
/// Scheme is `ws`/`wss` (not `http`/`https`) because the value being matched is
/// the client's connect URL embedded in the signed AUTH event; the helper
/// preserves the deployment's TLS posture from `config_relay_url`'s prefix so
/// `wss://` deployments stay `wss://` and `ws://` dev/test stays `ws://`.
/// Path is empty — clients put the bare WS origin (`ws://host[:port]`) in the
/// `relay` tag, matching how `EventBuilder::auth` accepts a [`nostr::RelayUrl`].
pub(crate) fn nip42_expected_relay_url(config_relay_url: &str, tenant: &TenantContext) -> String {
    let scheme = if config_relay_url.trim_start().starts_with("wss://") {
        "wss"
    } else {
        "ws"
    };
    format!("{scheme}://{}", tenant.host())
}

/// Extract a channel UUID from a single filter's `#h` tag.
fn extract_channel_from_filter(filter: &nostr::Filter) -> Option<uuid::Uuid> {
    let h_tag = nostr::SingleLetterTag::lowercase(nostr::Alphabet::H);
    filter.generic_tags.get(&h_tag).and_then(|vs| {
        if vs.len() == 1 {
            vs.iter().next()?.parse::<uuid::Uuid>().ok()
        } else {
            None
        }
    })
}

//
// The CLI injects extension fields (before_id, depth_limit, feed_types) into
// Nostr filter JSON. nostr::Filter silently drops unknown fields during
// deserialization, so we extract them from the raw JSON Value first.

const BRIDGE_FEED_MAX_LIMIT: i64 = 100;
const BRIDGE_THREAD_MAX_LIMIT: u32 = 500;

/// The `before_id` extension field, with "present but malformed" kept distinct
/// from "absent": NIP-CW's cursor grammar says a malformed value MUST reject
/// the request, never silently demote it to a half cursor or a head request.
enum BeforeId {
    Absent,
    Valid(Vec<u8>),
    Malformed,
}

fn extract_before_id(raw: &Value) -> BeforeId {
    let Some(value) = raw.get("before_id") else {
        return BeforeId::Absent;
    };
    match value
        .as_str()
        .filter(|hex_str| hex_str.len() == 64)
        .and_then(|hex_str| hex::decode(hex_str).ok())
    {
        Some(id) => BeforeId::Valid(id),
        None => BeforeId::Malformed,
    }
}

fn extract_buzz_channel(raw: &Value) -> Option<&str> {
    raw.get("#buzz-channel")
        .and_then(Value::as_array)
        .filter(|values| values.len() == 1)
        .and_then(|values| values.first())
        .and_then(Value::as_str)
}

/// True when the raw filter opts into a bridge extension flag (`top_level`,
/// `include_summaries`, `include_aux`). Absent or non-boolean = false.
fn extension_flag(raw: &Value, key: &str) -> bool {
    raw.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn extract_depth_limit(raw: &Value) -> Option<u32> {
    raw.get("depth_limit")?
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
}

/// Extract a thread pagination cursor from the raw filter JSON.
///
/// The desktop pages `get_thread_replies` forward with a keyset cursor derived
/// transparently from the last reply it has already loaded — no server-issued
/// token. The cursor is a composite of that reply's `created_at` (Unix seconds,
/// field `thread_cursor`/`threadCursor`) and its hex event id (field
/// `thread_cursor_id`/`threadCursorId`). The event id is the tiebreak that lets
/// pagination cross replies sharing the same `created_at` second — without it,
/// a timestamp-only cursor silently drops every tied reply past the page limit
/// (the exact "missed messages" bug this work exists to fix).
///
/// Wire → DB encoding: 8-byte big-endian i64 seconds, followed by the raw
/// event-id bytes when present. `get_thread_replies` decodes this layout back
/// into its `(timestamp, event_id)` keyset. A bare timestamp (no id) is still
/// accepted and paginates on time alone (unsafe across same-second ties).
fn extract_thread_cursor(raw: &Value) -> Option<Vec<u8>> {
    let secs = raw
        .get("thread_cursor")
        .or_else(|| raw.get("threadCursor"))?
        .as_i64()?;
    let mut bytes = secs.to_be_bytes().to_vec();

    if let Some(id_hex) = raw
        .get("thread_cursor_id")
        .or_else(|| raw.get("threadCursorId"))
        .and_then(Value::as_str)
    {
        if let Ok(id_bytes) = hex::decode(id_hex) {
            bytes.extend_from_slice(&id_bytes);
        }
    }

    Some(bytes)
}

fn extract_feed_types(raw: &Value) -> Option<Vec<String>> {
    let arr = raw.get("feed_types")?.as_array()?;
    let types: Vec<String> = arr
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    if types.is_empty() {
        None
    } else {
        Some(types)
    }
}

fn extract_search_mode(raw: &Value) -> buzz_search::SearchMode {
    match raw
        .get("search_mode")
        .or_else(|| raw.get("searchMode"))
        .and_then(Value::as_str)
    {
        Some("prefix") => buzz_search::SearchMode::Prefix,
        _ => buzz_search::SearchMode::FullText,
    }
}

fn extract_search_page(raw: &Value) -> u32 {
    raw.get("page")
        .or_else(|| raw.get("search_page"))
        .or_else(|| raw.get("searchPage"))
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .unwrap_or(1)
}

/// Compute the SQL `OFFSET` for a raw `page` extension on a non-search general
/// query, or `None` if paging shouldn't apply.
///
/// `page` is 1-based: page 1 → offset 0 (no change), page N → `(N-1) * limit`.
/// Returns `None` when `page` is absent or ≤ 1 (so unrelated general queries
/// keep their default offset) and when `limit` is missing (can't size a page).
/// This mirrors the FTS path's `page`/`per_page` for the non-search directory
/// listing (empty-query kind:0), whose deterministic `created_at DESC, id ASC`
/// ordering in `query_events` makes offset paging stable.
fn extract_page_offset(raw: &Value, limit: Option<i64>) -> Option<i64> {
    let page = raw
        .get("page")
        .and_then(Value::as_u64)
        .and_then(|value| i64::try_from(value).ok())
        .filter(|value| *value > 1)?;
    let per_page = limit.filter(|l| *l > 0)?;
    page.checked_sub(1)?.checked_mul(per_page)
}

/// Default and maximum row budget for a channel-window request. The budget
/// counts row events only; summary/bounds overlays and the aux closure never
/// consume it (docs/bridge-channel-window.md).
const BRIDGE_WINDOW_DEFAULT_LIMIT: u32 = 50;
const BRIDGE_WINDOW_MAX_LIMIT: u32 = 200;

/// Aux closure kinds: reactions, deletions (NIP-09 + NIP-29), edits.
const WINDOW_AUX_KINDS: [u32; 4] = [
    buzz_core::kind::KIND_DELETION,
    buzz_core::kind::KIND_REACTION,
    buzz_core::kind::KIND_NIP29_DELETE_EVENT,
    buzz_core::kind::KIND_STREAM_MESSAGE_EDIT,
];
/// Second-hop kinds: deletions targeting aux events (delete-of-a-reaction).
const WINDOW_AUX_DELETE_KINDS: [u32; 2] = [
    buzz_core::kind::KIND_DELETION,
    buzz_core::kind::KIND_NIP29_DELETE_EVENT,
];

/// Page size for one aux-closure hop. Matches the DB clamp
/// (`buzz_db::DEFAULT_MAX_PAGE_LIMIT`) so each page is one full query.
const AUX_PAGE_LIMIT: i64 = buzz_db::DEFAULT_MAX_PAGE_LIMIT;
/// Upper bound on pages drained per hop: 64k aux events referencing one page
/// of rows is far past any real thread; past it we log and stop rather than
/// loop forever against a pathological write pattern.
const AUX_MAX_PAGES: usize = 64;

fn build_aux_query(
    community: buzz_core::CommunityId,
    target_ids: Vec<String>,
    kinds: &[u32],
) -> buzz_db::EventQuery {
    let mut query = buzz_db::EventQuery::for_community(community);
    query.kinds = Some(kinds.iter().map(|kind| *kind as i32).collect());
    query.e_tags = Some(target_ids);
    query
}

/// Where an aux hop reads from: the window path pins the request's proved
/// read session; the thread path takes the routed display-read fast path.
enum AuxReader<'a> {
    Session(&'a mut buzz_db::ReadSession),
    Routed(&'a buzz_db::Db, &'static str),
    #[cfg(test)]
    Fake(&'a mut (dyn FnMut(&buzz_db::EventQuery) -> Vec<buzz_core::StoredEvent> + Send)),
}

impl AuxReader<'_> {
    async fn fetch(
        &mut self,
        query: &buzz_db::EventQuery,
    ) -> buzz_db::Result<Vec<buzz_core::StoredEvent>> {
        match self {
            AuxReader::Session(session) => session.query_events(query).await,
            AuxReader::Routed(db, path) => db.query_events_routed(path, query).await,
            #[cfg(test)]
            AuxReader::Fake(fetch) => Ok(fetch(query)),
        }
    }
}

/// Drain every event matching `query`, walking the `(created_at, id)` keyset
/// cursor `query_events` already orders by until a short page. An aux hop
/// over a reaction-heavy page can exceed a single page clamp, and because
/// results are newest-first a one-shot query silently drops the *oldest*
/// edits and deletions — rendering original or deleted content, not merely
/// losing decoration.
async fn query_all_pages(
    mut query: buzz_db::EventQuery,
    page_limit: i64,
    reader: &mut AuxReader<'_>,
) -> buzz_db::Result<Vec<buzz_core::StoredEvent>> {
    query.limit = Some(page_limit);
    let mut events = Vec::new();
    for _ in 0..AUX_MAX_PAGES {
        let page = reader.fetch(&query).await?;
        let next = if page.len() as i64 >= page_limit {
            page.last().map(|se| (se.event.created_at, se.event.id))
        } else {
            None
        };
        events.extend(page);
        let Some((created_at, id)) = next else {
            return Ok(events);
        };
        query.until = chrono::DateTime::from_timestamp(created_at.as_secs() as i64, 0);
        query.before_id = Some(id.to_bytes().to_vec());
    }
    tracing::warn!(
        pages = AUX_MAX_PAGES,
        events = events.len(),
        "aux closure hop exceeded page cap; returning truncated closure"
    );
    Ok(events)
}

/// Serve one `top_level: true` channel-window filter on the bridge `/query`
/// path (docs/bridge-channel-window.md). Appends, in order: row events, the
/// aux closure (`include_aux`), `39005` thread-summary overlays
/// (`include_summaries`), and exactly one `39006` window-bounds overlay.
///
/// Validation errors (missing `#h`, half a cursor) are deterministic client
/// mistakes and return `400`; an inaccessible channel is an access-scope skip
/// that still emits nothing, matching every other read path here.
async fn handle_channel_window_filter(
    state: &AppState,
    tenant: &buzz_core::TenantContext,
    raw: &Value,
    filter: &nostr::Filter,
    accessible_channels: &[uuid::Uuid],
    events: &mut Vec<Value>,
) -> Result<(), (StatusCode, Json<Value>)> {
    use buzz_core::kind::{KIND_THREAD_SUMMARY, KIND_WINDOW_BOUNDS};

    let Some(ch_id) = extract_channel_from_filter(filter) else {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "top_level requires exactly one #h channel",
        ));
    };
    if !accessible_channels.contains(&ch_id) {
        return Ok(());
    }

    // Composite request cursor: `until` + `before_id`, both or neither. The
    // window path has no timestamp-only fallback — that ambiguity is the
    // dense-second dup/loss bug this surface exists to kill. A malformed
    // `before_id` is likewise rejected outright (NIP-CW cursor grammar),
    // never demoted to a half cursor or a head request.
    let before_id = match extract_before_id(raw) {
        BeforeId::Malformed => {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                "top_level: before_id must be a 64-hex event id",
            ));
        }
        BeforeId::Valid(id) => Some(id),
        BeforeId::Absent => None,
    };
    let cursor = match (filter.until, before_id) {
        (Some(ts), Some(id)) => {
            let ts = chrono::DateTime::from_timestamp(ts.as_secs() as i64, 0).ok_or_else(|| {
                api_error(StatusCode::BAD_REQUEST, "top_level: until is out of range")
            })?;
            Some((ts, id))
        }
        (None, None) => None,
        _ => {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                "top_level cursor requires both until and before_id, or neither",
            ));
        }
    };

    let limit = filter
        .limit
        .map(|l| (l as u32).min(BRIDGE_WINDOW_MAX_LIMIT))
        .unwrap_or(BRIDGE_WINDOW_DEFAULT_LIMIT)
        .max(1);
    let kind_filter: Option<Vec<u32>> = filter
        .kinds
        .as_ref()
        .map(|ks| ks.iter().map(|k| k.as_u16() as u32).collect());

    let (window, mut session) = state
        .db
        .get_channel_window_with_session(
            tenant.community(),
            ch_id,
            limit,
            cursor.clone(),
            kind_filter.as_deref(),
        )
        .await
        .map_err(|e| internal_error(&format!("channel window error: {e}")))?;

    // 1. Rows, in keyset order.
    let mut row_ids_hex = Vec::with_capacity(window.rows.len());
    for row in &window.rows {
        row_ids_hex.push(row.stored_event.event.id.to_hex());
        let v = serde_json::to_value(&row.stored_event.event)
            .map_err(|e| internal_error(&format!("window row serialize: {e}")))?;
        events.push(v);
    }

    // 2. Aux closure: reactions/deletions/edits targeting retained rows, plus
    //    deletions targeting those aux events (the transitive second hop).
    //    One round trip for the client instead of an #e fan-out. Runs in the
    //    SAME request transaction that served the window: when the page came
    //    from a proved replica session, the heartbeat observation anchored a
    //    REPEATABLE READ snapshot, so the aux hops see exactly the state the
    //    proof covered — another pooled session (or even another autocommit
    //    statement) could sit at a different replay position.
    if extension_flag(raw, "include_aux") && !row_ids_hex.is_empty() {
        let mut seen_aux: std::collections::HashSet<nostr::EventId> =
            std::collections::HashSet::new();
        let mut hop_ids = row_ids_hex.clone();
        for hop_kinds in [&WINDOW_AUX_KINDS[..], &WINDOW_AUX_DELETE_KINDS[..]] {
            let aux_query =
                build_aux_query(tenant.community(), std::mem::take(&mut hop_ids), hop_kinds);
            let aux_events = query_all_pages(
                aux_query,
                AUX_PAGE_LIMIT,
                &mut AuxReader::Session(&mut session),
            )
            .await
            .map_err(|e| internal_error(&format!("window aux error: {e}")))?;
            for se in aux_events {
                if !seen_aux.insert(se.event.id) {
                    continue;
                }
                // Deletions can be stored channel-less; access-check instead
                // of channel-constraining so they aren't silently dropped.
                if !event_in_accessible_channel(&se, accessible_channels) {
                    continue;
                }
                hop_ids.push(se.event.id.to_hex());
                let v = serde_json::to_value(&se.event)
                    .map_err(|e| internal_error(&format!("window aux serialize: {e}")))?;
                events.push(v);
            }
            if hop_ids.is_empty() {
                break;
            }
        }
    }

    let sign_overlay = |kind: u32, tags: Vec<nostr::Tag>, content: String| {
        nostr::EventBuilder::new(nostr::Kind::Custom(kind as u16), content)
            .tags(tags)
            .sign_with_keys(&state.relay_keypair)
            .map_err(|e| internal_error(&format!("window overlay sign: {e}")))
    };
    let parse_tag = |parts: [&str; 2]| {
        nostr::Tag::parse(parts).map_err(|e| internal_error(&format!("window overlay tag: {e}")))
    };
    let ch_hex = ch_id.to_string();

    // 3. Thread-summary overlays: one relay-signed 39005 per row with replies.
    if extension_flag(raw, "include_summaries") {
        for row in &window.rows {
            let Some(summary) = &row.thread_summary else {
                continue;
            };
            let root_hex = row.stored_event.event.id.to_hex();
            let content = serde_json::json!({
                "reply_count": summary.reply_count,
                "descendant_count": summary.descendant_count,
                "last_reply_at": summary.last_reply_at.map(|t| t.timestamp()),
                "participants": summary.participants.iter().map(hex::encode).collect::<Vec<_>>(),
            });
            let tags = vec![
                parse_tag(["e", &root_hex])?,
                parse_tag(["d", &root_hex])?,
                parse_tag(["h", &ch_hex])?,
            ];
            let overlay = sign_overlay(KIND_THREAD_SUMMARY, tags, content.to_string())?;
            let v = serde_json::to_value(&overlay)
                .map_err(|e| internal_error(&format!("window overlay serialize: {e}")))?;
            events.push(v);
        }
    }

    // 4. Window bounds: exactly one 39006 per window response — the only
    //    authority on exhaustion. `rows < limit` proves nothing on an
    //    exact-multiple final page.
    let cursor_suffix = match &cursor {
        Some((ts, id)) => format!("{}:{}", ts.timestamp(), hex::encode(id)),
        None => "head".to_owned(),
    };
    let d_val = format!("{ch_hex}:{cursor_suffix}");
    let content = serde_json::json!({
        "has_more": window.has_more,
        "next_cursor": window.next_cursor.as_ref().map(|(ts, id)| serde_json::json!({
            "created_at": ts.timestamp(),
            "id": hex::encode(id),
        })),
    });
    let tags = vec![parse_tag(["d", &d_val])?, parse_tag(["h", &ch_hex])?];
    let overlay = sign_overlay(KIND_WINDOW_BOUNDS, tags, content.to_string())?;
    let v = serde_json::to_value(&overlay)
        .map_err(|e| internal_error(&format!("window overlay serialize: {e}")))?;
    events.push(v);

    Ok(())
}

fn event_in_accessible_channel(se: &buzz_core::StoredEvent, accessible: &[uuid::Uuid]) -> bool {
    match se.channel_id {
        Some(ch_id) => accessible.contains(&ch_id),
        None => true,
    }
}

/// Hard cap on the `reason` field logged for a rejected `/events` request.
///
/// The reject message can embed event-controlled content (e.g. a submitted
/// channel's `visibility`/`channel_type` tag values, or a raw tag pubkey) —
/// attacker-controlled text that must never reach Datadog unbounded.
const REJECT_REASON_MAX_BYTES: usize = 256;

/// Truncate `s` to at most `max_bytes`, cutting at the nearest UTF-8 character
/// boundary so a multi-byte codepoint straddling the cutoff is never split.
/// Bounds attacker-controlled text before it enters a structured log line —
/// the line's size must stay bounded regardless of the triggering input size.
fn truncate_reason(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[derive(Debug)]
enum KeyedHandlerError {
    InvalidHeader((StatusCode, Json<Value>)),
}

fn keyed_handler_error_response(error: KeyedHandlerError) -> Response {
    match error {
        KeyedHandlerError::InvalidHeader(response) => response.into_response(),
    }
}

#[derive(Debug)]
enum KeyedPreIngestError {
    Attempt(crate::admission::AdmissionError),
    Replay((StatusCode, Json<Value>)),
}

/// Process-global fail-fast cap on concurrent keyed POST /events after NIP-98
/// and before Redis attempt admission. Distinct from keyed ingress. Never queues.
const KEYED_PRE_ATTEMPT_GLOBAL_MAX: usize = 32;
/// Per-bound-community share of pre-attempt capacity. Strictly below global and
/// at most half of global so one community cannot occupy every slot.
const KEYED_PRE_ATTEMPT_COMMUNITY_MAX: usize = 16;
/// Physical bound on registry entries, including dead `Weak` generations
/// waiting for the cleanup thread. Vacant inserts fail closed at this cap.
const KEYED_PRE_ATTEMPT_REGISTRY_MAX: usize = 64;
/// Cleanup-thread `park_timeout` fallback so dead weaks are still reaped if a
/// Drop `unpark` is lost. Not used on Tokio request workers.
const KEYED_PRE_ATTEMPT_REAPER_PARK_TIMEOUT: Duration = Duration::from_secs(1);

const _: () = {
    assert!(KEYED_PRE_ATTEMPT_COMMUNITY_MAX > 0);
    assert!(KEYED_PRE_ATTEMPT_COMMUNITY_MAX < KEYED_PRE_ATTEMPT_GLOBAL_MAX);
    assert!(KEYED_PRE_ATTEMPT_COMMUNITY_MAX * 2 <= KEYED_PRE_ATTEMPT_GLOBAL_MAX);
    assert!(KEYED_PRE_ATTEMPT_GLOBAL_MAX == 32);
    assert!(KEYED_PRE_ATTEMPT_COMMUNITY_MAX == 16);
    assert!(KEYED_PRE_ATTEMPT_REGISTRY_MAX >= KEYED_PRE_ATTEMPT_GLOBAL_MAX);
    assert!(KEYED_PRE_ATTEMPT_REGISTRY_MAX == 64);
};

/// One registry generation. The weak keeps the map entry after the last permit
/// drops; `generation` identifies the slot so stale reclaim cannot remove a
/// replacement for the same UUID.
struct KeyedPreAttemptEntry {
    semaphore: Weak<Semaphore>,
    generation: u64,
}

/// Injectable process-global semaphore plus per-community weak slots.
/// Production uses the static pool; tests pass a local instance.
struct KeyedPreAttemptCapacity {
    global: Semaphore,
    registry: DashMap<Uuid, KeyedPreAttemptEntry>,
    live_entries: AtomicUsize,
    reaper: OnceLock<Thread>,
}

impl KeyedPreAttemptCapacity {
    fn new() -> Self {
        Self {
            global: Semaphore::new(KEYED_PRE_ATTEMPT_GLOBAL_MAX),
            registry: DashMap::new(),
            live_entries: AtomicUsize::new(0),
            reaper: OnceLock::new(),
        }
    }

    fn unpark_reaper(&self) {
        if let Some(thread) = self.reaper.get() {
            thread.unpark();
        }
    }

    /// Fail-fast community semaphore checkout. Shard contention, a full
    /// registry bound, and a closed semaphore return `Err` without touching
    /// global capacity. Occupied dead weaks are replaced in place with a new
    /// generation; the bound counter is unchanged for that replacement.
    fn try_checkout_community_semaphore(
        &self,
        community: Uuid,
    ) -> Result<(Arc<Semaphore>, u64), ()> {
        let Some(entry) = self.registry.try_entry(community) else {
            return Err(());
        };
        match entry {
            DashMapEntry::Occupied(mut occupied) => {
                if let Some(sem) = occupied.get().semaphore.upgrade() {
                    Ok((sem, occupied.get().generation))
                } else {
                    let generation = occupied.get().generation.wrapping_add(1);
                    let sem = Arc::new(Semaphore::new(KEYED_PRE_ATTEMPT_COMMUNITY_MAX));
                    occupied.insert(KeyedPreAttemptEntry {
                        semaphore: Arc::downgrade(&sem),
                        generation,
                    });
                    Ok((sem, generation))
                }
            }
            DashMapEntry::Vacant(vacant) => {
                if !reserve_keyed_pre_attempt_registry_slot(self) {
                    return Err(());
                }
                let sem = Arc::new(Semaphore::new(KEYED_PRE_ATTEMPT_COMMUNITY_MAX));
                vacant.insert(KeyedPreAttemptEntry {
                    semaphore: Arc::downgrade(&sem),
                    generation: 1,
                });
                Ok((sem, 1))
            }
        }
    }

    #[cfg(test)]
    fn global_available(&self) -> usize {
        self.global.available_permits()
    }

    #[cfg(test)]
    fn community_count(&self, community: Uuid) -> Option<usize> {
        self.registry.get(&community).and_then(|entry| {
            entry
                .semaphore
                .upgrade()
                .map(|sem| KEYED_PRE_ATTEMPT_COMMUNITY_MAX - sem.available_permits())
        })
    }

    #[cfg(test)]
    fn community_live_handles(&self, community: Uuid) -> Option<usize> {
        self.community_count(community)
    }

    #[cfg(test)]
    fn registry_len(&self) -> usize {
        self.registry.len()
    }

    #[cfg(test)]
    fn registry_bound(&self) -> usize {
        self.live_entries.load(Ordering::Acquire)
    }

    #[cfg(test)]
    fn registry_contains(&self, community: Uuid) -> bool {
        self.registry.contains_key(&community)
    }

    #[cfg(test)]
    fn community_generation(&self, community: Uuid) -> Option<u64> {
        self.registry.get(&community).map(|entry| entry.generation)
    }

    #[cfg(test)]
    fn community_live_generation(&self, community: Uuid) -> Option<u64> {
        self.registry
            .get(&community)
            .and_then(|entry| entry.semaphore.upgrade().map(|_| entry.generation))
    }

    /// Hold this community's registry shard with the same `try_entry` production
    /// acquire uses. Vacant holds do not insert. Same-thread nested `try_entry`
    /// on this shard returns `None`.
    #[cfg(test)]
    fn try_hold_registry(&self, community: Uuid) -> Option<KeyedPreAttemptRegistryHold<'_>> {
        self.registry
            .try_entry(community)
            .map(|entry| KeyedPreAttemptRegistryHold { _entry: entry })
    }
}

impl Drop for KeyedPreAttemptCapacity {
    fn drop(&mut self) {
        self.unpark_reaper();
    }
}

/// Test-only occupancy of one DashMap shard write lock.
#[cfg(test)]
struct KeyedPreAttemptRegistryHold<'a> {
    _entry: DashMapEntry<'a, Uuid, KeyedPreAttemptEntry>,
}

/// Fail-fast RAII process-global 32 + per-bound-community 16 pre-attempt
/// capacity. Distinct from [`KeyedIngressGuard`]. Drop releases the community
/// permit, then the global permit, then unparks the cleanup thread. Drop does
/// not park, spawn, or take a registry lock.
struct KeyedPreAttemptGuard<'a> {
    community_permit: Option<OwnedSemaphorePermit>,
    global: Option<SemaphorePermit<'a>>,
    capacity: &'a KeyedPreAttemptCapacity,
}

impl Drop for KeyedPreAttemptGuard<'_> {
    fn drop(&mut self) {
        drop(self.community_permit.take());
        drop(self.global.take());
        self.capacity.unpark_reaper();
    }
}

fn reserve_keyed_pre_attempt_registry_slot(capacity: &KeyedPreAttemptCapacity) -> bool {
    let prev = capacity.live_entries.fetch_add(1, Ordering::AcqRel);
    if prev >= KEYED_PRE_ATTEMPT_REGISTRY_MAX {
        capacity.live_entries.fetch_sub(1, Ordering::AcqRel);
        return false;
    }
    true
}

fn release_keyed_pre_attempt_registry_slots(capacity: &KeyedPreAttemptCapacity, n: usize) {
    if n == 0 {
        return;
    }
    let mut current = capacity.live_entries.load(Ordering::Acquire);
    loop {
        let next = current.saturating_sub(n);
        match capacity.live_entries.compare_exchange_weak(
            current,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return,
            Err(actual) => current = actual,
        }
    }
}

/// Remove `community` only when it still stores `expected` and that generation
/// is dead. A newer generation for the same UUID is left untouched.
fn reclaim_dead_keyed_pre_attempt_generation(
    capacity: &KeyedPreAttemptCapacity,
    community: Uuid,
    expected: u64,
) {
    let Some(entry) = capacity.registry.try_entry(community) else {
        return;
    };
    let DashMapEntry::Occupied(occupied) = entry else {
        return;
    };
    if occupied.get().generation != expected {
        return;
    }
    if occupied.get().semaphore.upgrade().is_some() {
        return;
    }
    occupied.remove();
    release_keyed_pre_attempt_registry_slots(capacity, 1);
}

/// Blocking retention of dead weak entries. Runs on the dedicated cleanup
/// thread, and from tests that observe reaper completion. Never called from
/// Drop or from a request-worker acquire path.
fn reap_dead_keyed_pre_attempt_entries(capacity: &KeyedPreAttemptCapacity) {
    let removed = AtomicUsize::new(0);
    capacity.registry.retain(|_, entry| {
        if entry.semaphore.upgrade().is_some() {
            true
        } else {
            removed.fetch_add(1, Ordering::Relaxed);
            false
        }
    });
    release_keyed_pre_attempt_registry_slots(capacity, removed.load(Ordering::Relaxed));
}

fn keyed_pre_attempt_reaper_loop(capacity: Weak<KeyedPreAttemptCapacity>) {
    loop {
        thread::park_timeout(KEYED_PRE_ATTEMPT_REAPER_PARK_TIMEOUT);
        let Some(capacity) = capacity.upgrade() else {
            return;
        };
        reap_dead_keyed_pre_attempt_entries(&capacity);
    }
}

fn try_init_keyed_pre_attempt_capacity() -> Result<Arc<KeyedPreAttemptCapacity>, ()> {
    let capacity = Arc::new(KeyedPreAttemptCapacity::new());
    let worker = Arc::downgrade(&capacity);
    let join = thread::Builder::new()
        .name("buzz-keyed-pre-attempt-reaper".into())
        .spawn(move || keyed_pre_attempt_reaper_loop(worker))
        .map_err(|_| ())?;
    if capacity.reaper.set(join.thread().clone()).is_err() {
        join.thread().unpark();
        return Err(());
    }
    Ok(capacity)
}

fn keyed_pre_attempt_capacity() -> Result<&'static KeyedPreAttemptCapacity, ()> {
    static CAP: OnceLock<Result<Arc<KeyedPreAttemptCapacity>, ()>> = OnceLock::new();
    match CAP.get_or_init(try_init_keyed_pre_attempt_capacity) {
        Ok(capacity) => Ok(capacity.as_ref()),
        Err(()) => Err(()),
    }
}

/// Reserve per-community eligibility before consuming global capacity.
/// Over-cap community contenders, registry-shard contention, and a full
/// registry bound fail closed without queueing, parking, or taking a global
/// slot. Global exhaustion rolls back the community reservation exactly once.
fn try_acquire_keyed_pre_attempt_from<'a>(
    capacity: &'a KeyedPreAttemptCapacity,
    community: Uuid,
) -> Result<KeyedPreAttemptGuard<'a>, ()> {
    let (sem, generation) = capacity.try_checkout_community_semaphore(community)?;
    let community_permit = match sem.try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            reclaim_dead_keyed_pre_attempt_generation(capacity, community, generation);
            capacity.unpark_reaper();
            return Err(());
        }
    };
    match capacity.global.try_acquire() {
        Ok(global) => Ok(KeyedPreAttemptGuard {
            community_permit: Some(community_permit),
            global: Some(global),
            capacity,
        }),
        Err(_) => {
            drop(community_permit);
            reclaim_dead_keyed_pre_attempt_generation(capacity, community, generation);
            capacity.unpark_reaper();
            Err(())
        }
    }
}

fn try_acquire_keyed_pre_attempt(community: Uuid) -> Result<KeyedPreAttemptGuard<'static>, ()> {
    try_acquire_keyed_pre_attempt_from(keyed_pre_attempt_capacity()?, community)
}

/// Ingress is already held. Drop the pre-attempt guard only after that acquire
/// so there is no uncovered phase between the two.
fn handoff_keyed_pre_attempt_to_ingress(
    ingress: KeyedIngressGuard,
    pre_attempt: KeyedPreAttemptGuard<'_>,
) -> KeyedIngressGuard {
    drop(pre_attempt);
    ingress
}

/// Authenticated keyed attempt charge. Invoke exactly once after NIP-98
/// authentication and pre-attempt capacity, before local ingress or replay.
async fn admit_keyed_http_attempt<L: RateLimiter>(
    limiter: &L,
    tenant: &TenantContext,
    pubkey: &nostr::PublicKey,
) -> Result<(), KeyedPreIngestError> {
    crate::admission::check_keyed_http_attempt_admission(limiter, tenant, pubkey)
        .await
        .map_err(KeyedPreIngestError::Attempt)
}

/// Production keyed POST /events post-auth errors through body validation.
/// Fresh and persist admission run later, after committed classification.
#[derive(Debug)]
enum KeyedHttpAdmitError {
    PreIngest(KeyedPreIngestError),
    Parse(serde_json::Error),
    Membership((StatusCode, Json<Value>)),
    Body { kind: u32, error: IngestError },
}

/// Verified owner carried as metadata through classification. Identity
/// admission uses the authenticated signer, not this owner.
///
/// Closed-relay membership already returns a cryptographically verified owner
/// (`ViaOwner`). Open relays supply [`super::relay_members::extract_nip_oa_owner`],
/// which itself returns `None` for absent or invalid tags. An attacker-chosen
/// owner string never enters this function unverified.
fn keyed_http_verified_owner(
    membership_owner: Option<nostr::PublicKey>,
    open_relay_extracted_owner: Option<nostr::PublicKey>,
) -> Option<nostr::PublicKey> {
    membership_owner.or(open_relay_extracted_owner)
}

fn keyed_http_nip98_auth(pubkey: nostr::PublicKey) -> IngestAuth {
    IngestAuth::Http {
        pubkey,
        scopes: buzz_auth::Scope::all_known(),
        auth_method: crate::handlers::ingest::HttpAuthMethod::Nip98,
    }
}

/// Request-local tenant, pubkey, NIP-98 event id, and body.
struct KeyedHttpAdmitRequest<'req> {
    tenant: &'req TenantContext,
    pubkey: nostr::PublicKey,
    event_id_bytes: [u8; 32],
    body: &'req [u8],
    signed_created_at: Option<u64>,
}

async fn keyed_deadline_io<T, F>(
    deadline: KeyedEarlyDeadline,
    fut: F,
) -> Result<T, KeyedPreIngestError>
where
    F: Future<Output = T>,
{
    let remaining = deadline.remaining();
    if remaining.is_zero() {
        return Err(KeyedPreIngestError::Attempt(
            crate::admission::AdmissionError::Unavailable,
        ));
    }
    match tokio::time::timeout(remaining, fut).await {
        Ok(value) => Ok(value),
        Err(_elapsed) => Err(KeyedPreIngestError::Attempt(
            crate::admission::AdmissionError::Unavailable,
        )),
    }
}

/// Production keyed POST /events post-attempt orchestration.
///
/// Attempt admission and ingress acquisition happen before this helper.
/// Order here: NIP-98 replay → JSON parse → event signature and
/// authenticated-author binding → relay membership → cryptographically
/// verified owner metadata → supported-kind/body/`p` cap. Replay and
/// membership consume the remaining absolute early deadline. Signature
/// verification runs in `spawn_blocking` that owns this request's
/// [`KeyedHttpEarlyContext`], so a timeout cannot release ingress while CPU
/// work continues. Fresh and persist admission stay with keyed ingest after
/// committed classification. The returned [`KeyedHttpValidatedEvent`] is the
/// only input the keyed ingest seam accepts. The same early context is
/// returned for ingest; it is not reconstructed.
///
/// `open_relay_auth_tag` may return a request-local raw NIP-OA auth tag only
/// when open-relay extraction is applicable. A closed-relay caller must
/// return `None` so this seam cannot acquire an owner from the header. The
/// tag is verified here with [`super::relay_members::extract_nip_oa_owner`]
/// against the authenticated agent; a pre-extracted owner cannot be injected.
async fn admit_keyed_http_after_attempt<'req, 'tag, Mem, MemFut, Tag>(
    replay_guard: &dyn Nip98ReplayGuard,
    request: KeyedHttpAdmitRequest<'req>,
    membership: Mem,
    open_relay_auth_tag: Tag,
    early: KeyedHttpEarlyContext,
) -> Result<(KeyedHttpValidatedEvent, KeyedHttpEarlyContext), KeyedHttpAdmitError>
where
    Mem: FnOnce() -> MemFut + 'req,
    MemFut:
        Future<Output = Result<Option<nostr::PublicKey>, (StatusCode, Json<Value>)>> + Send + 'req,
    Tag: FnOnce() -> Option<&'tag str> + 'req,
{
    let KeyedHttpAdmitRequest {
        tenant,
        pubkey,
        event_id_bytes,
        body,
        signed_created_at,
    } = request;
    let deadline = early.deadline;
    match keyed_deadline_io(
        deadline,
        check_nip98_replay_with_guard(replay_guard, tenant, event_id_bytes),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(response)) => {
            return Err(KeyedHttpAdmitError::PreIngest(KeyedPreIngestError::Replay(
                response,
            )));
        }
        Err(error) => return Err(KeyedHttpAdmitError::PreIngest(error)),
    }
    let event: nostr::Event = serde_json::from_slice(body).map_err(KeyedHttpAdmitError::Parse)?;
    let auth = keyed_http_nip98_auth(pubkey);
    let kind = buzz_core::kind::event_kind_u32(&event);
    // Blocking verification owns `early` (ingress included). Do not wrap this
    // join in `timeout`/`select!` — dropping that JoinHandle while the request
    // still owned the guard would release permits during CPU work. An
    // already-expired deadline fails closed before verification starts.
    if early.deadline.expired() {
        return Err(KeyedHttpAdmitError::PreIngest(
            KeyedPreIngestError::Attempt(crate::admission::AdmissionError::Unavailable),
        ));
    }
    let (signed, mut early) =
        KeyedHttpValidatedEvent::verify_signature_and_author_with_early(event, auth, early)
            .await
            .map_err(|error| KeyedHttpAdmitError::Body { kind, error })?;
    let membership_owner = match keyed_deadline_io(deadline, membership()).await {
        Ok(Ok(owner)) => owner,
        Ok(Err(response)) => return Err(KeyedHttpAdmitError::Membership(response)),
        Err(error) => return Err(KeyedHttpAdmitError::PreIngest(error)),
    };
    let agent_bytes = pubkey.to_bytes();
    early.verified_owner = keyed_http_verified_owner(
        membership_owner,
        super::relay_members::extract_nip_oa_owner(
            &agent_bytes,
            open_relay_auth_tag(),
            signed_created_at,
        ),
    );
    let validated = KeyedHttpValidatedEvent::finish_after_owner(signed)
        .map_err(|error| KeyedHttpAdmitError::Body { kind, error })?;
    Ok((validated, early))
}

fn json_parse_submit_outcome(e: serde_json::Error) -> SubmitOutcome {
    // Never log `e`'s Display string: serde_json embeds the offending
    // input verbatim in its error message, so a malformed field of
    // arbitrary size (the router allows 1 MiB bodies) would otherwise
    // reflect attacker-controlled text into a log line at full size.
    // `category`/`line`/`column` are bounded, structured, and still
    // enough to tell "which parse failure" apart at a glance.
    crate::handlers::ingest::reject_with_transport("http", "invalid");
    SubmitOutcome::ParseFail {
        category: match e.classify() {
            serde_json::error::Category::Io => "io",
            serde_json::error::Category::Syntax => "syntax",
            serde_json::error::Category::Data => "data",
            serde_json::error::Category::Eof => "eof",
        },
        line: e.line(),
        column: e.column(),
        response: api_error(StatusCode::BAD_REQUEST, &format!("invalid event JSON: {e}")),
    }
}

fn ingest_error_to_submit_outcome(kind_u32: u32, error: IngestError) -> SubmitOutcome {
    match error {
        IngestError::Rejected(msg) => {
            // `msg` can embed event-controlled content (e.g. a channel
            // create's raw `visibility`/`channel_type` tag values, or a raw
            // tag pubkey) — truncate before logging, but return the full msg
            // in the HTTP response body (unchanged from prior behaviour).
            let reason = truncate_reason(&msg, REJECT_REASON_MAX_BYTES).to_owned();
            crate::handlers::ingest::reject_with_transport("http", "invalid");
            SubmitOutcome::Rejected {
                kind: kind_u32,
                reason,
                response: api_error(StatusCode::BAD_REQUEST, &msg),
            }
        }
        IngestError::AuthFailed(msg) => {
            crate::handlers::ingest::reject_with_transport("http", "auth");
            let e = api_error(StatusCode::FORBIDDEN, &msg);
            SubmitOutcome::Err {
                status: e.0,
                response: e,
            }
        }
        IngestError::Internal(msg) => {
            crate::handlers::ingest::reject_with_transport("http", "error");
            let e = internal_error(&msg);
            SubmitOutcome::Err {
                status: e.0,
                response: e,
            }
        }
    }
}

fn keyed_admit_outcome(error: KeyedHttpAdmitError) -> SubmitOutcome {
    match error {
        KeyedHttpAdmitError::PreIngest(error) => keyed_pre_ingest_outcome(error),
        KeyedHttpAdmitError::Parse(error) => json_parse_submit_outcome(error),
        KeyedHttpAdmitError::Membership(e) => SubmitOutcome::Err {
            status: e.0,
            response: e,
        },
        KeyedHttpAdmitError::Body { kind, error } => ingest_error_to_submit_outcome(kind, error),
    }
}

fn keyed_pre_ingest_outcome(error: KeyedPreIngestError) -> SubmitOutcome {
    match error {
        KeyedPreIngestError::Attempt(error) => {
            let retry_after_secs = match error {
                crate::admission::AdmissionError::Exceeded { reset_in_secs } => reset_in_secs,
                crate::admission::AdmissionError::Unavailable => KEYED_BUSY_RETRY_AFTER_SECS,
            };
            let (status, retry_after, body) = keyed_busy_http_parts(retry_after_secs);
            SubmitOutcome::Busy {
                status,
                response: (status, retry_after, body).into_response(),
            }
        }
        KeyedPreIngestError::Replay(response) => SubmitOutcome::Err {
            status: response.0,
            response,
        },
    }
}

/// Submit a signed Nostr event via HTTP bridge (NIP-98 auth).
pub async fn submit_event(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, Response> {
    let idempotency_key = match parse_idempotency_key_header(&headers) {
        Ok(key) => key,
        Err(error) => {
            return Err(keyed_handler_error_response(
                KeyedHandlerError::InvalidHeader(error),
            ));
        }
    };
    // Row zero: bind this HTTP request to its community from the request host
    // before any tenant-scoped write, identical to the WS door in `router.rs`.
    // Unmapped host or lookup failure fails closed with a generic 404 — never a
    // default tenant, never echoing the host. Keyed pre-attempt capacity is not
    // acquired until this bind and NIP-98 verification both succeed, and only
    // for a present Idempotency-Key.
    let raw_host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let tenant = crate::tenant::bind_community(&state.db, raw_host)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::NOT_FOUND,
                "relay: no community is configured for this host",
            )
            .into_response()
        })?;

    let url = nip98_expected_url(&state.config.relay_url, &tenant, "/events");
    let VerifiedBridgeAuth {
        pubkey,
        event_id_bytes,
        signed_created_at,
    } = verify_bridge_auth(
        &headers,
        "POST",
        &url,
        Some(&body),
        state.config.require_auth_token || idempotency_key.is_some(),
    )
    .map_err(IntoResponse::into_response)?;
    let pubkey_hex = pubkey.to_hex();

    let mut early = None;
    if idempotency_key.is_some() {
        // After NIP-98, before KeyedEarlyDeadline and Redis attempt admission.
        // Fail-fast process-global 32 and per-bound-community 16; never queues.
        let pre_attempt = match try_acquire_keyed_pre_attempt(*tenant.community().as_uuid()) {
            Ok(permit) => permit,
            Err(()) => {
                let (status, retry_after, body) =
                    keyed_busy_http_parts(KEYED_BUSY_RETRY_AFTER_SECS);
                return Err((status, retry_after, body).into_response());
            }
        };
        let deadline = KeyedEarlyDeadline::start();
        if deadline.expired() {
            let (status, retry_after, body) = keyed_busy_http_parts(KEYED_BUSY_RETRY_AFTER_SECS);
            return Err((status, retry_after, body).into_response());
        }
        match tokio::time::timeout(
            deadline.remaining(),
            admit_keyed_http_attempt(state.admission_rate_limiter.as_ref(), &tenant, &pubkey),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                return Err(match keyed_pre_ingest_outcome(error).into_response() {
                    Ok(json) => json.into_response(),
                    Err(response) => *response,
                });
            }
            Err(_elapsed) => {
                let (status, retry_after, body) =
                    keyed_busy_http_parts(KEYED_BUSY_RETRY_AFTER_SECS);
                return Err((status, retry_after, body).into_response());
            }
        }
        let ingress = match try_acquire_keyed_ingress(*tenant.community().as_uuid()) {
            Ok(guard) => guard,
            Err(KeyedHttpError::Busy { retry_after_secs }) => {
                let (status, retry_after, body) = keyed_busy_http_parts(retry_after_secs);
                return Err((status, retry_after, body).into_response());
            }
            Err(_) => {
                let (status, retry_after, body) =
                    keyed_busy_http_parts(KEYED_BUSY_RETRY_AFTER_SECS);
                return Err((status, retry_after, body).into_response());
            }
        };
        let ingress = handoff_keyed_pre_attempt_to_ingress(ingress, pre_attempt);
        early = Some(KeyedHttpEarlyContext {
            ingress: Some(ingress),
            deadline,
            verified_owner: None,
        });
    }

    // Everything after auth — admission, replay, membership, parse, ingest —
    // runs inside the helper.  The thin wrapper here owns the single terminal
    // attribution line so it fires for every outcome, including admission/
    // replay/membership failures that previously returned before any log fired.
    let outcome = submit_event_authed(
        &state,
        &tenant,
        &headers,
        &body,
        pubkey,
        event_id_bytes,
        signed_created_at,
        SubmitEventKeyedContext {
            idempotency_key,
            early,
        },
    )
    .await;

    match &outcome {
        SubmitOutcome::Ok { accepted, kind, .. } => {
            tracing::info!(
                pubkey = %pubkey_hex,
                route = "/events",
                status = 200u16,
                accepted,
                kind,
                "HTTP bridge request"
            );
        }
        SubmitOutcome::ParseFail {
            category,
            line,
            column,
            ..
        } => {
            tracing::warn!(
                pubkey = %pubkey_hex,
                route = "/events",
                status = 400u16,
                accepted = false,
                category,
                line,
                column,
                "HTTP bridge request"
            );
        }
        SubmitOutcome::Rejected { kind, reason, .. } => {
            tracing::warn!(
                pubkey = %pubkey_hex,
                route = "/events",
                status = 400u16,
                accepted = false,
                kind,
                reason = %reason,
                "HTTP bridge request"
            );
        }
        SubmitOutcome::Err { status, .. } => {
            tracing::warn!(
                pubkey = %pubkey_hex,
                route = "/events",
                status = status.as_u16(),
                accepted = false,
                "HTTP bridge request"
            );
        }
        SubmitOutcome::Busy { status, .. } => {
            tracing::warn!(
                pubkey = %pubkey_hex,
                route = "/events",
                status = status.as_u16(),
                accepted = false,
                "HTTP bridge request"
            );
        }
    }

    outcome.into_response().map_err(|response| *response)
}

fn parse_idempotency_key_header(
    headers: &HeaderMap,
) -> Result<Option<[u8; 32]>, (StatusCode, Json<Value>)> {
    let values: Vec<_> = headers
        .get_all(buzz_core::idempotency::HEADER_NAME)
        .iter()
        .collect();
    if values.is_empty() {
        return Ok(None);
    }
    if values.len() != 1 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "invalid: Idempotency-Key",
        ));
    }
    let Ok(raw) = values[0].to_str() else {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "invalid: Idempotency-Key",
        ));
    };
    if raw.contains(',') {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "invalid: Idempotency-Key",
        ));
    }
    buzz_core::idempotency::parse_idempotency_key(raw)
        .map(Some)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid: Idempotency-Key"))
}

/// Keyed HTTP 503 for writer busy, reservation-capacity exhaustion, and
/// open-reservation admission/persist timeout. `Retry-After` stays bounded.
fn keyed_busy_http_parts(
    retry_after_secs: u64,
) -> (StatusCode, [(header::HeaderName, String); 1], Json<Value>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::RETRY_AFTER, retry_after_secs.to_string())],
        Json(serde_json::json!({"error": "idempotency unavailable"})),
    )
}

fn keyed_conflict_http_parts() -> (StatusCode, Json<Value>) {
    api_error(StatusCode::CONFLICT, "idempotency-key conflict")
}

/// Log-context outcome for a single [`submit_event`] call.
///
/// Carries enough structured data for the terminal attribution log while also
/// holding the HTTP response so the thin wrapper can return it unchanged.
#[derive(Debug)]
enum SubmitOutcome {
    /// Ingest pipeline ran and returned a result (accepted or not).
    Ok {
        accepted: bool,
        kind: u32,
        response: Json<Value>,
    },
    /// JSON parse failure before ingest — log category/line/column, not msg.
    ParseFail {
        category: &'static str,
        line: usize,
        column: usize,
        response: (StatusCode, Json<Value>),
    },
    /// IngestError::Rejected — log kind + truncated reason.
    Rejected {
        kind: u32,
        reason: String,
        response: (StatusCode, Json<Value>),
    },
    /// Any other error (admission, replay, membership, auth, internal) —
    /// only the HTTP status is logged; the response body is returned as-is.
    Err {
        status: StatusCode,
        response: (StatusCode, Json<Value>),
    },
    /// Keyed writer busy — HTTP 503 with Retry-After.
    Busy {
        status: StatusCode,
        response: Response,
    },
}

impl SubmitOutcome {
    fn into_response(self) -> Result<Json<Value>, Box<Response>> {
        match self {
            SubmitOutcome::Ok { response, .. } => Ok(response),
            SubmitOutcome::ParseFail { response, .. } => Err(Box::new(response.into_response())),
            SubmitOutcome::Rejected { response, .. } => Err(Box::new(response.into_response())),
            SubmitOutcome::Err { response, .. } => Err(Box::new(response.into_response())),
            SubmitOutcome::Busy { response, .. } => Err(Box::new(response)),
        }
    }
}

struct SubmitEventKeyedContext {
    idempotency_key: Option<[u8; 32]>,
    early: Option<KeyedHttpEarlyContext>,
}

/// Post-auth execution for [`submit_event`]: admission, replay, membership,
/// parse, and ingest.  Returns a [`SubmitOutcome`] that carries both the log
/// fields and the HTTP response so the thin wrapper can emit exactly one
/// terminal attribution line covering every outcome.
#[allow(
    clippy::too_many_arguments,
    reason = "combines upstream signed_created_at auth metadata with Goal1 keyed context"
)]
async fn submit_event_authed(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    headers: &HeaderMap,
    body: &[u8],
    pubkey: nostr::PublicKey,
    event_id_bytes: [u8; 32],
    signed_auth_created_at: Option<u64>,
    keyed: SubmitEventKeyedContext,
) -> SubmitOutcome {
    let SubmitEventKeyedContext {
        idempotency_key,
        early,
    } = keyed;
    // Per-principal admission and NIP-98 replay fire before body parse for
    // unkeyed requests — a 429 or replay reject on a malformed body must still
    // be attributed. Keyed requests already charged attempt and hold ingress.
    // Replay, parse, membership, and body validation run here. Fresh and
    // persist admission run inside ingest only after committed classification.
    // Owner materialization waits for an accepted terminal result after early
    // permits are released.
    if let Some(key) = idempotency_key {
        let Some(early) = early else {
            return SubmitOutcome::Busy {
                status: StatusCode::SERVICE_UNAVAILABLE,
                response: {
                    let (status, retry_after, body) =
                        keyed_busy_http_parts(KEYED_BUSY_RETRY_AFTER_SECS);
                    (status, retry_after, body).into_response()
                },
            };
        };
        let deadline = early.deadline;
        if deadline.expired() {
            return keyed_pre_ingest_outcome(KeyedPreIngestError::Attempt(
                crate::admission::AdmissionError::Unavailable,
            ));
        }
        let pubkey_bytes = pubkey.to_bytes();
        let auth_tag = super::relay_members::extract_auth_tag_header(headers);
        let (validated, early) = match admit_keyed_http_after_attempt(
            state.nip98_replay.as_ref(),
            KeyedHttpAdmitRequest {
                tenant,
                pubkey,
                event_id_bytes,
                body,
                signed_created_at: signed_auth_created_at,
            },
            || {
                super::relay_members::enforce_relay_membership(
                    state,
                    tenant.community(),
                    &pubkey_bytes,
                    auth_tag,
                    signed_auth_created_at,
                )
            },
            || {
                if !state.config.require_relay_membership {
                    auth_tag
                } else {
                    None
                }
            },
            early,
        )
        .await
        {
            Ok(admitted) => admitted,
            Err(error) => return keyed_admit_outcome(error),
        };
        let kind_u32 = buzz_core::kind::event_kind_u32(validated.event());
        let ingest_result =
            match ingest_keyed_http_event(state, tenant, validated, key, early).await {
                Ok(result) => Ok(result),
                Err(KeyedHttpError::Ingest(error)) => Err(error),
                Err(KeyedHttpError::Conflict) => {
                    let response = keyed_conflict_http_parts();
                    return SubmitOutcome::Err {
                        status: response.0,
                        response,
                    };
                }
                Err(KeyedHttpError::Busy { retry_after_secs }) => {
                    let (status, retry_after, body) = keyed_busy_http_parts(retry_after_secs);
                    return SubmitOutcome::Busy {
                        status,
                        response: (status, retry_after, body).into_response(),
                    };
                }
                Err(KeyedHttpError::Principal(error)) => {
                    let response = http_admission_error_response(error);
                    return SubmitOutcome::Err {
                        status: response.0,
                        response,
                    };
                }
            };
        return match ingest_result {
            Ok(result) => SubmitOutcome::Ok {
                accepted: result.accepted,
                kind: kind_u32,
                response: Json(serde_json::json!({
                    "event_id": result.event_id,
                    "accepted": result.accepted,
                    "message": result.message,
                })),
            },
            Err(error) => ingest_error_to_submit_outcome(kind_u32, error),
        };
    }

    if let Err(e) = enforce_http_admission(state, tenant, &pubkey).await {
        return SubmitOutcome::Err {
            status: e.0,
            response: e,
        };
    }
    if let Err(e) = check_nip98_replay(state, tenant, event_id_bytes).await {
        return SubmitOutcome::Err {
            status: e.0,
            response: e,
        };
    }
    let pubkey_bytes = pubkey.to_bytes().to_vec();

    let event: nostr::Event = match serde_json::from_slice(body) {
        Ok(ev) => ev,
        Err(e) => {
            return json_parse_submit_outcome(e);
        }
    };

    // Enforce relay membership (with NIP-OA fallback via x-auth-tag header).
    let auth_tag = super::relay_members::extract_auth_tag_header(headers);
    let membership = super::relay_members::enforce_relay_membership(
        state,
        tenant.community(),
        &pubkey_bytes,
        auth_tag,
        signed_auth_created_at,
    )
    .await;
    let nip_oa_owner = match membership {
        Ok(owner) => keyed_http_verified_owner(
            owner,
            if !state.config.require_relay_membership {
                super::relay_members::extract_nip_oa_owner(
                    &pubkey_bytes,
                    auth_tag,
                    signed_auth_created_at,
                )
            } else {
                None
            },
        ),
        Err(e) => {
            return SubmitOutcome::Err {
                status: e.0,
                response: e,
            };
        }
    };
    if let Some(owner) = nip_oa_owner {
        super::relay_members::materialize_nip_oa_owner(state, tenant, &pubkey, &owner).await;
    }

    let kind_u32 = buzz_core::kind::event_kind_u32(&event);
    let auth = keyed_http_nip98_auth(pubkey);

    match crate::handlers::ingest::ingest_event(state, tenant, event, auth).await {
        Ok(result) => SubmitOutcome::Ok {
            accepted: result.accepted,
            kind: kind_u32,
            response: Json(serde_json::json!({
                "event_id": result.event_id,
                "accepted": result.accepted,
                "message": result.message,
            })),
        },
        Err(error) => ingest_error_to_submit_outcome(kind_u32, error),
    }
}

/// Query events via HTTP bridge (NIP-98 auth). Returns JSON array of events.
///
/// Enforces channel access: results are filtered to channels the user can access.
pub async fn query_events(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Row zero: bind this HTTP request to its community from the request host
    // before any tenant-scoped read, identical to the WS door in `router.rs`.
    // An unmapped host or lookup failure fails closed with a generic 404 — never
    // a default tenant, never echoing the host (so an unauthenticated caller
    // cannot probe which communities exist on this deployment).
    let raw_host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let tenant = crate::tenant::bind_community(&state.db, raw_host)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::NOT_FOUND,
                "relay: no community is configured for this host",
            )
        })?;

    let url = nip98_expected_url(&state.config.relay_url, &tenant, "/query");
    let VerifiedBridgeAuth {
        pubkey,
        event_id_bytes,
        signed_created_at,
    } = verify_bridge_auth(
        &headers,
        "POST",
        &url,
        Some(&body),
        state.config.require_auth_token,
    )?;
    let pubkey_hex = pubkey.to_hex();

    // Admission, replay, membership, and filter execution all run inside the
    // helper.  The single terminal attribution line fires here from the Result
    // so every outcome — including admission/replay/membership failures that
    // previously returned before any log — is attributed.
    let result = query_events_authed(
        &state,
        &tenant,
        &headers,
        &body,
        pubkey,
        event_id_bytes,
        signed_created_at,
    )
    .await;
    match &result {
        Ok(Json(Value::Array(events))) => {
            tracing::info!(
                pubkey = %pubkey_hex,
                route = "/query",
                status = 200u16,
                result_count = events.len(),
                "HTTP bridge request"
            );
        }
        Ok(_) => {
            tracing::info!(pubkey = %pubkey_hex, route = "/query", status = 200u16, "HTTP bridge request");
        }
        Err((status, _)) => {
            tracing::warn!(
                pubkey = %pubkey_hex,
                route = "/query",
                status = status.as_u16(),
                "HTTP bridge request"
            );
        }
    }
    result
}

/// Filter execution for [`query_events`], run once NIP-98 auth succeeds.
/// Handles admission, replay, membership, and all filter paths so the thin
/// wrapper above can emit exactly one terminal attribution line from the Result.
async fn query_events_authed(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    headers: &HeaderMap,
    body: &[u8],
    pubkey: nostr::PublicKey,
    event_id_bytes: [u8; 32],
    signed_auth_created_at: Option<u64>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    enforce_http_admission(state, tenant, &pubkey).await?;
    check_nip98_replay(state, tenant, event_id_bytes).await?;
    let pubkey_bytes = pubkey.to_bytes().to_vec();

    let auth_tag = super::relay_members::extract_auth_tag_header(headers);
    super::relay_members::enforce_relay_membership(
        state,
        tenant.community(),
        &pubkey_bytes,
        auth_tag,
        signed_auth_created_at,
    )
    .await?;

    // Two-pass parse: preserve raw JSON for custom extension fields (before_id,
    // depth_limit, feed_types) that nostr::Filter silently drops.
    let raw_filters: Vec<Value> = serde_json::from_slice(body)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &format!("invalid filters: {e}")))?;
    let filters: Vec<nostr::Filter> = raw_filters
        .iter()
        .map(|v| serde_json::from_value(v.clone()))
        .collect::<Result<_, _>>()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &format!("invalid filters: {e}")))?;
    crate::handlers::req::extract_channel_ids_from_filters_limited(&filters)
        .map_err(|()| api_error(StatusCode::BAD_REQUEST, "too many explicit channels"))?;

    // P-gated kinds (gift wraps, member notifications, observer frames) require
    // the caller's own pubkey in the #p tag — same enforcement as WS REQ handler.
    let authed_pubkey_hex = pubkey.to_hex();
    if !crate::handlers::req::p_gated_filters_authorized(&filters, &authed_pubkey_hex) {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "restricted: p-gated kinds require #p tag matching your pubkey",
        ));
    }
    if !crate::handlers::req::engram_filters_authorized(&filters, &authed_pubkey_hex) {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "restricted: agent-engram reads require authors=[self] or #p=[self]",
        ));
    }
    if !crate::handlers::req::author_only_filters_authorized(&filters, &authed_pubkey_hex) {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "restricted: author-only kinds require authors=[self]",
        ));
    }

    // Get channels this user can access — same enforcement as WS REQ handler.
    let mut accessible_channels = state
        .get_accessible_channel_ids_cached(tenant.community(), &pubkey_bytes)
        .await
        .map_err(|e| internal_error(&format!("channel access lookup: {e}")))?;
    repair_requested_channel_access(
        state,
        tenant,
        &filters,
        &pubkey_bytes,
        &mut accessible_channels,
    )
    .await?;

    if filters.iter().any(|f| f.search.is_some()) {
        if has_mixed_search_filters(&filters) {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                "mixed search and non-search filters not supported",
            ));
        }
        return handle_bridge_search(
            state,
            &raw_filters,
            &filters,
            &accessible_channels,
            tenant,
            &authed_pubkey_hex,
            &pubkey_bytes,
        )
        .await;
    }

    if let Some(presence_result) =
        synthesize_presence(&state.pubsub, &state.relay_keypair, tenant, &filters).await
    {
        return presence_result.map(|events| Json(Value::Array(events)));
    }

    let mut events: Vec<Value> = Vec::new();
    let mut handled: std::collections::HashSet<usize> = std::collections::HashSet::new();

    // Channel-window filters (`top_level: true`) — the GUI read-model surface.
    // Dispatched first: a window filter is never a feed/thread/catchall query.
    for (idx, (raw, filter)) in raw_filters.iter().zip(filters.iter()).enumerate() {
        if !extension_flag(raw, "top_level") {
            continue;
        }
        handle_channel_window_filter(
            state,
            tenant,
            raw,
            filter,
            &accessible_channels,
            &mut events,
        )
        .await?;
        handled.insert(idx);
    }

    for (idx, (raw, filter)) in raw_filters.iter().zip(filters.iter()).enumerate() {
        if handled.contains(&idx) {
            continue;
        }
        let feed_types = match extract_feed_types(raw) {
            Some(t) => t,
            None => continue,
        };

        let limit = filter
            .limit
            .map(|l| (l as i64).min(BRIDGE_FEED_MAX_LIMIT))
            .unwrap_or(20);
        let since = filter
            .since
            .and_then(|s| chrono::DateTime::from_timestamp(s.as_secs() as i64, 0));

        let mut seen_types = std::collections::HashSet::new();
        let mut seen = std::collections::HashSet::new();
        let mut feed_count = 0i64;
        for feed_type in &feed_types {
            let canonical = if feed_type == "agent_activity" {
                "activity"
            } else {
                feed_type.as_str()
            };
            if !seen_types.insert(canonical) {
                continue;
            }
            if feed_count >= limit {
                break;
            }
            let remaining = limit - feed_count;
            let type_events = match canonical {
                "mentions" => state
                    .db
                    .query_feed_mentions_routed(
                        "bridge_feed",
                        tenant.community(),
                        &pubkey_bytes,
                        &accessible_channels,
                        since,
                        remaining,
                    )
                    .await
                    .map_err(|e| internal_error(&format!("feed mentions error: {e}")))?,
                "needs_action" => state
                    .db
                    .query_feed_needs_action_routed(
                        "bridge_feed",
                        tenant.community(),
                        &pubkey_bytes,
                        &accessible_channels,
                        since,
                        remaining,
                    )
                    .await
                    .map_err(|e| internal_error(&format!("feed needs_action error: {e}")))?,
                "activity" => state
                    .db
                    .query_feed_activity_routed(
                        "bridge_feed",
                        tenant.community(),
                        &accessible_channels,
                        since,
                        remaining,
                    )
                    .await
                    .map_err(|e| internal_error(&format!("feed activity error: {e}")))?,
                _ => continue,
            };
            for se in type_events {
                if !seen.insert(se.event.id) {
                    continue;
                }
                if !event_in_accessible_channel(&se, &accessible_channels) {
                    continue;
                }
                // Defense-in-depth: never deliver a result-gated event (e.g. kind:44200
                // or kind:30622) to a non-owner via the feed path, even though feed SQL
                // kind allowlists already exclude these kinds.
                if !buzz_core::filter::reader_authorized_for_event(&se.event, &authed_pubkey_hex) {
                    continue;
                }
                if let Ok(v) = serde_json::to_value(&se.event) {
                    events.push(v);
                    feed_count += 1;
                }
            }
        }
        handled.insert(idx);
    }

    let e_tag_key = nostr::SingleLetterTag::lowercase(nostr::Alphabet::E);
    for (idx, (raw, filter)) in raw_filters.iter().zip(filters.iter()).enumerate() {
        if handled.contains(&idx) {
            continue;
        }
        let depth = match extract_depth_limit(raw) {
            Some(d) => d,
            None => continue,
        };
        let e_values = match filter.generic_tags.get(&e_tag_key) {
            Some(vs) if vs.len() == 1 => vs,
            _ => continue,
        };
        let root_hex = match e_values.iter().next() {
            Some(h) => h,
            None => continue,
        };
        let root_bytes = match hex::decode(root_hex) {
            Ok(b) if b.len() == 32 => b,
            _ => continue,
        };

        if let Some(ch_id) = extract_channel_from_filter(filter) {
            if !accessible_channels.contains(&ch_id) {
                handled.insert(idx);
                continue;
            }
        }

        let limit = filter
            .limit
            .unwrap_or(100)
            .min(BRIDGE_THREAD_MAX_LIMIT as usize) as u32;
        let thread_cursor = extract_thread_cursor(raw);
        let thread_replies = state
            .db
            .get_thread_replies(
                tenant.community(),
                &root_bytes,
                Some(depth),
                limit,
                thread_cursor.as_deref(),
            )
            .await
            .map_err(|e| internal_error(&format!("thread query error: {e}")))?;

        let mut thread_row_ids = Vec::with_capacity(thread_replies.len() + 1);
        thread_row_ids.push(root_hex.to_string());
        for reply in thread_replies {
            let se = reply.stored_event;
            if !event_in_accessible_channel(&se, &accessible_channels) {
                continue;
            }
            // Defense-in-depth: never deliver a result-gated event (e.g. kind:44200
            // or kind:30622) to a non-owner via the thread path, even though
            // requires_h_channel_scope already excludes these kinds from thread metadata.
            if !buzz_core::filter::reader_authorized_for_event(&se.event, &authed_pubkey_hex) {
                continue;
            }
            thread_row_ids.push(se.event.id.to_hex());
            if let Ok(v) = serde_json::to_value(&se.event) {
                events.push(v);
            }
        }

        if extension_flag(raw, "include_aux") && !thread_row_ids.is_empty() {
            let mut seen_aux = std::collections::HashSet::new();
            let mut hop_ids = thread_row_ids;
            for hop_kinds in [&WINDOW_AUX_KINDS[..], &WINDOW_AUX_DELETE_KINDS[..]] {
                let aux_query =
                    build_aux_query(tenant.community(), std::mem::take(&mut hop_ids), hop_kinds);
                let aux_events = query_all_pages(
                    aux_query,
                    AUX_PAGE_LIMIT,
                    &mut AuxReader::Routed(&state.db, "bridge_thread_aux"),
                )
                .await
                .map_err(|e| internal_error(&format!("thread aux query error: {e}")))?;
                for se in aux_events {
                    if !seen_aux.insert(se.event.id)
                        || !event_in_accessible_channel(&se, &accessible_channels)
                        || !buzz_core::filter::reader_authorized_for_event(
                            &se.event,
                            &authed_pubkey_hex,
                        )
                    {
                        continue;
                    }
                    hop_ids.push(se.event.id.to_hex());
                    if let Ok(value) = serde_json::to_value(&se.event) {
                        events.push(value);
                    }
                }
                if hop_ids.is_empty() {
                    break;
                }
            }
        }
        handled.insert(idx);
    }

    // Phase 1 — pure construction + validation, in filter order. Access-scope
    // skips and the `before_id` BAD_REQUEST are decided here, before any DB
    // work is issued (validation errors are deterministic client mistakes, so
    // surfacing them ahead of transient DB errors is strictly more predictable).
    let mut catchall_queries: Vec<(usize, buzz_db::EventQuery)> = Vec::new();
    for (idx, (raw, filter)) in raw_filters.iter().zip(filters.iter()).enumerate() {
        if handled.contains(&idx) {
            continue;
        }

        if let Some(ch_id) = extract_channel_from_filter(filter) {
            if !accessible_channels.contains(&ch_id) {
                continue;
            }
        }

        let mut query = crate::handlers::req::build_event_query_from_filter(
            filter,
            &pubkey_bytes,
            state,
            tenant.community(),
        )
        .await;
        crate::handlers::req::apply_channel_scope_to_query(
            &mut query,
            filter,
            extract_channel_from_filter(filter),
            &accessible_channels,
        );
        if let Some(channel) = extract_buzz_channel(raw) {
            query.custom_tag = Some(("buzz-channel".into(), channel.into()));
        }
        // Shared-gated visibility pushdown: must mirror WS REQ so that a page of
        // newer private events does not starve older shared ones off the page.
        if crate::handlers::req::filter_can_match_shared_gated_kinds(filter) {
            query.shared_gated_reader = Some(pubkey_bytes.clone());
        }

        match extract_before_id(raw) {
            BeforeId::Malformed => {
                return Err(api_error(
                    StatusCode::BAD_REQUEST,
                    "before_id must be a 64-char hex event id",
                ));
            }
            BeforeId::Valid(bid) => {
                if query.until.is_none() {
                    return Err(api_error(
                        StatusCode::BAD_REQUEST,
                        "before_id requires until to be set",
                    ));
                }
                query.before_id = Some(bid);
            }
            BeforeId::Absent => {}
        }

        // Honor `page` on non-search general queries so offset paging works for
        // the empty-query people directory (kind:0 listing). The FTS path
        // (`handle_bridge_search`) has its own `page`/`per_page`; a filter with
        // no `search` field lands here instead, where paging would otherwise be
        // dropped and the directory would terminate at its first page. Deterministic
        // ordering in `query_events` (`created_at DESC, id ASC`) makes offset paging
        // stable. `page` defaults to 1 → offset 0, so unrelated general queries are
        // unaffected.
        if let Some(offset) = extract_page_offset(raw, query.limit) {
            query.offset = Some(offset);
        }

        catchall_queries.push((idx, query));
    }

    // Phase 2 — DB reads, bounded-concurrent, order-preserving (`buffered`).
    // Phase 3 consumes results in original filter order, so response ordering
    // and error semantics match the previous serial loop.
    use futures_util::stream::{self, StreamExt};
    let db = state.db.clone();
    let mut catchall_results = stream::iter(catchall_queries.into_iter().map(|(idx, query)| {
        let db = db.clone();
        async move { (idx, db.query_events_routed("bridge_query", &query).await) }
    }))
    .buffered(crate::handlers::req::FILTER_QUERY_CONCURRENCY);

    // Phase 3 — post-processing, strictly in filter order.
    while let Some((idx, filter_events)) = catchall_results.next().await {
        let filter = &filters[idx];
        match filter_events {
            Ok(stored_events) => {
                for se in stored_events {
                    if !event_in_accessible_channel(&se, &accessible_channels) {
                        continue;
                    }
                    if !buzz_core::filter::filters_match(std::slice::from_ref(filter), &se) {
                        continue;
                    }
                    // Result-level read auth: never hand a viewer-private snapshot
                    // (kind:30622) to anyone but its owner, even via kindless `ids`.
                    // Also enforces author-only kinds (30300/30350) and the persona
                    // shared-gate (kind:30175 without ["shared","true"]). Single call
                    // covers all three gated event classes.
                    if !crate::handlers::req::event_visible_to_reader(&se.event, &pubkey_bytes) {
                        continue;
                    }
                    if let Ok(v) = serde_json::to_value(&se.event) {
                        events.push(v);
                    }
                }
            }
            Err(e) => {
                return Err(internal_error(&format!("query error: {e}")));
            }
        }
    }

    Ok(Json(Value::Array(events)))
}

async fn repair_requested_channel_access(
    state: &AppState,
    tenant: &TenantContext,
    filters: &[nostr::Filter],
    pubkey_bytes: &[u8],
    accessible_channels: &mut Vec<uuid::Uuid>,
) -> Result<(), (StatusCode, Json<Value>)> {
    for filter in filters {
        let Some(requested) =
            crate::handlers::req::extract_channel_ids_from_filters(std::slice::from_ref(filter))
        else {
            continue;
        };
        for channel_id in requested {
            if accessible_channels.contains(&channel_id) {
                continue;
            }
            let is_member = state
                .db
                .is_member(tenant.community(), channel_id, pubkey_bytes)
                .await
                .map_err(|e| internal_error(&format!("channel membership confirmation: {e}")))?;
            crate::handlers::req::resolve_request_local_access(
                accessible_channels,
                channel_id,
                true,
                Some(is_member),
            );
        }
    }
    Ok(())
}

/// Count events via HTTP bridge (NIP-98 auth). Returns `{"count": N}`.
///
/// Enforces channel access: only counts events in channels the user can access.
/// For filters without a `#h` tag, falls back to per-event counting with access checks.
pub async fn count_events(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Row zero: bind this HTTP request to its community from the request host
    // before any tenant-scoped read, identical to the WS door in `router.rs`
    // and `query_events`/`submit_event` above. Fail-closed; never a default
    // tenant, never echoing the host.
    let raw_host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let tenant = crate::tenant::bind_community(&state.db, raw_host)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::NOT_FOUND,
                "relay: no community is configured for this host",
            )
        })?;

    let url = nip98_expected_url(&state.config.relay_url, &tenant, "/count");
    let VerifiedBridgeAuth {
        pubkey,
        event_id_bytes,
        signed_created_at,
    } = verify_bridge_auth(
        &headers,
        "POST",
        &url,
        Some(&body),
        state.config.require_auth_token,
    )?;
    let pubkey_hex = pubkey.to_hex();

    // Admission, replay, membership, and count execution all run inside the
    // helper.  The single terminal attribution line fires here from the Result
    // so every outcome — including admission/replay/membership failures that
    // previously returned before any log — is attributed.
    let result = count_events_authed(
        &state,
        &tenant,
        &headers,
        &body,
        pubkey,
        event_id_bytes,
        signed_created_at,
    )
    .await;
    match &result {
        Ok(Json(value)) => {
            let count = value.get("count").and_then(Value::as_u64);
            tracing::info!(
                pubkey = %pubkey_hex,
                route = "/count",
                status = 200u16,
                result_count = count,
                "HTTP bridge request"
            );
        }
        Err((status, _)) => {
            tracing::warn!(
                pubkey = %pubkey_hex,
                route = "/count",
                status = status.as_u16(),
                "HTTP bridge request"
            );
        }
    }
    result
}

/// Filter execution for [`count_events`], run once NIP-98 auth succeeds.
/// Handles admission, replay, membership, and count execution so the thin
/// wrapper above can emit exactly one terminal attribution line from the Result.
async fn count_events_authed(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    headers: &HeaderMap,
    body: &[u8],
    pubkey: nostr::PublicKey,
    event_id_bytes: [u8; 32],
    signed_auth_created_at: Option<u64>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    enforce_http_admission(state, tenant, &pubkey).await?;
    check_nip98_replay(state, tenant, event_id_bytes).await?;
    let pubkey_bytes = pubkey.to_bytes().to_vec();

    let auth_tag = super::relay_members::extract_auth_tag_header(headers);
    super::relay_members::enforce_relay_membership(
        state,
        tenant.community(),
        &pubkey_bytes,
        auth_tag,
        signed_auth_created_at,
    )
    .await?;

    let filters: Vec<nostr::Filter> = serde_json::from_slice(body)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &format!("invalid filters: {e}")))?;
    crate::handlers::req::extract_channel_ids_from_filters_limited(&filters)
        .map_err(|()| api_error(StatusCode::BAD_REQUEST, "too many explicit channels"))?;

    // P-gated kinds enforcement — same as WS REQ and /query.
    let authed_pubkey_hex = pubkey.to_hex();
    if !crate::handlers::req::p_gated_filters_authorized(&filters, &authed_pubkey_hex) {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "restricted: p-gated kinds require #p tag matching your pubkey",
        ));
    }
    if !crate::handlers::req::engram_filters_authorized(&filters, &authed_pubkey_hex) {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "restricted: agent-engram reads require authors=[self] or #p=[self]",
        ));
    }
    if !crate::handlers::req::author_only_filters_authorized(&filters, &authed_pubkey_hex) {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "restricted: author-only kinds require authors=[self]",
        ));
    }

    // Get channels this user can access.
    let mut accessible_channels = state
        .get_accessible_channel_ids_cached(tenant.community(), &pubkey_bytes)
        .await
        .map_err(|e| internal_error(&format!("channel access lookup: {e}")))?;
    repair_requested_channel_access(
        state,
        tenant,
        &filters,
        &pubkey_bytes,
        &mut accessible_channels,
    )
    .await?;

    let mut total: u64 = 0;
    for filter in &filters {
        let needs_author_only_filtering =
            crate::handlers::req::filter_can_match_author_only_kinds(filter);
        // Same result-gated guard as the WS COUNT handler: force the per-event
        // fallback for filters that can match 44200 or 30622 unless #p=[self]
        // is safely pushed down (existence leak otherwise).
        let needs_result_gated_filtering =
            crate::handlers::req::filter_can_match_result_gated_kinds(filter)
                && !crate::handlers::req::result_gated_count_safe_for_pushdown(
                    filter,
                    &authed_pubkey_hex,
                );
        // Force per-event fallback for filters that can match a shared-gated
        // kind — the fast SQL count_events() path has no per-event gate and
        // would over-count foreign unshared events (existence leak).
        let needs_shared_gate_filtering =
            crate::handlers::req::filter_can_match_shared_gated_kinds(filter);

        // If filter targets a specific channel, verify access.
        if crate::handlers::req::extract_channel_ids_from_filters(std::slice::from_ref(filter))
            .is_some()
        {
            let ch_id = extract_channel_from_filter(filter);
            let requested = crate::handlers::req::extract_channel_ids_from_filters(
                std::slice::from_ref(filter),
            )
            .unwrap_or_default();
            if !requested
                .iter()
                .any(|channel_id| accessible_channels.contains(channel_id))
            {
                continue;
            }
            // Channel is accessible — count with pushability check.
            let mut query = crate::handlers::req::build_event_query_from_filter(
                filter,
                &pubkey_bytes,
                state,
                tenant.community(),
            )
            .await;
            crate::handlers::req::apply_channel_scope_to_query(
                &mut query,
                filter,
                ch_id,
                &accessible_channels,
            );
            // Shared-gated visibility pushdown: same as REQ and /query paths, so
            // the fallback's query_events call doesn't over-fetch private rows.
            if needs_shared_gate_filtering {
                query.shared_gated_reader = Some(pubkey_bytes.clone());
            }
            let author_is_self = filter.authors.as_ref().is_some_and(|authors| {
                !authors.is_empty()
                    && authors
                        .iter()
                        .all(|a| a.to_hex().eq_ignore_ascii_case(&authed_pubkey_hex))
            });
            if crate::handlers::req::filter_fully_pushable(filter)
                && (!needs_author_only_filtering || author_is_self)
                && !needs_result_gated_filtering
                && !needs_shared_gate_filtering
            {
                match state.db.count_events_routed("bridge_count", &query).await {
                    Ok(n) => total += n as u64,
                    Err(e) => {
                        return Err(internal_error(&format!("count error: {e}")));
                    }
                }
            } else {
                // Fallback: query + post-filter for non-pushable constraints.
                let mut q = query;
                crate::handlers::req::apply_count_fallback_limit(&mut q);
                match state
                    .db
                    .query_events_routed_bounded("bridge_count_fallback", &q)
                    .await
                {
                    Ok(stored_events) => {
                        if crate::handlers::req::count_fallback_exceeded(stored_events.len()) {
                            metrics::counter!("buzz_count_fallback_rejections_total").increment(1);
                            return Err(api_error(
                                StatusCode::BAD_REQUEST,
                                "count filter requires narrower constraints",
                            ));
                        }
                        for se in stored_events {
                            if !buzz_core::filter::filters_match(std::slice::from_ref(filter), &se)
                            {
                                continue;
                            }
                            if !crate::handlers::req::event_visible_to_reader(
                                &se.event,
                                &pubkey_bytes,
                            ) {
                                continue;
                            }
                            total += 1;
                        }
                    }
                    Err(e) => {
                        return Err(internal_error(&format!("count error: {e}")));
                    }
                }
            }
        } else {
            // No channel filter — use SQL-level channel_ids pushdown to count
            // only events in accessible channels (+ global events).
            let mut query = crate::handlers::req::build_event_query_from_filter(
                filter,
                &pubkey_bytes,
                state,
                tenant.community(),
            )
            .await;
            query.channel_ids = Some(accessible_channels.to_vec());
            // Shared-gated visibility pushdown: pre-filter before ORDER/LIMIT on
            // the fallback query_events path.
            if needs_shared_gate_filtering {
                query.shared_gated_reader = Some(pubkey_bytes.clone());
            }

            let author_is_self = filter.authors.as_ref().is_some_and(|authors| {
                !authors.is_empty()
                    && authors
                        .iter()
                        .all(|a| a.to_hex().eq_ignore_ascii_case(&authed_pubkey_hex))
            });
            if crate::handlers::req::filter_fully_pushable(filter)
                && (!needs_author_only_filtering || author_is_self)
                && !needs_result_gated_filtering
                && !needs_shared_gate_filtering
            {
                query.limit = None;
                match state.db.count_events_routed("bridge_count", &query).await {
                    Ok(n) => total += n as u64,
                    Err(e) => {
                        return Err(internal_error(&format!("count error: {e}")));
                    }
                }
            } else {
                // Fallback: query a bounded candidate set + post-filter.
                crate::handlers::req::apply_count_fallback_limit(&mut query);
                match state
                    .db
                    .query_events_routed_bounded("bridge_count_fallback", &query)
                    .await
                {
                    Ok(stored_events) => {
                        if crate::handlers::req::count_fallback_exceeded(stored_events.len()) {
                            metrics::counter!("buzz_count_fallback_rejections_total").increment(1);
                            return Err(api_error(
                                StatusCode::BAD_REQUEST,
                                "count filter requires narrower constraints",
                            ));
                        }
                        for se in stored_events {
                            if !buzz_core::filter::filters_match(std::slice::from_ref(filter), &se)
                            {
                                continue;
                            }
                            if !crate::handlers::req::event_visible_to_reader(
                                &se.event,
                                &pubkey_bytes,
                            ) {
                                continue;
                            }
                            total += 1;
                        }
                    }
                    Err(e) => {
                        return Err(internal_error(&format!("count error: {e}")));
                    }
                }
            }
        }
    }

    Ok(Json(serde_json::json!({ "count": total })))
}

fn has_mixed_search_filters(filters: &[nostr::Filter]) -> bool {
    filters.iter().any(|f| f.search.is_some()) && filters.iter().any(|f| f.search.is_none())
}

/// Decide whether a search hit should be returned to the caller.
///
/// Mirrors the WS NIP-50 path's post-filter step in `handlers/req.rs`:
/// the FTS backend receives only the kind/authors/time pushdown, so any other filter
/// constraint (`#p`, `#h`, `#e`, `#d`, `ids`, …) must be enforced here against
/// the full stored event. Without this, an authorized engram search such as
/// `{"kinds":[30174],"#p":[self]}` would leak text-matching envelopes whose
/// `#p` belongs to a different owner — the NIP-AE read gate at the filter
/// layer would be bypassed for `/query`.
///
/// `accessible_channels` is the caller's channel scope; channel-scoped hits
/// outside that set are rejected regardless of NIP-01 match.
fn search_hit_accepted(
    filter: &nostr::Filter,
    stored: &buzz_core::StoredEvent,
    accessible_channels: &[uuid::Uuid],
    reader_pubkey_hex: &str,
) -> bool {
    if !buzz_core::filter::filters_match(std::slice::from_ref(filter), stored) {
        return false;
    }
    if let Some(ch_id) = stored.channel_id {
        if !accessible_channels.contains(&ch_id) {
            return false;
        }
    }
    if !buzz_core::filter::reader_authorized_for_event(&stored.event, reader_pubkey_hex) {
        return false;
    }
    true
}

/// Handle search filters by routing to Postgres FTS, then fetching full events
/// from DB. Supports a bridge-only `page` extension over the FTS result set.
async fn handle_bridge_search(
    state: &AppState,
    raw_filters: &[Value],
    filters: &[nostr::Filter],
    accessible_channels: &[uuid::Uuid],
    tenant: &buzz_core::tenant::TenantContext,
    reader_pubkey_hex: &str,
    pubkey_bytes: &[u8],
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Bridge always includes global (channel-less) events — same as WS with
    // full scopes. `None` means no accessible channels and no global access →
    // empty result set (the caller short-circuits exactly as the WS door EOSEs).
    let channel_scope = match crate::handlers::req::build_search_channel_scope_filter(
        accessible_channels,
        true, // include_global
    ) {
        Some(scope) => scope,
        None => return Ok(Json(Value::Array(Vec::new()))),
    };

    let mut events: Vec<Value> = Vec::new();
    let mut seen_ids: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();

    for (raw, filter) in raw_filters.iter().zip(filters) {
        let search_mode = extract_search_mode(raw);
        let search_page = extract_search_page(raw);
        let search_text = match &filter.search {
            Some(s) if !s.is_empty() => s.clone(),
            _ => continue,
        };

        let limit = filter.limit.unwrap_or(100).min(500) as u32;
        if limit == 0 {
            continue;
        }

        // Scope by channel — push the #h tag (intersected with accessible
        // channels) if present, else the community-wide scope.
        let h_tag = nostr::SingleLetterTag::lowercase(nostr::Alphabet::H);
        let filter_channel_scope =
            if let Some(vs) = filter.generic_tags.get(&h_tag).filter(|vs| !vs.is_empty()) {
                let valid: Vec<uuid::Uuid> = vs
                    .iter()
                    .filter_map(|v| v.parse::<uuid::Uuid>().ok())
                    .filter(|id| accessible_channels.contains(id))
                    .collect();
                if valid.is_empty() {
                    continue; // All #h values inaccessible — skip filter.
                }
                buzz_search::ChannelScope::Channels(valid)
            } else {
                channel_scope.clone()
            };

        let kinds = filter.kinds.as_ref().and_then(|ks| {
            if ks.is_empty() {
                None
            } else {
                Some(ks.iter().map(|k| k.as_u16() as i32).collect::<Vec<_>>())
            }
        });
        let authors = filter.authors.as_ref().and_then(|au| {
            if au.is_empty() {
                None
            } else {
                Some(au.iter().map(|a| a.to_bytes().to_vec()).collect::<Vec<_>>())
            }
        });
        let since = filter.since.map(|s| s.as_secs() as i64);
        let until = filter.until.map(|u| u.as_secs() as i64);

        let search_query = buzz_search::SearchQuery {
            community: tenant.community(),
            q: search_text,
            channel_scope: filter_channel_scope,
            kinds,
            authors,
            since,
            until,
            page: search_page,
            per_page: limit,
            mode: search_mode,
        };

        let search_result = state
            .search
            .search(&search_query)
            .await
            .map_err(|e| internal_error(&format!("search error: {e}")))?;

        // Fetch full events from DB by ID. Hit ids are already raw 32-byte
        // arrays from the FTS layer — no hex decode.
        let hit_ids: Vec<[u8; 32]> = search_result.hits.into_iter().map(|h| h.event_id).collect();

        if hit_ids.is_empty() {
            continue;
        }

        let id_refs: Vec<&[u8]> = hit_ids.iter().map(|b| b.as_slice()).collect();
        let stored_events = state
            .db
            .get_events_by_ids_routed("bridge_search_hydrate", tenant.community(), &id_refs)
            .await
            .map_err(|e| internal_error(&format!("search fetch error: {e}")))?;

        // Build lookup map to preserve FTS relevance ordering.
        let event_map: std::collections::HashMap<[u8; 32], &buzz_core::StoredEvent> = stored_events
            .iter()
            .map(|ev| (ev.event.id.to_bytes(), ev))
            .collect();

        for id_array in &hit_ids {
            let stored = match event_map.get(id_array) {
                Some(ev) => ev,
                None => continue,
            };
            if !search_hit_accepted(filter, stored, accessible_channels, reader_pubkey_hex) {
                continue;
            }
            // Defense-in-depth: apply the full per-event visibility gate, which
            // covers author-only kinds, the persona shared-gate (kind:30175), and
            // result-gated kinds. Kind:30175 is not in the FTS positive allowlist
            // today (migration 8 indexes only 0,9,40002,45001,45003), so this
            // branch cannot currently return unshared persona content — but the
            // check here ensures that a future FTS allowlist change cannot silently
            // reopen the bypass.
            if !crate::handlers::req::event_visible_to_reader(&stored.event, pubkey_bytes) {
                continue;
            }
            // Dedup across filters.
            if !seen_ids.insert(*id_array) {
                continue;
            }
            if let Ok(v) = serde_json::to_value(&stored.event) {
                events.push(v);
            }
        }
    }

    Ok(Json(Value::Array(events)))
}

/// Query parameters for the webhook trigger endpoint.
#[derive(serde::Deserialize)]
pub struct WebhookQuery {
    /// Webhook secret for authentication. Prefer the `X-Webhook-Secret` header instead.
    pub secret: Option<String>,
}

/// Webhook trigger endpoint. No user auth — the webhook secret authenticates the caller.
///
/// Prefers `X-Webhook-Secret` header over `?secret=` query param (headers aren't logged
/// by most proxies). Returns 202 Accepted; execution is async.
pub async fn workflow_webhook(
    State(state): State<Arc<AppState>>,
    Path(id_str): Path<String>,
    Query(query): Query<WebhookQuery>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let id = uuid::Uuid::parse_str(&id_str)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid workflow UUID"))?;

    // Row zero: bind this webhook to its community from the request host before
    // any tenant-scoped lookup or write. The host — not the workflow row —
    // determines the tenant: a request for community A's host may only reach
    // community A's workflows, even when the same workflow UUID also exists in
    // community B. Unmapped host, lookup failure, and a workflow that does not
    // exist in *this* community all fail closed with the same generic 404, so a
    // caller cannot probe which hosts or workflow ids exist on other tenants.
    let raw_host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let tenant = crate::tenant::bind_community(&state.db, raw_host)
        .await
        .map_err(|_| not_found("workflow not found"))?;
    let community_id = tenant.community();

    let workflow = state
        .db
        .get_workflow(community_id, id)
        .await
        .map_err(|_| not_found("workflow not found"))?;

    let def: buzz_workflow::WorkflowDef = serde_json::from_value(workflow.definition.clone())
        .map_err(|e| super::internal_error(&format!("corrupt workflow definition: {e}")))?;

    if !matches!(def.trigger, buzz_workflow::TriggerDef::Webhook) {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "workflow does not have a webhook trigger",
        ));
    }

    // Verify webhook secret. Prefer header (not logged by proxies); fall back to query param.
    let stored_secret = crate::webhook_secret::extract_secret(&workflow.definition);
    let provided_secret = headers
        .get("x-webhook-secret")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| query.secret.clone())
        .unwrap_or_default();

    match &stored_secret {
        Some(secret) => {
            if !crate::webhook_secret::verify_secret(&provided_secret, secret) {
                tracing::warn!("webhook: invalid secret for workflow {id}");
                return Err(api_error(StatusCode::UNAUTHORIZED, "authentication failed"));
            }
        }
        None => {
            return Err(api_error(
                StatusCode::UNAUTHORIZED,
                "webhook secret required but not configured — re-save the workflow to generate one",
            ));
        }
    }

    // Parse optional JSON body as trigger context.
    let body_json: Option<Value> =
        if body.is_empty() {
            None
        } else {
            Some(serde_json::from_slice(&body).map_err(|e| {
                api_error(StatusCode::BAD_REQUEST, &format!("invalid JSON body: {e}"))
            })?)
        };

    // Build trigger context from webhook body fields.
    let mut trigger_ctx = buzz_workflow::executor::TriggerContext {
        channel_id: workflow
            .channel_id
            .map(|ch| ch.to_string())
            .unwrap_or_default(),
        ..Default::default()
    };
    if let Some(Value::Object(ref map)) = body_json {
        for (k, v) in map {
            let val_str = match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            trigger_ctx.webhook_fields.insert(k.clone(), val_str);
        }
    }
    let trigger_ctx_json = serde_json::to_value(&trigger_ctx).ok();

    // SEC-006: the webhook secret authenticates the *caller*, but the run
    // executes with the workflow **owner's** standing authority — so the
    // secret alone is insufficient. Immediately before run creation, reject
    // disabled/inactive workflows and recheck the owner's current channel
    // membership (and role, for exfiltration-capable definitions). Fail
    // closed with the same generic 404 as the lookups above so a
    // revoked-owner workflow is indistinguishable from a nonexistent one.
    if !workflow.enabled || workflow.status != buzz_db::workflow::WorkflowStatus::Active {
        return Err(not_found("workflow not found"));
    }
    let Some(wf_channel_id) = workflow.channel_id else {
        // No channel scope means no channel authority to verify — fail closed.
        return Err(not_found("workflow not found"));
    };
    state
        .workflow_engine
        .check_owner_authority(community_id, wf_channel_id, &workflow.owner_pubkey, &def)
        .await
        .map_err(|_| not_found("workflow not found"))?;

    let run_id = state
        .db
        .create_workflow_run(community_id, id, None, trigger_ctx_json.as_ref())
        .await
        .map_err(|e| super::internal_error(&format!("db error: {e}")))?;

    // Spawn workflow execution asynchronously.
    let engine = Arc::clone(&state.workflow_engine);
    let db = state.db.clone();
    let def_value = workflow.definition.clone();
    let trigger_ctx_clone = trigger_ctx.clone();
    tokio::spawn(async move {
        let def: buzz_workflow::WorkflowDef = match serde_json::from_value(def_value) {
            Ok(d) => d,
            Err(e) => {
                tracing::error!("webhook: failed to parse definition: {e}");
                if let Err(db_err) = db
                    .update_workflow_run(
                        community_id,
                        run_id,
                        buzz_db::workflow::RunStatus::Failed,
                        0,
                        &serde_json::json!([]),
                        Some(buzz_db::workflow::WorkflowRunFailure {
                            code: "invalid_definition",
                            message: &format!("definition parse error: {e}"),
                        }),
                    )
                    .await
                {
                    tracing::error!("webhook: failed to mark run as failed: {db_err}");
                }
                return;
            }
        };

        let result = buzz_workflow::executor::execute_from_step(
            &engine,
            community_id,
            run_id,
            &def,
            &trigger_ctx_clone,
            0,
            None,
        )
        .await;
        engine
            .finalize_run(community_id, run_id, result, None)
            .await;
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "run_id": run_id.to_string(),
            "workflow_id": id.to_string(),
            "status": "pending",
        })),
    ))
}

/// If all filters target kind:20001 or kind:40902 with authors, synthesize
/// presence from Redis instead of querying the DB (ephemeral events are never
/// stored, and kind:40902 snapshots are relay-generated on demand).
///
/// Returns `None` when the filters are not a presence query (fall through to
/// the normal query path). Returns `Some(Ok(events))` when a presence snapshot
/// was produced — an empty vec is an authoritative "all offline" answer.
/// Returns `Some(Err(_))` when the backing Redis lookup failed: callers must
/// propagate that as an error response rather than a fake-empty success, so a
/// consumer cannot mistake a backend outage for an authoritative snapshot.
#[allow(clippy::type_complexity)]
async fn synthesize_presence(
    pubsub: &buzz_pubsub::PubSubManager,
    relay_keypair: &nostr::Keys,
    tenant: &buzz_core::tenant::TenantContext,
    filters: &[nostr::Filter],
) -> Option<Result<Vec<Value>, (StatusCode, Json<Value>)>> {
    use buzz_core::kind::{KIND_PRESENCE_SNAPSHOT, KIND_PRESENCE_UPDATE};

    // Only intercept if every filter targets kind:20001 or 40902 with authors.
    let mut all_pubkeys: Vec<nostr::PublicKey> = Vec::new();
    for filter in filters {
        let kinds = filter.kinds.as_ref()?;
        let only_kind = kinds.iter().next()?;
        let k = only_kind.as_u16() as u32;
        if kinds.len() != 1 || (k != KIND_PRESENCE_UPDATE && k != KIND_PRESENCE_SNAPSHOT) {
            return None;
        }
        let authors = filter.authors.as_ref()?;
        if authors.is_empty() {
            return None;
        }
        all_pubkeys.extend(authors.iter().copied());
    }

    if all_pubkeys.is_empty() {
        return Some(Ok(Vec::new()));
    }

    // Dedup pubkeys.
    all_pubkeys.sort_by_key(|pk| pk.to_hex());
    all_pubkeys.dedup();

    // Look up Redis. A lookup failure must surface as an error, not a
    // fake-empty success — otherwise a Redis outage is indistinguishable from
    // an authoritative all-offline snapshot to the consumer.
    let presence_map = match pubsub.get_presence_bulk(tenant, &all_pubkeys).await {
        Ok(map) => map,
        Err(e) => return Some(Err(internal_error(&format!("presence lookup: {e}")))),
    };

    if presence_map.is_empty() {
        return Some(Ok(Vec::new()));
    }

    // Synthesize kind:20001 events signed by the relay.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut events = Vec::with_capacity(presence_map.len());
    for (pubkey_hex, status) in &presence_map {
        // Build a synthetic event: relay-signed, content = status, p-tag = subject.
        // A build/sign failure here is an internal fault, not a "not a presence
        // query" signal, so surface it as an error rather than falling through.
        let tags = match nostr::Tag::parse(["p", pubkey_hex]) {
            Ok(tag) => vec![tag],
            Err(e) => return Some(Err(internal_error(&format!("presence tag: {e}")))),
        };
        let event = match nostr::EventBuilder::new(
            nostr::Kind::Custom(KIND_PRESENCE_UPDATE as u16),
            status,
        )
        .tags(tags)
        .custom_created_at(nostr::Timestamp::from(now))
        .sign_with_keys(relay_keypair)
        {
            Ok(event) => event,
            Err(e) => return Some(Err(internal_error(&format!("presence sign: {e}")))),
        };

        if let Ok(v) = serde_json::to_value(&event) {
            events.push(v);
        }
    }

    Some(Ok(events))
}

// ── Moderation queue reads (L6 — Quinn) ───────────────────────────────────────
//
// Mod-only structured rows (`moderation_reports`/`moderation_actions`/
// `community_bans`) are not nostr events, so they are served over dedicated
// NIP-98-authed GET endpoints rather than the REQ/`/query` path (which would
// force a synthetic event shape and thread a privileged branch onto the shared
// read hot path). Gated on `ModerationAction::ViewQueue` via the one capability
// helper — never an inline role check. Host-scoped: community from the request
// host, no channel context (queue reads are community-wide).

/// Shared prelude for a moderation read: bind tenant, verify NIP-98 GET auth,
/// replay-check, and confirm the caller may view the queue.
///
/// `raw_query` is the request's raw query string (from [`axum::extract::RawQuery`]),
/// e.g. `Some("limit=20&status=open")`. NIP-98 signs the *full* request URL, so the
/// client's `u` tag includes any query string; the expected URL reconstructed here
/// must therefore append the same query verbatim or query-bearing reads
/// (`reports?limit=…`, `audit?limit=…`) 401 on a URL mismatch. Query-less reads
/// (`restricted`) pass `None` and keep the bare-path expectation. The verbatim
/// request query is used (not a re-serialized parse) so the match stays byte-exact
/// with what the client signed regardless of param order or encoding.
async fn authorize_moderation_read(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    path: &str,
    raw_query: Option<&str>,
) -> Result<TenantContext, (StatusCode, Json<Value>)> {
    let raw_host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let tenant = crate::tenant::bind_community(&state.db, raw_host)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::NOT_FOUND,
                "relay: no community is configured for this host",
            )
        })?;

    let path_with_query = match raw_query {
        Some(q) if !q.is_empty() => format!("{path}?{q}"),
        _ => path.to_string(),
    };
    let url = nip98_expected_url(&state.config.relay_url, &tenant, &path_with_query);
    let VerifiedBridgeAuth {
        pubkey,
        event_id_bytes,
        ..
    } = verify_bridge_auth(headers, "GET", &url, None, state.config.require_auth_token)?;
    check_nip98_replay(state, &tenant, event_id_bytes).await?;
    let pubkey_bytes = pubkey.to_bytes().to_vec();

    crate::handlers::moderation_authz::authorize_moderation_action(
        &tenant,
        state,
        &pubkey_bytes,
        None,
        crate::handlers::moderation_authz::ModerationTarget::None,
        crate::handlers::moderation_authz::ModerationAction::ViewQueue,
    )
    .await
    .map_err(|_| {
        api_error(
            StatusCode::FORBIDDEN,
            "restricted: moderator access required",
        )
    })?;

    Ok(tenant)
}

/// Cap on rows returned by a single moderation read.
const MODERATION_READ_LIMIT: i64 = 500;

/// Optional `?status=` and `?limit=` query for moderation reads.
#[derive(serde::Deserialize, Default)]
pub struct ModerationReadQuery {
    status: Option<String>,
    limit: Option<i64>,
}

fn clamp_limit(requested: Option<i64>) -> i64 {
    requested
        .filter(|n| *n > 0)
        .map(|n| n.min(MODERATION_READ_LIMIT))
        .unwrap_or(MODERATION_READ_LIMIT)
}

/// `GET /moderation/reports` — the moderation queue (NIP-98 + mod-authz).
pub async fn moderation_reports(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
    Query(q): Query<ModerationReadQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let tenant = authorize_moderation_read(
        &state,
        &headers,
        "/moderation/reports",
        raw_query.as_deref(),
    )
    .await?;
    let rows = state
        .db
        .list_moderation_reports(
            tenant.community(),
            q.status.as_deref(),
            clamp_limit(q.limit),
        )
        .await
        .map_err(|e| internal_error(&format!("list reports: {e}")))?;
    Ok(Json(Value::Array(rows.iter().map(report_json).collect())))
}

/// `GET /moderation/audit` — the moderation audit log (NIP-98 + mod-authz).
pub async fn moderation_audit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
    Query(q): Query<ModerationReadQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let tenant =
        authorize_moderation_read(&state, &headers, "/moderation/audit", raw_query.as_deref())
            .await?;
    let rows = state
        .db
        .list_moderation_actions(tenant.community(), clamp_limit(q.limit))
        .await
        .map_err(|e| internal_error(&format!("list actions: {e}")))?;
    Ok(Json(Value::Array(rows.iter().map(action_json).collect())))
}

/// `GET /moderation/restricted` — currently banned/timed-out members.
pub async fn moderation_restricted(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let tenant =
        authorize_moderation_read(&state, &headers, "/moderation/restricted", None).await?;
    let rows = state
        .db
        .list_community_restrictions(tenant.community())
        .await
        .map_err(|e| internal_error(&format!("list restrictions: {e}")))?;
    Ok(Json(Value::Array(rows.iter().map(ban_json).collect())))
}

fn report_json(r: &buzz_db::moderation::ReportRecord) -> Value {
    let (target_kind, target) = match &r.target {
        buzz_db::moderation::ReportTarget::Event(id) => ("event", hex::encode(id)),
        buzz_db::moderation::ReportTarget::Pubkey(pk) => ("pubkey", hex::encode(pk)),
        buzz_db::moderation::ReportTarget::Blob(sha) => ("blob", hex::encode(sha)),
    };
    serde_json::json!({
        "id": r.id,
        "report_event_id": hex::encode(&r.report_event_id),
        "reporter_pubkey": hex::encode(&r.reporter_pubkey),
        "target_kind": target_kind,
        "target": target,
        "channel_id": r.channel_id,
        "report_type": r.report_type,
        "note": r.note,
        "status": r.status,
        "resolved_by": r.resolved_by.as_ref().map(hex::encode),
        "resolved_at": r.resolved_at,
        "action_id": r.action_id,
        "created_at": r.created_at,
    })
}

fn action_json(a: &buzz_db::moderation::ActionRecord) -> Value {
    serde_json::json!({
        "id": a.id,
        "actor_pubkey": hex::encode(&a.actor_pubkey),
        "action": a.action,
        "target_pubkey": a.target_pubkey.as_ref().map(hex::encode),
        "target_event_id": a.target_event_id.as_ref().map(hex::encode),
        "channel_id": a.channel_id,
        "reason_code": a.reason_code,
        "public_reason": a.public_reason,
        "private_reason": a.private_reason,
        "matched_principal": a.matched_principal,
        "created_at": a.created_at,
    })
}

fn ban_json(b: &buzz_db::moderation::BanRecord) -> Value {
    serde_json::json!({
        "pubkey": hex::encode(&b.pubkey),
        "banned": b.banned,
        "ban_expires_at": b.ban_expires_at,
        "ban_reason": b.ban_reason,
        "muted_until": b.muted_until,
        "mute_reason": b.mute_reason,
        "actor_pubkey": hex::encode(&b.actor_pubkey),
        "updated_at": b.updated_at,
    })
}

#[cfg(test)]
mod postgres_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use buzz_auth::rate_limit::{
        HierarchicalAdmissionOutcome, HierarchicalAdmissionRequest,
        HierarchicalIdentityDenialPeekOutcome, HierarchicalIdentityDenialPeekRequest,
        PairedAdmissionOutcome, PairedAdmissionRequest,
    };
    use buzz_auth::RateLimiter;
    use buzz_db::idempotency::KeyedCommittedOutcome;
    use buzz_sdk::nip_oa::compute_auth_tag;
    use nostr::{Alphabet, EventBuilder, Keys, Kind, SingleLetterTag, Tag, Timestamp};

    use crate::admission::{
        keyed_http_attempt_admission_principal, keyed_http_fresh_admission_principal,
        KEYED_HTTP_ATTEMPT_FLEET_SENTINEL, KEYED_HTTP_ATTEMPT_LIMIT_TYPE,
        KEYED_HTTP_ATTEMPT_WINDOW_SECS, KEYED_HTTP_FAIR_SHARE_PER_MIN,
        KEYED_HTTP_FRESH_FLEET_SENTINEL, KEYED_HTTP_FRESH_LIMIT_TYPE,
        KEYED_HTTP_PREAUTH_IDENTITY_CARDINALITY_BOUND,
    };
    use crate::handlers::ingest::{
        enforce_keyed_events_fleet_admission, install_keyed_verify_watch,
        keyed_community_admission_principal, keyed_http_error_from_fleet, lock_keyed_ingress_tests,
        lock_keyed_ingress_tests_async, maybe_enforce_keyed_events_fleet_admission,
        try_acquire_keyed_ingress, KeyedWriterCapacityGuard, KEYED_BUSY_RETRY_AFTER_SECS,
        KEYED_COMMUNITY_ADMISSION_LIMIT_TYPE, KEYED_EVENTS_COMMUNITY_ADMISSION_PER_MIN,
        KEYED_EVENTS_FLEET_ADMISSION_PER_MIN, KEYED_EVENTS_FLEET_ADMISSION_SENTINEL,
        KEYED_EVENTS_FLEET_ADMISSION_WINDOW_SECS, KEYED_INGRESS_COMMUNITY_MAX,
        KEYED_INGRESS_GLOBAL_MAX, KEYED_RESERVATION_ADMISSION_BUDGET,
        KEYED_RESERVATION_ADMISSION_BUDGET_SECS, KEYED_RESERVATION_PERSIST_BUDGET_SECS,
    };

    // Serializes `router_*` tests that share production fleet sentinel keys.
    static ROUTER_FLEET_SENTINEL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn redis_pool() -> deadpool_redis::Pool {
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        deadpool_redis::Config::from_url(url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("create redis pool")
    }

    fn fresh_tenant(host: &str) -> TenantContext {
        TenantContext::resolved(
            buzz_core::CommunityId::from_uuid(uuid::Uuid::new_v4()),
            host,
        )
    }

    fn fresh_nip98_event_id_bytes() -> [u8; 32] {
        EventBuilder::new(Kind::HttpAuth, "")
            .sign_with_keys(&Keys::generate())
            .expect("sign auth event")
            .id
            .to_bytes()
    }

    #[test]
    fn bridge_detects_mixed_search_and_non_search_filters() {
        let filters = vec![
            nostr::Filter::new().search("hello"),
            nostr::Filter::new().kind(Kind::TextNote),
        ];

        assert!(has_mixed_search_filters(&filters));
    }

    #[test]
    fn bridge_accepts_all_search_filters() {
        let filters = vec![
            nostr::Filter::new().search("hello"),
            nostr::Filter::new().search("world"),
        ];

        assert!(!has_mixed_search_filters(&filters));
    }

    #[test]
    fn bridge_accepts_all_non_search_filters() {
        let filters = vec![
            nostr::Filter::new().kind(Kind::TextNote),
            nostr::Filter::new().kind(Kind::Metadata),
        ];

        assert!(!has_mixed_search_filters(&filters));
    }

    /// Production-wiring seam for the Redis-outage boundary. Drives the real
    /// `synthesize_presence` with a `PubSubManager` whose pool points at a
    /// closed port, so the `get_presence_bulk` lookup fails. A presence-snapshot
    /// filter must yield `Some(Err(500))` — never `Some(Ok([]))`, which would
    /// let a consumer mistake a backend outage for an authoritative all-offline
    /// snapshot. Restoring `unwrap_or_default()` inside `synthesize_presence`
    /// turns this red (it would return `Some(Ok([]))`), which is what protects
    /// the error-mapping seam Thufir found otherwise mutation-unprotected.
    #[tokio::test]
    async fn synthesize_presence_surfaces_redis_failure_as_error_response() {
        use buzz_core::kind::KIND_PRESENCE_SNAPSHOT;

        // Pool at a closed port: get_presence_bulk's connection attempt fails.
        let dead_pool = deadpool_redis::Config::from_url("redis://127.0.0.1:1")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("pool builds lazily");
        let pubsub = buzz_pubsub::PubSubManager::new("redis://127.0.0.1:1", dead_pool)
            .await
            .expect("PubSubManager::new performs no IO");
        let relay_keypair = Keys::generate();
        let tenant = fresh_tenant("relay.example");

        // A presence-snapshot query for a concrete author reaches the Redis
        // lookup (an empty author set would short-circuit to an empty snapshot).
        let filters = vec![nostr::Filter::new()
            .kind(Kind::Custom(KIND_PRESENCE_SNAPSHOT as u16))
            .author(Keys::generate().public_key())];

        let result = synthesize_presence(&pubsub, &relay_keypair, &tenant, &filters).await;

        match result {
            Some(Err((status, _))) => assert_eq!(
                status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "a Redis lookup failure must surface as HTTP 500"
            ),
            other => panic!(
                "a Redis outage must yield Some(Err(500)), not a fake-empty success: {other:?}"
            ),
        }
    }

    #[test]
    fn thread_aux_query_targets_root_and_replies() {
        let tenant = fresh_tenant("relay.example");
        let targets = vec!["root".to_string(), "reply".to_string()];
        let query = build_aux_query(tenant.community(), targets.clone(), &WINDOW_AUX_KINDS);

        assert_eq!(query.e_tags, Some(targets));
        assert_eq!(
            query.kinds,
            Some(WINDOW_AUX_KINDS.iter().map(|kind| *kind as i32).collect())
        );
        assert_eq!(query.limit, None);
        assert_eq!(query.until, None);
        assert_eq!(query.before_id, None);
    }

    fn aux_event(keys: &Keys, created_at: u64, content: &str) -> buzz_core::StoredEvent {
        let ev = EventBuilder::new(Kind::Custom(7), content)
            .custom_created_at(nostr::Timestamp::from(created_at))
            .sign_with_keys(keys)
            .unwrap();
        buzz_core::StoredEvent::new(ev, None)
    }

    /// Carl/#6572: a one-shot `limit=1000` aux query is newest-first, so the
    /// oldest reactions/edits/deletions past the clamp vanished. The paged
    /// drain must walk the keyset cursor until a short page and return every
    /// event exactly once.
    #[tokio::test]
    async fn query_all_pages_drains_past_the_page_clamp() {
        let keys = Keys::generate();
        // Newest-first store: 5 events, two sharing a second so the id
        // tiebreak is exercised.
        let mut store = [
            aux_event(&keys, 50, "e"),
            aux_event(&keys, 40, "d1"),
            aux_event(&keys, 40, "d2"),
            aux_event(&keys, 30, "c"),
            aux_event(&keys, 10, "a"),
        ];
        store.sort_by(|l, r| {
            r.event
                .created_at
                .cmp(&l.event.created_at)
                .then(l.event.id.cmp(&r.event.id))
        });
        let expected: Vec<_> = store.iter().map(|se| se.event.id).collect();
        let mut calls = Vec::new();

        let tenant = fresh_tenant("relay.example");
        let query = build_aux_query(tenant.community(), vec!["root".into()], &WINDOW_AUX_KINDS);
        let mut fetch = |q: &buzz_db::EventQuery| {
            calls.push((q.limit, q.until, q.before_id.clone()));
            // Emulate `query_events_on`: `created_at < until OR
            // (created_at = until AND id > before_id)`, newest-first, limit.
            let page: Vec<_> = store
                .iter()
                .filter(|se| match (q.until, q.before_id.as_deref()) {
                    (Some(until), Some(before)) => {
                        let ts = se.event.created_at.as_secs() as i64;
                        ts < until.timestamp()
                            || (ts == until.timestamp()
                                && se.event.id.as_bytes().as_slice() > before)
                    }
                    _ => true,
                })
                .take(q.limit.unwrap() as usize)
                .cloned()
                .collect();
            page
        };
        let events = query_all_pages(query, 2, &mut AuxReader::Fake(&mut fetch))
            .await
            .unwrap();

        assert_eq!(
            events.iter().map(|se| se.event.id).collect::<Vec<_>>(),
            expected
        );
        assert_eq!(calls.len(), 3, "2 full pages + 1 short page");
        assert!(calls.iter().all(|(limit, _, _)| *limit == Some(2)));
        assert_eq!(calls[0].1, None);
        // Second page resumes from the last row of the first (ts 40, larger id).
        assert_eq!(calls[1].1.unwrap().timestamp(), 40);
        assert_eq!(
            calls[1].2.as_deref(),
            Some(store[1].event.id.as_bytes().as_slice())
        );
        assert_eq!(calls[2].1.unwrap().timestamp(), 30);
    }

    #[tokio::test]
    async fn query_all_pages_stops_at_one_short_page() {
        let tenant = fresh_tenant("relay.example");
        let query = build_aux_query(tenant.community(), vec!["root".into()], &WINDOW_AUX_KINDS);
        let mut calls = 0;
        let mut fetch = |_q: &buzz_db::EventQuery| {
            calls += 1;
            Vec::new()
        };
        let events = query_all_pages(query, 1000, &mut AuxReader::Fake(&mut fetch))
            .await
            .unwrap();
        assert!(events.is_empty());
        assert_eq!(calls, 1);
    }

    #[test]
    fn bridge_search_mode_extension_defaults_to_full_text() {
        assert_eq!(
            extract_search_mode(&serde_json::json!({ "search": "pro" })),
            buzz_search::SearchMode::FullText
        );
        assert_eq!(
            extract_search_mode(&serde_json::json!({ "search": "pro", "search_mode": "word" })),
            buzz_search::SearchMode::FullText
        );
    }

    #[test]
    fn bridge_search_mode_extension_accepts_prefix_snake_or_camel_case() {
        assert_eq!(
            extract_search_mode(&serde_json::json!({ "search": "pro", "search_mode": "prefix" })),
            buzz_search::SearchMode::Prefix
        );
        assert_eq!(
            extract_search_mode(&serde_json::json!({ "search": "pro", "searchMode": "prefix" })),
            buzz_search::SearchMode::Prefix
        );
    }

    /// Attack 3 proof: two stateless relay pods sharing Redis must share one
    /// community-scoped NIP-98 seen-set. Pod A's first claim succeeds; pod B's
    /// replay of the same event id in the same community is rejected. The same
    /// id in a different community still succeeds, proving the key is scoped by
    /// server-resolved tenant rather than global process memory.
    async fn nip98_replay_guard_rejects_cross_pod_replay_on_bridge_path() {
        let pool = redis_pool();
        let pod_a = buzz_pubsub::RedisNip98ReplayGuard::new(pool.clone());
        let pod_b = buzz_pubsub::RedisNip98ReplayGuard::new(pool);
        let tenant_a = fresh_tenant("relay-a.example");
        let tenant_b = fresh_tenant("relay-b.example");
        let event_id_bytes = fresh_nip98_event_id_bytes();

        check_nip98_replay_with_guard(&pod_a, &tenant_a, event_id_bytes)
            .await
            .expect("first pod should claim fresh NIP-98 event id");

        let (status, _) = check_nip98_replay_with_guard(&pod_b, &tenant_a, event_id_bytes)
            .await
            .expect_err("second pod must reject same-community replay");
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        check_nip98_replay_with_guard(&pod_b, &tenant_b, event_id_bytes)
            .await
            .expect("same event id in a different community uses a distinct seen-set");
    }

    /// Attack 3 same-pod regression guard: replacing the process-local moka
    /// cache with a shared Redis seen-set must not weaken same-pod replay
    /// rejection. A single guard instance, called twice with the same
    /// `TenantContext` and the same event id, MUST reject the second call.
    /// Bites if `try_mark`'s admit/reject mapping is reversed or no-op'd.
    async fn nip98_replay_guard_rejects_same_pod_same_community_replay() {
        let pool = redis_pool();
        let pod = buzz_pubsub::RedisNip98ReplayGuard::new(pool);
        let tenant = fresh_tenant("relay-a.example");
        let event_id_bytes = fresh_nip98_event_id_bytes();

        check_nip98_replay_with_guard(&pod, &tenant, event_id_bytes)
            .await
            .expect("first claim on a fresh event id must succeed");

        let (status, _) = check_nip98_replay_with_guard(&pod, &tenant, event_id_bytes)
            .await
            .expect_err("same-pod replay of the same id+community must reject");
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    mod external_infra_redis_tests {
        use super::*;

        #[tokio::test]
        #[ignore = "requires Redis"]
        async fn nip98_replay_guard_rejects_cross_pod_replay_on_bridge_path() {
            super::nip98_replay_guard_rejects_cross_pod_replay_on_bridge_path().await;
        }

        #[tokio::test]
        #[ignore = "requires Redis"]
        async fn nip98_replay_guard_rejects_same_pod_same_community_replay() {
            super::nip98_replay_guard_rejects_same_pod_same_community_replay().await;
        }

        /// Sub-floor TTL proof: production `RedisNip98ReplayGuard` must lift a
        /// 30-second request to the default 120-second floor. Reads PTTL of the
        /// canonical community-scoped key immediately after the first claim so
        /// the proof does not sleep for 30 seconds or reimplement the clamp.
        #[tokio::test]
        #[ignore = "requires Redis"]
        async fn nip98_replay_guard_sub_floor_ttl_is_lifted_to_default_floor() {
            let pool = redis_pool();
            let guard = buzz_pubsub::RedisNip98ReplayGuard::new(pool.clone());
            let tenant = fresh_tenant("nip98-sub-floor.example");
            let event_id = EventBuilder::new(Kind::HttpAuth, "")
                .sign_with_keys(&Keys::generate())
                .expect("sign auth event")
                .id;
            let key = buzz_auth::nip98_replay::nip98_replay_key_for_scope(
                &tenant.community().to_string(),
                &event_id,
            );
            const REQUESTED_TTL_SECS: u64 = 30;

            assert!(
                guard
                    .try_mark(&tenant, &event_id, REQUESTED_TTL_SECS)
                    .await
                    .expect("first claim"),
                "first claim of a unique NIP-98 event id must succeed"
            );

            let mut conn = pool.get().await.expect("redis conn");
            let pttl_ms: i64 = redis::cmd("PTTL")
                .arg(&key)
                .query_async(&mut *conn)
                .await
                .expect("pttl");
            let _: i64 = redis::cmd("DEL")
                .arg(&key)
                .query_async(&mut *conn)
                .await
                .expect("del unique nip98 key");

            let requested_ms = i64::try_from(REQUESTED_TTL_SECS)
                .expect("requested ttl fits pttl")
                .saturating_mul(1000);
            let floor_ms = i64::try_from(DEFAULT_REPLAY_TTL_SECS)
                .expect("replay floor fits pttl")
                .saturating_mul(1000);
            // Local Redis SET EX is millisecond-close to the requested seconds.
            // Keep slack far below 30s so a raw EX 30 cannot satisfy the floor.
            const TOLERANCE_MS: i64 = 5_000;
            assert!(
                TOLERANCE_MS < requested_ms,
                "timing tolerance must not make a raw {REQUESTED_TTL_SECS}s TTL pass"
            );
            assert!(
                pttl_ms > requested_ms,
                "sub-floor claim must not keep the requested {REQUESTED_TTL_SECS}s TTL, pttl_ms={pttl_ms}"
            );
            assert!(
                pttl_ms <= floor_ms,
                "marker TTL must not exceed the default floor, pttl_ms={pttl_ms} floor_ms={floor_ms}"
            );
            assert!(
                pttl_ms >= floor_ms - TOLERANCE_MS,
                "marker must receive the {DEFAULT_REPLAY_TTL_SECS}s default floor rather than raw {REQUESTED_TTL_SECS}s, pttl_ms={pttl_ms}"
            );
        }
    }

    /// Attack 3 fail-closed guard: a stateless worker that loses Redis MUST
    /// reject the request, never admit it. The shared seen-set is the
    /// freshness fence; degrading to "best effort, allow on error" forfeits
    /// the proof (per the `Nip98ReplayGuard` trait contract,
    /// `buzz-auth/src/nip98_replay.rs:70-73`).
    ///
    /// This test does not require Redis — it injects a guard that always
    /// returns `Err`, exercising the `Err =>` arm in
    /// `check_nip98_replay_with_guard` directly. Bites if the arm is changed
    /// to admit (`Ok(())` / `Ok(true)`) instead of returning 401.
    #[tokio::test]
    async fn nip98_replay_check_fails_closed_when_guard_errors() {
        use buzz_auth::AuthError;
        use nostr::EventId;
        use std::future::Future;
        use std::pin::Pin;

        struct AlwaysErrGuard;
        impl Nip98ReplayGuard for AlwaysErrGuard {
            fn try_mark_in_scope<'a>(
                &'a self,
                _scope: &'a str,
                _event_id: &'a EventId,
                _ttl_secs: u64,
            ) -> Pin<Box<dyn Future<Output = Result<bool, AuthError>> + Send + 'a>> {
                Box::pin(async {
                    Err(AuthError::Internal(
                        "simulated Redis pool acquire failure".into(),
                    ))
                })
            }
        }

        let guard = AlwaysErrGuard;
        let tenant = fresh_tenant("relay-a.example");
        let event_id_bytes = fresh_nip98_event_id_bytes();

        let (status, body) = check_nip98_replay_with_guard(&guard, &tenant, event_id_bytes)
            .await
            .expect_err("guard error MUST fail closed, never admit");
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "fail-closed must return 401"
        );
        let msg = body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        assert!(
            msg.contains("replay check unavailable"),
            "fail-closed body must carry the unavailable signal so callers can \
             distinguish unavailability from replay; got body = {body:?}"
        );
    }

    /// Build a signed NIP-98 event JSON string for `url` + `method`, mirroring
    /// `buzz_auth::nip98::tests::make_nip98_event` so the bridge tests don't
    /// reach into buzz-auth's test scope.
    ///
    /// A per-request test-only custom tag is included before signing so two
    /// helper-issued tokens for the same key/url/method in the same second
    /// still get distinct event IDs. Content stays empty; no payload tag.
    fn build_nip98_event_json(keys: &Keys, url: &str, method: &str) -> String {
        let request_tag = uuid::Uuid::new_v4().to_string();
        let tags = vec![
            Tag::parse(["u", url]).expect("u tag"),
            Tag::parse(["method", method]).expect("method tag"),
            Tag::parse(["bridge-test", &request_tag]).expect("per-request test tag"),
        ];
        let event = EventBuilder::new(Kind::HttpAuth, "")
            .tags(tags)
            .sign_with_keys(keys)
            .expect("sign NIP-98 event");
        serde_json::to_string(&event).expect("serialize")
    }

    #[test]
    fn freshly_issued_nip98_request_tokens_have_distinct_ids() {
        let keys = Keys::generate();
        let url = "https://relay.example/events";
        let first = build_nip98_event_json(&keys, url, "POST");
        let second = build_nip98_event_json(&keys, url, "POST");
        let first_id = serde_json::from_str::<nostr::Event>(&first)
            .expect("first token")
            .id
            .to_bytes();
        let second_id = serde_json::from_str::<nostr::Event>(&second)
            .expect("second token")
            .id
            .to_bytes();
        assert_ne!(
            first_id, second_id,
            "two freshly issued signed request tokens must not share an event ID"
        );
        assert!(!first.contains("payload"));
        assert!(!second.contains("payload"));
    }

    /// Build a `HeaderMap` with the NIP-98 event base64-encoded in
    /// `Authorization: Nostr <base64>`, matching the production bridge auth
    /// header shape.
    fn nip98_auth_headers(event_json: &str) -> axum::http::HeaderMap {
        use base64::engine::general_purpose::STANDARD as BASE64;
        let mut headers = axum::http::HeaderMap::new();
        let value = format!("Nostr {}", BASE64.encode(event_json.as_bytes()));
        headers.insert(
            axum::http::header::AUTHORIZATION,
            value.parse().expect("valid header value"),
        );
        headers
    }

    /// Row 44 obligation: a NIP-98 event signed against community A's host
    /// MUST be rejected at the bridge when the request resolves to community
    /// B's host. The conformance text in `docs/multi-tenant-conformance.md`
    /// states: "NIP-98 `u` URL host must match `req.community`". Before this
    /// gap closed, `expected_url` was derived from `state.config.relay_url`
    /// (one static string per deployment), so any request to *any* host on a
    /// multi-tenant deployment would verify against community A's URL — both
    /// admitting cross-host forgeries (event signed for A presented at B) and
    /// rejecting every legitimate request whose community host wasn't the
    /// single configured one.
    ///
    /// This test bites if `nip98_expected_url` is reverted to use
    /// `config.relay_url`'s host (the original `canonical_url` behavior).
    #[test]
    fn verify_bridge_auth_rejects_nip98_event_signed_for_wrong_communitys_host() {
        let keys = Keys::generate();
        // Client signs an event for community A's host, then presents it at a
        // request whose `Host` header resolved to community B.
        let signed_url = "https://host-a.example/events";
        let event_json = build_nip98_event_json(&keys, signed_url, "POST");
        let headers = nip98_auth_headers(&event_json);

        let config_relay_url = "wss://host-a.example"; // doesn't matter — only used for scheme.
        let tenant_b = fresh_tenant("host-b.example");
        let expected_url = nip98_expected_url(config_relay_url, &tenant_b, "/events");

        let (status, body) = verify_bridge_auth(&headers, "POST", &expected_url, Some(b""), true)
            .expect_err(
                "cross-host NIP-98 event MUST be rejected — row 44: `u` URL host \
                 must match req.community",
            );
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "cross-host rejection must be a 401, not silently admitted"
        );
        let msg = body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        assert!(
            msg.contains("URL mismatch"),
            "rejection must carry the URL-mismatch signal so callers can \
             distinguish it from other auth failures; got body = {body:?}"
        );
    }

    #[test]
    fn verify_bridge_auth_can_require_payload_tag_for_json_body_endpoints() {
        let keys = Keys::generate();
        let signed_url = "https://host-a.example/operator/communities";
        let event_json = build_nip98_event_json(&keys, signed_url, "POST");
        let headers = nip98_auth_headers(&event_json);

        let (status, body) = verify_bridge_auth_with_options(
            &headers,
            "POST",
            signed_url,
            Some(br#"{"host":"created.example"}"#),
            true,
            true,
        )
        .expect_err("body-bearing operator requests must require a payload tag");

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let msg = body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        assert!(
            msg.contains("missing payload tag"),
            "rejection should explain the payload binding failure; got body = {body:?}"
        );
    }

    /// Positive control for the cross-host test: a NIP-98 event signed for
    /// host A MUST be accepted at a request whose tenant resolved to host A.
    /// Without this, the cross-host test could be passing vacuously (e.g. if
    /// `nip98_expected_url` always produced a URL no event could match).
    #[test]
    fn verify_bridge_auth_accepts_nip98_event_signed_for_matching_host() {
        let keys = Keys::generate();
        let signed_url = "https://host-a.example/events";
        let event_json = build_nip98_event_json(&keys, signed_url, "POST");
        let headers = nip98_auth_headers(&event_json);

        // Configured relay URL deliberately differs in host from the request's
        // tenant host — proving the helper uses `tenant.host()`, not the config.
        let config_relay_url = "wss://other-config-host.example";
        let tenant_a = fresh_tenant("host-a.example");
        let expected_url = nip98_expected_url(config_relay_url, &tenant_a, "/events");

        let VerifiedBridgeAuth {
            pubkey,
            signed_created_at,
            ..
        } = verify_bridge_auth(&headers, "POST", &expected_url, Some(b""), true)
            .expect("matching-host NIP-98 event must verify");
        assert_eq!(
            pubkey,
            keys.public_key(),
            "returned pubkey must be the signer's"
        );
        assert!(
            signed_created_at.is_some(),
            "verified NIP-98 auth must retain its signed timestamp"
        );
    }

    /// Mirror of the query-reconstruction `authorize_moderation_read` performs
    /// before calling [`nip98_expected_url`], so the tests below pin the exact
    /// seam without a DB harness. Kept in lockstep with the production match arm.
    fn moderation_read_expected_url(
        config_relay_url: &str,
        tenant: &TenantContext,
        path: &str,
        raw_query: Option<&str>,
    ) -> String {
        let path_with_query = match raw_query {
            Some(q) if !q.is_empty() => format!("{path}?{q}"),
            _ => path.to_string(),
        };
        nip98_expected_url(config_relay_url, tenant, &path_with_query)
    }

    /// L7 read-auth blocker (Wren, #1591 sweep): the CLI signs the *full*
    /// request URL — including `?limit=…&status=…` — but the relay used to
    /// reconstruct the expected URL from the bare path only, so
    /// `buzz moderation reports` / `audit` 401'd on a NIP-98 URL mismatch in
    /// normal use. This pins that a query-bearing GET verifies iff the expected
    /// URL carries the same query verbatim. Bites if the query is ever dropped
    /// from `authorize_moderation_read`'s expected-URL reconstruction.
    #[test]
    fn moderation_read_query_bearing_nip98_event_verifies_with_matching_query() {
        let keys = Keys::generate();
        // CLI signs the URL it actually requests, query and all.
        let signed_url = "https://host-a.example/moderation/reports?limit=20&status=open";
        let event_json = build_nip98_event_json(&keys, signed_url, "GET");
        let headers = nip98_auth_headers(&event_json);

        let tenant_a = fresh_tenant("host-a.example");
        let expected_url = moderation_read_expected_url(
            "wss://config-host.example",
            &tenant_a,
            "/moderation/reports",
            Some("limit=20&status=open"),
        );

        let VerifiedBridgeAuth { pubkey, .. } =
            verify_bridge_auth(&headers, "GET", &expected_url, None, true)
                .expect("query-bearing moderation read must verify against the same query");
        assert_eq!(pubkey, keys.public_key());
    }

    /// Anti-regression control proving the fix is load-bearing: the same
    /// query-bearing event MUST be rejected when the expected URL omits the
    /// query — the pre-fix behavior. If this ever passes, the relay has
    /// silently reverted to bare-path reconstruction.
    #[test]
    fn moderation_read_query_bearing_nip98_event_rejected_against_bare_path() {
        let keys = Keys::generate();
        let signed_url = "https://host-a.example/moderation/reports?limit=20&status=open";
        let event_json = build_nip98_event_json(&keys, signed_url, "GET");
        let headers = nip98_auth_headers(&event_json);

        let tenant_a = fresh_tenant("host-a.example");
        // No query — the broken pre-fix reconstruction.
        let bare_url = moderation_read_expected_url(
            "wss://config-host.example",
            &tenant_a,
            "/moderation/reports",
            None,
        );

        let (status, body) = verify_bridge_auth(&headers, "GET", &bare_url, None, true)
            .expect_err("query-signed event MUST NOT match a bare-path expected URL");
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let msg = body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        assert!(
            msg.contains("URL mismatch"),
            "rejection must be a URL mismatch; got body = {body:?}"
        );
    }

    /// `audit?limit=20` — the second query-bearing read path — verifies the
    /// same way. Pins that the reconstruction is generic over the path, not
    /// special-cased to `reports`.
    #[test]
    fn moderation_read_audit_query_bearing_nip98_event_verifies() {
        let keys = Keys::generate();
        let signed_url = "https://host-a.example/moderation/audit?limit=20";
        let event_json = build_nip98_event_json(&keys, signed_url, "GET");
        let headers = nip98_auth_headers(&event_json);

        let tenant_a = fresh_tenant("host-a.example");
        let expected_url = moderation_read_expected_url(
            "wss://config-host.example",
            &tenant_a,
            "/moderation/audit",
            Some("limit=20"),
        );

        let VerifiedBridgeAuth { pubkey, .. } =
            verify_bridge_auth(&headers, "GET", &expected_url, None, true)
                .expect("audit query-bearing read must verify");
        assert_eq!(pubkey, keys.public_key());
    }

    /// `restricted` has no query and passes `None`, so its expected URL stays
    /// the bare path — a query-less signed event verifies. Pins Wren's
    /// "preserve restricted no-query behavior" checklist item.
    #[test]
    fn moderation_read_restricted_no_query_still_verifies() {
        let keys = Keys::generate();
        let signed_url = "https://host-a.example/moderation/restricted";
        let event_json = build_nip98_event_json(&keys, signed_url, "GET");
        let headers = nip98_auth_headers(&event_json);

        let tenant_a = fresh_tenant("host-a.example");
        let expected_url = moderation_read_expected_url(
            "wss://config-host.example",
            &tenant_a,
            "/moderation/restricted",
            None,
        );
        assert_eq!(expected_url, "https://host-a.example/moderation/restricted");

        let VerifiedBridgeAuth { pubkey, .. } =
            verify_bridge_auth(&headers, "GET", &expected_url, None, true)
                .expect("query-less restricted read must verify against the bare path");
        assert_eq!(pubkey, keys.public_key());
    }

    /// `nip98_expected_url` derives host from `tenant`, not from
    /// `config_relay_url`. Pin both directions: changing the tenant's host
    /// changes the output; changing the config's host does NOT.
    #[test]
    fn nip98_expected_url_uses_tenant_host_not_config_host() {
        let tenant_a = fresh_tenant("host-a.example");
        let tenant_b = fresh_tenant("host-b.example");

        let url_a = nip98_expected_url("wss://config-host.example", &tenant_a, "/events");
        let url_b = nip98_expected_url("wss://config-host.example", &tenant_b, "/events");
        assert_eq!(url_a, "https://host-a.example/events");
        assert_eq!(url_b, "https://host-b.example/events");

        // Same tenant, two different config hosts → output is identical.
        // (If config-host ever leaked into the URL, this assertion would bite.)
        let url_a_alt_config =
            nip98_expected_url("wss://different-config.example", &tenant_a, "/events");
        assert_eq!(
            url_a, url_a_alt_config,
            "config-relay-url's host MUST NOT influence the NIP-98 expected URL — \
             only its scheme contributes"
        );
    }

    /// `nip98_expected_url` derives scheme from `config_relay_url`'s prefix:
    /// `wss://` → `https`, everything else → `http`. Deployments that run
    /// `ws://` in dev/test still need a NIP-98 URL the client can sign against.
    #[test]
    fn nip98_expected_url_derives_scheme_from_config() {
        let tenant = fresh_tenant("host-a.example");
        assert_eq!(
            nip98_expected_url("wss://config.example", &tenant, "/events"),
            "https://host-a.example/events",
            "wss:// production config → https:// URL"
        );
        assert_eq!(
            nip98_expected_url("ws://config.example", &tenant, "/events"),
            "http://host-a.example/events",
            "ws:// dev config → http:// URL"
        );
    }

    // ----- NIP-42 host-binding tests (sibling of NIP-98 row 44 obligation) -----

    /// Sign a NIP-42 AUTH event with `relay` tag = `relay_url`, then verify
    /// it against `expected_relay_url`. Returns the `verify_nip42_event` result.
    fn verify_nip42_with_urls(
        challenge: &str,
        signed_relay_url: &str,
        expected_relay_url: &str,
    ) -> Result<(), buzz_auth::AuthError> {
        let keys = Keys::generate();
        let parsed = nostr::RelayUrl::parse(signed_relay_url).expect("valid relay url");
        let event = EventBuilder::auth(challenge, parsed)
            .sign_with_keys(&keys)
            .expect("sign auth event");
        buzz_auth::nip42::verify_nip42_event(&event, challenge, expected_relay_url)
    }

    /// Row 44 obligation (WS side): a NIP-42 AUTH event signed against
    /// community A's host MUST be rejected on a connection whose tenant
    /// resolved to community B's host. Before this gap closed, `handle_auth`
    /// verified against `state.config.relay_url` (one static string per
    /// deployment), so a token-of-A presented on B's connection would pass —
    /// the cross-host hole `nip98_expected_url` already closed on the HTTP
    /// side, mirrored here on the WS side.
    ///
    /// Scenario: a multi-tenant deployment whose `config.relay_url` is set to
    /// community A's host (a realistic accident — config can only hold one
    /// host). An attacker on a B-bound connection signs an AUTH event matching
    /// that config URL (publicly knowable). Pre-fix: expected = config = A's
    /// URL = the signed URL → ACCEPT (cross-host hole). Post-fix: expected
    /// derives from `tenant.host() = B` ≠ signed (A) → REJECT.
    ///
    /// This test bites if `nip42_expected_relay_url` is reverted to return
    /// `config.relay_url` verbatim — the exact regression the helper guards.
    #[test]
    fn verify_nip42_rejects_event_signed_for_wrong_communitys_host() {
        let challenge = "fixed-challenge-for-test";
        // Config URL is A's host (deployment-wide static), and the attacker
        // signs an AUTH event with that same URL. Both are knowable to the
        // attacker. Connection arrived at community B.
        let config_relay_url = "ws://host-a.example:3100";
        let signed_relay_url = "ws://host-a.example:3100";
        let tenant_b = fresh_tenant("host-b.example:3100");
        let expected = nip42_expected_relay_url(config_relay_url, &tenant_b);

        let err = verify_nip42_with_urls(challenge, signed_relay_url, &expected).expect_err(
            "cross-host NIP-42 AUTH event MUST be rejected — row 44 sibling: \
             `relay` URL host must match the per-tenant host, NOT the \
             deployment-wide config URL",
        );
        assert!(
            matches!(err, buzz_auth::AuthError::RelayUrlMismatch),
            "rejection must carry RelayUrlMismatch (not a generic failure) so \
             callers can distinguish it from other auth failures; got {err:?}"
        );
    }

    /// Positive control: a NIP-42 AUTH event signed for host A MUST be
    /// accepted on a connection whose tenant resolved to host A. Without
    /// this, the cross-host test could be passing vacuously (e.g. if
    /// `nip42_expected_relay_url` always produced a URL no event could match).
    #[test]
    fn verify_nip42_accepts_event_signed_for_matching_host() {
        let challenge = "fixed-challenge-for-test";
        let signed_relay_url = "ws://host-a.example:3100";
        // Configured relay URL deliberately differs in host from the tenant's
        // host — proving the helper uses `tenant.host()`, not the config.
        let config_relay_url = "ws://other-config-host.example";
        let tenant_a = fresh_tenant("host-a.example:3100");
        let expected = nip42_expected_relay_url(config_relay_url, &tenant_a);

        verify_nip42_with_urls(challenge, signed_relay_url, &expected)
            .expect("matching-host NIP-42 AUTH event must verify");
    }

    /// `nip42_expected_relay_url` derives host from `tenant`, not from
    /// `config_relay_url`. Pin both directions: changing the tenant's host
    /// changes the output; changing the config's host does NOT.
    #[test]
    fn nip42_expected_relay_url_uses_tenant_host_not_config_host() {
        let tenant_a = fresh_tenant("host-a.example:3100");
        let tenant_b = fresh_tenant("host-b.example:3100");

        let url_a = nip42_expected_relay_url("ws://config-host.example", &tenant_a);
        let url_b = nip42_expected_relay_url("ws://config-host.example", &tenant_b);
        assert_eq!(url_a, "ws://host-a.example:3100");
        assert_eq!(url_b, "ws://host-b.example:3100");

        // Same tenant, two different config hosts → output is identical.
        // (If config-host ever leaked into the URL, this assertion would bite —
        // catches the exact "reverted to config host" regression.)
        let url_a_alt_config = nip42_expected_relay_url("ws://different-config.example", &tenant_a);
        assert_eq!(
            url_a, url_a_alt_config,
            "config-relay-url's host MUST NOT influence the NIP-42 expected URL — \
             only its scheme contributes"
        );
    }

    /// `nip42_expected_relay_url` derives scheme from `config_relay_url`'s
    /// prefix: `wss://` → `wss`, everything else → `ws`. Deployments that run
    /// `ws://` in dev/test must produce a `ws://` URL that matches what
    /// tungstenite clients put in the AUTH event's `relay` tag.
    #[test]
    fn nip42_expected_relay_url_derives_scheme_from_config() {
        let tenant = fresh_tenant("host-a.example:3100");
        assert_eq!(
            nip42_expected_relay_url("wss://config.example", &tenant),
            "wss://host-a.example:3100",
            "wss:// production config → wss:// URL"
        );
        assert_eq!(
            nip42_expected_relay_url("ws://config.example", &tenant),
            "ws://host-a.example:3100",
            "ws:// dev config → ws:// URL"
        );
    }

    /// Build a kind:30174 engram envelope authored by `agent`, tagged with `owner`.
    fn engram_envelope(agent: &Keys, owner_hex: &str) -> buzz_core::StoredEvent {
        let d_tag = Tag::custom(
            nostr::TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::D)),
            ["abcd1234"],
        );
        let p_tag = Tag::custom(
            nostr::TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::P)),
            [owner_hex],
        );
        let ev = EventBuilder::new(Kind::Custom(30174), "engram body")
            .tags([d_tag, p_tag])
            .sign_with_keys(agent)
            .expect("sign engram");
        buzz_core::StoredEvent::new(ev, None)
    }

    /// Regression test for the NIP-AE `/query` search leak (PR #593 review).
    ///
    /// Setup: two engram envelopes by different agents for different owners.
    /// An authorized search for `{kinds:[30174], #p:[owner_a]}` would be
    /// approved by the engram gate (owner_a is querying engrams addressed to
    /// them). The FTS pushdown only carries `kind:=[30174]`, so the
    /// envelope for owner_b can come back as a text-match hit. The post-filter
    /// in `search_hit_accepted` must reject it.
    #[test]
    fn search_hit_rejects_envelope_with_mismatched_p_tag() {
        let agent_a = Keys::generate();
        let agent_b = Keys::generate();
        let owner_a = Keys::generate().public_key().to_hex();
        let owner_b = Keys::generate().public_key().to_hex();

        let env_for_a = engram_envelope(&agent_a, &owner_a);
        let env_for_b = engram_envelope(&agent_b, &owner_b);

        let p_tag = SingleLetterTag::lowercase(Alphabet::P);
        let filter = nostr::Filter::new()
            .kind(Kind::Custom(30174))
            .custom_tags(p_tag, [&owner_a]);

        // 30174 is not owner-gated, so any reader hex is fine here.
        let reader = Keys::generate().public_key().to_hex();
        assert!(
            search_hit_accepted(&filter, &env_for_a, &[], &reader),
            "envelope addressed to owner_a must be returned"
        );
        assert!(
            !search_hit_accepted(&filter, &env_for_b, &[], &reader),
            "envelope addressed to owner_b must NOT be returned for a #p=[owner_a] search"
        );
    }

    /// `authors=[agent_a]` search must not return an envelope authored by agent_b,
    /// even if the FTS text match would otherwise surface it. (The FTS query does
    /// carry an `authors` pushdown today, so this is defence-in-depth; mirroring
    /// the WS contract.)
    #[test]
    fn search_hit_rejects_event_with_mismatched_author() {
        let agent_a = Keys::generate();
        let agent_b = Keys::generate();
        let owner = Keys::generate().public_key().to_hex();

        let env_a = engram_envelope(&agent_a, &owner);
        let env_b = engram_envelope(&agent_b, &owner);

        let filter = nostr::Filter::new()
            .kind(Kind::Custom(30174))
            .author(agent_a.public_key());

        let reader = Keys::generate().public_key().to_hex();
        assert!(search_hit_accepted(&filter, &env_a, &[], &reader));
        assert!(
            !search_hit_accepted(&filter, &env_b, &[], &reader),
            "authors=[agent_a] search must not return events authored by agent_b"
        );
    }

    /// Channel-scoped events outside the caller's accessible-channel set are
    /// rejected by the post-filter regardless of NIP-01 match.
    #[test]
    fn search_hit_rejects_inaccessible_channel() {
        let agent = Keys::generate();
        let owner = Keys::generate().public_key().to_hex();
        let mut stored = engram_envelope(&agent, &owner);
        let scoped_channel = uuid::Uuid::new_v4();
        stored.channel_id = Some(scoped_channel);

        let p_tag = SingleLetterTag::lowercase(Alphabet::P);
        let filter = nostr::Filter::new()
            .kind(Kind::Custom(30174))
            .custom_tags(p_tag, [&owner]);

        let reader = Keys::generate().public_key().to_hex();
        assert!(
            !search_hit_accepted(&filter, &stored, &[], &reader),
            "channel-scoped hit must be rejected when caller has no channel access"
        );
        assert!(
            search_hit_accepted(&filter, &stored, &[scoped_channel], &reader),
            "channel-scoped hit must be accepted when caller has access to that channel"
        );
    }

    #[test]
    fn extract_buzz_channel_requires_one_string_value() {
        assert_eq!(
            extract_buzz_channel(&serde_json::json!({"#buzz-channel": ["channel-a"]})),
            Some("channel-a")
        );
        assert_eq!(
            extract_buzz_channel(&serde_json::json!({"#buzz-channel": ["channel-a", "channel-b"]})),
            None
        );
        assert_eq!(
            extract_buzz_channel(&serde_json::json!({"#buzz-channel": [42]})),
            None
        );
    }

    #[test]
    fn extract_before_id_valid_hex() {
        let hex = "a".repeat(64);
        let raw = serde_json::json!({ "before_id": hex });
        match extract_before_id(&raw) {
            BeforeId::Valid(id) => assert_eq!(id.len(), 32),
            _ => panic!("64-char hex must parse as Valid"),
        }
    }

    #[test]
    fn extract_before_id_short_hex() {
        let raw = serde_json::json!({ "before_id": "a".repeat(63) });
        assert!(matches!(extract_before_id(&raw), BeforeId::Malformed));
    }

    #[test]
    fn extract_before_id_long_hex() {
        let raw = serde_json::json!({ "before_id": "a".repeat(65) });
        assert!(matches!(extract_before_id(&raw), BeforeId::Malformed));
    }

    #[test]
    fn extract_before_id_invalid_hex_chars() {
        let raw = serde_json::json!({ "before_id": "z".repeat(64) });
        assert!(matches!(extract_before_id(&raw), BeforeId::Malformed));
    }

    #[test]
    fn extract_before_id_absent() {
        let raw = serde_json::json!({});
        assert!(matches!(extract_before_id(&raw), BeforeId::Absent));
    }

    #[test]
    fn extract_before_id_non_string() {
        let raw = serde_json::json!({ "before_id": 12345 });
        assert!(matches!(extract_before_id(&raw), BeforeId::Malformed));
    }

    /// Extension flags opt in only on a literal JSON `true` — absent,
    /// non-boolean, and truthy-but-not-bool values all read as false, so a
    /// malformed filter degrades to a normal query instead of a wrong window.
    #[test]
    fn extension_flag_only_true_on_literal_bool() {
        assert!(extension_flag(
            &serde_json::json!({ "top_level": true }),
            "top_level"
        ));
        assert!(!extension_flag(
            &serde_json::json!({ "top_level": false }),
            "top_level"
        ));
        assert!(!extension_flag(&serde_json::json!({}), "top_level"));
        assert!(!extension_flag(
            &serde_json::json!({ "top_level": "true" }),
            "top_level"
        ));
        assert!(!extension_flag(
            &serde_json::json!({ "top_level": 1 }),
            "top_level"
        ));
    }

    #[test]
    fn extract_page_offset_absent_is_none() {
        // No `page` → default offset (unrelated general queries untouched).
        let raw = serde_json::json!({ "kinds": [0], "limit": 50 });
        assert_eq!(extract_page_offset(&raw, Some(50)), None);
    }

    #[test]
    fn extract_page_offset_page_one_is_none() {
        // Page 1 is the first page → offset 0, expressed as no override.
        let raw = serde_json::json!({ "kinds": [0], "limit": 50, "page": 1 });
        assert_eq!(extract_page_offset(&raw, Some(50)), None);
    }

    #[test]
    fn extract_page_offset_computes_offset_from_page_and_limit() {
        // Empty people-directory contract: page N → (N-1) * limit.
        let raw = serde_json::json!({ "kinds": [0], "limit": 50, "page": 3 });
        assert_eq!(extract_page_offset(&raw, Some(50)), Some(100));
    }

    #[test]
    fn extract_page_offset_missing_limit_is_none() {
        // Can't size a page without a limit.
        let raw = serde_json::json!({ "kinds": [0], "page": 2 });
        assert_eq!(extract_page_offset(&raw, None), None);
    }

    /// Offsets are sized from the *clamped* limit the DB will honor, not from
    /// what the client asked for. `filter_to_query_params` clamps an absent or
    /// over-ceiling `limit` to `DEFAULT_MAX_PAGE_LIMIT` (guarded in
    /// `handlers::req::tests::req_filter_limit_clamps_to_advertised_nip11_max_limit`)
    /// and that clamped value is what arrives here — so page N starts exactly
    /// N-1 full pages in. Sizing from an unclamped limit would step past rows
    /// the previous page never returned.
    #[test]
    fn extract_page_offset_sizes_pages_from_clamped_limit() {
        let clamped = buzz_db::DEFAULT_MAX_PAGE_LIMIT;

        assert_eq!(
            extract_page_offset(&serde_json::json!({ "page": 2 }), Some(clamped)),
            Some(clamped)
        );
        assert_eq!(
            extract_page_offset(&serde_json::json!({ "page": 3 }), Some(clamped)),
            Some(clamped * 2)
        );
    }

    #[test]
    fn extract_depth_limit_valid() {
        let raw = serde_json::json!({ "depth_limit": 3 });
        assert_eq!(extract_depth_limit(&raw), Some(3));
    }

    #[test]
    fn extract_thread_cursor_valid() {
        // Timestamp-only cursor: 8-byte BE seconds, no tiebreak id.
        let raw = serde_json::json!({ "thread_cursor": 1_782_866_946_i64 });
        assert_eq!(
            extract_thread_cursor(&raw),
            Some(1_782_866_946_i64.to_be_bytes().to_vec())
        );
    }

    #[test]
    fn extract_thread_cursor_camel_case() {
        let raw = serde_json::json!({ "threadCursor": 42_i64 });
        assert_eq!(
            extract_thread_cursor(&raw),
            Some(42_i64.to_be_bytes().to_vec())
        );
    }

    #[test]
    fn extract_thread_cursor_composite() {
        // Composite cursor: 8-byte BE seconds followed by the raw event-id bytes.
        let id_hex = "aa".repeat(32);
        let raw = serde_json::json!({
            "thread_cursor": 1_782_866_946_i64,
            "thread_cursor_id": id_hex,
        });
        let mut expected = 1_782_866_946_i64.to_be_bytes().to_vec();
        expected.extend_from_slice(&[0xaa; 32]);
        assert_eq!(extract_thread_cursor(&raw), Some(expected));
    }

    #[test]
    fn extract_thread_cursor_composite_camel_case() {
        let id_hex = "bb".repeat(32);
        let raw = serde_json::json!({
            "threadCursor": 7_i64,
            "threadCursorId": id_hex,
        });
        let mut expected = 7_i64.to_be_bytes().to_vec();
        expected.extend_from_slice(&[0xbb; 32]);
        assert_eq!(extract_thread_cursor(&raw), Some(expected));
    }

    #[test]
    fn extract_thread_cursor_ignores_bad_id_hex() {
        // A malformed id falls back to timestamp-only rather than erroring.
        let raw = serde_json::json!({
            "thread_cursor": 5_i64,
            "thread_cursor_id": "not-hex",
        });
        assert_eq!(
            extract_thread_cursor(&raw),
            Some(5_i64.to_be_bytes().to_vec())
        );
    }

    #[test]
    fn extract_thread_cursor_absent() {
        let raw = serde_json::json!({ "depth_limit": 3 });
        assert!(extract_thread_cursor(&raw).is_none());
    }

    #[test]
    fn extract_depth_limit_zero() {
        let raw = serde_json::json!({ "depth_limit": 0 });
        assert_eq!(extract_depth_limit(&raw), Some(0));
    }

    #[test]
    fn extract_depth_limit_u32_max() {
        let raw = serde_json::json!({ "depth_limit": u32::MAX });
        assert_eq!(extract_depth_limit(&raw), Some(u32::MAX));
    }

    #[test]
    fn extract_depth_limit_overflow() {
        let raw = serde_json::json!({ "depth_limit": (u32::MAX as u64) + 1 });
        assert!(extract_depth_limit(&raw).is_none());
    }

    #[test]
    fn extract_depth_limit_negative() {
        let raw = serde_json::json!({ "depth_limit": -1 });
        assert!(extract_depth_limit(&raw).is_none());
    }

    #[test]
    fn extract_depth_limit_absent() {
        let raw = serde_json::json!({});
        assert!(extract_depth_limit(&raw).is_none());
    }

    #[test]
    fn extract_depth_limit_float() {
        let raw = serde_json::json!({ "depth_limit": 3.5 });
        assert!(extract_depth_limit(&raw).is_none());
    }

    #[test]
    fn extract_feed_types_valid() {
        let raw = serde_json::json!({ "feed_types": ["mentions", "activity"] });
        assert_eq!(
            extract_feed_types(&raw),
            Some(vec!["mentions".to_string(), "activity".to_string()])
        );
    }

    #[test]
    fn extract_feed_types_empty_array() {
        let raw = serde_json::json!({ "feed_types": [] });
        assert!(extract_feed_types(&raw).is_none());
    }

    #[test]
    fn extract_feed_types_mixed_types() {
        let raw = serde_json::json!({ "feed_types": ["mentions", 42, "activity"] });
        assert_eq!(
            extract_feed_types(&raw),
            Some(vec!["mentions".to_string(), "activity".to_string()])
        );
    }

    #[test]
    fn extract_feed_types_absent() {
        let raw = serde_json::json!({});
        assert!(extract_feed_types(&raw).is_none());
    }

    #[test]
    fn extract_feed_types_non_array() {
        let raw = serde_json::json!({ "feed_types": "mentions" });
        assert!(extract_feed_types(&raw).is_none());
    }

    #[test]
    fn event_accessible_no_channel() {
        let keys = Keys::generate();
        let ev = EventBuilder::new(Kind::Custom(1), "test")
            .sign_with_keys(&keys)
            .unwrap();
        let se = buzz_core::StoredEvent::new(ev, None);
        assert!(event_in_accessible_channel(&se, &[]));
    }

    #[test]
    fn event_accessible_matching_channel() {
        let keys = Keys::generate();
        let ev = EventBuilder::new(Kind::Custom(1), "test")
            .sign_with_keys(&keys)
            .unwrap();
        let ch = uuid::Uuid::new_v4();
        let mut se = buzz_core::StoredEvent::new(ev, None);
        se.channel_id = Some(ch);
        assert!(event_in_accessible_channel(&se, &[ch]));
    }

    #[test]
    fn event_inaccessible_channel() {
        let keys = Keys::generate();
        let ev = EventBuilder::new(Kind::Custom(1), "test")
            .sign_with_keys(&keys)
            .unwrap();
        let ch = uuid::Uuid::new_v4();
        let other = uuid::Uuid::new_v4();
        let mut se = buzz_core::StoredEvent::new(ev, None);
        se.channel_id = Some(ch);
        assert!(!event_in_accessible_channel(&se, &[other]));
    }

    /// NIP-DV regression: a relay-signed kind:30622 snapshot must not leak via
    /// search through a kindless `ids:[snapshot_id]` filter that carries no #p.
    /// `filters_match` passes (id matches), channel check passes (channel_id =
    /// None), so only the result-level `reader_authorized_for_event` check
    /// stands between a third party and the owner's private hide set.
    #[test]
    fn search_hit_rejects_dm_visibility_for_kindless_ids_third_party() {
        let relay = Keys::generate();
        let viewer = Keys::generate().public_key().to_hex();
        let third_party = Keys::generate().public_key().to_hex();

        let d_tag = Tag::custom(
            nostr::TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::D)),
            [&viewer],
        );
        let p_tag = Tag::custom(
            nostr::TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::P)),
            [&viewer],
        );
        let ev = EventBuilder::new(Kind::Custom(buzz_core::kind::KIND_DM_VISIBILITY as u16), "")
            .tags([d_tag, p_tag])
            .sign_with_keys(&relay)
            .expect("sign snapshot");
        let stored = buzz_core::StoredEvent::new(ev.clone(), None);

        // Kindless filter — the exact bypass shape: no #p, just the id.
        let filter = nostr::Filter::new().id(ev.id);

        assert!(
            !search_hit_accepted(&filter, &stored, &[], &third_party),
            "third party must not receive a DM-visibility snapshot via kindless ids search"
        );
        assert!(
            search_hit_accepted(&filter, &stored, &[], &viewer),
            "owner must still receive their own snapshot"
        );
    }

    // ──────────────────────────────────────────────────────────────────────────
    // truncate_reason regression tests
    //
    // Required by T1: prove a near-limit malformed input cannot produce a
    // near-limit log payload.  No infrastructure needed — pure unit tests.
    // ──────────────────────────────────────────────────────────────────────────

    /// Near-limit ASCII input (1 MiB) must be capped at exactly `max_bytes`.
    #[test]
    fn truncate_reason_large_ascii_input_is_bounded() {
        let big = "a".repeat(1024 * 1024); // 1 MiB
        let result = truncate_reason(&big, 256);
        assert_eq!(result.len(), 256);
        assert!(result.is_ascii());
    }

    /// A multi-byte codepoint that straddles the byte boundary must not be
    /// split: the output must end at the last complete codepoint before the
    /// cap, keeping the slice valid UTF-8.
    #[test]
    fn truncate_reason_multibyte_codepoint_at_boundary_is_not_split() {
        // Build a string of 255 ASCII bytes followed by a 3-byte codepoint (€, U+20AC).
        // Naïve cutoff at byte 256 would land inside the 3-byte sequence.
        let mut s = "a".repeat(255);
        s.push('€'); // 3 bytes: 0xE2 0x82 0xAC — spans bytes 255..258
        assert_eq!(s.len(), 258);

        let result = truncate_reason(&s, 256);
        // Must end before the multi-byte codepoint.
        assert_eq!(result.len(), 255);
        assert_eq!(result, "a".repeat(255));
        assert!(std::str::from_utf8(result.as_bytes()).is_ok());
    }

    /// Short input well under the cap must be returned unchanged.
    #[test]
    fn truncate_reason_short_input_returned_unchanged() {
        let s = "invalid: kind 24620 rejected";
        let result = truncate_reason(s, 256);
        assert_eq!(result, s);
    }

    fn idempotency_header_map(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append("idempotency-key", value.parse().expect("header value"));
        }
        headers
    }

    fn assert_invalid_idempotency_key(headers: HeaderMap) {
        let (status, Json(body)) =
            parse_idempotency_key_header(&headers).expect_err("must be HTTP 400");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let msg = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            msg.contains("Idempotency-Key"),
            "invalid header body must name Idempotency-Key; got {body:?}"
        );
    }

    #[test]
    fn parse_idempotency_key_absent_is_unkeyed() {
        let headers = HeaderMap::new();
        assert_eq!(parse_idempotency_key_header(&headers).unwrap(), None);
    }

    #[test]
    fn parse_idempotency_key_lowercase_64_hex() {
        let hex = "ab".repeat(32);
        let headers = idempotency_header_map(&[&hex]);
        let key = parse_idempotency_key_header(&headers)
            .unwrap()
            .expect("decoded key");
        assert_eq!(hex::encode(key), hex);
    }

    #[test]
    fn parse_idempotency_key_duplicate_physical_headers_are_400() {
        let hex = "ab".repeat(32);
        assert_invalid_idempotency_key(idempotency_header_map(&[&hex, &hex]));
    }

    #[test]
    fn parse_idempotency_key_comma_folded_is_400() {
        let folded = format!("{},{}", "ab".repeat(32), "cd".repeat(32));
        assert_invalid_idempotency_key(idempotency_header_map(&[&folded]));
    }

    #[test]
    fn parse_idempotency_key_uppercase_is_400() {
        assert_invalid_idempotency_key(idempotency_header_map(&[&"AB".repeat(32)]));
    }

    #[test]
    fn parse_idempotency_key_non_hex_is_400() {
        assert_invalid_idempotency_key(idempotency_header_map(&[&"g".repeat(64)]));
    }

    #[test]
    fn parse_idempotency_key_wrong_length_is_400() {
        assert_invalid_idempotency_key(idempotency_header_map(&[&"ab".repeat(31)]));
    }

    #[test]
    fn parse_idempotency_key_whitespace_is_400() {
        let hex = format!(" {} ", "ab".repeat(32));
        assert_invalid_idempotency_key(idempotency_header_map(&[&hex]));
    }

    #[test]
    fn parse_idempotency_key_non_utf8_is_400() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "idempotency-key",
            axum::http::HeaderValue::from_bytes(&[0xff, 0xfe]).expect("opaque header bytes"),
        );
        assert_invalid_idempotency_key(headers);
    }

    #[test]
    fn keyed_busy_response_is_generic_503_with_retry_after() {
        let (status, retry_after, Json(body)) = keyed_busy_http_parts(KEYED_BUSY_RETRY_AFTER_SECS);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(retry_after[0].0, header::RETRY_AFTER);
        assert_eq!(retry_after[0].1, "5");
        assert_eq!(
            body,
            serde_json::json!({"error": "idempotency unavailable"})
        );
        let dumped = body.to_string();
        assert!(
            !dumped.contains("event_id"),
            "busy body must stay generic: {dumped}"
        );
    }

    #[test]
    fn reservation_timeout_and_capacity_exhaustion_use_keyed_busy_503() {
        assert_eq!(
            KEYED_RESERVATION_ADMISSION_BUDGET.as_secs(),
            KEYED_BUSY_RETRY_AFTER_SECS
        );
        const {
            assert!(
                KEYED_RESERVATION_ADMISSION_BUDGET_SECS
                    < buzz_db::idempotency::KEYED_RESERVATION_IDLE_TIMEOUT_SECS
            );
            assert!(
                buzz_db::idempotency::KEYED_RESERVATION_IDLE_TIMEOUT_SECS
                    <= KEYED_RESERVATION_PERSIST_BUDGET_SECS
            );
        }
        let timeout_busy = KeyedHttpError::Busy {
            retry_after_secs: KEYED_RESERVATION_ADMISSION_BUDGET.as_secs(),
        };
        let KeyedHttpError::Busy { retry_after_secs } = timeout_busy else {
            panic!("timeout/capacity must stay on the keyed Busy path");
        };
        let (status, retry_after, Json(body)) = keyed_busy_http_parts(retry_after_secs);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(retry_after[0].0, header::RETRY_AFTER);
        assert_eq!(retry_after[0].1, "5");
        assert_eq!(
            body,
            serde_json::json!({"error": "idempotency unavailable"})
        );
    }

    #[test]
    fn idle_in_transaction_sqlstate_uses_keyed_busy_503() {
        // SQLSTATE 25P03 is classed as idempotency-unavailable in buzz-db;
        // ingest maps that to KeyedHttpError::Busy with the default Retry-After.
        let (status, retry_after, Json(body)) = keyed_busy_http_parts(KEYED_BUSY_RETRY_AFTER_SECS);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(retry_after[0].1, "5");
        assert_eq!(
            body,
            serde_json::json!({"error": "idempotency unavailable"})
        );
    }

    #[test]
    fn keyed_conflict_response_does_not_disclose_bound_event_id() {
        let (status, Json(body)) = keyed_conflict_http_parts();
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            body.get("error").and_then(|v| v.as_str()),
            Some("idempotency-key conflict")
        );
        let dumped = body.to_string();
        assert!(
            !dumped.contains("event_id"),
            "conflict body must not disclose the bound event id: {dumped}"
        );
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Handler-level tests: submit_event HTTP-counter seam
    //
    // These tests drive real HTTP requests through the axum router to prove
    // that the bridge code path (not just the shared helper) actually
    // increments buzz_events_rejected_total{transport="http"}.  They are
    // discriminating: removing either bridge call site causes the corresponding
    // test to fail.
    //
    // Why `#[ignore = "requires Postgres"]`: submit_event calls bind_community
    // (needs a real communities row) and enforce_http_admission (needs Redis).
    // Both services run locally in dev.  The admission check succeeds for a
    // freshly generated pubkey (first request, far below quota), so no Redis
    // seeding is required beyond the default local instance.
    //
    // Why `#[test]` + manual runtime instead of `#[tokio::test]`:
    // metrics::with_local_recorder stores the recorder in a thread-local.  An
    // async test uses a multi-thread scheduler by default; when submit_event
    // runs, it may land on a different thread and miss the recorder entirely.
    // Using a current_thread runtime with rt.block_on() inside the recorder
    // closure guarantees the handler runs on the same thread as the recorder.
    // ──────────────────────────────────────────────────────────────────────────

    struct AlwaysFreshReplayGuard;

    impl Nip98ReplayGuard for AlwaysFreshReplayGuard {
        fn try_mark_in_scope<'a>(
            &'a self,
            _scope: &'a str,
            _event_id: &'a nostr::EventId,
            _ttl_secs: u64,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<bool, buzz_auth::AuthError>> + Send + 'a>,
        > {
            Box::pin(async { Ok(true) })
        }
    }

    /// Build an AppState suitable for handler-level bridge tests.
    ///
    /// - `require_auth_token = false` → X-Pubkey dev-mode fallback active.
    /// - `require_relay_membership = false` → membership check short-circuits to
    ///   OpenRelay without a DB lookup.
    /// - `nip98_replay` replaced with an always-fresh guard → no Redis needed
    ///   for replay detection.
    /// - Redis pool points at the local dev instance for the admission check.
    ///
    /// Returns `None` when local Postgres is not reachable.
    async fn bridge_handler_test_state() -> Option<Arc<crate::state::AppState>> {
        let mut config = crate::config::Config::from_env().ok()?;
        config.database_url = crate::test_support::database_url();
        // Use the real local Redis so enforce_http_admission can pass.
        config.redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        config.relay_url = "wss://bridge-test.local".to_string();
        config.require_auth_token = false;
        config.require_relay_membership = false;

        let pool = sqlx::PgPool::connect(&crate::test_support::database_url())
            .await
            .ok()?;
        let db = buzz_db::Db::from_pool(pool.clone());
        let redis_pool = deadpool_redis::Config::from_url(&config.redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .ok()?;
        let pubsub = Arc::new(
            buzz_pubsub::PubSubManager::new(&config.redis_url, redis_pool.clone())
                .await
                .ok()?,
        );
        let audit = buzz_audit::AuditService::new(pool.clone());
        let auth = buzz_auth::AuthService::new(config.auth.clone());
        let search = buzz_search::SearchService::new(pool.clone());
        let workflow_engine = Arc::new(buzz_workflow::WorkflowEngine::new(
            db.clone(),
            buzz_workflow::WorkflowConfig::default(),
        ));
        let media_storage = buzz_media::MediaStorage::new(&config.media).ok()?;

        let (mut state, _audit_shutdown) = crate::state::AppState::new(
            config,
            db,
            redis_pool,
            audit,
            pubsub,
            auth,
            search,
            workflow_engine,
            Keys::generate(),
            media_storage,
        );
        state.nip98_replay = Arc::new(AlwaysFreshReplayGuard);
        Some(Arc::new(state))
    }

    /// Drive a single POST /events request through the router and return the
    /// HTTP status code.
    async fn post_events(
        state: Arc<crate::state::AppState>,
        host: &str,
        pubkey_hex: &str,
        body: &[u8],
    ) -> axum::http::StatusCode {
        use axum::body::Body;
        use axum::http::{header, Request};
        use tower::ServiceExt;

        crate::router::build_router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/events")
                    .header(header::HOST, host)
                    .header("x-pubkey", pubkey_hex)
                    .body(Body::from(body.to_vec()))
                    .expect("build request"),
            )
            .await
            .expect("router oneshot")
            .status()
    }

    /// Collect buzz_events_rejected_total with (transport, reason) labels from
    /// a DebuggingRecorder snapshot.
    fn http_reject_counts(
        snapshotter: &metrics_util::debugging::Snapshotter,
    ) -> std::collections::HashMap<(String, String), u64> {
        snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .filter(|(key, ..)| key.key().name() == "buzz_events_rejected_total")
            .map(|(key, _, _, value)| {
                let metrics_util::debugging::DebugValue::Counter(n) = value else {
                    panic!("buzz_events_rejected_total must be a counter");
                };
                let labels: Vec<_> = key.key().labels().collect();
                let transport = labels
                    .iter()
                    .find(|l| l.key() == "transport")
                    .map(|l| l.value().to_owned())
                    .unwrap_or_default();
                let reason = labels
                    .iter()
                    .find(|l| l.key() == "reason")
                    .map(|l| l.value().to_owned())
                    .unwrap_or_default();
                ((transport, reason), n)
            })
            .collect()
    }

    /// T2a — pre-parse 400 arm: a POST /events with an invalid JSON body must
    /// increment buzz_events_rejected_total{transport="http",reason="invalid"}.
    ///
    /// Discriminating: if the `reject_with_transport` call in bridge.rs's
    /// `serde_json::from_slice` map_err closure is removed, this test fails.
    #[test]
    #[ignore = "requires Postgres"]
    fn submit_event_invalid_json_body_increments_http_transport_counter() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current_thread runtime");

        let Some(state) = rt.block_on(bridge_handler_test_state()) else {
            panic!("local Postgres not reachable — start Postgres on 127.0.0.1:5432 before running ignored bridge handler tests");
        };

        // Provision a fresh community so bind_community succeeds.
        let host = {
            let h = format!("bridge-test-{}.local", uuid::Uuid::new_v4().simple());
            rt.block_on(state.db.ensure_configured_community(&h))
                .expect("ensure community");
            h
        };

        let pubkey_hex = Keys::generate().public_key().to_hex();

        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        metrics::with_local_recorder(&recorder, || {
            let status = rt.block_on(post_events(
                state.clone(),
                &host,
                &pubkey_hex,
                b"not valid json at all",
            ));
            assert_eq!(
                status,
                axum::http::StatusCode::BAD_REQUEST,
                "malformed body must yield 400"
            );
        });

        let counts = http_reject_counts(&snapshotter);
        assert_eq!(
            counts.get(&("http".to_owned(), "invalid".to_owned())),
            Some(&1),
            "pre-parse 400 arm must increment transport=http,reason=invalid"
        );
    }

    /// T2b — post-parse IngestError::Rejected arm: a POST /events with a
    /// valid but relay-only-kind event (kind 13534 = membership snapshot) must
    /// increment buzz_events_rejected_total{transport="http",reason="invalid"}.
    ///
    /// Kind 13534 is rejected in ingest_event before signature verification,
    /// so any properly signed Nostr event of this kind triggers the arm.
    ///
    /// Discriminating: if the `reject_with_transport` call in bridge.rs's
    /// IngestError::Rejected match arm is removed, this test fails.
    #[test]
    #[ignore = "requires Postgres"]
    fn submit_event_relay_only_kind_increments_http_transport_counter() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current_thread runtime");

        let Some(state) = rt.block_on(bridge_handler_test_state()) else {
            panic!("local Postgres not reachable — start Postgres on 127.0.0.1:5432 before running ignored bridge handler tests");
        };

        let host = {
            let h = format!("bridge-test-{}.local", uuid::Uuid::new_v4().simple());
            rt.block_on(state.db.ensure_configured_community(&h))
                .expect("ensure community");
            h
        };

        let client_keys = Keys::generate();
        let pubkey_hex = client_keys.public_key().to_hex();

        // Kind 13534 (membership snapshot) is relay-only; ingest_event rejects
        // it before reaching signature verification.
        let relay_only_event = EventBuilder::new(
            Kind::Custom(buzz_core::kind::KIND_NIP43_MEMBERSHIP_LIST as u16),
            "",
        )
        .sign_with_keys(&client_keys)
        .expect("sign relay-only event");
        let event_json = serde_json::to_vec(&relay_only_event).expect("serialize event");

        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        metrics::with_local_recorder(&recorder, || {
            let status = rt.block_on(post_events(state.clone(), &host, &pubkey_hex, &event_json));
            assert_eq!(
                status,
                axum::http::StatusCode::BAD_REQUEST,
                "relay-only-kind event must yield 400"
            );
        });

        let counts = http_reject_counts(&snapshotter);
        assert_eq!(
            counts.get(&("http".to_owned(), "invalid".to_owned())),
            Some(&1),
            "IngestError::Rejected arm must increment transport=http,reason=invalid"
        );
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Log-capture helpers and attribution-invariant tests
    //
    // These tests assert that exactly ONE "HTTP bridge request" log line
    // appears per authed request, pinning the W1 single-terminal-log invariant
    // and the E1 no-double-log rule.
    //
    // Infrastructure: same `#[ignore = "requires Postgres"]` + current_thread
    // runtime discipline as the HTTP-counter tests above.
    // ──────────────────────────────────────────────────────────────────────────

    /// Shared buffer that collects all bytes written by the tracing fmt layer.
    #[derive(Clone)]
    struct CapturingMakeWriter {
        buf: Arc<Mutex<Vec<u8>>>,
    }

    struct CapturingWriter {
        buf: Arc<Mutex<Vec<u8>>>,
    }

    impl std::io::Write for CapturingWriter {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.buf.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturingMakeWriter {
        type Writer = CapturingWriter;
        fn make_writer(&'a self) -> Self::Writer {
            CapturingWriter {
                buf: Arc::clone(&self.buf),
            }
        }
    }

    /// Run `post_events` with a capturing subscriber and return `(status_code, captured_log)`.
    fn run_and_capture(
        rt: &tokio::runtime::Runtime,
        state: Arc<crate::state::AppState>,
        host: &str,
        pubkey_hex: &str,
        body: &[u8],
    ) -> (axum::http::StatusCode, String) {
        let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let make_writer = CapturingMakeWriter {
            buf: Arc::clone(&buf),
        };
        let subscriber = tracing_subscriber::fmt()
            .with_writer(make_writer)
            .with_ansi(false)
            .finish();

        let status = tracing::subscriber::with_default(subscriber, || {
            rt.block_on(post_events(state, host, pubkey_hex, body))
        });

        let captured = String::from_utf8(buf.lock().unwrap().clone()).unwrap_or_default();
        (status, captured)
    }

    /// Count lines that contain the terminal attribution marker.
    fn count_attribution_lines(log: &str) -> usize {
        log.lines()
            .filter(|l| l.contains("HTTP bridge request"))
            .count()
    }

    /// T3a — exactly-once invariant, pre-parse 400 arm (invalid JSON).
    ///
    /// An authenticated client that submits a non-JSON body must produce
    /// exactly ONE "HTTP bridge request" log line.  This pins W1 (early exits
    /// are attributed) and E1 (no double line even for the parse-fail arm).
    ///
    /// Discriminating: if the attribution log is removed from the ParseFail
    /// arm in submit_event, this test fails.
    #[test]
    #[ignore = "requires Postgres"]
    fn submit_event_invalid_json_emits_exactly_one_attribution_line() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current_thread runtime");

        let state = rt
            .block_on(bridge_handler_test_state())
            .expect("local Postgres not reachable — start Postgres on 127.0.0.1:5432 before running ignored bridge handler tests");

        let host = {
            let h = format!("bridge-attr-{}.local", uuid::Uuid::new_v4().simple());
            rt.block_on(state.db.ensure_configured_community(&h))
                .expect("ensure community");
            h
        };

        let pubkey_hex = Keys::generate().public_key().to_hex();

        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let (status, log) = metrics::with_local_recorder(&recorder, || {
            run_and_capture(&rt, state, &host, &pubkey_hex, b"not valid json at all")
        });

        assert_eq!(
            status,
            axum::http::StatusCode::BAD_REQUEST,
            "invalid JSON must yield 400"
        );

        let n = count_attribution_lines(&log);
        assert_eq!(
            n, 1,
            "expected exactly 1 attribution line for invalid-JSON arm, got {n};\nlog:\n{log}"
        );
        assert!(
            log.contains(&pubkey_hex[..16]),
            "attribution line must carry the pubkey;\nlog:\n{log}"
        );
    }

    /// T3b — exactly-once invariant, post-parse IngestError::Rejected arm (relay-only kind).
    ///
    /// An authenticated client that submits a relay-only-kind event (kind 13534)
    /// must produce exactly ONE "HTTP bridge request" log line — not two
    /// (the old code emitted both an info! attribution and a warn! reason line).
    ///
    /// Discriminating: if two log lines are emitted (old double-log bug), this
    /// test fails.
    #[test]
    #[ignore = "requires Postgres"]
    fn submit_event_relay_only_kind_emits_exactly_one_attribution_line() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current_thread runtime");

        let state = rt
            .block_on(bridge_handler_test_state())
            .expect("local Postgres not reachable — start Postgres on 127.0.0.1:5432 before running ignored bridge handler tests");

        let host = {
            let h = format!("bridge-attr-{}.local", uuid::Uuid::new_v4().simple());
            rt.block_on(state.db.ensure_configured_community(&h))
                .expect("ensure community");
            h
        };

        let client_keys = Keys::generate();
        let pubkey_hex = client_keys.public_key().to_hex();

        let relay_only_event = EventBuilder::new(
            Kind::Custom(buzz_core::kind::KIND_NIP43_MEMBERSHIP_LIST as u16),
            "",
        )
        .sign_with_keys(&client_keys)
        .expect("sign relay-only event");
        let event_json = serde_json::to_vec(&relay_only_event).expect("serialize event");

        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let (status, log) = metrics::with_local_recorder(&recorder, || {
            run_and_capture(&rt, state, &host, &pubkey_hex, &event_json)
        });

        assert_eq!(
            status,
            axum::http::StatusCode::BAD_REQUEST,
            "relay-only-kind event must yield 400"
        );

        let n = count_attribution_lines(&log);
        assert_eq!(
            n, 1,
            "expected exactly 1 attribution line for IngestError::Rejected arm, got {n};\nlog:\n{log}"
        );
        assert!(
            log.contains(&pubkey_hex[..16]),
            "attribution line must carry the pubkey;\nlog:\n{log}"
        );
    }

    #[derive(Clone, Copy)]
    enum FleetLimiterOutcome {
        Allow,
        Deny,
        Fail,
    }

    type KeyedPrincipalCall = (uuid::Uuid, [u8; 32], LimitType, u64, u64);

    struct FleetLimiter {
        community_outcome: FleetLimiterOutcome,
        fleet_outcome: FleetLimiterOutcome,
        ip_calls: Mutex<Vec<(IpAddr, u64, u64)>>,
        principal_calls: Mutex<Vec<KeyedPrincipalCall>>,
    }

    impl RateLimiter for FleetLimiter {
        async fn check_and_increment(
            &self,
            ctx: &TenantContext,
            pubkey: &nostr::PublicKey,
            limit_type: LimitType,
            window_secs: u64,
            limit: u64,
        ) -> Result<buzz_auth::RateLimitResult, buzz_auth::AuthError> {
            self.principal_calls.lock().unwrap().push((
                *ctx.community().as_uuid(),
                pubkey.to_bytes(),
                limit_type,
                window_secs,
                limit,
            ));
            match self.community_outcome {
                FleetLimiterOutcome::Allow => {
                    Ok(buzz_auth::RateLimitResult::allowed(1, limit, window_secs))
                }
                FleetLimiterOutcome::Deny => {
                    Ok(buzz_auth::RateLimitResult::denied(limit + 1, limit, 59))
                }
                FleetLimiterOutcome::Fail => Err(buzz_auth::AuthError::Internal(
                    "shared admission unavailable".to_owned(),
                )),
            }
        }

        async fn check_ip_connection(
            &self,
            ip: &IpAddr,
            window_secs: u64,
            limit: u64,
        ) -> Result<buzz_auth::RateLimitResult, buzz_auth::AuthError> {
            self.ip_calls
                .lock()
                .unwrap()
                .push((*ip, window_secs, limit));
            match self.fleet_outcome {
                FleetLimiterOutcome::Allow => {
                    Ok(buzz_auth::RateLimitResult::allowed(1, limit, window_secs))
                }
                FleetLimiterOutcome::Deny => {
                    Ok(buzz_auth::RateLimitResult::denied(limit + 1, limit, 59))
                }
                FleetLimiterOutcome::Fail => Err(buzz_auth::AuthError::Internal(
                    "shared admission unavailable".to_owned(),
                )),
            }
        }

        async fn check_paired_admission(
            &self,
            request: PairedAdmissionRequest<'_>,
        ) -> Result<PairedAdmissionOutcome, buzz_auth::AuthError> {
            self.principal_calls.lock().unwrap().push((
                *request.tenant.community().as_uuid(),
                request.pubkey.to_bytes(),
                request.limit_type.clone(),
                request.window_secs(),
                request.tenant_limit,
            ));
            match self.community_outcome {
                FleetLimiterOutcome::Allow => {}
                FleetLimiterOutcome::Deny => {
                    return Ok(PairedAdmissionOutcome::TenantDenied(
                        buzz_auth::RateLimitResult::denied(
                            request.tenant_limit + 1,
                            request.tenant_limit,
                            59,
                        ),
                    ));
                }
                FleetLimiterOutcome::Fail => {
                    return Err(buzz_auth::AuthError::Internal(
                        "shared admission unavailable".to_owned(),
                    ));
                }
            }
            self.ip_calls.lock().unwrap().push((
                *request.fleet_ip,
                request.window_secs(),
                request.fleet_limit,
            ));
            match self.fleet_outcome {
                FleetLimiterOutcome::Allow => Ok(PairedAdmissionOutcome::Allowed {
                    tenant: buzz_auth::RateLimitResult::allowed(
                        1,
                        request.tenant_limit,
                        request.window_secs(),
                    ),
                    fleet: buzz_auth::RateLimitResult::allowed(
                        1,
                        request.fleet_limit,
                        request.window_secs(),
                    ),
                }),
                FleetLimiterOutcome::Deny => Ok(PairedAdmissionOutcome::FleetDenied(
                    buzz_auth::RateLimitResult::denied(
                        request.fleet_limit + 1,
                        request.fleet_limit,
                        59,
                    ),
                )),
                FleetLimiterOutcome::Fail => Err(buzz_auth::AuthError::Internal(
                    "shared admission unavailable".to_owned(),
                )),
            }
        }

        async fn check_hierarchical_admission(
            &self,
            request: HierarchicalAdmissionRequest<'_>,
        ) -> Result<HierarchicalAdmissionOutcome, buzz_auth::AuthError> {
            self.principal_calls.lock().unwrap().push((
                *request.tenant.community().as_uuid(),
                request.community.to_bytes(),
                request.limit_type.clone(),
                request.window_secs(),
                request.limits.community,
            ));
            match self.community_outcome {
                FleetLimiterOutcome::Allow => {}
                FleetLimiterOutcome::Deny => {
                    return Ok(HierarchicalAdmissionOutcome::CommunityDenied(
                        buzz_auth::RateLimitResult::denied(
                            request.limits.community + 1,
                            request.limits.community,
                            59,
                        ),
                    ));
                }
                FleetLimiterOutcome::Fail => {
                    return Err(buzz_auth::AuthError::Internal(
                        "shared admission unavailable".to_owned(),
                    ));
                }
            }
            self.ip_calls.lock().unwrap().push((
                *request.fleet_ip,
                request.window_secs(),
                request.limits.fleet,
            ));
            match self.fleet_outcome {
                FleetLimiterOutcome::Allow => Ok(HierarchicalAdmissionOutcome::Allowed {
                    identity: buzz_auth::RateLimitResult::allowed(
                        1,
                        request.limits.identity,
                        request.window_secs(),
                    ),
                    community: buzz_auth::RateLimitResult::allowed(
                        1,
                        request.limits.community,
                        request.window_secs(),
                    ),
                    fleet: buzz_auth::RateLimitResult::allowed(
                        1,
                        request.limits.fleet,
                        request.window_secs(),
                    ),
                }),
                FleetLimiterOutcome::Deny => Ok(HierarchicalAdmissionOutcome::FleetDenied(
                    buzz_auth::RateLimitResult::denied(
                        request.limits.fleet + 1,
                        request.limits.fleet,
                        59,
                    ),
                )),
                FleetLimiterOutcome::Fail => Err(buzz_auth::AuthError::Internal(
                    "shared admission unavailable".to_owned(),
                )),
            }
        }
    }

    fn fleet_limiter(outcome: FleetLimiterOutcome) -> FleetLimiter {
        fleet_limiter_stages(outcome, outcome)
    }

    fn fleet_limiter_stages(
        community_outcome: FleetLimiterOutcome,
        fleet_outcome: FleetLimiterOutcome,
    ) -> FleetLimiter {
        FleetLimiter {
            community_outcome,
            fleet_outcome,
            ip_calls: Mutex::new(Vec::new()),
            principal_calls: Mutex::new(Vec::new()),
        }
    }

    fn keyed_tenant(community: uuid::Uuid) -> TenantContext {
        TenantContext::resolved(
            buzz_core::CommunityId::from_uuid(community),
            "keyed-admission.test",
        )
    }

    fn expected_community_call(community: uuid::Uuid) -> KeyedPrincipalCall {
        (
            community,
            keyed_community_admission_principal().to_bytes(),
            KEYED_COMMUNITY_ADMISSION_LIMIT_TYPE,
            KEYED_EVENTS_FLEET_ADMISSION_WINDOW_SECS,
            KEYED_EVENTS_COMMUNITY_ADMISSION_PER_MIN,
        )
    }

    fn expected_fleet_call() -> (IpAddr, u64, u64) {
        (
            KEYED_EVENTS_FLEET_ADMISSION_SENTINEL,
            KEYED_EVENTS_FLEET_ADMISSION_WINDOW_SECS,
            KEYED_EVENTS_FLEET_ADMISSION_PER_MIN,
        )
    }

    #[test]
    fn keyed_events_fleet_ceiling_is_at_most_1200_per_minute() {
        assert_eq!(KEYED_EVENTS_FLEET_ADMISSION_PER_MIN, 1_200);
        const { assert!(KEYED_EVENTS_FLEET_ADMISSION_PER_MIN <= 1_200) };
        assert_eq!(KEYED_EVENTS_FLEET_ADMISSION_WINDOW_SECS, 60);
        const { assert!(KEYED_EVENTS_FLEET_ADMISSION_PER_MIN > 417) };
    }

    #[test]
    fn keyed_events_fleet_sentinel_is_unreachable_broadcast() {
        match KEYED_EVENTS_FLEET_ADMISSION_SENTINEL {
            IpAddr::V4(addr) => assert!(addr.is_broadcast()),
            IpAddr::V6(_) => panic!("fleet sentinel must not be a unicast IPv6 client identity"),
        }
        assert_eq!(
            KEYED_EVENTS_FLEET_ADMISSION_SENTINEL,
            IpAddr::V4(Ipv4Addr::BROADCAST)
        );
    }

    #[tokio::test]
    async fn keyed_events_admission_is_tenant_fair_then_fleet_aggregate() {
        let limiter = fleet_limiter(FleetLimiterOutcome::Allow);
        let community_a = uuid::Uuid::from_u128(1);
        let community_b = uuid::Uuid::from_u128(2);
        let tenant_a = keyed_tenant(community_a);
        let tenant_b = keyed_tenant(community_b);
        let persist_identity = Keys::generate().public_key();
        enforce_keyed_events_fleet_admission(&limiter, &tenant_a, &persist_identity, 300)
            .await
            .expect("first tenant-shaped call");
        enforce_keyed_events_fleet_admission(&limiter, &tenant_b, &persist_identity, 300)
            .await
            .expect("second tenant-shaped call");
        let principal_calls = limiter.principal_calls.lock().unwrap().clone();
        let ip_calls = limiter.ip_calls.lock().unwrap().clone();
        assert_eq!(
            principal_calls,
            vec![
                expected_community_call(community_a),
                expected_community_call(community_b),
            ]
        );
        assert_ne!(principal_calls[0].0, principal_calls[1].0);
        assert_eq!(principal_calls[0].1, principal_calls[1].1);
        assert_eq!(
            principal_calls[0].1,
            keyed_community_admission_principal().to_bytes()
        );
        assert_eq!(principal_calls[0].2, LimitType::ApiCalls);
        assert_eq!(ip_calls, vec![expected_fleet_call(), expected_fleet_call()]);
        assert_eq!(ip_calls[0], ip_calls[1]);
        assert_eq!(ip_calls[0].0, KEYED_EVENTS_FLEET_ADMISSION_SENTINEL);
    }

    #[tokio::test]
    async fn keyed_events_community_denial_preserves_reset_as_retry_after() {
        let limiter = fleet_limiter(FleetLimiterOutcome::Deny);
        let community = uuid::Uuid::from_u128(1);
        let err = enforce_keyed_events_fleet_admission(
            &limiter,
            &keyed_tenant(community),
            &Keys::generate().public_key(),
            300,
        )
        .await
        .expect_err("denied community admission");
        let crate::admission::AdmissionError::Exceeded { reset_in_secs } = err else {
            panic!("community quota denial must stay Exceeded, not Unavailable: {err:?}");
        };
        assert_eq!(reset_in_secs, 59);
        assert_eq!(
            limiter.principal_calls.lock().unwrap().clone(),
            vec![expected_community_call(community)]
        );
        assert!(
            limiter.ip_calls.lock().unwrap().is_empty(),
            "a denied community must not charge the fleet sentinel"
        );
        match keyed_http_error_from_fleet(err) {
            KeyedHttpError::Busy { retry_after_secs } => {
                assert_eq!(retry_after_secs, 59);
                let (status, retry_after, Json(body)) = keyed_busy_http_parts(retry_after_secs);
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(retry_after[0].0, header::RETRY_AFTER);
                assert_eq!(retry_after[0].1, "59");
                assert_ne!(retry_after[0].1, "5");
                assert_eq!(
                    body,
                    serde_json::json!({"error": "idempotency unavailable"})
                );
            }
            other => panic!("community Exceeded must map to Busy with reset, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn keyed_events_fleet_denial_preserves_reset_as_retry_after() {
        let limiter = fleet_limiter_stages(FleetLimiterOutcome::Allow, FleetLimiterOutcome::Deny);
        let community = uuid::Uuid::from_u128(1);
        let err = enforce_keyed_events_fleet_admission(
            &limiter,
            &keyed_tenant(community),
            &Keys::generate().public_key(),
            300,
        )
        .await
        .expect_err("denied fleet admission");
        let crate::admission::AdmissionError::Exceeded { reset_in_secs } = err else {
            panic!("fleet quota denial must stay Exceeded, not Unavailable: {err:?}");
        };
        assert_eq!(reset_in_secs, 59);
        assert_eq!(
            limiter.principal_calls.lock().unwrap().clone(),
            vec![expected_community_call(community)]
        );
        assert_eq!(
            limiter.ip_calls.lock().unwrap().clone(),
            vec![expected_fleet_call()]
        );
        match keyed_http_error_from_fleet(err) {
            KeyedHttpError::Busy { retry_after_secs } => {
                assert_eq!(retry_after_secs, 59);
                let (status, retry_after, Json(body)) = keyed_busy_http_parts(retry_after_secs);
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(retry_after[0].0, header::RETRY_AFTER);
                assert_eq!(retry_after[0].1, "59");
                assert_ne!(retry_after[0].1, "5");
                assert_eq!(
                    body,
                    serde_json::json!({"error": "idempotency unavailable"})
                );
            }
            other => panic!("fleet Exceeded must map to Busy with reset, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn keyed_events_community_unavailable_fails_closed_to_default_retry_after() {
        let limiter = fleet_limiter(FleetLimiterOutcome::Fail);
        let community = uuid::Uuid::from_u128(1);
        let err = enforce_keyed_events_fleet_admission(
            &limiter,
            &keyed_tenant(community),
            &Keys::generate().public_key(),
            300,
        )
        .await
        .expect_err("unavailable community admission must fail closed");
        assert_eq!(err, crate::admission::AdmissionError::Unavailable);
        assert_eq!(
            limiter.principal_calls.lock().unwrap().clone(),
            vec![expected_community_call(community)]
        );
        assert!(
            limiter.ip_calls.lock().unwrap().is_empty(),
            "community unavailability must not charge the fleet sentinel"
        );
        match keyed_http_error_from_fleet(err) {
            KeyedHttpError::Busy { retry_after_secs } => {
                assert_eq!(retry_after_secs, KEYED_BUSY_RETRY_AFTER_SECS);
                let (status, retry_after, Json(body)) = keyed_busy_http_parts(retry_after_secs);
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(retry_after[0].1, "5");
                assert_eq!(
                    body.get("error").and_then(|v| v.as_str()),
                    Some("idempotency unavailable")
                );
            }
            other => panic!("community Unavailable must map to default Busy, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn keyed_events_fleet_unavailable_fails_closed_to_default_retry_after() {
        let limiter = fleet_limiter_stages(FleetLimiterOutcome::Allow, FleetLimiterOutcome::Fail);
        let community = uuid::Uuid::from_u128(1);
        let err = enforce_keyed_events_fleet_admission(
            &limiter,
            &keyed_tenant(community),
            &Keys::generate().public_key(),
            300,
        )
        .await
        .expect_err("unavailable fleet admission must fail closed");
        assert_eq!(err, crate::admission::AdmissionError::Unavailable);
        assert_eq!(
            limiter.principal_calls.lock().unwrap().clone(),
            vec![expected_community_call(community)]
        );
        assert_eq!(
            limiter.ip_calls.lock().unwrap().clone(),
            vec![expected_fleet_call()]
        );
        match keyed_http_error_from_fleet(err) {
            KeyedHttpError::Busy { retry_after_secs } => {
                assert_eq!(retry_after_secs, KEYED_BUSY_RETRY_AFTER_SECS);
                let (status, retry_after, Json(body)) = keyed_busy_http_parts(retry_after_secs);
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(retry_after[0].1, "5");
                assert_eq!(
                    body.get("error").and_then(|v| v.as_str()),
                    Some("idempotency unavailable")
                );
            }
            other => panic!("fleet Unavailable must map to default Busy, got {other:?}"),
        }
    }

    #[test]
    fn keyed_busy_retry_after_fifty_nine_is_not_collapsed_to_five() {
        let (status, retry_after, Json(body)) = keyed_busy_http_parts(59);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(retry_after[0].1, "59");
        assert_eq!(
            body,
            serde_json::json!({"error": "idempotency unavailable"})
        );
    }

    #[tokio::test]
    async fn one_keyed_admission_charges_community_then_fleet() {
        let limiter = fleet_limiter(FleetLimiterOutcome::Allow);
        let community = uuid::Uuid::from_u128(1);
        enforce_keyed_events_fleet_admission(
            &limiter,
            &keyed_tenant(community),
            &Keys::generate().public_key(),
            300,
        )
        .await
        .expect("valid keyed persist may charge the fleet bucket");
        assert_eq!(
            limiter.principal_calls.lock().unwrap().clone(),
            vec![expected_community_call(community)]
        );
        assert_eq!(
            limiter.ip_calls.lock().unwrap().clone(),
            vec![expected_fleet_call()]
        );
    }

    #[tokio::test]
    async fn unkeyed_and_pre_ingest_paths_do_not_consume_keyed_fleet_bucket() {
        let limiter = fleet_limiter(FleetLimiterOutcome::Deny);
        let community = uuid::Uuid::from_u128(1);
        let tenant = keyed_tenant(community);
        let persist_identity = Keys::generate().public_key();
        maybe_enforce_keyed_events_fleet_admission(
            &limiter,
            &tenant,
            &persist_identity,
            300,
            false,
        )
        .await
        .expect(
            "malformed JSON, NIP-98 replay, nonmember, and unkeyed /events never set keyed=true",
        );
        assert!(limiter.principal_calls.lock().unwrap().is_empty());
        assert!(
            limiter.ip_calls.lock().unwrap().is_empty(),
            "pre-ingest and unkeyed paths must not increment the keyed fleet aggregate"
        );
        maybe_enforce_keyed_events_fleet_admission(&limiter, &tenant, &persist_identity, 300, true)
            .await
            .expect_err("keyed persist path must consult the community bucket");
        assert_eq!(
            limiter.principal_calls.lock().unwrap().clone(),
            vec![expected_community_call(community)]
        );
        assert!(
            limiter.ip_calls.lock().unwrap().is_empty(),
            "a denying community stage must not charge the fleet sentinel"
        );
    }

    async fn redis_int(state: &crate::state::AppState, key: &str) -> i64 {
        let mut conn = state.redis_pool.get().await.expect("redis conn");
        let value: Option<i64> = redis::cmd("GET")
            .arg(key)
            .query_async(&mut *conn)
            .await
            .expect("GET");
        value.unwrap_or(0)
    }

    async fn redis_pexpiretime_ms(state: &crate::state::AppState, key: &str) -> i64 {
        let mut conn = state.redis_pool.get().await.expect("redis conn");
        redis::cmd("PEXPIRETIME")
            .arg(key)
            .query_async(&mut *conn)
            .await
            .expect("PEXPIRETIME")
    }

    async fn redis_time_ms(state: &crate::state::AppState) -> i64 {
        let mut conn = state.redis_pool.get().await.expect("redis conn");
        let (secs, micros): (i64, i64) = redis::cmd("TIME")
            .query_async(&mut *conn)
            .await
            .expect("TIME");
        secs.saturating_mul(1000).saturating_add(micros / 1000)
    }

    async fn redis_set_int_pexpireat(
        state: &crate::state::AppState,
        key: &str,
        value: i64,
        expire_at_ms: i64,
    ) {
        let mut conn = state.redis_pool.get().await.expect("redis conn");
        redis::cmd("SET")
            .arg(key)
            .arg(value)
            .query_async::<()>(&mut *conn)
            .await
            .expect("SET");
        let _: i64 = redis::cmd("PEXPIREAT")
            .arg(key)
            .arg(expire_at_ms)
            .query_async(&mut *conn)
            .await
            .expect("PEXPIREAT");
    }

    async fn redis_del(state: &crate::state::AppState, key: &str) {
        let mut conn = state.redis_pool.get().await.expect("redis conn");
        let _: i64 = redis::cmd("DEL")
            .arg(key)
            .query_async(&mut *conn)
            .await
            .expect("DEL");
    }

    async fn redis_restore_int(
        state: &crate::state::AppState,
        key: &str,
        value: i64,
        expire_at_ms: i64,
    ) {
        if expire_at_ms == -2 {
            redis_del(state, key).await;
            return;
        }
        let mut conn = state.redis_pool.get().await.expect("redis conn");
        redis::cmd("SET")
            .arg(key)
            .arg(value)
            .query_async::<()>(&mut *conn)
            .await
            .expect("SET");
        if expire_at_ms > 0 {
            let _: i64 = redis::cmd("PEXPIREAT")
                .arg(key)
                .arg(expire_at_ms)
                .query_async(&mut *conn)
                .await
                .expect("PEXPIREAT");
        }
    }

    fn unique_idempotency_key_hex() -> String {
        let uuid = uuid::Uuid::new_v4();
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(uuid.as_bytes());
        bytes[16..].copy_from_slice(uuid.as_bytes());
        hex::encode(bytes)
    }

    fn parse_test_idempotency_key(hex_key: &str) -> [u8; 32] {
        buzz_core::idempotency::parse_idempotency_key(hex_key).expect("test idempotency key")
    }

    async fn post_events_with_idempotency(
        state: Arc<crate::state::AppState>,
        host: &str,
        keys: &Keys,
        body: &[u8],
        idempotency_key: Option<&str>,
    ) -> axum::http::StatusCode {
        post_events_with_idempotency_response(state, host, keys, body, idempotency_key)
            .await
            .status()
    }

    async fn post_events_with_idempotency_response(
        state: Arc<crate::state::AppState>,
        host: &str,
        keys: &Keys,
        body: &[u8],
        idempotency_key: Option<&str>,
    ) -> axum::http::Response<axum::body::Body> {
        use axum::body::Body;
        use axum::http::{header, Request};
        use tower::ServiceExt;

        let mut builder = Request::builder()
            .method("POST")
            .uri("/events")
            .header(header::HOST, host)
            .header("content-type", "application/json");
        if let Some(key) = idempotency_key {
            builder = builder.header("Idempotency-Key", key);
            let tenant = fresh_tenant(host);
            let url = nip98_expected_url(&state.config.relay_url, &tenant, "/events");
            let event_json = build_nip98_event_json(keys, &url, "POST");
            let headers = nip98_auth_headers(&event_json);
            let authorization = headers
                .get(header::AUTHORIZATION)
                .expect("NIP-98 Authorization")
                .clone();
            builder = builder.header(header::AUTHORIZATION, authorization);
        } else {
            builder = builder.header("x-pubkey", keys.public_key().to_hex());
        }
        crate::router::build_router(state)
            .oneshot(
                builder
                    .body(Body::from(body.to_vec()))
                    .expect("build request"),
            )
            .await
            .expect("router oneshot")
    }

    /// POST /events with a valid Idempotency-Key and only the unsigned
    /// development `X-Pubkey` identity — no NIP-98 Authorization.
    async fn post_events_unsigned_x_pubkey_with_key(
        state: Arc<crate::state::AppState>,
        host: &str,
        pubkey_hex: &str,
        body: &[u8],
        idempotency_key: &str,
    ) -> axum::http::Response<axum::body::Body> {
        use axum::body::Body;
        use axum::http::{header, Request};
        use tower::ServiceExt;

        crate::router::build_router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/events")
                    .header(header::HOST, host)
                    .header("content-type", "application/json")
                    .header("x-pubkey", pubkey_hex)
                    .header("Idempotency-Key", idempotency_key)
                    .body(Body::from(body.to_vec()))
                    .expect("build request"),
            )
            .await
            .expect("router oneshot")
    }

    fn kind9_event(keys: &Keys, channel: uuid::Uuid) -> (Vec<u8>, String) {
        let event = EventBuilder::new(Kind::Custom(9), "keyed-router")
            .tags([Tag::parse(["h", &channel.to_string()]).expect("h tag")])
            .sign_with_keys(keys)
            .expect("sign kind 9");
        (
            serde_json::to_vec(&event).expect("serialize"),
            keys.public_key().to_hex(),
        )
    }

    async fn insert_open_channel(
        database_url: &str,
        community: buzz_core::CommunityId,
    ) -> uuid::Uuid {
        let pool = sqlx::PgPool::connect(database_url)
            .await
            .expect("connect test db");
        let id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO channels (id, community_id, name, created_by) VALUES ($1, $2, $3, $4)",
        )
        .bind(id)
        .bind(*community.as_uuid())
        .bind(format!("keyed-{}", id.simple()))
        .bind(vec![7_u8; 32])
        .execute(&pool)
        .await
        .expect("insert channel");
        id
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn router_keyed_admission_charges_only_fresh_hierarchy_after_validation() {
        let _router_fleet_guard = ROUTER_FLEET_SENTINEL_LOCK.lock().await;
        let state = bridge_handler_test_state()
            .await
            .expect("local Postgres/Redis not reachable");
        let host = format!("keyed-router-{}.local", uuid::Uuid::new_v4().simple());
        let community = state
            .db
            .ensure_configured_community(&host)
            .await
            .expect("community");
        let channel = insert_open_channel(&state.config.database_url, community.id).await;
        let tenant = crate::tenant::bind_community(&state.db, &host)
            .await
            .expect("bind");
        let keys = Keys::generate();
        let (body, _) = kind9_event(&keys, channel);
        let event: nostr::Event = serde_json::from_slice(&body).expect("kind 9 event");
        let historical_identity_key = buzz_auth::rate_limit::rate_limit_key(
            &tenant,
            &keys.public_key(),
            &KEYED_HTTP_ATTEMPT_LIMIT_TYPE,
        );
        let historical_community_key = buzz_auth::rate_limit::rate_limit_key(
            &tenant,
            &keyed_http_attempt_admission_principal(),
            &KEYED_HTTP_ATTEMPT_LIMIT_TYPE,
        );
        let historical_fleet_key =
            buzz_auth::rate_limit::ip_rate_limit_key(&KEYED_HTTP_ATTEMPT_FLEET_SENTINEL);
        let fresh_identity_key = buzz_auth::rate_limit::rate_limit_key(
            &tenant,
            &keys.public_key(),
            &KEYED_HTTP_FRESH_LIMIT_TYPE,
        );
        let fresh_community_key = buzz_auth::rate_limit::rate_limit_key(
            &tenant,
            &keyed_http_fresh_admission_principal(),
            &KEYED_HTTP_FRESH_LIMIT_TYPE,
        );
        let fresh_fleet_key =
            buzz_auth::rate_limit::ip_rate_limit_key(&KEYED_HTTP_FRESH_FLEET_SENTINEL);
        let persist_community_key = buzz_auth::rate_limit::rate_limit_key(
            &tenant,
            &keyed_community_admission_principal(),
            &KEYED_COMMUNITY_ADMISSION_LIMIT_TYPE,
        );
        let persist_fleet_key =
            buzz_auth::rate_limit::ip_rate_limit_key(&KEYED_EVENTS_FLEET_ADMISSION_SENTINEL);
        let principal_key = buzz_auth::rate_limit::rate_limit_key(
            &tenant,
            &keys.public_key(),
            &LimitType::ApiCalls,
        );
        let historical_i0 = redis_int(&state, &historical_identity_key).await;
        let historical_c0 = redis_int(&state, &historical_community_key).await;
        let historical_f0 = redis_int(&state, &historical_fleet_key).await;
        let fresh_i0 = redis_int(&state, &fresh_identity_key).await;
        let fresh_c0 = redis_int(&state, &fresh_community_key).await;
        let fresh_f0 = redis_int(&state, &fresh_fleet_key).await;
        let persist_c0 = redis_int(&state, &persist_community_key).await;
        let persist_f0 = redis_int(&state, &persist_fleet_key).await;
        let principal_0 = redis_int(&state, &principal_key).await;
        let fresh_f_expire_at = redis_pexpiretime_ms(&state, &fresh_fleet_key).await;
        let persist_f_expire_at = redis_pexpiretime_ms(&state, &persist_fleet_key).await;
        let key = unique_idempotency_key_hex();
        let key_bytes = parse_test_idempotency_key(&key);
        let author = event.pubkey.to_bytes();
        let status =
            post_events_with_idempotency(Arc::clone(&state), &host, &keys, &body, Some(&key)).await;
        let historical_i1 = redis_int(&state, &historical_identity_key).await;
        let historical_c1 = redis_int(&state, &historical_community_key).await;
        let historical_f1 = redis_int(&state, &historical_fleet_key).await;
        let fresh_i1 = redis_int(&state, &fresh_identity_key).await;
        let fresh_c1 = redis_int(&state, &fresh_community_key).await;
        let fresh_f1 = redis_int(&state, &fresh_fleet_key).await;
        let persist_c1 = redis_int(&state, &persist_community_key).await;
        let persist_f1 = redis_int(&state, &persist_fleet_key).await;
        let principal_1 = redis_int(&state, &principal_key).await;
        let classified = state
            .db
            .classify_committed_keyed_stream(
                tenant.community(),
                author,
                key_bytes,
                &event,
                Some(channel),
                None,
            )
            .await
            .expect("classify committed keyed stream");
        let event_id = event.id.to_bytes();
        let stored = state
            .db
            .get_events_by_ids_routed("bridge_query", tenant.community(), &[event_id.as_slice()])
            .await
            .expect("fetch persisted event");
        let pool = sqlx::PgPool::connect(&state.config.database_url)
            .await
            .expect("connect test db");
        let idempotency_rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM event_idempotency_keys WHERE community_id = $1 AND author_pubkey = $2 AND idempotency_key = $3",
        )
        .bind(*tenant.community().as_uuid())
        .bind(author.as_slice())
        .bind(key_bytes.as_slice())
        .fetch_one(&pool)
        .await
        .expect("count idempotency rows");
        sqlx::query(
            "DELETE FROM event_idempotency_keys WHERE community_id = $1 AND author_pubkey = $2 AND idempotency_key = $3",
        )
        .bind(*tenant.community().as_uuid())
        .bind(author.as_slice())
        .bind(key_bytes.as_slice())
        .execute(&pool)
        .await
        .expect("cleanup idempotency row");
        redis_del(&state, &fresh_identity_key).await;
        redis_del(&state, &fresh_community_key).await;
        redis_del(&state, &principal_key).await;
        redis_del(&state, &persist_community_key).await;
        redis_restore_int(&state, &fresh_fleet_key, fresh_f0, fresh_f_expire_at).await;
        redis_restore_int(&state, &persist_fleet_key, persist_f0, persist_f_expire_at).await;
        assert_eq!(status, axum::http::StatusCode::OK, "valid keyed kind 9");
        assert_eq!(historical_i1, historical_i0 + 1);
        assert_eq!(historical_c1, historical_c0 + 1);
        assert_eq!(historical_f1, historical_f0 + 1);
        assert_eq!(fresh_i1, fresh_i0 + 1);
        assert_eq!(fresh_c1, fresh_c0 + 1);
        assert_eq!(fresh_f1, fresh_f0 + 1);
        assert_eq!(persist_c1, persist_c0 + 1);
        assert_eq!(persist_f1, persist_f0 + 1);
        assert_eq!(principal_1, principal_0 + 1);
        match classified {
            Some(KeyedCommittedOutcome::Replay { original_event_id }) => {
                assert_eq!(original_event_id, event_id);
            }
            other => panic!("successful keyed ingest must persist a keyed row, got {other:?}"),
        }
        assert_eq!(stored.len(), 1, "event row must be persisted");
        assert_eq!(idempotency_rows, 1);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn router_keyed_writer_capacity_exhaustion_is_busy_then_succeeds_after_release() {
        let _router_fleet_guard = ROUTER_FLEET_SENTINEL_LOCK.lock().await;
        let state = bridge_handler_test_state()
            .await
            .expect("local Postgres/Redis not reachable");
        let host = format!("keyed-writer-cap-{}.local", uuid::Uuid::new_v4().simple());
        let community = state
            .db
            .ensure_configured_community(&host)
            .await
            .expect("community");
        let channel = insert_open_channel(&state.config.database_url, community.id).await;
        let tenant = crate::tenant::bind_community(&state.db, &host)
            .await
            .expect("bind");
        let keys = Keys::generate();
        let (body, _) = kind9_event(&keys, channel);
        let event: nostr::Event = serde_json::from_slice(&body).expect("kind 9 event");
        let author = event.pubkey.to_bytes();
        let event_id = event.id.to_bytes();
        let key = unique_idempotency_key_hex();
        let key_bytes = parse_test_idempotency_key(&key);
        let pool = sqlx::PgPool::connect(&state.config.database_url)
            .await
            .expect("connect test db");

        {
            let _capacity = KeyedWriterCapacityGuard::hold_all();
            let response = post_events_with_idempotency_response(
                Arc::clone(&state),
                &host,
                &keys,
                &body,
                Some(&key),
            )
            .await;
            let status = response.status();
            let retry_after = response.headers().get(header::RETRY_AFTER).cloned();
            let body_bytes = axum::body::to_bytes(response.into_body(), 256)
                .await
                .expect("bounded keyed-busy body");
            let classified = state
                .db
                .classify_committed_keyed_stream(
                    tenant.community(),
                    author,
                    key_bytes,
                    &event,
                    Some(channel),
                    None,
                )
                .await
                .expect("classify committed keyed stream");
            let stored = state
                .db
                .get_events_by_ids_routed(
                    "bridge_query",
                    tenant.community(),
                    &[event_id.as_slice()],
                )
                .await
                .expect("fetch event");
            let idempotency_rows: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM event_idempotency_keys WHERE community_id = $1 AND author_pubkey = $2 AND idempotency_key = $3",
            )
            .bind(*tenant.community().as_uuid())
            .bind(author.as_slice())
            .bind(key_bytes.as_slice())
            .fetch_one(&pool)
            .await
            .expect("count idempotency rows");
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(
                retry_after.as_ref().and_then(|value| value.to_str().ok()),
                Some("5")
            );
            assert_eq!(KEYED_BUSY_RETRY_AFTER_SECS, 5);
            let json: Value = serde_json::from_slice(&body_bytes).expect("keyed-busy JSON");
            assert_eq!(
                json,
                serde_json::json!({"error": "idempotency unavailable"})
            );
            assert!(
                classified.is_none(),
                "writer-capacity Busy must not leave a committed keyed row"
            );
            assert!(
                stored.is_empty(),
                "writer-capacity Busy must not persist the event"
            );
            assert_eq!(
                idempotency_rows, 0,
                "writer-capacity Busy must abort the reservation"
            );
        }

        let success =
            post_events_with_idempotency(Arc::clone(&state), &host, &keys, &body, Some(&key)).await;
        let classified = state
            .db
            .classify_committed_keyed_stream(
                tenant.community(),
                author,
                key_bytes,
                &event,
                Some(channel),
                None,
            )
            .await
            .expect("classify committed keyed stream");
        let stored = state
            .db
            .get_events_by_ids_routed("bridge_query", tenant.community(), &[event_id.as_slice()])
            .await
            .expect("fetch persisted event");
        let idempotency_rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM event_idempotency_keys WHERE community_id = $1 AND author_pubkey = $2 AND idempotency_key = $3",
        )
        .bind(*tenant.community().as_uuid())
        .bind(author.as_slice())
        .bind(key_bytes.as_slice())
        .fetch_one(&pool)
        .await
        .expect("count idempotency rows");
        sqlx::query(
            "DELETE FROM event_idempotency_keys WHERE community_id = $1 AND author_pubkey = $2 AND idempotency_key = $3",
        )
        .bind(*tenant.community().as_uuid())
        .bind(author.as_slice())
        .bind(key_bytes.as_slice())
        .execute(&pool)
        .await
        .expect("cleanup idempotency row");
        assert_eq!(
            success,
            axum::http::StatusCode::OK,
            "same keyed request must succeed after capacity is released"
        );
        match classified {
            Some(KeyedCommittedOutcome::Replay { original_event_id }) => {
                assert_eq!(original_event_id, event_id);
            }
            other => panic!("retry after capacity release must persist a keyed row, got {other:?}"),
        }
        assert_eq!(stored.len(), 1, "event row must be persisted on retry");
        assert_eq!(idempotency_rows, 1);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn router_keyed_saturated_attempt_identity_is_rejected_without_side_effects() {
        let _router_fleet_guard = ROUTER_FLEET_SENTINEL_LOCK.lock().await;
        let state = bridge_handler_test_state()
            .await
            .expect("local Postgres/Redis not reachable");
        let host = format!("keyed-fresh-deny-{}.local", uuid::Uuid::new_v4().simple());
        let community = state
            .db
            .ensure_configured_community(&host)
            .await
            .expect("community");
        let channel = insert_open_channel(&state.config.database_url, community.id).await;
        let tenant = crate::tenant::bind_community(&state.db, &host)
            .await
            .expect("bind");
        let keys = Keys::generate();
        let (body, _) = kind9_event(&keys, channel);
        let event: nostr::Event = serde_json::from_slice(&body).expect("kind 9 event");
        let historical_identity_key = buzz_auth::rate_limit::rate_limit_key(
            &tenant,
            &keys.public_key(),
            &KEYED_HTTP_ATTEMPT_LIMIT_TYPE,
        );
        let historical_community_key = buzz_auth::rate_limit::rate_limit_key(
            &tenant,
            &keyed_http_attempt_admission_principal(),
            &KEYED_HTTP_ATTEMPT_LIMIT_TYPE,
        );
        let historical_fleet_key =
            buzz_auth::rate_limit::ip_rate_limit_key(&KEYED_HTTP_ATTEMPT_FLEET_SENTINEL);
        let fresh_identity_key = buzz_auth::rate_limit::rate_limit_key(
            &tenant,
            &keys.public_key(),
            &KEYED_HTTP_FRESH_LIMIT_TYPE,
        );
        let fresh_community_key = buzz_auth::rate_limit::rate_limit_key(
            &tenant,
            &keyed_http_fresh_admission_principal(),
            &KEYED_HTTP_FRESH_LIMIT_TYPE,
        );
        let fresh_fleet_key =
            buzz_auth::rate_limit::ip_rate_limit_key(&KEYED_HTTP_FRESH_FLEET_SENTINEL);
        let persist_community_key = buzz_auth::rate_limit::rate_limit_key(
            &tenant,
            &keyed_community_admission_principal(),
            &KEYED_COMMUNITY_ADMISSION_LIMIT_TYPE,
        );
        let persist_fleet_key =
            buzz_auth::rate_limit::ip_rate_limit_key(&KEYED_EVENTS_FLEET_ADMISSION_SENTINEL);
        let principal_key = buzz_auth::rate_limit::rate_limit_key(
            &tenant,
            &keys.public_key(),
            &LimitType::ApiCalls,
        );
        let historical_i0 = redis_int(&state, &historical_identity_key).await;
        let historical_c0 = redis_int(&state, &historical_community_key).await;
        let historical_f0 = redis_int(&state, &historical_fleet_key).await;
        let persist_c0 = redis_int(&state, &persist_community_key).await;
        let persist_f0 = redis_int(&state, &persist_fleet_key).await;
        let principal_0 = redis_int(&state, &principal_key).await;
        let fresh_fleet_prev = redis_int(&state, &fresh_fleet_key).await;
        let fresh_fleet_expire_at = redis_pexpiretime_ms(&state, &fresh_fleet_key).await;
        let author = event.pubkey.to_bytes();
        let expire_at_ms = redis_time_ms(&state).await.saturating_add(
            i64::try_from(KEYED_HTTP_ATTEMPT_WINDOW_SECS.saturating_mul(1000)).expect("window ms"),
        );
        let seeded_attempt_identity =
            i64::try_from(KEYED_HTTP_FAIR_SHARE_PER_MIN).expect("fair share");
        let seeded_attempt_community = 1_i64;
        let seeded_attempt_fleet = 1_i64;
        redis_set_int_pexpireat(
            &state,
            &historical_identity_key,
            seeded_attempt_identity,
            expire_at_ms,
        )
        .await;
        redis_set_int_pexpireat(
            &state,
            &historical_community_key,
            seeded_attempt_community,
            expire_at_ms,
        )
        .await;
        redis_set_int_pexpireat(
            &state,
            &historical_fleet_key,
            seeded_attempt_fleet,
            expire_at_ms,
        )
        .await;
        let seeded_i_expire_at = redis_pexpiretime_ms(&state, &historical_identity_key).await;
        let seeded_c_expire_at = redis_pexpiretime_ms(&state, &historical_community_key).await;
        let seeded_f_expire_at = redis_pexpiretime_ms(&state, &historical_fleet_key).await;
        let key = unique_idempotency_key_hex();
        let key_bytes = parse_test_idempotency_key(&key);
        let response = post_events_with_idempotency_response(
            Arc::clone(&state),
            &host,
            &keys,
            &body,
            Some(&key),
        )
        .await;
        let status = response.status();
        let retry_after = response.headers().get(header::RETRY_AFTER).cloned();
        let body_bytes = axum::body::to_bytes(response.into_body(), 256)
            .await
            .expect("bounded keyed-busy body");
        let historical_i1 = redis_int(&state, &historical_identity_key).await;
        let historical_c1 = redis_int(&state, &historical_community_key).await;
        let historical_f1 = redis_int(&state, &historical_fleet_key).await;
        let fresh_i1 = redis_int(&state, &fresh_identity_key).await;
        let fresh_c1 = redis_int(&state, &fresh_community_key).await;
        let fresh_f1 = redis_int(&state, &fresh_fleet_key).await;
        let fresh_i_expire_at = redis_pexpiretime_ms(&state, &fresh_identity_key).await;
        let fresh_c_expire_at = redis_pexpiretime_ms(&state, &fresh_community_key).await;
        let fresh_f_expire_at = redis_pexpiretime_ms(&state, &fresh_fleet_key).await;
        let persist_c1 = redis_int(&state, &persist_community_key).await;
        let persist_f1 = redis_int(&state, &persist_fleet_key).await;
        let principal_1 = redis_int(&state, &principal_key).await;
        let classified = state
            .db
            .classify_committed_keyed_stream(
                tenant.community(),
                author,
                key_bytes,
                &event,
                Some(channel),
                None,
            )
            .await
            .expect("classify committed keyed stream");
        let event_id = event.id.to_bytes();
        let stored = state
            .db
            .get_events_by_ids_routed("bridge_query", tenant.community(), &[event_id.as_slice()])
            .await
            .expect("fetch event");
        let pool = sqlx::PgPool::connect(&state.config.database_url)
            .await
            .expect("connect test db");
        let idempotency_rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM event_idempotency_keys WHERE community_id = $1 AND author_pubkey = $2 AND idempotency_key = $3",
        )
        .bind(*tenant.community().as_uuid())
        .bind(author.as_slice())
        .bind(key_bytes.as_slice())
        .fetch_one(&pool)
        .await
        .expect("count idempotency rows");
        sqlx::query(
            "DELETE FROM event_idempotency_keys WHERE community_id = $1 AND author_pubkey = $2 AND idempotency_key = $3",
        )
        .bind(*tenant.community().as_uuid())
        .bind(author.as_slice())
        .bind(key_bytes.as_slice())
        .execute(&pool)
        .await
        .expect("cleanup idempotency row");
        redis_del(&state, &fresh_identity_key).await;
        redis_del(&state, &fresh_community_key).await;
        redis_del(&state, &principal_key).await;
        redis_del(&state, &historical_identity_key).await;
        redis_del(&state, &historical_community_key).await;
        redis_restore_int(
            &state,
            &historical_fleet_key,
            historical_f0,
            redis_pexpiretime_ms(&state, &historical_fleet_key).await,
        )
        .await;
        redis_restore_int(
            &state,
            &fresh_fleet_key,
            fresh_fleet_prev,
            fresh_fleet_expire_at,
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            retry_after.is_some(),
            "attempt identity denial must keep the opaque keyed busy Retry-After"
        );
        let body: Value = serde_json::from_slice(&body_bytes).expect("keyed-busy JSON");
        assert_eq!(
            body,
            serde_json::json!({"error": "idempotency unavailable"})
        );
        assert_eq!(
            historical_i0, 0,
            "historical identity must be uncharged before seeding attempt denial"
        );
        assert_eq!(
            historical_c0, 0,
            "historical community must be uncharged before seeding attempt denial"
        );
        assert_eq!(
            historical_i1, seeded_attempt_identity,
            "attempt identity denial must not increment the historical identity counter"
        );
        assert_eq!(
            historical_c1, seeded_attempt_community,
            "attempt identity denial must not increment the historical community counter"
        );
        assert_eq!(historical_f1, seeded_attempt_fleet);
        assert_eq!(fresh_i1, 0);
        assert_eq!(fresh_c1, 0);
        assert_eq!(fresh_f1, fresh_fleet_prev);
        let _ = (
            fresh_i_expire_at,
            fresh_c_expire_at,
            fresh_f_expire_at,
            seeded_i_expire_at,
            seeded_c_expire_at,
            seeded_f_expire_at,
        );
        assert_eq!(persist_c1, persist_c0);
        assert_eq!(persist_f1, persist_f0);
        assert_eq!(principal_1, principal_0);
        assert!(
            classified.is_none(),
            "attempt identity denial must not reserve or persist a keyed row"
        );
        assert!(
            stored.is_empty(),
            "attempt identity denial must not persist the event"
        );
        assert_eq!(idempotency_rows, 0);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn router_keyed_replay_does_not_charge_principal_or_fleet() {
        let _router_fleet_guard = ROUTER_FLEET_SENTINEL_LOCK.lock().await;
        let state = bridge_handler_test_state()
            .await
            .expect("local Postgres/Redis not reachable");
        let host = format!("keyed-replay-{}.local", uuid::Uuid::new_v4().simple());
        let community = state
            .db
            .ensure_configured_community(&host)
            .await
            .expect("community");
        let channel = insert_open_channel(&state.config.database_url, community.id).await;
        let tenant = crate::tenant::bind_community(&state.db, &host)
            .await
            .expect("bind");
        let keys = Keys::generate();
        let (body, _) = kind9_event(&keys, channel);
        let principal_key = buzz_auth::rate_limit::rate_limit_key(
            &tenant,
            &keys.public_key(),
            &LimitType::ApiCalls,
        );
        let tenant_key = buzz_auth::rate_limit::rate_limit_key(
            &tenant,
            &keyed_community_admission_principal(),
            &KEYED_COMMUNITY_ADMISSION_LIMIT_TYPE,
        );
        let fleet_key =
            buzz_auth::rate_limit::ip_rate_limit_key(&KEYED_EVENTS_FLEET_ADMISSION_SENTINEL);
        let p0 = redis_int(&state, &principal_key).await;
        let t0 = redis_int(&state, &tenant_key).await;
        let f0 = redis_int(&state, &fleet_key).await;
        let key = "ef".repeat(32);
        let first =
            post_events_with_idempotency(Arc::clone(&state), &host, &keys, &body, Some(&key)).await;
        assert_eq!(first, axum::http::StatusCode::OK, "first keyed insert");
        assert_eq!(redis_int(&state, &principal_key).await, p0 + 1);
        assert_eq!(redis_int(&state, &tenant_key).await, t0 + 1);
        assert_eq!(redis_int(&state, &fleet_key).await, f0 + 1);
        let replay =
            post_events_with_idempotency(Arc::clone(&state), &host, &keys, &body, Some(&key)).await;
        assert_eq!(replay, axum::http::StatusCode::OK, "exact replay");
        assert_eq!(
            redis_int(&state, &principal_key).await,
            p0 + 1,
            "replay must not charge principal quota"
        );
        assert_eq!(
            redis_int(&state, &tenant_key).await,
            t0 + 1,
            "replay must not charge the community bucket"
        );
        assert_eq!(
            redis_int(&state, &fleet_key).await,
            f0 + 1,
            "replay must not charge the fleet sentinel"
        );
    }

    #[test]
    fn keyed_principal_quota_keeps_http_429() {
        let (status, Json(body)) =
            http_admission_error_response(crate::admission::AdmissionError::Exceeded {
                reset_in_secs: 11,
            });
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        let text = body.to_string();
        assert!(
            text.contains("retry in 11s"),
            "principal denial must keep the existing 429 contract, got {text}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn router_malformed_keyed_and_unkeyed_do_not_charge_admission() {
        let _router_fleet_guard = ROUTER_FLEET_SENTINEL_LOCK.lock().await;
        let state = bridge_handler_test_state()
            .await
            .expect("local Postgres/Redis not reachable");
        let host = format!("keyed-pre-{}.local", uuid::Uuid::new_v4().simple());
        let community = state
            .db
            .ensure_configured_community(&host)
            .await
            .expect("community");
        let channel = insert_open_channel(&state.config.database_url, community.id).await;
        let tenant = crate::tenant::bind_community(&state.db, &host)
            .await
            .expect("bind");
        let keys = Keys::generate();
        let (body, _) = kind9_event(&keys, channel);
        let tenant_key = buzz_auth::rate_limit::rate_limit_key(
            &tenant,
            &keyed_community_admission_principal(),
            &KEYED_COMMUNITY_ADMISSION_LIMIT_TYPE,
        );
        let fleet_key =
            buzz_auth::rate_limit::ip_rate_limit_key(&KEYED_EVENTS_FLEET_ADMISSION_SENTINEL);
        let t0 = redis_int(&state, &tenant_key).await;
        let f0 = redis_int(&state, &fleet_key).await;
        let key = "cd".repeat(32);
        let malformed =
            post_events_with_idempotency(Arc::clone(&state), &host, &keys, b"{", Some(&key)).await;
        assert_eq!(malformed, axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(redis_int(&state, &tenant_key).await, t0);
        assert_eq!(redis_int(&state, &fleet_key).await, f0);
        let unkeyed =
            post_events_with_idempotency(Arc::clone(&state), &host, &keys, &body, None).await;
        assert_eq!(unkeyed, axum::http::StatusCode::OK);
        assert_eq!(redis_int(&state, &tenant_key).await, t0);
        assert_eq!(redis_int(&state, &fleet_key).await, f0);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn router_two_communities_charge_distinct_tenant_keys_and_one_fleet_key() {
        let _router_fleet_guard = ROUTER_FLEET_SENTINEL_LOCK.lock().await;
        let state = bridge_handler_test_state()
            .await
            .expect("local Postgres/Redis not reachable");
        let host_a = format!("keyed-a-{}.local", uuid::Uuid::new_v4().simple());
        let host_b = format!("keyed-b-{}.local", uuid::Uuid::new_v4().simple());
        let community_a = state
            .db
            .ensure_configured_community(&host_a)
            .await
            .expect("community a");
        let community_b = state
            .db
            .ensure_configured_community(&host_b)
            .await
            .expect("community b");
        let channel_a = insert_open_channel(&state.config.database_url, community_a.id).await;
        let channel_b = insert_open_channel(&state.config.database_url, community_b.id).await;
        let tenant_a = crate::tenant::bind_community(&state.db, &host_a)
            .await
            .expect("bind a");
        let tenant_b = crate::tenant::bind_community(&state.db, &host_b)
            .await
            .expect("bind b");
        let keys_a = Keys::generate();
        let keys_b = Keys::generate();
        let (body_a, _) = kind9_event(&keys_a, channel_a);
        let (body_b, _) = kind9_event(&keys_b, channel_b);
        let key_a = buzz_auth::rate_limit::rate_limit_key(
            &tenant_a,
            &keyed_community_admission_principal(),
            &KEYED_COMMUNITY_ADMISSION_LIMIT_TYPE,
        );
        let key_b = buzz_auth::rate_limit::rate_limit_key(
            &tenant_b,
            &keyed_community_admission_principal(),
            &KEYED_COMMUNITY_ADMISSION_LIMIT_TYPE,
        );
        let fleet_key =
            buzz_auth::rate_limit::ip_rate_limit_key(&KEYED_EVENTS_FLEET_ADMISSION_SENTINEL);
        assert_ne!(key_a, key_b);
        let a0 = redis_int(&state, &key_a).await;
        let b0 = redis_int(&state, &key_b).await;
        let f0 = redis_int(&state, &fleet_key).await;
        let status_a = post_events_with_idempotency(
            Arc::clone(&state),
            &host_a,
            &keys_a,
            &body_a,
            Some(&"11".repeat(32)),
        )
        .await;
        let status_b = post_events_with_idempotency(
            Arc::clone(&state),
            &host_b,
            &keys_b,
            &body_b,
            Some(&"22".repeat(32)),
        )
        .await;
        assert_eq!(status_a, axum::http::StatusCode::OK);
        assert_eq!(status_b, axum::http::StatusCode::OK);
        assert_eq!(redis_int(&state, &key_a).await, a0 + 1);
        assert_eq!(redis_int(&state, &key_b).await, b0 + 1);
        assert_eq!(redis_int(&state, &fleet_key).await, f0 + 2);
    }

    #[derive(Clone, Copy)]
    enum IdentityPeekOutcome {
        NotDenied,
        Denied,
        Fail,
    }

    struct LaneRecordingLimiter {
        increment_outcome: FleetLimiterOutcome,
        attempt_pair_outcome: FleetLimiterOutcome,
        fresh_pair_outcome: FleetLimiterOutcome,
        peek_outcome: IdentityPeekOutcome,
        steps: Arc<Mutex<Vec<&'static str>>>,
        paired_types: Mutex<Vec<LimitType>>,
        principal_types: Mutex<Vec<LimitType>>,
        increment_pubkeys: Mutex<Vec<[u8; 32]>>,
        paired_pubkeys: Mutex<Vec<[u8; 32]>>,
        paired_fleet_ips: Mutex<Vec<IpAddr>>,
        identity_pubkeys: Mutex<Vec<[u8; 32]>>,
        community_pubkeys: Mutex<Vec<[u8; 32]>>,
        peek_calls: AtomicUsize,
        peek_identities: Mutex<Vec<[u8; 32]>>,
        peek_limit_types: Mutex<Vec<LimitType>>,
        peek_fleet_ips: Mutex<Vec<IpAddr>>,
        peek_identity_limits: Mutex<Vec<u64>>,
        attempt_identity_charged: AtomicUsize,
        attempt_tenant_charged: AtomicUsize,
        attempt_fleet_charged: AtomicUsize,
        fresh_identity_charged: AtomicUsize,
        fresh_tenant_charged: AtomicUsize,
        fresh_fleet_charged: AtomicUsize,
        hierarchical_calls: AtomicUsize,
        paired_calls: AtomicUsize,
        principal_calls: AtomicUsize,
        attempt_fleet_deny: bool,
    }

    impl LaneRecordingLimiter {
        fn new(outcome: FleetLimiterOutcome) -> Self {
            Self::lanes(FleetLimiterOutcome::Allow, outcome, outcome)
        }

        fn lanes(
            increment_outcome: FleetLimiterOutcome,
            attempt_pair_outcome: FleetLimiterOutcome,
            fresh_pair_outcome: FleetLimiterOutcome,
        ) -> Self {
            Self::with_peek(
                increment_outcome,
                attempt_pair_outcome,
                fresh_pair_outcome,
                IdentityPeekOutcome::NotDenied,
            )
        }

        fn with_peek(
            increment_outcome: FleetLimiterOutcome,
            attempt_pair_outcome: FleetLimiterOutcome,
            fresh_pair_outcome: FleetLimiterOutcome,
            peek_outcome: IdentityPeekOutcome,
        ) -> Self {
            Self {
                increment_outcome,
                attempt_pair_outcome,
                fresh_pair_outcome,
                peek_outcome,
                steps: Arc::new(Mutex::new(Vec::new())),
                paired_types: Mutex::new(Vec::new()),
                principal_types: Mutex::new(Vec::new()),
                increment_pubkeys: Mutex::new(Vec::new()),
                paired_pubkeys: Mutex::new(Vec::new()),
                paired_fleet_ips: Mutex::new(Vec::new()),
                identity_pubkeys: Mutex::new(Vec::new()),
                community_pubkeys: Mutex::new(Vec::new()),
                peek_calls: AtomicUsize::new(0),
                peek_identities: Mutex::new(Vec::new()),
                peek_limit_types: Mutex::new(Vec::new()),
                peek_fleet_ips: Mutex::new(Vec::new()),
                peek_identity_limits: Mutex::new(Vec::new()),
                attempt_identity_charged: AtomicUsize::new(0),
                attempt_tenant_charged: AtomicUsize::new(0),
                attempt_fleet_charged: AtomicUsize::new(0),
                fresh_identity_charged: AtomicUsize::new(0),
                fresh_tenant_charged: AtomicUsize::new(0),
                fresh_fleet_charged: AtomicUsize::new(0),
                hierarchical_calls: AtomicUsize::new(0),
                paired_calls: AtomicUsize::new(0),
                principal_calls: AtomicUsize::new(0),
                attempt_fleet_deny: false,
            }
        }

        fn attempt_fleet_denied() -> Self {
            let mut limiter = Self::lanes(
                FleetLimiterOutcome::Allow,
                FleetLimiterOutcome::Deny,
                FleetLimiterOutcome::Allow,
            );
            limiter.attempt_fleet_deny = true;
            limiter
        }

        fn pair_outcome(&self, limit_type: &LimitType) -> FleetLimiterOutcome {
            match limit_type {
                LimitType::KeyedHttpFresh => self.fresh_pair_outcome,
                _ => self.attempt_pair_outcome,
            }
        }

        fn hierarchical_lane_outcome(&self, limit_type: &LimitType) -> FleetLimiterOutcome {
            match self.increment_outcome {
                FleetLimiterOutcome::Deny | FleetLimiterOutcome::Fail => self.increment_outcome,
                FleetLimiterOutcome::Allow => self.pair_outcome(limit_type),
            }
        }
    }

    impl RateLimiter for LaneRecordingLimiter {
        async fn check_and_increment(
            &self,
            _ctx: &TenantContext,
            pubkey: &nostr::PublicKey,
            limit_type: LimitType,
            window_secs: u64,
            limit: u64,
        ) -> Result<buzz_auth::RateLimitResult, buzz_auth::AuthError> {
            let step = match &limit_type {
                LimitType::KeyedHttpAttempts => "attempt_fair_share",
                LimitType::KeyedHttpFresh => "fresh_fair_share",
                LimitType::ApiCalls => "unkeyed_api",
                _ => "other_increment",
            };
            self.steps.lock().unwrap().push(step);
            self.principal_calls.fetch_add(1, Ordering::Relaxed);
            self.principal_types.lock().unwrap().push(limit_type);
            self.increment_pubkeys
                .lock()
                .unwrap()
                .push(pubkey.to_bytes());
            match self.increment_outcome {
                FleetLimiterOutcome::Allow => {
                    Ok(buzz_auth::RateLimitResult::allowed(1, limit, window_secs))
                }
                FleetLimiterOutcome::Deny => {
                    Ok(buzz_auth::RateLimitResult::denied(limit + 1, limit, 13))
                }
                FleetLimiterOutcome::Fail => Err(buzz_auth::AuthError::Internal(
                    "shared admission unavailable".to_owned(),
                )),
            }
        }

        async fn check_ip_connection(
            &self,
            _ip: &IpAddr,
            window_secs: u64,
            limit: u64,
        ) -> Result<buzz_auth::RateLimitResult, buzz_auth::AuthError> {
            Ok(buzz_auth::RateLimitResult::allowed(1, limit, window_secs))
        }

        async fn check_paired_admission(
            &self,
            request: PairedAdmissionRequest<'_>,
        ) -> Result<PairedAdmissionOutcome, buzz_auth::AuthError> {
            let step = match &request.limit_type {
                LimitType::KeyedHttpAttempts => "attempt_shared",
                LimitType::KeyedHttpFresh => "fresh_shared",
                _ => "other_shared",
            };
            self.steps.lock().unwrap().push(step);
            self.paired_calls.fetch_add(1, Ordering::Relaxed);
            self.paired_types
                .lock()
                .unwrap()
                .push(request.limit_type.clone());
            self.paired_pubkeys
                .lock()
                .unwrap()
                .push(request.pubkey.to_bytes());
            self.paired_fleet_ips
                .lock()
                .unwrap()
                .push(*request.fleet_ip);
            match self.pair_outcome(&request.limit_type) {
                FleetLimiterOutcome::Allow => {
                    match request.limit_type {
                        LimitType::KeyedHttpFresh => {
                            self.fresh_tenant_charged.fetch_add(1, Ordering::Relaxed);
                            self.fresh_fleet_charged.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {
                            self.attempt_tenant_charged.fetch_add(1, Ordering::Relaxed);
                            self.attempt_fleet_charged.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Ok(PairedAdmissionOutcome::Allowed {
                        tenant: buzz_auth::RateLimitResult::allowed(
                            1,
                            request.tenant_limit,
                            request.window_secs(),
                        ),
                        fleet: buzz_auth::RateLimitResult::allowed(
                            1,
                            request.fleet_limit,
                            request.window_secs(),
                        ),
                    })
                }
                FleetLimiterOutcome::Deny => Ok(PairedAdmissionOutcome::TenantDenied(
                    buzz_auth::RateLimitResult::denied(
                        request.tenant_limit + 1,
                        request.tenant_limit,
                        17,
                    ),
                )),
                FleetLimiterOutcome::Fail => Err(buzz_auth::AuthError::Internal(
                    "shared admission unavailable".to_owned(),
                )),
            }
        }

        async fn check_hierarchical_admission(
            &self,
            request: HierarchicalAdmissionRequest<'_>,
        ) -> Result<HierarchicalAdmissionOutcome, buzz_auth::AuthError> {
            let step = match &request.limit_type {
                LimitType::KeyedHttpAttempts => "attempt_hierarchical",
                LimitType::KeyedHttpFresh => "fresh_hierarchical",
                _ => "other_hierarchical",
            };
            self.steps.lock().unwrap().push(step);
            self.hierarchical_calls.fetch_add(1, Ordering::Relaxed);
            self.principal_types
                .lock()
                .unwrap()
                .push(request.limit_type.clone());
            self.paired_types
                .lock()
                .unwrap()
                .push(request.limit_type.clone());
            self.increment_pubkeys
                .lock()
                .unwrap()
                .push(request.identity.to_bytes());
            self.identity_pubkeys
                .lock()
                .unwrap()
                .push(request.identity.to_bytes());
            self.community_pubkeys
                .lock()
                .unwrap()
                .push(request.community.to_bytes());
            self.paired_pubkeys
                .lock()
                .unwrap()
                .push(request.community.to_bytes());
            self.paired_fleet_ips
                .lock()
                .unwrap()
                .push(*request.fleet_ip);
            let identity_deny = matches!(self.increment_outcome, FleetLimiterOutcome::Deny);
            match self.hierarchical_lane_outcome(&request.limit_type) {
                FleetLimiterOutcome::Allow => {
                    match request.limit_type {
                        LimitType::KeyedHttpFresh => {
                            self.fresh_identity_charged.fetch_add(1, Ordering::Relaxed);
                            self.fresh_tenant_charged.fetch_add(1, Ordering::Relaxed);
                            self.fresh_fleet_charged.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {
                            self.attempt_identity_charged
                                .fetch_add(1, Ordering::Relaxed);
                            self.attempt_tenant_charged.fetch_add(1, Ordering::Relaxed);
                            self.attempt_fleet_charged.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Ok(HierarchicalAdmissionOutcome::Allowed {
                        identity: buzz_auth::RateLimitResult::allowed(
                            1,
                            request.limits.identity,
                            request.window_secs(),
                        ),
                        community: buzz_auth::RateLimitResult::allowed(
                            1,
                            request.limits.community,
                            request.window_secs(),
                        ),
                        fleet: buzz_auth::RateLimitResult::allowed(
                            1,
                            request.limits.fleet,
                            request.window_secs(),
                        ),
                    })
                }
                FleetLimiterOutcome::Deny if identity_deny => {
                    Ok(HierarchicalAdmissionOutcome::IdentityDenied(
                        buzz_auth::RateLimitResult::denied(
                            request.limits.identity + 1,
                            request.limits.identity,
                            13,
                        ),
                    ))
                }
                FleetLimiterOutcome::Deny if self.attempt_fleet_deny => Ok(
                    HierarchicalAdmissionOutcome::FleetDenied(buzz_auth::RateLimitResult::denied(
                        request.limits.fleet + 1,
                        request.limits.fleet,
                        23,
                    )),
                ),
                FleetLimiterOutcome::Deny => Ok(HierarchicalAdmissionOutcome::CommunityDenied(
                    buzz_auth::RateLimitResult::denied(
                        request.limits.community + 1,
                        request.limits.community,
                        17,
                    ),
                )),
                FleetLimiterOutcome::Fail => Err(buzz_auth::AuthError::Internal(
                    "shared admission unavailable".to_owned(),
                )),
            }
        }

        async fn peek_hierarchical_identity_denial(
            &self,
            request: HierarchicalIdentityDenialPeekRequest<'_>,
        ) -> Result<HierarchicalIdentityDenialPeekOutcome, buzz_auth::AuthError> {
            self.steps.lock().unwrap().push("attempt_peek");
            self.peek_calls.fetch_add(1, Ordering::Relaxed);
            self.peek_identities
                .lock()
                .unwrap()
                .push(request.identity.to_bytes());
            self.peek_limit_types
                .lock()
                .unwrap()
                .push(request.limit_type.clone());
            self.peek_fleet_ips.lock().unwrap().push(*request.fleet_ip);
            self.peek_identity_limits
                .lock()
                .unwrap()
                .push(request.identity_limit());
            match self.peek_outcome {
                IdentityPeekOutcome::NotDenied => {
                    Ok(HierarchicalIdentityDenialPeekOutcome::NotDenied)
                }
                IdentityPeekOutcome::Denied => Ok(HierarchicalIdentityDenialPeekOutcome::Denied(
                    buzz_auth::RateLimitResult::denied(
                        request.identity_limit() + 1,
                        request.identity_limit(),
                        19,
                    ),
                )),
                IdentityPeekOutcome::Fail => Err(buzz_auth::AuthError::Internal(
                    "shared admission unavailable".to_owned(),
                )),
            }
        }
    }

    struct OrderedReplayGuard {
        steps: Arc<Mutex<Vec<&'static str>>>,
        admit: bool,
    }

    impl Nip98ReplayGuard for OrderedReplayGuard {
        fn try_mark_in_scope<'a>(
            &'a self,
            _scope: &'a str,
            _event_id: &'a nostr::EventId,
            _ttl_secs: u64,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<bool, buzz_auth::AuthError>> + Send + 'a>,
        > {
            Box::pin(async {
                self.steps.lock().unwrap().push("replay");
                Ok(self.admit)
            })
        }
    }

    type MembershipReady =
        std::future::Ready<Result<Option<nostr::PublicKey>, (StatusCode, Json<Value>)>>;
    type KeyedBodyValidationCase = (
        &'static str,
        Vec<u8>,
        nostr::PublicKey,
        fn(&IngestError) -> bool,
    );

    fn recording_membership(
        steps: &Arc<Mutex<Vec<&'static str>>>,
        result: Result<Option<nostr::PublicKey>, (StatusCode, Json<Value>)>,
    ) -> impl FnOnce() -> MembershipReady {
        let steps = Arc::clone(steps);
        move || {
            steps.lock().unwrap().push("membership");
            std::future::ready(result)
        }
    }

    fn recording_owner<'a>(
        steps: &Arc<Mutex<Vec<&'static str>>>,
        result: Option<&'a str>,
    ) -> impl FnOnce() -> Option<&'a str> {
        let steps = Arc::clone(steps);
        move || {
            steps.lock().unwrap().push("owner_select");
            result
        }
    }

    fn unreachable_membership() -> impl FnOnce() -> MembershipReady {
        || {
            panic!(
                "membership must not run before attempt, ingress, replay, parse, \
             signature, and author binding succeed"
            )
        }
    }

    fn unreachable_owner() -> impl FnOnce() -> Option<&'static str> {
        || {
            panic!(
            "owner selection must not run before signature, author binding, and membership succeed"
        )
        }
    }

    fn signed_text_note_body(keys: &Keys) -> Vec<u8> {
        let event = EventBuilder::new(Kind::TextNote, "fresh")
            .sign_with_keys(keys)
            .expect("sign");
        serde_json::to_vec(&event).expect("serialize")
    }

    fn signed_kind9_body(keys: &Keys) -> Vec<u8> {
        let event = EventBuilder::new(Kind::Custom(9), "fresh")
            .sign_with_keys(keys)
            .expect("sign");
        serde_json::to_vec(&event).expect("serialize")
    }

    fn stale_kind9_body(keys: &Keys) -> Vec<u8> {
        let event = EventBuilder::new(Kind::Custom(9), "fresh")
            .custom_created_at(Timestamp::from(1u64))
            .sign_with_keys(keys)
            .expect("sign");
        serde_json::to_vec(&event).expect("serialize")
    }

    fn extreme_signed_kind9_body(keys: &Keys) -> Vec<u8> {
        let fixed_now: u64 = 1_700_000_000;
        let event = EventBuilder::new(Kind::Custom(9), "fresh")
            .custom_created_at(Timestamp::from(fixed_now.wrapping_add(1u64 << 63)))
            .sign_with_keys(keys)
            .expect("sign");
        serde_json::to_vec(&event).expect("serialize")
    }

    fn oversized_kind9_body(keys: &Keys) -> Vec<u8> {
        let content = "x".repeat(256 * 1024 + 1);
        let event = EventBuilder::new(Kind::Custom(9), content)
            .sign_with_keys(keys)
            .expect("sign");
        serde_json::to_vec(&event).expect("serialize")
    }

    fn excessive_p_tag_kind9_body(keys: &Keys) -> Vec<u8> {
        let hex = keys.public_key().to_hex();
        let tags: Vec<Tag> = (0..=buzz_core::idempotency::KEYED_MAX_P_TAGS)
            .map(|_| Tag::parse(["p", &hex]).expect("p tag"))
            .collect();
        let event = EventBuilder::new(Kind::Custom(9), "fresh")
            .tags(tags)
            .allow_self_tagging()
            .sign_with_keys(keys)
            .expect("sign");
        assert_eq!(
            event.tags.len(),
            buzz_core::idempotency::KEYED_MAX_P_TAGS + 1
        );
        serde_json::to_vec(&event).expect("serialize")
    }

    fn forged_kind9_body(keys: &Keys) -> Vec<u8> {
        let event = EventBuilder::new(Kind::Custom(9), "fresh")
            .sign_with_keys(keys)
            .expect("sign");
        let mut value = serde_json::to_value(&event).expect("json");
        for field in ["id", "sig"] {
            let Some(serde_json::Value::String(hex)) = value.get(field).cloned() else {
                panic!("{field} must serialize as hex");
            };
            let flipped = format!(
                "{}{}",
                if hex.as_bytes()[0] == b'0' { '1' } else { '0' },
                &hex[1..]
            );
            value[field] = serde_json::Value::String(flipped);
        }
        serde_json::to_vec(&value).expect("serialize")
    }

    fn assert_fresh_untouched(limiter: &LaneRecordingLimiter) {
        assert_eq!(limiter.fresh_identity_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.fresh_tenant_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.fresh_fleet_charged.load(Ordering::Relaxed), 0);
        assert!(
            !limiter
                .paired_types
                .lock()
                .unwrap()
                .contains(&LimitType::KeyedHttpFresh),
            "fresh LimitType must not be consulted"
        );
        assert!(
            !limiter
                .steps
                .lock()
                .unwrap()
                .contains(&"fresh_hierarchical"),
            "fresh hierarchy must not run before committed miss"
        );
    }

    fn assert_attempt_charged_once(limiter: &LaneRecordingLimiter, pubkey: &nostr::PublicKey) {
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 1);
        assert_eq!(limiter.attempt_identity_charged.load(Ordering::Relaxed), 1);
        assert_eq!(limiter.attempt_tenant_charged.load(Ordering::Relaxed), 1);
        assert_eq!(limiter.attempt_fleet_charged.load(Ordering::Relaxed), 1);
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            limiter.identity_pubkeys.lock().unwrap()[0],
            pubkey.to_bytes()
        );
        assert_eq!(
            limiter.community_pubkeys.lock().unwrap()[0],
            keyed_http_attempt_admission_principal().to_bytes()
        );
        assert_eq!(
            limiter.paired_fleet_ips.lock().unwrap()[0],
            KEYED_HTTP_ATTEMPT_FLEET_SENTINEL
        );
        assert_eq!(
            limiter.principal_types.lock().unwrap()[0],
            LimitType::KeyedHttpAttempts
        );
    }

    fn assert_attempt_invoked_without_charge(limiter: &LaneRecordingLimiter) {
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 1);
        assert_eq!(limiter.attempt_identity_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.attempt_tenant_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.attempt_fleet_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
    }

    async fn attempt_then_after<'req, 'tag, L, Mem, MemFut, Tag>(
        limiter: &L,
        replay_guard: &dyn Nip98ReplayGuard,
        request: KeyedHttpAdmitRequest<'req>,
        membership: Mem,
        open_relay_auth_tag: Tag,
    ) -> Result<(KeyedHttpValidatedEvent, Option<nostr::PublicKey>), KeyedHttpAdmitError>
    where
        L: RateLimiter,
        Mem: FnOnce() -> MemFut + 'req,
        MemFut: Future<Output = Result<Option<nostr::PublicKey>, (StatusCode, Json<Value>)>>
            + Send
            + 'req,
        Tag: FnOnce() -> Option<&'tag str> + 'req,
    {
        let _ingress_lock = lock_keyed_ingress_tests_async().await;
        admit_keyed_http_attempt(limiter, request.tenant, &request.pubkey)
            .await
            .map_err(KeyedHttpAdmitError::PreIngest)?;
        let community = *request.tenant.community().as_uuid();
        let ingress = try_acquire_keyed_ingress(community).map_err(|_| {
            KeyedHttpAdmitError::PreIngest(KeyedPreIngestError::Attempt(
                crate::admission::AdmissionError::Unavailable,
            ))
        })?;
        let early = KeyedHttpEarlyContext {
            ingress: Some(ingress),
            deadline: KeyedEarlyDeadline::start(),
            verified_owner: None,
        };
        let (validated, early) = admit_keyed_http_after_attempt(
            replay_guard,
            request,
            membership,
            open_relay_auth_tag,
            early,
        )
        .await?;
        Ok((validated, early.verified_owner))
    }

    #[test]
    fn keyed_handler_header_errors_are_rejected_before_ingress() {
        let headers = idempotency_header_map(&["not-a-key"]);
        let parse_err = parse_idempotency_key_header(&headers).expect_err("invalid key");
        let err = keyed_handler_error_response(KeyedHandlerError::InvalidHeader(parse_err));
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        assert_eq!(KEYED_INGRESS_GLOBAL_MAX, 32);
        assert_eq!(KEYED_INGRESS_COMMUNITY_MAX, 16);
    }

    #[test]
    fn unkeyed_parse_consumes_no_ingress() {
        let headers = HeaderMap::new();
        let key = parse_idempotency_key_header(&headers).expect("unkeyed parse");
        assert!(key.is_none());
    }

    #[test]
    fn unmapped_host_and_failed_auth_happen_before_attempt_and_ingress() {
        let hex = "ab".repeat(32);
        let mut headers = idempotency_header_map(&[&hex]);
        headers.insert(header::HOST, "unmapped.example".parse().expect("host"));
        let key = parse_idempotency_key_header(&headers)
            .expect("valid key parses before bind")
            .expect("decoded key");
        assert_eq!(hex::encode(key), hex);

        let missing_auth = verify_bridge_auth(
            &headers,
            "POST",
            "http://unmapped.example/events",
            Some(b"{}"),
            true,
        );
        assert!(missing_auth.is_err(), "missing Nostr auth must fail closed");

        headers.insert(
            header::AUTHORIZATION,
            "Nostr not-base64".parse().expect("authorization"),
        );
        let invalid_auth = verify_bridge_auth(
            &headers,
            "POST",
            "http://unmapped.example/events",
            Some(b"{}"),
            true,
        );
        assert!(
            invalid_auth.is_err(),
            "invalid NIP-98 auth must fail closed"
        );
    }

    #[test]
    fn unkeyed_dev_x_pubkey_identity_is_accepted() {
        let keys = Keys::generate();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-pubkey",
            keys.public_key().to_hex().parse().expect("x-pubkey"),
        );
        let VerifiedBridgeAuth {
            pubkey,
            event_id_bytes,
            ..
        } = verify_bridge_auth(
            &headers,
            "POST",
            "https://relay.example/events",
            Some(b"{}"),
            false,
        )
        .expect("unkeyed development X-Pubkey remains accepted");
        assert_eq!(pubkey, keys.public_key());
        assert_eq!(event_id_bytes, [0u8; 32]);
    }

    /// Keyed POST /events with dev `require_auth_token = false`, a valid
    /// Idempotency-Key, and only `X-Pubkey` must 401 after host bind and
    /// before pre-attempt capacity. Bites if `submit_event` drops
    /// `require_auth_token || idempotency_key.is_some()` or acquires capacity
    /// first (community slots are already full, so that path would 503).
    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn keyed_unsigned_dev_identity_is_rejected_after_host_binding_before_capacity() {
        let _router_fleet_guard = ROUTER_FLEET_SENTINEL_LOCK.lock().await;
        let state = bridge_handler_test_state()
            .await
            .expect("local Postgres/Redis not reachable");
        assert!(
            !state.config.require_auth_token,
            "dev config must leave the X-Pubkey fallback available"
        );

        let host = format!("keyed-unsigned-{}.local", uuid::Uuid::new_v4().simple());
        let community = state
            .db
            .ensure_configured_community(&host)
            .await
            .expect("community");
        let channel = insert_open_channel(&state.config.database_url, community.id).await;
        let tenant = crate::tenant::bind_community(&state.db, &host)
            .await
            .expect("host binding is a required prerequisite");
        let community_id = *tenant.community().as_uuid();
        let keys = Keys::generate();
        let (body, pubkey_hex) = kind9_event(&keys, channel);
        let event: nostr::Event = serde_json::from_slice(&body).expect("kind 9 event");
        let author = event.pubkey.to_bytes();
        let key = unique_idempotency_key_hex();
        let key_bytes = parse_test_idempotency_key(&key);

        let unmapped = post_events_unsigned_x_pubkey_with_key(
            Arc::clone(&state),
            &format!("unmapped-{}.local", uuid::Uuid::new_v4().simple()),
            &pubkey_hex,
            &body,
            &key,
        )
        .await;
        assert_eq!(
            unmapped.status(),
            StatusCode::NOT_FOUND,
            "unsigned keyed traffic on an unbound host must fail at host binding"
        );

        let capacity = keyed_pre_attempt_capacity().expect("production pre-attempt capacity");
        let global_before_hold = capacity.global_available();
        let mut held = Vec::with_capacity(KEYED_PRE_ATTEMPT_COMMUNITY_MAX);
        for _ in 0..KEYED_PRE_ATTEMPT_COMMUNITY_MAX {
            held.push(
                try_acquire_keyed_pre_attempt(community_id).expect("hold community pre-attempt"),
            );
        }
        assert_eq!(
            capacity.community_count(community_id),
            Some(KEYED_PRE_ATTEMPT_COMMUNITY_MAX)
        );
        let global_held = capacity.global_available();
        assert_eq!(
            global_held,
            global_before_hold - KEYED_PRE_ATTEMPT_COMMUNITY_MAX
        );

        let historical_identity_key = buzz_auth::rate_limit::rate_limit_key(
            &tenant,
            &keys.public_key(),
            &KEYED_HTTP_ATTEMPT_LIMIT_TYPE,
        );
        let historical_community_key = buzz_auth::rate_limit::rate_limit_key(
            &tenant,
            &keyed_http_attempt_admission_principal(),
            &KEYED_HTTP_ATTEMPT_LIMIT_TYPE,
        );
        let historical_fleet_key =
            buzz_auth::rate_limit::ip_rate_limit_key(&KEYED_HTTP_ATTEMPT_FLEET_SENTINEL);
        let persist_community_key = buzz_auth::rate_limit::rate_limit_key(
            &tenant,
            &keyed_community_admission_principal(),
            &KEYED_COMMUNITY_ADMISSION_LIMIT_TYPE,
        );
        let persist_fleet_key =
            buzz_auth::rate_limit::ip_rate_limit_key(&KEYED_EVENTS_FLEET_ADMISSION_SENTINEL);
        let principal_key = buzz_auth::rate_limit::rate_limit_key(
            &tenant,
            &keys.public_key(),
            &LimitType::ApiCalls,
        );
        let historical_i0 = redis_int(&state, &historical_identity_key).await;
        let historical_c0 = redis_int(&state, &historical_community_key).await;
        let historical_f0 = redis_int(&state, &historical_fleet_key).await;
        let persist_c0 = redis_int(&state, &persist_community_key).await;
        let persist_f0 = redis_int(&state, &persist_fleet_key).await;
        let principal_0 = redis_int(&state, &principal_key).await;

        let response = post_events_unsigned_x_pubkey_with_key(
            Arc::clone(&state),
            &host,
            &pubkey_hex,
            &body,
            &key,
        )
        .await;
        let status = response.status();
        let body_bytes = axum::body::to_bytes(response.into_body(), 256)
            .await
            .expect("bounded unsigned-keyed body");
        let json: Value = serde_json::from_slice(&body_bytes).expect("unsigned-keyed JSON");
        let msg = json
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_ne!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "full pre-attempt capacity must not be consulted for unsigned keyed identity"
        );
        assert_ne!(status, StatusCode::NOT_FOUND);
        assert!(
            msg.contains("missing Nostr auth"),
            "keyed unsigned identity must fail closed as missing NIP-98 after host binding; got {msg}"
        );
        assert_eq!(
            capacity.community_count(community_id),
            Some(KEYED_PRE_ATTEMPT_COMMUNITY_MAX)
        );
        assert_eq!(capacity.global_available(), global_held);
        assert_eq!(
            redis_int(&state, &historical_identity_key).await,
            historical_i0
        );
        assert_eq!(
            redis_int(&state, &historical_community_key).await,
            historical_c0
        );
        assert_eq!(
            redis_int(&state, &historical_fleet_key).await,
            historical_f0
        );
        assert_eq!(redis_int(&state, &persist_community_key).await, persist_c0);
        assert_eq!(redis_int(&state, &persist_fleet_key).await, persist_f0);
        assert_eq!(redis_int(&state, &principal_key).await, principal_0);

        let pool = sqlx::PgPool::connect(&state.config.database_url)
            .await
            .expect("connect test db");
        let idempotency_rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM event_idempotency_keys WHERE community_id = $1 AND author_pubkey = $2 AND idempotency_key = $3",
        )
        .bind(community_id)
        .bind(author.as_slice())
        .bind(key_bytes.as_slice())
        .fetch_one(&pool)
        .await
        .expect("count idempotency rows");
        assert_eq!(
            idempotency_rows, 0,
            "unsigned keyed reject must not reserve"
        );

        let unkeyed_keys = Keys::generate();
        let (unkeyed_body, _) = kind9_event(&unkeyed_keys, channel);
        let unkeyed = post_events_with_idempotency(
            Arc::clone(&state),
            &host,
            &unkeyed_keys,
            &unkeyed_body,
            None,
        )
        .await;
        assert_eq!(
            unkeyed,
            StatusCode::OK,
            "unkeyed development X-Pubkey remains accepted"
        );
        assert_eq!(
            capacity.community_count(community_id),
            Some(KEYED_PRE_ATTEMPT_COMMUNITY_MAX),
            "unkeyed development success must not take keyed pre-attempt capacity"
        );
        assert_eq!(
            redis_int(&state, &historical_identity_key).await,
            historical_i0
        );
        assert_eq!(redis_int(&state, &persist_community_key).await, persist_c0);

        drop(held);
        let signed =
            post_events_with_idempotency(Arc::clone(&state), &host, &keys, &body, Some(&key)).await;
        let signed_rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM event_idempotency_keys WHERE community_id = $1 AND author_pubkey = $2 AND idempotency_key = $3",
        )
        .bind(community_id)
        .bind(author.as_slice())
        .bind(key_bytes.as_slice())
        .fetch_one(&pool)
        .await
        .expect("count signed keyed idempotency rows");
        sqlx::query(
            "DELETE FROM event_idempotency_keys WHERE community_id = $1 AND author_pubkey = $2 AND idempotency_key = $3",
        )
        .bind(community_id)
        .bind(author.as_slice())
        .bind(key_bytes.as_slice())
        .execute(&pool)
        .await
        .expect("cleanup idempotency row");
        assert_eq!(
            signed,
            StatusCode::OK,
            "signed keyed NIP-98 remains accepted"
        );
        assert_eq!(signed_rows, 1);
    }

    #[test]
    fn keyed_locally_signed_nip98_succeeds_without_payload_tag() {
        let keys = Keys::generate();
        let url = "https://relay.example/events";
        let event_json = build_nip98_event_json(&keys, url, "POST");
        let mut headers = nip98_auth_headers(&event_json);
        let hex = "cd".repeat(32);
        headers.append(
            buzz_core::idempotency::HEADER_NAME,
            hex.parse().expect("idempotency key"),
        );
        headers.insert(header::HOST, "relay.example".parse().expect("host"));
        headers.insert(
            "x-pubkey",
            keys.public_key().to_hex().parse().expect("x-pubkey"),
        );

        let key = parse_idempotency_key_header(&headers)
            .expect("valid key parses before bind")
            .expect("decoded key");
        assert_eq!(hex::encode(key), hex);
        assert!(
            headers.contains_key(header::HOST),
            "host binding remains the first post-header-parse prerequisite"
        );

        let VerifiedBridgeAuth {
            pubkey,
            event_id_bytes,
            ..
        } = verify_bridge_auth(&headers, "POST", url, Some(b"{}"), true)
            .expect("keyed lane accepts locally signed NIP-98 without a payload tag");
        assert_eq!(pubkey, keys.public_key());
        assert_ne!(event_id_bytes, [0u8; 32]);
        assert!(!event_json.contains("payload"));
    }

    fn assert_pre_attempt_busy_is_opaque_503() {
        let (status, retry_after, Json(body)) = keyed_busy_http_parts(KEYED_BUSY_RETRY_AFTER_SECS);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_ne!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(retry_after[0].0, header::RETRY_AFTER);
        assert_eq!(retry_after[0].1, "5");
        assert_eq!(
            body,
            serde_json::json!({"error": "idempotency unavailable"})
        );
        let dumped = body.to_string();
        assert!(!dumped.contains("capacity"));
        assert!(!dumped.contains("redis"));
        assert!(!dumped.contains("quota"));
        assert!(!dumped.contains("tenant"));
    }

    fn isolated_pre_attempt_communities(capacity: &KeyedPreAttemptCapacity) -> (Uuid, Uuid) {
        for a in 1u128..4_096 {
            let mix = a.wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(17);
            let community_a = Uuid::from_u128(mix ^ 0xA11);
            let Some(hold_a) = capacity.try_hold_registry(community_a) else {
                continue;
            };
            for b in a + 1..a + 512 {
                let mix_b = b.wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(17);
                let community_b = Uuid::from_u128(mix_b ^ 0xB22);
                if let Some(hold_b) = capacity.try_hold_registry(community_b) {
                    drop(hold_b);
                    drop(hold_a);
                    return (community_a, community_b);
                }
            }
            drop(hold_a);
        }
        panic!("could not find two communities on distinct pre-attempt registry shards");
    }

    fn same_shard_pre_attempt_communities(capacity: &KeyedPreAttemptCapacity) -> (Uuid, Uuid) {
        for a in 1u128..8_192 {
            let mix = a.wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(17);
            let community_a = Uuid::from_u128(mix ^ 0x51A);
            let Some(hold_a) = capacity.try_hold_registry(community_a) else {
                continue;
            };
            for b in a + 1..a + 4_096 {
                let mix_b = b.wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(17);
                let community_b = Uuid::from_u128(mix_b ^ 0x51B);
                if community_a == community_b {
                    continue;
                }
                if capacity.try_hold_registry(community_b).is_none() {
                    drop(hold_a);
                    return (community_a, community_b);
                }
            }
            drop(hold_a);
        }
        panic!("could not find two communities on the same pre-attempt registry shard");
    }

    fn assert_pre_attempt_fully_idle(capacity: &KeyedPreAttemptCapacity) {
        reap_dead_keyed_pre_attempt_entries(capacity);
        assert_eq!(capacity.global_available(), KEYED_PRE_ATTEMPT_GLOBAL_MAX);
        assert_eq!(capacity.registry_len(), 0);
        assert_eq!(capacity.registry_bound(), 0);
    }

    fn wait_pre_attempt_key_absent(
        capacity: &KeyedPreAttemptCapacity,
        community: Uuid,
        timeout: Duration,
    ) {
        let deadline = Instant::now() + timeout;
        while capacity.registry_contains(community) {
            if Instant::now() >= deadline {
                panic!("reaper did not remove stale pre-attempt key without a new checkout");
            }
            capacity.unpark_reaper();
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn keyed_pre_attempt_community_isolation_and_global_exhaustion() {
        let limiter = LaneRecordingLimiter::new(FleetLimiterOutcome::Allow);
        let capacity = KeyedPreAttemptCapacity::new();
        let community_a = Uuid::from_u128(0xA11);
        let community_b = Uuid::from_u128(0xB22);
        let community_c = Uuid::from_u128(0xC33);
        assert_eq!(KEYED_PRE_ATTEMPT_GLOBAL_MAX, 32);
        assert_eq!(KEYED_PRE_ATTEMPT_COMMUNITY_MAX, 16);

        let mut held_a = Vec::with_capacity(KEYED_PRE_ATTEMPT_COMMUNITY_MAX);
        for _ in 0..KEYED_PRE_ATTEMPT_COMMUNITY_MAX {
            held_a.push(
                try_acquire_keyed_pre_attempt_from(&capacity, community_a).expect("community A"),
            );
        }
        assert_eq!(
            capacity.community_count(community_a),
            Some(KEYED_PRE_ATTEMPT_COMMUNITY_MAX)
        );
        assert_eq!(
            capacity.community_live_handles(community_a),
            Some(KEYED_PRE_ATTEMPT_COMMUNITY_MAX)
        );
        assert_eq!(
            capacity.global_available(),
            KEYED_PRE_ATTEMPT_GLOBAL_MAX - KEYED_PRE_ATTEMPT_COMMUNITY_MAX
        );
        match try_acquire_keyed_pre_attempt_from(&capacity, community_a) {
            Err(()) => assert_pre_attempt_busy_is_opaque_503(),
            Ok(_) => panic!("community A at 16 must fail fast without queueing"),
        }
        assert_eq!(
            capacity.community_count(community_a),
            Some(KEYED_PRE_ATTEMPT_COMMUNITY_MAX)
        );
        assert_eq!(
            capacity.community_live_handles(community_a),
            Some(KEYED_PRE_ATTEMPT_COMMUNITY_MAX)
        );
        assert_eq!(
            capacity.global_available(),
            KEYED_PRE_ATTEMPT_GLOBAL_MAX - KEYED_PRE_ATTEMPT_COMMUNITY_MAX
        );
        assert!(!capacity.registry_contains(community_b));
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.principal_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);

        let mut held_b = Vec::with_capacity(KEYED_PRE_ATTEMPT_COMMUNITY_MAX);
        for _ in 0..KEYED_PRE_ATTEMPT_COMMUNITY_MAX {
            held_b.push(
                try_acquire_keyed_pre_attempt_from(&capacity, community_b)
                    .expect("community B while A is full"),
            );
        }
        assert_eq!(
            capacity.community_count(community_b),
            Some(KEYED_PRE_ATTEMPT_COMMUNITY_MAX)
        );
        assert_eq!(capacity.global_available(), 0);
        assert_eq!(capacity.registry_len(), 2);
        match try_acquire_keyed_pre_attempt_from(&capacity, community_c) {
            Err(()) => assert_pre_attempt_busy_is_opaque_503(),
            Ok(_) => panic!("global 32 must fail fast for a third community"),
        }
        assert!(!capacity.registry_contains(community_c));
        assert_eq!(capacity.community_count(community_c), None);
        assert_eq!(capacity.community_live_handles(community_c), None);
        assert_eq!(capacity.registry_len(), 2);
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.principal_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);

        drop(held_a);
        drop(held_b);
        assert_eq!(capacity.global_available(), KEYED_PRE_ATTEMPT_GLOBAL_MAX);
        assert_pre_attempt_fully_idle(&capacity);
        assert!(!capacity.registry_contains(community_a));
        assert!(!capacity.registry_contains(community_b));
        let restored =
            try_acquire_keyed_pre_attempt_from(&capacity, community_a).expect("restored");
        assert_eq!(
            capacity.global_available(),
            KEYED_PRE_ATTEMPT_GLOBAL_MAX - 1
        );
        assert_eq!(capacity.community_count(community_a), Some(1));
        drop(restored);
        assert_eq!(capacity.global_available(), KEYED_PRE_ATTEMPT_GLOBAL_MAX);
        assert_pre_attempt_fully_idle(&capacity);
    }

    #[test]
    fn unkeyed_path_does_not_acquire_pre_attempt_capacity() {
        let capacity = KeyedPreAttemptCapacity::new();
        let headers = HeaderMap::new();
        let key = parse_idempotency_key_header(&headers).expect("unkeyed parse");
        // Production acquires only inside `if idempotency_key.is_some()` after auth.
        match key {
            None => {}
            Some(_) => {
                let community = Uuid::from_u128(0xE11);
                let _permit = try_acquire_keyed_pre_attempt_from(&capacity, community)
                    .expect("would acquire only for keyed");
                panic!("unkeyed parse must not present a key");
            }
        }
        assert_eq!(capacity.global_available(), KEYED_PRE_ATTEMPT_GLOBAL_MAX);
        assert_eq!(capacity.registry_len(), 0);
    }

    #[test]
    fn malformed_idempotency_header_is_rejected_before_pre_attempt_capacity() {
        let capacity = KeyedPreAttemptCapacity::new();
        let headers = idempotency_header_map(&["not-a-key"]);
        let parse_err = parse_idempotency_key_header(&headers).expect_err("invalid key");
        let err = keyed_handler_error_response(KeyedHandlerError::InvalidHeader(parse_err));
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        assert_ne!(err.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(capacity.global_available(), KEYED_PRE_ATTEMPT_GLOBAL_MAX);
        assert_eq!(capacity.registry_len(), 0);
    }

    #[test]
    fn keyed_pre_attempt_handoff_holds_through_attempt_then_releases_after_ingress() {
        let _ingress_lock = lock_keyed_ingress_tests();
        let limiter = LaneRecordingLimiter::new(FleetLimiterOutcome::Allow);
        let tenant = fresh_tenant("keyed-pre-attempt.example");
        let keys = Keys::generate();
        let capacity = KeyedPreAttemptCapacity::new();
        let community = *tenant.community().as_uuid();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let pre_attempt =
            try_acquire_keyed_pre_attempt_from(&capacity, community).expect("pre-attempt");
        assert_eq!(
            capacity.global_available(),
            KEYED_PRE_ATTEMPT_GLOBAL_MAX - 1
        );
        assert_eq!(capacity.community_count(community), Some(1));
        rt.block_on(admit_keyed_http_attempt(
            &limiter,
            &tenant,
            &keys.public_key(),
        ))
        .expect("attempt allowed");
        assert_eq!(
            capacity.global_available(),
            KEYED_PRE_ATTEMPT_GLOBAL_MAX - 1
        );
        assert_eq!(capacity.community_count(community), Some(1));
        assert_attempt_charged_once(&limiter, &keys.public_key());
        let ingress = try_acquire_keyed_ingress(community).expect("ingress");
        assert_eq!(
            capacity.global_available(),
            KEYED_PRE_ATTEMPT_GLOBAL_MAX - 1,
            "pre-attempt stays held until after ingress is acquired"
        );
        assert_eq!(capacity.community_count(community), Some(1));
        let ingress = handoff_keyed_pre_attempt_to_ingress(ingress, pre_attempt);
        assert_eq!(capacity.global_available(), KEYED_PRE_ATTEMPT_GLOBAL_MAX);
        assert_eq!(capacity.community_count(community), None);
        assert_pre_attempt_fully_idle(&capacity);
        drop(ingress);
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert_fresh_untouched(&limiter);
    }

    #[test]
    fn keyed_pre_attempt_denial_and_early_drop_reclaim() {
        let capacity = KeyedPreAttemptCapacity::new();
        let community = Uuid::from_u128(0xD44);
        let held = try_acquire_keyed_pre_attempt_from(&capacity, community).expect("held");
        assert_eq!(
            capacity.global_available(),
            KEYED_PRE_ATTEMPT_GLOBAL_MAX - 1
        );
        assert_eq!(capacity.community_count(community), Some(1));
        drop(held);
        assert_eq!(capacity.global_available(), KEYED_PRE_ATTEMPT_GLOBAL_MAX);
        assert_pre_attempt_fully_idle(&capacity);
        assert!(!capacity.registry_contains(community));

        let mut held = Vec::with_capacity(KEYED_PRE_ATTEMPT_COMMUNITY_MAX);
        for _ in 0..KEYED_PRE_ATTEMPT_COMMUNITY_MAX {
            held.push(try_acquire_keyed_pre_attempt_from(&capacity, community).expect("fill"));
        }
        let global_at_community_cap = capacity.global_available();
        assert!(try_acquire_keyed_pre_attempt_from(&capacity, community).is_err());
        assert_eq!(capacity.global_available(), global_at_community_cap);
        assert_eq!(
            capacity.community_count(community),
            Some(KEYED_PRE_ATTEMPT_COMMUNITY_MAX)
        );
        assert_eq!(
            capacity.community_live_handles(community),
            Some(KEYED_PRE_ATTEMPT_COMMUNITY_MAX)
        );
        drop(held);
        assert_eq!(capacity.global_available(), KEYED_PRE_ATTEMPT_GLOBAL_MAX);
        assert_pre_attempt_fully_idle(&capacity);

        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = try_acquire_keyed_pre_attempt_from(&capacity, community).expect("permit");
            panic!("pre-attempt must drop on unwind");
        }));
        assert!(panicked.is_err());
        assert_eq!(capacity.global_available(), KEYED_PRE_ATTEMPT_GLOBAL_MAX);
        assert_eq!(capacity.community_live_handles(community), None);
        assert_pre_attempt_fully_idle(&capacity);
        assert!(!capacity.registry_contains(community));
    }

    #[test]
    fn keyed_pre_attempt_registry_contention_is_fail_fast_and_preserves_capacity() {
        let capacity = KeyedPreAttemptCapacity::new();
        let community = Uuid::from_u128(0xA11);
        let global_before = capacity.global_available();
        let registry_before = capacity.registry_len();
        {
            let _hold = capacity
                .try_hold_registry(community)
                .expect("occupy registry shard");
            let started = Instant::now();
            match try_acquire_keyed_pre_attempt_from(&capacity, community) {
                Err(()) => assert_pre_attempt_busy_is_opaque_503(),
                Ok(_) => panic!("registry contention must fail fast without queueing"),
            }
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "registry contention must not park a Tokio/request worker"
            );
            assert_eq!(capacity.global_available(), global_before);
        }
        assert_eq!(capacity.global_available(), global_before);
        assert_eq!(capacity.registry_len(), registry_before);
        assert_eq!(capacity.community_count(community), None);
        assert_eq!(capacity.community_live_handles(community), None);
        assert!(!capacity.registry_contains(community));
    }

    #[test]
    fn keyed_pre_attempt_overcap_a_registry_contention_does_not_consume_global_or_starve_b() {
        let capacity = Arc::new(KeyedPreAttemptCapacity::new());
        let (community_a, community_b) = isolated_pre_attempt_communities(&capacity);
        let mut held_a = Vec::with_capacity(KEYED_PRE_ATTEMPT_COMMUNITY_MAX);
        for _ in 0..KEYED_PRE_ATTEMPT_COMMUNITY_MAX {
            held_a.push(
                try_acquire_keyed_pre_attempt_from(&capacity, community_a).expect("community A"),
            );
        }
        let global_before = capacity.global_available();
        assert_eq!(
            global_before,
            KEYED_PRE_ATTEMPT_GLOBAL_MAX - KEYED_PRE_ATTEMPT_COMMUNITY_MAX
        );
        assert_eq!(
            capacity.community_count(community_a),
            Some(KEYED_PRE_ATTEMPT_COMMUNITY_MAX)
        );
        let overcap = KEYED_PRE_ATTEMPT_COMMUNITY_MAX;
        let (tx, rx) = mpsc::channel();
        let hold = capacity
            .try_hold_registry(community_a)
            .expect("coordinate old registry-contention interleaving on A");
        let mut workers = Vec::with_capacity(overcap);
        for _ in 0..overcap {
            let tx = tx.clone();
            let capacity = Arc::clone(&capacity);
            workers.push(std::thread::spawn(move || {
                let started = Instant::now();
                let result = try_acquire_keyed_pre_attempt_from(&capacity, community_a);
                tx.send((result.is_err(), started.elapsed()))
                    .expect("send over-cap A outcome");
            }));
        }
        drop(tx);
        let deadline = Instant::now() + Duration::from_secs(1);
        for _ in 0..overcap {
            match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok((failed, elapsed)) => {
                    assert!(
                        failed,
                        "over-cap A must fail closed during registry contention"
                    );
                    assert!(
                        elapsed < Duration::from_secs(1),
                        "over-cap A must fail fast, not park on the registry"
                    );
                }
                Err(_) => {
                    drop(hold);
                    panic!("over-cap A contenders parked on the registry instead of fail-fast");
                }
            }
        }
        assert_eq!(
            capacity.global_available(),
            global_before,
            "over-cap A must never reduce global availability"
        );
        let held_b = try_acquire_keyed_pre_attempt_from(&capacity, community_b)
            .expect("eligible B must acquire while over-cap A registry is contended");
        assert_eq!(capacity.global_available(), global_before - 1);
        assert_eq!(capacity.community_count(community_b), Some(1));
        drop(held_b);
        assert_eq!(capacity.global_available(), global_before);
        drop(hold);
        for worker in workers {
            worker.join().expect("over-cap A worker");
        }
        assert_eq!(capacity.global_available(), global_before);
        assert_eq!(
            capacity.community_count(community_a),
            Some(KEYED_PRE_ATTEMPT_COMMUNITY_MAX)
        );
        assert_eq!(
            capacity.community_live_handles(community_a),
            Some(KEYED_PRE_ATTEMPT_COMMUNITY_MAX)
        );
        assert_eq!(capacity.community_count(community_b), None);
        drop(held_a);
        assert_eq!(capacity.global_available(), KEYED_PRE_ATTEMPT_GLOBAL_MAX);
        assert_pre_attempt_fully_idle(&capacity);
    }

    #[test]
    fn keyed_pre_attempt_global_failure_rolls_back_community_reservation() {
        let capacity = KeyedPreAttemptCapacity::new();
        let community_a = Uuid::from_u128(0xA11);
        let community_b = Uuid::from_u128(0xB22);
        let community_c = Uuid::from_u128(0xC33);
        let mut held = Vec::with_capacity(KEYED_PRE_ATTEMPT_GLOBAL_MAX);
        for _ in 0..KEYED_PRE_ATTEMPT_COMMUNITY_MAX {
            held.push(try_acquire_keyed_pre_attempt_from(&capacity, community_a).expect("A"));
        }
        for _ in 0..KEYED_PRE_ATTEMPT_COMMUNITY_MAX {
            held.push(try_acquire_keyed_pre_attempt_from(&capacity, community_b).expect("B"));
        }
        assert_eq!(capacity.global_available(), 0);
        match try_acquire_keyed_pre_attempt_from(&capacity, community_c) {
            Err(()) => assert_pre_attempt_busy_is_opaque_503(),
            Ok(_) => panic!("global exhaustion must fail closed"),
        }
        assert_eq!(capacity.global_available(), 0);
        assert_eq!(capacity.community_count(community_c), None);
        assert_eq!(capacity.community_live_handles(community_c), None);
        assert!(!capacity.registry_contains(community_c));
        drop(held.pop());
        assert_eq!(capacity.global_available(), 1);
        let held_c = try_acquire_keyed_pre_attempt_from(&capacity, community_c)
            .expect("C after exact community rollback");
        assert_eq!(capacity.community_count(community_c), Some(1));
        assert_eq!(capacity.community_live_handles(community_c), Some(1));
        assert_eq!(capacity.global_available(), 0);
        drop(held_c);
        drop(held);
        assert_eq!(capacity.global_available(), KEYED_PRE_ATTEMPT_GLOBAL_MAX);
        assert_pre_attempt_fully_idle(&capacity);
    }

    #[test]
    fn keyed_pre_attempt_error_return_and_cancellation_reclaim() {
        let capacity = KeyedPreAttemptCapacity::new();
        let community = Uuid::from_u128(0xE77);
        let result: Result<(), ()> = (|| {
            let _guard = try_acquire_keyed_pre_attempt_from(&capacity, community)?;
            Err(())
        })();
        assert!(result.is_err());
        assert_eq!(capacity.global_available(), KEYED_PRE_ATTEMPT_GLOBAL_MAX);
        assert_eq!(capacity.community_count(community), None);
        assert_eq!(capacity.community_live_handles(community), None);
        assert_pre_attempt_fully_idle(&capacity);
        assert!(!capacity.registry_contains(community));

        let first = try_acquire_keyed_pre_attempt_from(&capacity, community).expect("first");
        drop(first);
        assert_pre_attempt_fully_idle(&capacity);
        assert!(!capacity.registry_contains(community));
        let second =
            try_acquire_keyed_pre_attempt_from(&capacity, community).expect("next generation");
        assert_eq!(capacity.community_count(community), Some(1));
        assert_eq!(capacity.community_live_handles(community), Some(1));
        drop(second);
        assert_pre_attempt_fully_idle(&capacity);

        let capacity = Arc::new(KeyedPreAttemptCapacity::new());
        let community = Uuid::from_u128(0xCA11);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let cap = Arc::clone(&capacity);
            let (acquired_tx, acquired_rx) = tokio::sync::oneshot::channel::<()>();
            let handle = tokio::spawn(async move {
                let _guard = try_acquire_keyed_pre_attempt_from(&cap, community).expect("permit");
                let _ = acquired_tx.send(());
                std::future::pending::<()>().await;
            });
            acquired_rx.await.expect("acquired");
            assert_eq!(
                capacity.global_available(),
                KEYED_PRE_ATTEMPT_GLOBAL_MAX - 1
            );
            assert_eq!(capacity.community_count(community), Some(1));
            handle.abort();
            let _ = handle.await;
            assert_eq!(capacity.global_available(), KEYED_PRE_ATTEMPT_GLOBAL_MAX);
            assert_eq!(capacity.community_count(community), None);
            assert_eq!(capacity.community_live_handles(community), None);
            assert_pre_attempt_fully_idle(&capacity);
            assert!(!capacity.registry_contains(community));
        });
    }

    #[test]
    fn keyed_pre_attempt_last_drop_while_shard_held_returns_and_reaper_removes_key() {
        let capacity = KeyedPreAttemptCapacity::new();
        let community = Uuid::from_u128(0x51AD);
        let guard = try_acquire_keyed_pre_attempt_from(&capacity, community).expect("live permit");
        assert_eq!(
            capacity.global_available(),
            KEYED_PRE_ATTEMPT_GLOBAL_MAX - 1
        );
        assert_eq!(capacity.community_count(community), Some(1));
        assert_eq!(capacity.registry_bound(), 1);
        let hold = capacity
            .try_hold_registry(community)
            .expect("hold the live community's registry shard");
        let started = Instant::now();
        drop(guard);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "last Drop must return promptly while the registry shard is held"
        );
        assert_eq!(capacity.global_available(), KEYED_PRE_ATTEMPT_GLOBAL_MAX);
        drop(hold);
        assert!(
            capacity.registry_contains(community),
            "stale key must remain until reaper runs; no checkout in between"
        );
        assert_eq!(capacity.community_count(community), None);
        assert_eq!(capacity.community_live_handles(community), None);
        assert_eq!(capacity.registry_bound(), 1);
        reap_dead_keyed_pre_attempt_entries(&capacity);
        assert!(
            !capacity.registry_contains(community),
            "shared reaper must remove the stale key without a new checkout"
        );
        assert_eq!(capacity.registry_bound(), 0);
        assert_eq!(capacity.registry_len(), 0);
        assert_eq!(capacity.global_available(), KEYED_PRE_ATTEMPT_GLOBAL_MAX);
    }

    #[test]
    fn keyed_pre_attempt_reaper_thread_removes_stale_key_without_checkout() {
        let capacity = try_init_keyed_pre_attempt_capacity().expect("cleanup thread");
        let community = Uuid::from_u128(0x5EED);
        let guard = try_acquire_keyed_pre_attempt_from(&capacity, community).expect("live permit");
        let hold = capacity
            .try_hold_registry(community)
            .expect("hold occupied shard so Drop cannot reap");
        drop(guard);
        assert_eq!(capacity.global_available(), KEYED_PRE_ATTEMPT_GLOBAL_MAX);
        drop(hold);
        wait_pre_attempt_key_absent(&capacity, community, Duration::from_secs(2));
        assert_eq!(capacity.community_count(community), None);
        assert_eq!(capacity.registry_bound(), 0);
        assert_eq!(capacity.registry_len(), 0);
        assert_eq!(capacity.global_available(), KEYED_PRE_ATTEMPT_GLOBAL_MAX);
    }

    #[test]
    fn keyed_pre_attempt_registry_bound_fails_closed_until_reap() {
        let capacity = KeyedPreAttemptCapacity::new();
        assert_eq!(KEYED_PRE_ATTEMPT_REGISTRY_MAX, 64);
        let mut communities = Vec::with_capacity(KEYED_PRE_ATTEMPT_REGISTRY_MAX);
        for i in 0..KEYED_PRE_ATTEMPT_REGISTRY_MAX {
            let community = Uuid::from_u128(0xB000 + i as u128);
            let guard = try_acquire_keyed_pre_attempt_from(&capacity, community)
                .expect("fill bounded registry");
            communities.push(community);
            drop(guard);
        }
        assert_eq!(capacity.registry_len(), KEYED_PRE_ATTEMPT_REGISTRY_MAX);
        assert_eq!(capacity.registry_bound(), KEYED_PRE_ATTEMPT_REGISTRY_MAX);
        assert_eq!(capacity.global_available(), KEYED_PRE_ATTEMPT_GLOBAL_MAX);
        let extra = Uuid::from_u128(0xB0FF);
        match try_acquire_keyed_pre_attempt_from(&capacity, extra) {
            Err(()) => assert_pre_attempt_busy_is_opaque_503(),
            Ok(_) => panic!("new UUID must fail closed while the registry bound is full"),
        }
        assert!(!capacity.registry_contains(extra));
        assert_eq!(capacity.registry_bound(), KEYED_PRE_ATTEMPT_REGISTRY_MAX);
        assert_eq!(capacity.registry_len(), KEYED_PRE_ATTEMPT_REGISTRY_MAX);
        reap_dead_keyed_pre_attempt_entries(&capacity);
        assert_eq!(capacity.registry_bound(), 0);
        assert_eq!(capacity.registry_len(), 0);
        let restored = try_acquire_keyed_pre_attempt_from(&capacity, extra)
            .expect("acquire after reaper restored the bound");
        assert_eq!(capacity.registry_bound(), 1);
        assert_eq!(capacity.community_count(extra), Some(1));
        drop(restored);
        assert_pre_attempt_fully_idle(&capacity);
        let _ = communities;
    }

    #[test]
    fn keyed_pre_attempt_same_shard_communities_do_not_corrupt_each_other() {
        let capacity = KeyedPreAttemptCapacity::new();
        let (community_a, community_b) = same_shard_pre_attempt_communities(&capacity);
        assert_ne!(community_a, community_b);
        let hold_a = capacity.try_hold_registry(community_a).expect("hold A");
        assert!(
            capacity.try_hold_registry(community_b).is_none(),
            "A and B must share a registry shard"
        );
        drop(hold_a);

        let guard_a = try_acquire_keyed_pre_attempt_from(&capacity, community_a).expect("A");
        let guard_b = try_acquire_keyed_pre_attempt_from(&capacity, community_b).expect("B");
        let gen_a = capacity
            .community_live_generation(community_a)
            .expect("live A");
        let gen_b = capacity
            .community_live_generation(community_b)
            .expect("live B");
        assert_eq!(capacity.community_count(community_a), Some(1));
        assert_eq!(capacity.community_count(community_b), Some(1));
        assert_eq!(capacity.registry_bound(), 2);

        drop(guard_a);
        reclaim_dead_keyed_pre_attempt_generation(&capacity, community_a, gen_a);
        assert!(!capacity.registry_contains(community_a));
        assert_eq!(capacity.community_count(community_b), Some(1));
        assert_eq!(capacity.community_live_generation(community_b), Some(gen_b));
        reclaim_dead_keyed_pre_attempt_generation(&capacity, community_b, gen_a);
        assert_eq!(capacity.community_count(community_b), Some(1));
        assert_eq!(capacity.community_live_generation(community_b), Some(gen_b));
        assert_eq!(
            capacity.global_available(),
            KEYED_PRE_ATTEMPT_GLOBAL_MAX - 1
        );
        drop(guard_b);
        assert_pre_attempt_fully_idle(&capacity);
    }

    #[test]
    fn keyed_pre_attempt_stale_generation_cleanup_does_not_remove_replacement() {
        let capacity = KeyedPreAttemptCapacity::new();
        let community = Uuid::from_u128(0xABA1);
        let first = try_acquire_keyed_pre_attempt_from(&capacity, community).expect("generation 1");
        let gen1 = capacity
            .community_generation(community)
            .expect("generation 1 id");
        assert_eq!(capacity.community_live_generation(community), Some(gen1));
        drop(first);
        assert!(capacity.registry_contains(community));
        assert_eq!(capacity.community_live_generation(community), None);
        assert_eq!(capacity.community_generation(community), Some(gen1));
        assert_eq!(capacity.registry_bound(), 1);

        let second =
            try_acquire_keyed_pre_attempt_from(&capacity, community).expect("generation 2");
        let gen2 = capacity
            .community_live_generation(community)
            .expect("generation 2 id");
        assert_ne!(gen1, gen2);
        assert_eq!(capacity.community_count(community), Some(1));
        assert_eq!(capacity.registry_bound(), 1);

        reclaim_dead_keyed_pre_attempt_generation(&capacity, community, gen1);
        assert!(capacity.registry_contains(community));
        assert_eq!(capacity.community_live_generation(community), Some(gen2));
        assert_eq!(capacity.community_count(community), Some(1));
        assert_eq!(capacity.registry_bound(), 1);
        assert_eq!(
            capacity.global_available(),
            KEYED_PRE_ATTEMPT_GLOBAL_MAX - 1
        );

        drop(second);
        reap_dead_keyed_pre_attempt_entries(&capacity);
        assert!(!capacity.registry_contains(community));
        assert_eq!(capacity.registry_bound(), 0);
        assert_eq!(capacity.global_available(), KEYED_PRE_ATTEMPT_GLOBAL_MAX);
    }

    #[test]
    fn local_capacity_denial_is_after_attempt_and_before_replay() {
        let _ingress_lock = lock_keyed_ingress_tests();
        let limiter = LaneRecordingLimiter::new(FleetLimiterOutcome::Allow);
        let tenant = fresh_tenant("keyed-attempt.example");
        let keys = Keys::generate();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(admit_keyed_http_attempt(
            &limiter,
            &tenant,
            &keys.public_key(),
        ))
        .expect("attempt allowed");
        assert_attempt_charged_once(&limiter, &keys.public_key());
        let community = *tenant.community().as_uuid();
        let mut held = Vec::new();
        for _ in 0..KEYED_INGRESS_COMMUNITY_MAX {
            held.push(try_acquire_keyed_ingress(community).expect("fill community"));
        }
        match try_acquire_keyed_ingress(community) {
            Err(KeyedHttpError::Busy { .. }) => {}
            other => panic!("ingress saturation must fail fast after attempt, got {other:?}"),
        }
        drop(held);
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert_fresh_untouched(&limiter);
    }

    #[test]
    fn keyed_attempt_quota_denial_maps_to_opaque_busy_without_limiter_details() {
        let outcome = keyed_pre_ingest_outcome(KeyedPreIngestError::Attempt(
            crate::admission::AdmissionError::Exceeded { reset_in_secs: 17 },
        ));
        match outcome {
            SubmitOutcome::Busy { status, response } => {
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(
                    response
                        .headers()
                        .get(header::RETRY_AFTER)
                        .and_then(|v| v.to_str().ok()),
                    Some("17")
                );
            }
            other => panic!("attempt Exceeded must be opaque Busy, got {other:?}"),
        }
        let unavailable = keyed_pre_ingest_outcome(KeyedPreIngestError::Attempt(
            crate::admission::AdmissionError::Unavailable,
        ));
        match unavailable {
            SubmitOutcome::Busy { status, response } => {
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(
                    response
                        .headers()
                        .get(header::RETRY_AFTER)
                        .and_then(|v| v.to_str().ok()),
                    Some("5")
                );
            }
            other => panic!("attempt Unavailable must be opaque Busy, got {other:?}"),
        }
        let (status, _retry, Json(body)) = keyed_busy_http_parts(17);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let dumped = body.to_string();
        assert_eq!(
            body,
            serde_json::json!({"error": "idempotency unavailable"})
        );
        assert!(!dumped.contains("redis"));
        assert!(!dumped.contains("quota"));
        assert!(!dumped.contains("katt"));
        assert!(!dumped.contains("kfsh"));
    }

    #[test]
    fn keyed_attempt_identity_is_the_authenticated_signer_not_the_owner() {
        let agent = Keys::generate().public_key();
        let owner = Keys::generate().public_key();
        assert_ne!(agent, owner);
        assert_eq!(keyed_http_verified_owner(None, Some(owner)), Some(owner));
    }

    #[test]
    fn keyed_verified_owner_ignores_absent_extraction_and_prefers_membership() {
        let member_owner = Keys::generate().public_key();
        let extracted = Keys::generate().public_key();
        assert_eq!(keyed_http_verified_owner(None, None), None);
        assert_eq!(
            keyed_http_verified_owner(None, Some(extracted)),
            Some(extracted)
        );
        assert_eq!(
            keyed_http_verified_owner(Some(member_owner), Some(extracted)),
            Some(member_owner)
        );
        assert_eq!(
            keyed_http_verified_owner(Some(member_owner), None),
            Some(member_owner)
        );
    }

    #[tokio::test]
    async fn keyed_attempt_allow_then_malformed_body_charges_attempt_not_fresh() {
        let limiter = LaneRecordingLimiter::new(FleetLimiterOutcome::Allow);
        let replay = OrderedReplayGuard {
            steps: Arc::clone(&limiter.steps),
            admit: true,
        };
        let tenant = fresh_tenant("keyed-attempt.example");
        let keys = Keys::generate();
        match attempt_then_after(
            &limiter,
            &replay,
            KeyedHttpAdmitRequest {
                tenant: &tenant,
                pubkey: keys.public_key(),
                event_id_bytes: fresh_nip98_event_id_bytes(),
                signed_created_at: None,
                body: b"{",
            },
            unreachable_membership(),
            unreachable_owner(),
        )
        .await
        {
            Err(KeyedHttpAdmitError::Parse(error)) => {
                assert_eq!(error.classify(), serde_json::error::Category::Eof);
            }
            other => panic!("malformed body must fail at parse, got {other:?}"),
        }
        assert_eq!(
            *limiter.steps.lock().unwrap(),
            vec!["attempt_hierarchical", "replay"]
        );
        assert_attempt_charged_once(&limiter, &keys.public_key());
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert_fresh_untouched(&limiter);
        assert_eq!(limiter.principal_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn keyed_attempt_identity_denial_skips_replay_and_writes_nothing() {
        let limiter = LaneRecordingLimiter::lanes(
            FleetLimiterOutcome::Deny,
            FleetLimiterOutcome::Allow,
            FleetLimiterOutcome::Allow,
        );
        let replay = OrderedReplayGuard {
            steps: Arc::clone(&limiter.steps),
            admit: true,
        };
        let tenant = fresh_tenant("keyed-attempt.example");
        let keys = Keys::generate();
        let err = attempt_then_after(
            &limiter,
            &replay,
            KeyedHttpAdmitRequest {
                tenant: &tenant,
                pubkey: keys.public_key(),
                event_id_bytes: fresh_nip98_event_id_bytes(),
                signed_created_at: None,
                body: b"{\"id\":\"00\"}",
            },
            unreachable_membership(),
            unreachable_owner(),
        )
        .await
        .expect_err("denied attempt");
        assert!(matches!(
            err,
            KeyedHttpAdmitError::PreIngest(KeyedPreIngestError::Attempt(
                crate::admission::AdmissionError::Exceeded { reset_in_secs: 13 }
            ))
        ));
        assert_eq!(*limiter.steps.lock().unwrap(), vec!["attempt_hierarchical"]);
        assert_attempt_invoked_without_charge(&limiter);
        assert_fresh_untouched(&limiter);
        assert_eq!(limiter.principal_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn keyed_after_attempt_does_not_charge_fresh() {
        let limiter = LaneRecordingLimiter::new(FleetLimiterOutcome::Allow);
        let replay = OrderedReplayGuard {
            steps: Arc::clone(&limiter.steps),
            admit: true,
        };
        let tenant = fresh_tenant("keyed-attempt.example");
        let keys = Keys::generate();
        let (validated, owner) = attempt_then_after(
            &limiter,
            &replay,
            KeyedHttpAdmitRequest {
                tenant: &tenant,
                pubkey: keys.public_key(),
                event_id_bytes: fresh_nip98_event_id_bytes(),
                signed_created_at: None,
                body: &signed_kind9_body(&keys),
            },
            recording_membership(&limiter.steps, Ok(None)),
            recording_owner(&limiter.steps, None),
        )
        .await
        .expect("validated after attempt");
        assert_eq!(validated.event().pubkey, keys.public_key());
        assert_eq!(owner, None);
        assert_eq!(
            *limiter.steps.lock().unwrap(),
            vec![
                "attempt_hierarchical",
                "replay",
                "membership",
                "owner_select"
            ]
        );
        assert_attempt_charged_once(&limiter, &keys.public_key());
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 1);
        assert_fresh_untouched(&limiter);
        assert_eq!(
            *limiter.increment_pubkeys.lock().unwrap().last().unwrap(),
            keys.public_key().to_bytes()
        );
    }

    #[tokio::test]
    async fn expired_deadline_does_not_start_detached_verification() {
        let _ingress_lock = lock_keyed_ingress_tests_async().await;
        let limiter = LaneRecordingLimiter::new(FleetLimiterOutcome::Allow);
        let replay = OrderedReplayGuard {
            steps: Arc::clone(&limiter.steps),
            admit: true,
        };
        let tenant = fresh_tenant("keyed-attempt.example");
        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::Custom(9), "fresh")
            .sign_with_keys(&keys)
            .expect("sign");
        let body = serde_json::to_vec(&event).expect("serialize");
        let guard = install_keyed_verify_watch(event.id);
        let community = *tenant.community().as_uuid();
        let ingress = try_acquire_keyed_ingress(community).expect("permit");
        let early = KeyedHttpEarlyContext {
            ingress: Some(ingress),
            deadline: KeyedEarlyDeadline::already_expired(),
            verified_owner: None,
        };
        let err = admit_keyed_http_after_attempt(
            &replay,
            KeyedHttpAdmitRequest {
                tenant: &tenant,
                pubkey: keys.public_key(),
                event_id_bytes: fresh_nip98_event_id_bytes(),
                signed_created_at: None,
                body: &body,
            },
            unreachable_membership(),
            unreachable_owner(),
            early,
        )
        .await
        .err()
        .expect("expired verification guard");
        assert!(matches!(
            err,
            KeyedHttpAdmitError::PreIngest(KeyedPreIngestError::Attempt(
                crate::admission::AdmissionError::Unavailable
            ))
        ));
        assert_eq!(guard.in_flight(), 0);
    }

    #[tokio::test]
    async fn keyed_rotating_signers_replay_parse_and_membership_cannot_charge_fresh() {
        let limiter = LaneRecordingLimiter::new(FleetLimiterOutcome::Allow);
        let tenant = fresh_tenant("keyed-attempt.example");
        let parse_keys = Keys::generate();
        let replay_keys = Keys::generate();
        let member_keys = Keys::generate();
        let error_keys = Keys::generate();
        assert_ne!(parse_keys.public_key(), replay_keys.public_key());
        assert_ne!(replay_keys.public_key(), member_keys.public_key());
        assert_ne!(member_keys.public_key(), error_keys.public_key());

        let replay_ok = OrderedReplayGuard {
            steps: Arc::clone(&limiter.steps),
            admit: true,
        };
        match attempt_then_after(
            &limiter,
            &replay_ok,
            KeyedHttpAdmitRequest {
                tenant: &tenant,
                pubkey: parse_keys.public_key(),
                event_id_bytes: fresh_nip98_event_id_bytes(),
                signed_created_at: None,
                body: b"{",
            },
            unreachable_membership(),
            unreachable_owner(),
        )
        .await
        {
            Err(KeyedHttpAdmitError::Parse(error)) => {
                assert_eq!(error.classify(), serde_json::error::Category::Eof);
            }
            other => panic!("malformed must fail at parse, got {other:?}"),
        }

        let replay_hit = OrderedReplayGuard {
            steps: Arc::clone(&limiter.steps),
            admit: false,
        };
        match attempt_then_after(
            &limiter,
            &replay_hit,
            KeyedHttpAdmitRequest {
                tenant: &tenant,
                pubkey: replay_keys.public_key(),
                event_id_bytes: fresh_nip98_event_id_bytes(),
                signed_created_at: None,
                body: &signed_kind9_body(&replay_keys),
            },
            unreachable_membership(),
            unreachable_owner(),
        )
        .await
        {
            Err(KeyedHttpAdmitError::PreIngest(KeyedPreIngestError::Replay(response))) => {
                assert_eq!(response.0, StatusCode::UNAUTHORIZED);
            }
            other => panic!("exact NIP-98 replay must keep replay HTTP mapping, got {other:?}"),
        }

        let replay_member = OrderedReplayGuard {
            steps: Arc::clone(&limiter.steps),
            admit: true,
        };
        match attempt_then_after(
            &limiter,
            &replay_member,
            KeyedHttpAdmitRequest {
                tenant: &tenant,
                pubkey: member_keys.public_key(),
                event_id_bytes: fresh_nip98_event_id_bytes(),
                signed_created_at: None,
                body: &signed_kind9_body(&member_keys),
            },
            recording_membership(
                &limiter.steps,
                Err(api_error(
                    StatusCode::FORBIDDEN,
                    "restricted: not a relay member",
                )),
            ),
            unreachable_owner(),
        )
        .await
        {
            Err(KeyedHttpAdmitError::Membership(response)) => {
                assert_eq!(response.0, StatusCode::FORBIDDEN);
            }
            other => panic!("non-member must keep membership HTTP mapping, got {other:?}"),
        }

        match attempt_then_after(
            &limiter,
            &replay_member,
            KeyedHttpAdmitRequest {
                tenant: &tenant,
                pubkey: error_keys.public_key(),
                event_id_bytes: fresh_nip98_event_id_bytes(),
                signed_created_at: None,
                body: &signed_kind9_body(&error_keys),
            },
            recording_membership(
                &limiter.steps,
                Err(api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "relay membership unavailable",
                )),
            ),
            unreachable_owner(),
        )
        .await
        {
            Err(KeyedHttpAdmitError::Membership(response)) => {
                assert_eq!(response.0, StatusCode::SERVICE_UNAVAILABLE);
            }
            other => panic!("membership error must fail before fresh, got {other:?}"),
        }

        assert!(limiter
            .paired_types
            .lock()
            .unwrap()
            .iter()
            .all(|limit_type| *limit_type != LimitType::ApiCalls
                && *limit_type != LimitType::IpConnections
                && *limit_type != LimitType::Messages));
        assert_fresh_untouched(&limiter);
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 4);
        assert_eq!(limiter.attempt_identity_charged.load(Ordering::Relaxed), 4);
        assert_eq!(limiter.attempt_tenant_charged.load(Ordering::Relaxed), 4);
        assert_eq!(limiter.attempt_fleet_charged.load(Ordering::Relaxed), 4);
        assert_eq!(
            limiter.identity_pubkeys.lock().unwrap().clone(),
            vec![
                parse_keys.public_key().to_bytes(),
                replay_keys.public_key().to_bytes(),
                member_keys.public_key().to_bytes(),
                error_keys.public_key().to_bytes(),
            ]
        );
        assert_eq!(
            *limiter.steps.lock().unwrap(),
            vec![
                "attempt_hierarchical",
                "replay",
                "attempt_hierarchical",
                "replay",
                "attempt_hierarchical",
                "replay",
                "membership",
                "attempt_hierarchical",
                "replay",
                "membership",
            ]
        );
    }

    #[tokio::test]
    async fn keyed_invalid_id_signature_and_author_mismatch_do_not_reach_membership() {
        let limiter = LaneRecordingLimiter::new(FleetLimiterOutcome::Allow);
        let replay = OrderedReplayGuard {
            steps: Arc::clone(&limiter.steps),
            admit: true,
        };
        let tenant = fresh_tenant("keyed-attempt.example");
        let keys = Keys::generate();
        let caller = Keys::generate();

        let cases: [KeyedBodyValidationCase; 3] = [
            (
                "invalid id/signature",
                forged_kind9_body(&keys),
                keys.public_key(),
                |error| matches!(error, IngestError::Rejected(msg) if msg.starts_with("invalid:")),
            ),
            (
                "oversized content",
                oversized_kind9_body(&keys),
                keys.public_key(),
                |error| {
                    matches!(
                        error,
                        IngestError::Rejected(msg)
                            if msg.starts_with("invalid: content exceeds maximum size of")
                    )
                },
            ),
            (
                "authenticated-pubkey mismatch",
                signed_kind9_body(&keys),
                caller.public_key(),
                |error| {
                    matches!(
                        error,
                        IngestError::AuthFailed(msg)
                            if msg == "invalid: event pubkey does not match authenticated identity"
                    )
                },
            ),
        ];

        for (name, body, pubkey, check) in cases {
            match attempt_then_after(
                &limiter,
                &replay,
                KeyedHttpAdmitRequest {
                    tenant: &tenant,
                    pubkey,
                    event_id_bytes: fresh_nip98_event_id_bytes(),
                    signed_created_at: None,
                    body: &body,
                },
                unreachable_membership(),
                unreachable_owner(),
            )
            .await
            {
                Err(KeyedHttpAdmitError::Body { error, .. }) => {
                    assert!(check(&error), "{name} mapped to {error:?}");
                }
                other => panic!("{name} must fail before membership, got {other:?}"),
            }
        }

        assert_fresh_untouched(&limiter);
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert!(!limiter.steps.lock().unwrap().contains(&"membership"));
        assert!(!limiter.steps.lock().unwrap().contains(&"owner_select"));
        assert!(!limiter
            .steps
            .lock()
            .unwrap()
            .contains(&"fresh_hierarchical"));
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 3);
        assert_eq!(limiter.attempt_identity_charged.load(Ordering::Relaxed), 3);
        assert_eq!(limiter.fresh_identity_charged.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn keyed_body_validation_failures_do_not_charge_fresh() {
        let limiter = LaneRecordingLimiter::new(FleetLimiterOutcome::Allow);
        let replay = OrderedReplayGuard {
            steps: Arc::clone(&limiter.steps),
            admit: true,
        };
        let tenant = fresh_tenant("keyed-attempt.example");
        let keys = Keys::generate();

        let cases: [KeyedBodyValidationCase; 3] = [
            (
                "unsupported kind 1",
                signed_text_note_body(&keys),
                keys.public_key(),
                |error| {
                    matches!(
                        error,
                        IngestError::Rejected(msg)
                            if msg == "invalid: Idempotency-Key is not supported for this event kind"
                    )
                },
            ),
            (
                "stale timestamp",
                stale_kind9_body(&keys),
                keys.public_key(),
                |error| {
                    matches!(
                        error,
                        IngestError::Rejected(msg)
                            if msg == "invalid: event timestamp too far from server time"
                    )
                },
            ),
            (
                "excessive p-tags",
                excessive_p_tag_kind9_body(&keys),
                keys.public_key(),
                |error| {
                    matches!(
                        error,
                        IngestError::Rejected(msg) if msg == "invalid: too many p tags for keyed ingest"
                    )
                },
            ),
        ];

        for (name, body, pubkey, check) in cases {
            match attempt_then_after(
                &limiter,
                &replay,
                KeyedHttpAdmitRequest {
                    tenant: &tenant,
                    pubkey,
                    event_id_bytes: fresh_nip98_event_id_bytes(),
                    signed_created_at: None,
                    body: &body,
                },
                recording_membership(&limiter.steps, Ok(None)),
                recording_owner(&limiter.steps, Some("not-a-nip-oa-tag")),
            )
            .await
            {
                Err(KeyedHttpAdmitError::Body { error, .. }) => {
                    assert!(check(&error), "{name} mapped to {error:?}");
                }
                other => panic!("{name} must fail at body validation, got {other:?}"),
            }
        }

        assert_fresh_untouched(&limiter);
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert!(!limiter
            .steps
            .lock()
            .unwrap()
            .contains(&"fresh_hierarchical"));
        assert!(limiter
            .steps
            .lock()
            .unwrap()
            .contains(&"attempt_hierarchical"));
        assert!(limiter.steps.lock().unwrap().contains(&"membership"));
        assert!(limiter.steps.lock().unwrap().contains(&"owner_select"));
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 3);
        assert_eq!(limiter.attempt_identity_charged.load(Ordering::Relaxed), 3);
        assert_eq!(limiter.fresh_identity_charged.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn keyed_extreme_signed_timestamp_rejects_body_without_fresh_charge() {
        let limiter = LaneRecordingLimiter::new(FleetLimiterOutcome::Allow);
        let replay = OrderedReplayGuard {
            steps: Arc::clone(&limiter.steps),
            admit: true,
        };
        let tenant = fresh_tenant("keyed-attempt.example");
        let keys = Keys::generate();
        match attempt_then_after(
            &limiter,
            &replay,
            KeyedHttpAdmitRequest {
                tenant: &tenant,
                pubkey: keys.public_key(),
                event_id_bytes: fresh_nip98_event_id_bytes(),
                signed_created_at: None,
                body: &extreme_signed_kind9_body(&keys),
            },
            recording_membership(&limiter.steps, Ok(None)),
            recording_owner(&limiter.steps, None),
        )
        .await
        {
            Err(KeyedHttpAdmitError::Body { error, .. }) => {
                assert!(
                    matches!(
                        error,
                        IngestError::Rejected(ref msg)
                            if msg == "invalid: event timestamp too far from server time"
                    ),
                    "extreme timestamp mapped to {error:?}"
                );
            }
            other => panic!("extreme signed timestamp must fail at body validation, got {other:?}"),
        }
        assert_fresh_untouched(&limiter);
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert!(!limiter
            .steps
            .lock()
            .unwrap()
            .contains(&"fresh_hierarchical"));
        assert_eq!(limiter.fresh_identity_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.fresh_tenant_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.fresh_fleet_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 1);
        assert_attempt_charged_once(&limiter, &keys.public_key());
    }

    #[tokio::test]
    async fn keyed_denied_paired_fresh_admission_is_not_in_the_after_attempt_helper() {
        let limiter = LaneRecordingLimiter::lanes(
            FleetLimiterOutcome::Allow,
            FleetLimiterOutcome::Allow,
            FleetLimiterOutcome::Deny,
        );
        let replay = OrderedReplayGuard {
            steps: Arc::clone(&limiter.steps),
            admit: true,
        };
        let tenant = fresh_tenant("keyed-attempt.example");
        let keys = Keys::generate();
        let (validated, owner) = attempt_then_after(
            &limiter,
            &replay,
            KeyedHttpAdmitRequest {
                tenant: &tenant,
                pubkey: keys.public_key(),
                event_id_bytes: fresh_nip98_event_id_bytes(),
                signed_created_at: None,
                body: &signed_kind9_body(&keys),
            },
            recording_membership(&limiter.steps, Ok(None)),
            recording_owner(&limiter.steps, None),
        )
        .await
        .expect("fresh denial is not part of after-attempt");
        assert_eq!(validated.event().pubkey, keys.public_key());
        assert_eq!(owner, None);
        assert_eq!(
            *limiter.steps.lock().unwrap(),
            vec![
                "attempt_hierarchical",
                "replay",
                "membership",
                "owner_select"
            ]
        );
        assert_attempt_charged_once(&limiter, &keys.public_key());
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 1);
        assert_fresh_untouched(&limiter);
        let outcome = keyed_pre_ingest_outcome(KeyedPreIngestError::Attempt(
            crate::admission::AdmissionError::Exceeded { reset_in_secs: 17 },
        ));
        match outcome {
            SubmitOutcome::Busy { status, .. } => {
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            }
            other => panic!("fresh capacity denial must stay opaque 503, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn keyed_attempt_backend_failure_fails_closed_without_replay_or_fresh() {
        let limiter = LaneRecordingLimiter::lanes(
            FleetLimiterOutcome::Fail,
            FleetLimiterOutcome::Fail,
            FleetLimiterOutcome::Allow,
        );
        let replay = OrderedReplayGuard {
            steps: Arc::clone(&limiter.steps),
            admit: true,
        };
        let tenant = fresh_tenant("keyed-attempt.example");
        let keys = Keys::generate();
        let err = attempt_then_after(
            &limiter,
            &replay,
            KeyedHttpAdmitRequest {
                tenant: &tenant,
                pubkey: keys.public_key(),
                event_id_bytes: fresh_nip98_event_id_bytes(),
                signed_created_at: None,
                body: &signed_kind9_body(&keys),
            },
            unreachable_membership(),
            unreachable_owner(),
        )
        .await
        .expect_err("attempt backend failure");
        assert!(matches!(
            err,
            KeyedHttpAdmitError::PreIngest(KeyedPreIngestError::Attempt(
                crate::admission::AdmissionError::Unavailable
            ))
        ));
        assert_eq!(*limiter.steps.lock().unwrap(), vec!["attempt_hierarchical"]);
        assert_attempt_invoked_without_charge(&limiter);
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert_fresh_untouched(&limiter);
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 1);
        assert_eq!(limiter.principal_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn keyed_attempt_community_denial_skips_replay_and_charges_none() {
        let limiter = LaneRecordingLimiter::lanes(
            FleetLimiterOutcome::Allow,
            FleetLimiterOutcome::Deny,
            FleetLimiterOutcome::Allow,
        );
        let replay = OrderedReplayGuard {
            steps: Arc::clone(&limiter.steps),
            admit: true,
        };
        let tenant = fresh_tenant("keyed-attempt.example");
        let keys = Keys::generate();
        let err = attempt_then_after(
            &limiter,
            &replay,
            KeyedHttpAdmitRequest {
                tenant: &tenant,
                pubkey: keys.public_key(),
                event_id_bytes: fresh_nip98_event_id_bytes(),
                signed_created_at: None,
                body: b"{",
            },
            unreachable_membership(),
            unreachable_owner(),
        )
        .await
        .expect_err("community denial at attempt");
        assert!(matches!(
            err,
            KeyedHttpAdmitError::PreIngest(KeyedPreIngestError::Attempt(
                crate::admission::AdmissionError::Exceeded { reset_in_secs: 17 }
            ))
        ));
        assert_eq!(*limiter.steps.lock().unwrap(), vec!["attempt_hierarchical"]);
        assert_attempt_invoked_without_charge(&limiter);
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert_fresh_untouched(&limiter);
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn keyed_attempt_fleet_denial_skips_replay_and_charges_none() {
        let limiter = LaneRecordingLimiter::attempt_fleet_denied();
        let replay = OrderedReplayGuard {
            steps: Arc::clone(&limiter.steps),
            admit: true,
        };
        let tenant = fresh_tenant("keyed-attempt.example");
        let keys = Keys::generate();
        let err = attempt_then_after(
            &limiter,
            &replay,
            KeyedHttpAdmitRequest {
                tenant: &tenant,
                pubkey: keys.public_key(),
                event_id_bytes: fresh_nip98_event_id_bytes(),
                signed_created_at: None,
                body: b"{",
            },
            unreachable_membership(),
            unreachable_owner(),
        )
        .await
        .expect_err("fleet denial at attempt");
        assert!(matches!(
            err,
            KeyedHttpAdmitError::PreIngest(KeyedPreIngestError::Attempt(
                crate::admission::AdmissionError::Exceeded { reset_in_secs: 23 }
            ))
        ));
        assert_eq!(*limiter.steps.lock().unwrap(), vec!["attempt_hierarchical"]);
        assert_attempt_invoked_without_charge(&limiter);
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert_fresh_untouched(&limiter);
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn keyed_attempt_path_does_not_consult_identity_peek() {
        for peek_outcome in [IdentityPeekOutcome::Denied, IdentityPeekOutcome::Fail] {
            let limiter = LaneRecordingLimiter::with_peek(
                FleetLimiterOutcome::Allow,
                FleetLimiterOutcome::Allow,
                FleetLimiterOutcome::Allow,
                peek_outcome,
            );
            let replay = OrderedReplayGuard {
                steps: Arc::clone(&limiter.steps),
                admit: true,
            };
            let tenant = fresh_tenant("keyed-attempt.example");
            let keys = Keys::generate();
            attempt_then_after(
                &limiter,
                &replay,
                KeyedHttpAdmitRequest {
                    tenant: &tenant,
                    pubkey: keys.public_key(),
                    event_id_bytes: fresh_nip98_event_id_bytes(),
                    signed_created_at: None,
                    body: b"{",
                },
                unreachable_membership(),
                unreachable_owner(),
            )
            .await
            .expect_err("malformed body after attempt");
            assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
            assert_attempt_charged_once(&limiter, &keys.public_key());
            assert_fresh_untouched(&limiter);
            assert!(limiter
                .steps
                .lock()
                .unwrap()
                .contains(&"attempt_hierarchical"));
            assert!(limiter.steps.lock().unwrap().contains(&"replay"));
            assert!(!limiter.steps.lock().unwrap().contains(&"attempt_peek"));
        }
    }

    #[tokio::test]
    async fn keyed_valid_member_reaches_validation_without_fresh_charge() {
        let limiter = LaneRecordingLimiter::new(FleetLimiterOutcome::Allow);
        let replay = OrderedReplayGuard {
            steps: Arc::clone(&limiter.steps),
            admit: true,
        };
        let tenant = fresh_tenant("keyed-attempt.example");
        let keys = Keys::generate();
        let (validated, owner) = attempt_then_after(
            &limiter,
            &replay,
            KeyedHttpAdmitRequest {
                tenant: &tenant,
                pubkey: keys.public_key(),
                event_id_bytes: fresh_nip98_event_id_bytes(),
                signed_created_at: None,
                body: &signed_kind9_body(&keys),
            },
            recording_membership(&limiter.steps, Ok(None)),
            recording_owner(&limiter.steps, None),
        )
        .await
        .expect("validated member must reach keyed ingest without fresh");
        assert_eq!(validated.event().pubkey, keys.public_key());
        assert_eq!(owner, None);
        assert_eq!(
            *limiter.steps.lock().unwrap(),
            vec![
                "attempt_hierarchical",
                "replay",
                "membership",
                "owner_select"
            ]
        );
        assert_eq!(
            limiter.community_pubkeys.lock().unwrap()[0],
            keyed_http_attempt_admission_principal().to_bytes()
        );
        assert_eq!(
            limiter.paired_fleet_ips.lock().unwrap()[0],
            KEYED_HTTP_ATTEMPT_FLEET_SENTINEL
        );
        assert_attempt_charged_once(&limiter, &keys.public_key());
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 1);
        assert_fresh_untouched(&limiter);
        assert_ne!(
            KEYED_HTTP_ATTEMPT_FLEET_SENTINEL, KEYED_HTTP_FRESH_FLEET_SENTINEL,
            "historical attempt and legitimate fleet keys must not alias"
        );
        assert_eq!(KEYED_HTTP_PREAUTH_IDENTITY_CARDINALITY_BOUND, 1_200);
    }

    #[tokio::test]
    async fn keyed_two_agents_with_the_same_verified_owner_charge_distinct_attempt_identities() {
        let limiter = LaneRecordingLimiter::new(FleetLimiterOutcome::Allow);
        let replay = OrderedReplayGuard {
            steps: Arc::clone(&limiter.steps),
            admit: true,
        };
        let tenant = fresh_tenant("keyed-attempt.example");
        let owner = Keys::generate().public_key();
        let agent_a = Keys::generate();
        let agent_b = Keys::generate();
        assert_ne!(agent_a.public_key(), agent_b.public_key());
        assert_ne!(agent_a.public_key(), owner);

        let (_, owner_a) = attempt_then_after(
            &limiter,
            &replay,
            KeyedHttpAdmitRequest {
                tenant: &tenant,
                pubkey: agent_a.public_key(),
                event_id_bytes: fresh_nip98_event_id_bytes(),
                signed_created_at: None,
                body: &signed_kind9_body(&agent_a),
            },
            recording_membership(&limiter.steps, Ok(Some(owner))),
            recording_owner(&limiter.steps, None),
        )
        .await
        .expect("agent a");
        let (_, owner_b) = attempt_then_after(
            &limiter,
            &replay,
            KeyedHttpAdmitRequest {
                tenant: &tenant,
                pubkey: agent_b.public_key(),
                event_id_bytes: fresh_nip98_event_id_bytes(),
                signed_created_at: None,
                body: &signed_kind9_body(&agent_b),
            },
            recording_membership(&limiter.steps, Ok(Some(owner))),
            recording_owner(&limiter.steps, None),
        )
        .await
        .expect("agent b");

        assert_eq!(owner_a, Some(owner));
        assert_eq!(owner_b, Some(owner));
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 2);
        assert_eq!(limiter.attempt_identity_charged.load(Ordering::Relaxed), 2);
        assert_eq!(limiter.attempt_tenant_charged.load(Ordering::Relaxed), 2);
        assert_eq!(limiter.attempt_fleet_charged.load(Ordering::Relaxed), 2);
        assert_eq!(
            limiter.identity_pubkeys.lock().unwrap()[0],
            agent_a.public_key().to_bytes()
        );
        assert_eq!(
            limiter.identity_pubkeys.lock().unwrap()[1],
            agent_b.public_key().to_bytes()
        );
        assert_ne!(
            limiter.identity_pubkeys.lock().unwrap()[0],
            owner.to_bytes()
        );
        assert_fresh_untouched(&limiter);
    }

    #[tokio::test]
    async fn keyed_direct_membership_uses_the_authenticated_agent_as_attempt_identity() {
        let limiter = LaneRecordingLimiter::new(FleetLimiterOutcome::Allow);
        let replay = OrderedReplayGuard {
            steps: Arc::clone(&limiter.steps),
            admit: true,
        };
        let tenant = fresh_tenant("keyed-attempt.example");
        let keys = Keys::generate();
        let (_, owner) = attempt_then_after(
            &limiter,
            &replay,
            KeyedHttpAdmitRequest {
                tenant: &tenant,
                pubkey: keys.public_key(),
                event_id_bytes: fresh_nip98_event_id_bytes(),
                signed_created_at: None,
                body: &signed_kind9_body(&keys),
            },
            recording_membership(&limiter.steps, Ok(None)),
            recording_owner(&limiter.steps, None),
        )
        .await
        .expect("direct member");
        assert_eq!(owner, None);
        assert_attempt_charged_once(&limiter, &keys.public_key());
        assert_eq!(
            limiter.identity_pubkeys.lock().unwrap()[0],
            keys.public_key().to_bytes()
        );
        assert_eq!(limiter.identity_pubkeys.lock().unwrap().len(), 1);
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 1);
        assert_fresh_untouched(&limiter);
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn keyed_router_open_relay_raw_tag_for_a_different_agent_cannot_select_owner() {
        let limiter = LaneRecordingLimiter::new(FleetLimiterOutcome::Allow);
        let replay = OrderedReplayGuard {
            steps: Arc::clone(&limiter.steps),
            admit: true,
        };
        let tenant = fresh_tenant("keyed-attempt.example");
        let agent = Keys::generate();
        let other_agent = Keys::generate();
        let owner_keys = Keys::generate();
        assert_ne!(agent.public_key(), other_agent.public_key());
        assert_ne!(agent.public_key(), owner_keys.public_key());
        let foreign_tag = compute_auth_tag(&owner_keys, &other_agent.public_key(), "")
            .expect("compute_auth_tag must succeed");
        let (validated, owner) = attempt_then_after(
            &limiter,
            &replay,
            KeyedHttpAdmitRequest {
                tenant: &tenant,
                pubkey: agent.public_key(),
                event_id_bytes: fresh_nip98_event_id_bytes(),
                signed_created_at: Some(Timestamp::now().as_secs()),
                body: &signed_kind9_body(&agent),
            },
            recording_membership(&limiter.steps, Ok(None)),
            recording_owner(&limiter.steps, Some(foreign_tag.as_str())),
        )
        .await
        .expect("foreign-agent tag must not admit an owner");
        assert_eq!(validated.event().pubkey, agent.public_key());
        assert_eq!(owner, None);
        assert_ne!(owner, Some(owner_keys.public_key()));
        assert_eq!(
            *limiter.steps.lock().unwrap(),
            vec![
                "attempt_hierarchical",
                "replay",
                "membership",
                "owner_select"
            ]
        );
        assert_attempt_charged_once(&limiter, &agent.public_key());
        assert_eq!(
            limiter.identity_pubkeys.lock().unwrap()[0],
            agent.public_key().to_bytes()
        );
        assert_eq!(limiter.identity_pubkeys.lock().unwrap().len(), 1);
        assert_ne!(
            limiter.identity_pubkeys.lock().unwrap()[0],
            owner_keys.public_key().to_bytes()
        );
        assert_ne!(
            limiter.identity_pubkeys.lock().unwrap()[0],
            other_agent.public_key().to_bytes()
        );
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 1);
        assert_fresh_untouched(&limiter);
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn keyed_router_open_relay_verified_raw_auth_tag_keeps_attempt_on_the_agent() {
        let limiter = LaneRecordingLimiter::new(FleetLimiterOutcome::Allow);
        let replay = OrderedReplayGuard {
            steps: Arc::clone(&limiter.steps),
            admit: true,
        };
        let tenant = fresh_tenant("keyed-attempt.example");
        let agent = Keys::generate();
        let owner_keys = Keys::generate();
        assert_ne!(agent.public_key(), owner_keys.public_key());
        let tag = compute_auth_tag(&owner_keys, &agent.public_key(), "")
            .expect("compute_auth_tag must succeed");
        let (validated, owner) = attempt_then_after(
            &limiter,
            &replay,
            KeyedHttpAdmitRequest {
                tenant: &tenant,
                pubkey: agent.public_key(),
                event_id_bytes: fresh_nip98_event_id_bytes(),
                signed_created_at: Some(Timestamp::now().as_secs()),
                body: &signed_kind9_body(&agent),
            },
            recording_membership(&limiter.steps, Ok(None)),
            recording_owner(&limiter.steps, Some(tag.as_str())),
        )
        .await
        .expect("verified open-relay tag must yield the owner");
        assert_eq!(validated.event().pubkey, agent.public_key());
        assert_eq!(owner, Some(owner_keys.public_key()));
        assert_eq!(
            *limiter.steps.lock().unwrap(),
            vec![
                "attempt_hierarchical",
                "replay",
                "membership",
                "owner_select"
            ]
        );
        assert_attempt_charged_once(&limiter, &agent.public_key());
        assert_eq!(
            limiter.identity_pubkeys.lock().unwrap()[0],
            agent.public_key().to_bytes()
        );
        assert_ne!(
            limiter.identity_pubkeys.lock().unwrap()[0],
            owner_keys.public_key().to_bytes()
        );
        assert_eq!(limiter.identity_pubkeys.lock().unwrap().len(), 1);
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 1);
        assert_fresh_untouched(&limiter);
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn keyed_router_membership_owner_wins_over_open_relay_extraction() {
        let limiter = LaneRecordingLimiter::new(FleetLimiterOutcome::Allow);
        let replay = OrderedReplayGuard {
            steps: Arc::clone(&limiter.steps),
            admit: true,
        };
        let tenant = fresh_tenant("keyed-attempt.example");
        let agent = Keys::generate();
        let member_owner = Keys::generate().public_key();
        let extracted_owner_keys = Keys::generate();
        assert_ne!(member_owner, extracted_owner_keys.public_key());
        let extracted_tag = compute_auth_tag(&extracted_owner_keys, &agent.public_key(), "")
            .expect("compute_auth_tag must succeed");
        let (_, owner) = attempt_then_after(
            &limiter,
            &replay,
            KeyedHttpAdmitRequest {
                tenant: &tenant,
                pubkey: agent.public_key(),
                event_id_bytes: fresh_nip98_event_id_bytes(),
                signed_created_at: Some(Timestamp::now().as_secs()),
                body: &signed_kind9_body(&agent),
            },
            recording_membership(&limiter.steps, Ok(Some(member_owner))),
            recording_owner(&limiter.steps, Some(extracted_tag.as_str())),
        )
        .await
        .expect("membership owner wins");
        assert_eq!(owner, Some(member_owner));
        assert_ne!(owner, Some(extracted_owner_keys.public_key()));
        assert_eq!(
            *limiter.steps.lock().unwrap(),
            vec![
                "attempt_hierarchical",
                "replay",
                "membership",
                "owner_select"
            ]
        );
        assert_attempt_charged_once(&limiter, &agent.public_key());
        assert_eq!(
            limiter.identity_pubkeys.lock().unwrap()[0],
            agent.public_key().to_bytes()
        );
        assert_ne!(
            limiter.identity_pubkeys.lock().unwrap()[0],
            member_owner.to_bytes()
        );
        assert_ne!(
            limiter.identity_pubkeys.lock().unwrap()[0],
            extracted_owner_keys.public_key().to_bytes()
        );
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 1);
        assert_fresh_untouched(&limiter);
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn keyed_refactor_preserves_unkeyed_path_without_attempt_or_fresh_admission() {
        let limiter = LaneRecordingLimiter::new(FleetLimiterOutcome::Deny);
        let tenant = fresh_tenant("keyed-attempt.example");
        crate::admission::check_principal(
            &limiter,
            &tenant,
            &Keys::generate().public_key(),
            LimitType::ApiCalls,
            60,
            300,
        )
        .await
        .expect("unkeyed principal admission is independent");
        assert!(limiter.paired_types.lock().unwrap().is_empty());
        assert_eq!(
            limiter.principal_types.lock().unwrap().clone(),
            vec![LimitType::ApiCalls]
        );
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.attempt_tenant_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.attempt_fleet_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.fresh_tenant_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.fresh_fleet_charged.load(Ordering::Relaxed), 0);
        assert_eq!(*limiter.steps.lock().unwrap(), vec!["unkeyed_api"]);
    }

    #[tokio::test]
    async fn keyed_membership_rejection_does_not_invoke_fresh_admission() {
        let limiter = LaneRecordingLimiter::new(FleetLimiterOutcome::Allow);
        let replay = OrderedReplayGuard {
            steps: Arc::clone(&limiter.steps),
            admit: true,
        };
        let tenant = fresh_tenant("keyed-attempt.example");
        let keys = Keys::generate();
        let rejected = attempt_then_after(
            &limiter,
            &replay,
            KeyedHttpAdmitRequest {
                tenant: &tenant,
                pubkey: keys.public_key(),
                event_id_bytes: fresh_nip98_event_id_bytes(),
                signed_created_at: None,
                body: &signed_kind9_body(&keys),
            },
            recording_membership(
                &limiter.steps,
                Err(api_error(
                    StatusCode::FORBIDDEN,
                    "restricted: not a relay member",
                )),
            ),
            unreachable_owner(),
        )
        .await
        .expect_err("membership denial");
        assert!(matches!(
            rejected,
            KeyedHttpAdmitError::Membership((StatusCode::FORBIDDEN, _))
        ));
        assert_eq!(
            *limiter.steps.lock().unwrap(),
            vec!["attempt_hierarchical", "replay", "membership"]
        );
        assert_attempt_charged_once(&limiter, &keys.public_key());
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert_fresh_untouched(&limiter);
    }
}
