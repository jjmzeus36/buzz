//! Transport-neutral event ingestion pipeline.
//!
//! Both WebSocket `["EVENT", ...]` and HTTP `POST /events` feed into
//! [`ingest_event`] — two doors, one room.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use chrono::Utc;
use tokio::sync::{Semaphore, SemaphorePermit};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use buzz_auth::rate_limit::{
    HierarchicalAdmissionLimits, HierarchicalAdmissionOutcome, HierarchicalAdmissionRequest,
};
use buzz_auth::{LimitType, RateLimiter, Scope};
use buzz_core::idempotency::PreparedKeyedIntent;
use buzz_core::kind::{
    event_kind_u32, is_identity_archive_request_kind, is_parameterized_replaceable,
    is_relay_admin_kind, KIND_AGENT_ENGRAM, KIND_AGENT_PROFILE, KIND_AGENT_TURN_METRIC,
    KIND_APPROVAL_DENY, KIND_APPROVAL_GRANT, KIND_AUTH, KIND_BOOKMARK_LIST, KIND_BOOKMARK_SET,
    KIND_CANVAS, KIND_CONTACT_LIST, KIND_DELETION, KIND_DM_ADD_MEMBER, KIND_DM_HIDE, KIND_DM_OPEN,
    KIND_EMOJI_LIST, KIND_EMOJI_SET, KIND_EVENT_REMINDER, KIND_FOLLOW_SET, KIND_FORUM_COMMENT,
    KIND_FORUM_POST, KIND_FORUM_VOTE, KIND_GIFT_WRAP, KIND_GIT_ISSUE, KIND_GIT_PATCH,
    KIND_GIT_PR_UPDATE, KIND_GIT_PULL_REQUEST, KIND_GIT_REPO_ANNOUNCEMENT, KIND_GIT_REPO_STATE,
    KIND_GIT_STATUS_CLOSED, KIND_GIT_STATUS_DRAFT, KIND_GIT_STATUS_MERGED, KIND_GIT_STATUS_OPEN,
    KIND_HUDDLE_ENDED, KIND_HUDDLE_GUIDELINES, KIND_HUDDLE_PARTICIPANT_JOINED,
    KIND_HUDDLE_PARTICIPANT_LEFT, KIND_HUDDLE_STARTED, KIND_IA_ARCHIVE_REQUEST,
    KIND_IA_UNARCHIVE_REQUEST, KIND_LONG_FORM, KIND_MANAGED_AGENT, KIND_MEMBER_ADDED_NOTIFICATION,
    KIND_MEMBER_REMOVED_NOTIFICATION, KIND_MODERATION_BAN, KIND_MODERATION_RESOLVE_REPORT,
    KIND_MODERATION_TIMEOUT, KIND_MODERATION_UNBAN, KIND_MODERATION_UNTIMEOUT, KIND_MUTE_LIST,
    KIND_NIP29_CREATE_GROUP, KIND_NIP29_DELETE_EVENT, KIND_NIP29_DELETE_GROUP,
    KIND_NIP29_EDIT_METADATA, KIND_NIP29_JOIN_REQUEST, KIND_NIP29_LEAVE_REQUEST,
    KIND_NIP29_PUT_USER, KIND_NIP29_REMOVE_USER, KIND_NIP43_LEAVE_REQUEST,
    KIND_NIP65_RELAY_LIST_METADATA, KIND_PERSONA, KIND_PIN_LIST, KIND_PRESENCE_UPDATE,
    KIND_PRIVATE_MANAGED_AGENT, KIND_PRODUCT_FEEDBACK, KIND_PROFILE, KIND_PROJECT, KIND_REACTION,
    KIND_READ_STATE, KIND_REPORT, KIND_STREAM_MESSAGE, KIND_STREAM_MESSAGE_BOOKMARKED,
    KIND_STREAM_MESSAGE_DIFF, KIND_STREAM_MESSAGE_EDIT, KIND_STREAM_MESSAGE_PINNED,
    KIND_STREAM_MESSAGE_SCHEDULED, KIND_STREAM_MESSAGE_V2, KIND_STREAM_REMINDER, KIND_TEAM,
    KIND_TEAM_CATALOG, KIND_TEXT_NOTE, KIND_USER_STATUS, KIND_WORKFLOW_DEF, KIND_WORKFLOW_TRIGGER,
    RELAY_ADMIN_ADD_MEMBER, RELAY_ADMIN_CHANGE_ROLE, RELAY_ADMIN_REMOVE_MEMBER,
    RELAY_ADMIN_SET_WORKSPACE_PROFILE,
};
use buzz_core::tenant::TenantContext;
use buzz_core::verification::verify_event;
use buzz_core::CommunityId;
use nostr::Event;

use crate::state::AppState;

use super::event::dispatch_persistent_event;

use crate::conformance::{
    self as conf, channel_label, claimed_community_from_event, emit, msg_id_label,
    state_for_request, EmitGuard, SanitizedReason, TraceAction, Verdict,
};

fn huddle_backing_channel_id(event: &Event) -> Result<Uuid, IngestError> {
    let content: serde_json::Value = serde_json::from_str(&event.content).map_err(|_| {
        IngestError::Rejected("invalid: Huddle event content must be a JSON object".into())
    })?;
    let channel_id = content
        .get("ephemeral_channel_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            IngestError::Rejected("invalid: Huddle event must name an ephemeral_channel_id".into())
        })?;
    channel_id.parse::<Uuid>().map_err(|_| {
        IngestError::Rejected("invalid: Huddle ephemeral_channel_id must be a UUID".into())
    })
}

fn map_huddle_backing_channel_error(error: buzz_db::DbError) -> IngestError {
    match error {
        buzz_db::DbError::ChannelNotFound(_) => {
            IngestError::Rejected("invalid: Huddle backing channel not found".into())
        }
        error => IngestError::Internal(format!("error: loading Huddle backing channel: {error}")),
    }
}

fn expected_huddle_backing_ttl(ephemeral_ttl_override: Option<i32>) -> i32 {
    ephemeral_ttl_override.unwrap_or(3600)
}

async fn validate_huddle_lifecycle_event(
    tenant: &TenantContext,
    state: &AppState,
    event: &Event,
    kind: u32,
) -> Result<(), IngestError> {
    if kind != KIND_HUDDLE_STARTED && kind != KIND_HUDDLE_ENDED {
        return Ok(());
    }

    let backing_channel_id = huddle_backing_channel_id(event)?;
    let backing = state
        .db
        .get_channel_for_event_write(tenant.community(), backing_channel_id)
        .await
        .map_err(map_huddle_backing_channel_error)?;
    let signer = event.pubkey.to_bytes();
    let relay = state.relay_keypair.public_key().to_bytes();
    let signer_created_backing = backing.created_by.as_slice() == signer.as_slice();

    if kind == KIND_HUDDLE_STARTED {
        let expected_ttl = expected_huddle_backing_ttl(state.config.ephemeral_ttl_override);
        if !signer_created_backing
            || backing.channel_type != "stream"
            || backing.visibility != "private"
            || backing.ttl_seconds != Some(expected_ttl)
            || backing.archived_at.is_some()
        {
            return Err(IngestError::Rejected(
                "invalid: Huddle start must reference the signer's active private ephemeral stream"
                    .into(),
            ));
        }
    } else {
        if !signer_created_backing && signer.as_slice() != relay.as_slice() {
            return Err(IngestError::Rejected(
                "invalid: only the Huddle creator or relay may end it".into(),
            ));
        }
        let parent_channel_id = extract_channel_id(event).ok_or_else(|| {
            IngestError::Rejected("invalid: Huddle end must name its parent channel".into())
        })?;
        let linked = state
            .db
            .huddle_started_link_exists_for_event_write(
                tenant.community(),
                parent_channel_id,
                backing_channel_id,
                &backing.created_by,
            )
            .await
            .map_err(|error| {
                IngestError::Internal(format!("error: checking Huddle start linkage: {error}"))
            })?;
        if !linked {
            return Err(IngestError::Rejected(
                "invalid: Huddle end does not match a creator-signed start in this channel".into(),
            ));
        }
    }

    Ok(())
}

fn validate_custom_emoji_tags(event: &Event) -> Result<(), IngestError> {
    for tag in event.tags.iter() {
        let parts = tag.as_slice();
        if parts.first().map(String::as_str) != Some("emoji") {
            continue;
        }
        let shortcode = parts.get(1).ok_or_else(|| {
            IngestError::Rejected("invalid: emoji tag must include a shortcode".into())
        })?;
        buzz_sdk::normalize_custom_emoji_shortcode(shortcode)
            .map_err(|err| IngestError::Rejected(format!("invalid: {err}")))?;
    }
    Ok(())
}

fn validate_reaction_emoji(event: &Event, emoji: &str) -> Result<(), IngestError> {
    let emoji_char_count = emoji.chars().count();
    if emoji_char_count <= 64 {
        return Ok(());
    }

    let Some(shortcode) = emoji
        .strip_prefix(':')
        .and_then(|value| value.strip_suffix(':'))
    else {
        return Err(IngestError::Rejected(format!(
            "invalid: reaction emoji exceeds 64 characters (got {emoji_char_count})"
        )));
    };
    let normalized = buzz_sdk::normalize_custom_emoji_shortcode(shortcode)
        .map_err(|err| IngestError::Rejected(format!("invalid: {err}")))?;
    if shortcode != normalized {
        return Err(IngestError::Rejected(
            "invalid: long custom emoji reaction shortcode must be canonical lowercase".into(),
        ));
    }
    let has_matching_tag = event.tags.iter().any(|tag| {
        let parts = tag.as_slice();
        parts.first().map(String::as_str) == Some("emoji")
            && parts.get(1).is_some_and(|value| value == shortcode)
    });
    if !has_matching_tag || emoji_char_count > buzz_sdk::MAX_CUSTOM_EMOJI_REACTION_LEN {
        return Err(IngestError::Rejected(format!(
            "invalid: reaction emoji exceeds 64 characters (got {emoji_char_count})"
        )));
    }
    Ok(())
}

/// How the HTTP caller authenticated (for [`IngestAuth::Http`]).
#[derive(Debug, Clone)]
pub enum HttpAuthMethod {
    /// `Authorization: Nostr <base64>` — NIP-98 HTTP Auth.
    Nip98,
    /// `X-Pubkey: <hex>` dev-mode header (backward compat during transition).
    DevPubkey,
}

/// Authentication context for event ingestion — transport-neutral.
#[derive(Debug, Clone)]
pub enum IngestAuth {
    /// WebSocket NIP-42 authenticated connection.
    Nip42 {
        /// The authenticated Nostr public key.
        pubkey: nostr::PublicKey,
        /// Owner proven at transport authentication, used only for moderation.
        moderation_owner: Option<nostr::PublicKey>,
        /// Permission scopes granted to this connection.
        scopes: Vec<Scope>,
        /// Token-level channel restriction, if the WebSocket auth used an API token.
        channel_ids: Option<Vec<Uuid>>,
        /// WebSocket connection identifier.
        conn_id: Uuid,
    },
    /// HTTP bridge authenticated request (NIP-98 or dev X-Pubkey).
    Http {
        /// The authenticated Nostr public key.
        pubkey: nostr::PublicKey,
        /// Owner proven at transport authentication, used only for moderation.
        moderation_owner: Option<nostr::PublicKey>,
        /// Permission scopes granted to this request.
        scopes: Vec<Scope>,
        /// How the HTTP request was authenticated.
        auth_method: HttpAuthMethod,
    },
}

impl IngestAuth {
    /// The authenticated public key.
    pub fn pubkey(&self) -> &nostr::PublicKey {
        match self {
            Self::Nip42 { pubkey, .. } | Self::Http { pubkey, .. } => pubkey,
        }
    }

    /// Self-proving owner retained only for moderation restrictions.
    pub fn moderation_owner(&self) -> Option<&nostr::PublicKey> {
        match self {
            Self::Nip42 {
                moderation_owner, ..
            }
            | Self::Http {
                moderation_owner, ..
            } => moderation_owner.as_ref(),
        }
    }

    /// Pubkey used for principal-scoped accounting and policy lookups.
    pub fn principal_pubkey_bytes(&self) -> Vec<u8> {
        self.pubkey().to_bytes().to_vec()
    }

    /// Permission scopes for this auth context.
    pub fn scopes(&self) -> &[Scope] {
        match self {
            Self::Nip42 { scopes, .. } | Self::Http { scopes, .. } => scopes,
        }
    }

    /// WebSocket connection ID (Nip42 only).
    pub fn conn_id(&self) -> Option<Uuid> {
        match self {
            Self::Nip42 { conn_id, .. } => Some(*conn_id),
            Self::Http { .. } => None,
        }
    }

    /// Token-level channel restriction (WS connections with scoped tokens — legacy).
    /// In pure Nostr mode this always returns None; channel access is enforced
    /// via NIP-29 membership checks instead.
    pub fn channel_ids(&self) -> Option<&[Uuid]> {
        match self {
            Self::Nip42 {
                channel_ids: Some(ids),
                ..
            } => Some(ids),
            _ => None,
        }
    }

    /// Whether this auth context is an HTTP request (not WebSocket).
    pub fn is_http(&self) -> bool {
        matches!(self, Self::Http { .. })
    }
}

fn emit_product_feedback_success(
    tracer: &Arc<dyn buzz_conformance::Tracer>,
    tenant: &TenantContext,
    event: &Event,
    auth: &IngestAuth,
) {
    emit(
        tracer,
        TraceAction::WriteInsertGlobal {
            msg_id: msg_id_label(event.id.as_bytes()),
            claimed_community: claimed_community_from_event(event),
        },
        state_for_request(tenant, auth.pubkey()),
    );
}

/// Increment the rejection counter with a bounded reason and transport label.
///
/// Shared by the WS `EVENT` handler and the HTTP `POST /events` handler so
/// both transports feed the same series — `transport` distinguishes them so
/// existing WS-only dashboards aren't silently diluted by HTTP volume.
/// `reason` is one of a small closed set ("auth", "invalid", "scope",
/// "error") — bounded, no cardinality risk.
pub fn reject_with_transport(transport: &'static str, reason: &'static str) {
    metrics::counter!(
        "buzz_events_rejected_total",
        "transport" => transport,
        "reason" => reason
    )
    .increment(1);
}

fn valid_link_preview_text(value: &str, max: usize, allow_newlines: bool) -> bool {
    value.len() <= max
        && !value
            .chars()
            .any(|character| character.is_control() && !(allow_newlines && character == '\n'))
}

fn validate_link_preview_tags(event: &Event, media_base_url: &str) -> Result<(), String> {
    const MAX_SNAPSHOTS: usize = 8;
    const MAX_TITLE: usize = 300;
    const MAX_SITE: usize = 100;
    const MAX_DESCRIPTION: usize = 1000;

    let mut count = 0;
    let mut suppressed = false;
    let mut seen = std::collections::HashSet::new();
    for tag in event.tags.iter() {
        let parts = tag.as_slice();
        if parts.first().map(String::as_str) != Some("link-preview") {
            continue;
        }
        count += 1;
        if parts == ["link-preview", "none"] {
            if count > 1 {
                return Err("link-preview suppression cannot include snapshots".into());
            }
            suppressed = true;
            continue;
        }
        if suppressed
            || count > MAX_SNAPSHOTS
            || parts.len() != 11
            || parts[1] != "snapshot"
            || parts[2] != "1"
        {
            return Err("invalid link-preview snapshot tag".into());
        }
        let canonical =
            url::Url::parse(&parts[3]).map_err(|_| "invalid link-preview canonical URL")?;
        if canonical.scheme() != "https"
            || !canonical.username().is_empty()
            || canonical.password().is_some()
            || canonical.fragment().is_some()
            || !seen.insert(parts[3].clone())
            || !event.content.contains(&parts[3])
        {
            return Err("invalid link-preview canonical URL".into());
        }
        for (value, max, allow_newlines) in [
            (&parts[4], MAX_TITLE, false),
            (&parts[5], MAX_SITE, false),
            (&parts[6], MAX_DESCRIPTION, true),
        ] {
            if !valid_link_preview_text(value, max, allow_newlines) {
                return Err("invalid link-preview snapshot text".into());
            }
        }
        if !super::imeta::validate_local_image_media_pair(&parts[7], &parts[8], media_base_url)
            || !super::imeta::validate_local_image_media_pair(&parts[9], &parts[10], media_base_url)
        {
            return Err("link-preview media must reference matching local image blobs".into());
        }
    }
    Ok(())
}

/// Successful ingestion result.
pub struct IngestResult {
    /// Hex-encoded event ID.
    pub event_id: String,
    /// Whether the event was accepted.
    pub accepted: bool,
    /// Optional message (e.g. "duplicate:" for dedup).
    pub message: String,
}

/// Ingestion error — the caller maps this to their transport's error format.
#[derive(Debug)]
pub enum IngestError {
    /// Client error (bad event) — WS: OK false, HTTP: 400.
    Rejected(String),
    /// Auth/scope error — WS: OK false, HTTP: 401/403.
    AuthFailed(String),
    /// Server error — WS: OK false, HTTP: 500.
    Internal(String),
}

/// Cryptographically verified keyed event plus authenticated-author binding.
/// Membership, owner selection, and remaining kind/body/cap checks still run
/// before [`KeyedHttpValidatedEvent`] is issued.
#[derive(Debug)]
pub(crate) struct KeyedHttpSignedEvent {
    event: Event,
    auth: IngestAuth,
    kind_u32: u32,
}

/// Unforgeable proof that a keyed HTTP event passed the pre-command ingest
/// checks. Production keyed HTTP constructs this only through
/// [`Self::finish_after_owner`] after
/// [`Self::verify_signature_and_author_with_early`], which owns
/// [`KeyedHttpEarlyContext`] for the blocking verification window.
/// [`ingest_keyed_http_event`] accepts this type rather than a raw [`Event`]
/// so an unvalidated body cannot select the skip path. Construction consumes
/// the exact [`IngestAuth`] used for those checks; that auth cannot be swapped
/// after the proof is issued.
#[derive(Debug)]
pub(crate) struct KeyedHttpValidatedEvent {
    event: Event,
    auth: IngestAuth,
}

impl KeyedHttpValidatedEvent {
    /// Run the production keyed-HTTP pre-command checks. Failures keep the
    /// established [`IngestError`] variants and must be mapped before any
    /// `KeyedHttpFresh` charge. Direct callers do not hold ingress; the
    /// owned-context production seam is
    /// [`Self::verify_signature_and_author_with_early`] then
    /// [`Self::finish_after_owner`].
    #[cfg(test)]
    pub(crate) async fn validate(event: Event, auth: IngestAuth) -> Result<Self, IngestError> {
        match tokio::task::spawn_blocking(move || keyed_validate_pre_command(event, auth)).await {
            Ok(result) => result,
            Err(e) => Err(ingest_verify_join_error(e)),
        }
    }

    /// Parsed keyed-event signature verification and authenticated-author
    /// binding with owned early context. The blocking worker holds
    /// [`KeyedHttpEarlyContext`] (including ingress) for the whole CPU window
    /// so a request cancel cannot release the permit while verification still
    /// runs. The join is never wrapped in `timeout` or `select!`. Exactly one
    /// cryptographic validation of the immutable event.
    pub(crate) async fn verify_signature_and_author_with_early(
        event: Event,
        auth: IngestAuth,
        early: KeyedHttpEarlyContext,
    ) -> Result<(KeyedHttpSignedEvent, KeyedHttpEarlyContext), IngestError> {
        let join = tokio::task::spawn_blocking(move || {
            let result = keyed_validate_signature_and_author(event, auth);
            (result, early)
        });
        match join.await {
            Ok((Ok(signed), early)) => Ok((signed, early)),
            Ok((Err(error), early)) => {
                drop(early);
                Err(error)
            }
            Err(e) => Err(ingest_verify_join_error(e)),
        }
    }

    /// Remaining keyed kind/body/cap checks after membership and verified-owner
    /// metadata selection. Does not repeat cryptographic validation.
    pub(crate) fn finish_after_owner(signed: KeyedHttpSignedEvent) -> Result<Self, IngestError> {
        keyed_finish_pre_command(signed)
    }

    /// Keyed pre-command validation with owned early context. Test seam for
    /// join/cancel/ingress ownership; production splits signature/author from
    /// kind/body/cap around membership.
    #[cfg(test)]
    pub(crate) async fn validate_with_early(
        event: Event,
        auth: IngestAuth,
        early: KeyedHttpEarlyContext,
    ) -> Result<(Self, KeyedHttpEarlyContext), IngestError> {
        let (signed, early) =
            Self::verify_signature_and_author_with_early(event, auth, early).await?;
        match Self::finish_after_owner(signed) {
            Ok(validated) => Ok((validated, early)),
            Err(error) => {
                drop(early);
                Err(error)
            }
        }
    }

    pub(crate) fn event(&self) -> &Event {
        &self.event
    }

    #[cfg(test)]
    fn auth(&self) -> &IngestAuth {
        &self.auth
    }

    fn into_event_and_auth(self) -> (Event, IngestAuth) {
        (self.event, self.auth)
    }
}

enum IngestSource {
    Raw {
        event: Event,
    },
    /// Consumed from [`KeyedHttpValidatedEvent`] in [`ingest_keyed_http_event`],
    /// so WebSocket and unkeyed HTTP (`ingest_event` → `Raw`) cannot select the
    /// keyed skip path with an unvalidated body.
    KeyedValidated(Event),
}

const MAX_TIMESTAMP_DRIFT_SECS: i64 = 900; // ±15 minutes
const MAX_EVENT_CONTENT_BYTES: usize = 256 * 1024; // 256 KB

/// Overflow-safe `|event_created_at - now| > MAX_TIMESTAMP_DRIFT_SECS` on i128.
fn timestamp_drift_exceeds_max(event_created_at_secs: u64, now_unix_secs: i64) -> bool {
    let drift = i128::from(event_created_at_secs) - i128::from(now_unix_secs);
    drift.abs() > i128::from(MAX_TIMESTAMP_DRIFT_SECS)
}

fn ingest_verify_join_error(e: tokio::task::JoinError) -> IngestError {
    error!("spawn_blocking panicked: {e}");
    IngestError::Internal("error: internal verification error".into())
}

/// Prefix checks before signature verification, including keyed size-before-signature.
fn validate_ingest_pre_command_prefix(
    event: &Event,
    auth: &IngestAuth,
    keyed: bool,
) -> Result<u32, IngestError> {
    let kind_u32 = event_kind_u32(event);

    if kind_u32 == KIND_AUTH {
        return Err(IngestError::Rejected(
            "invalid: AUTH events cannot be submitted".into(),
        ));
    }
    if kind_u32 == KIND_MEMBER_ADDED_NOTIFICATION || kind_u32 == KIND_MEMBER_REMOVED_NOTIFICATION {
        return Err(IngestError::Rejected(
            "invalid: membership notifications are relay-signed only".into(),
        ));
    }

    if auth.is_http() && (kind_u32 == KIND_GIFT_WRAP || kind_u32 == KIND_PRESENCE_UPDATE) {
        return Err(IngestError::Rejected(format!(
            "invalid: kind {kind_u32} is only accepted via WebSocket"
        )));
    }

    if buzz_core::kind::is_relay_only_kind(kind_u32) {
        return Err(IngestError::Rejected("restricted: relay-only kind".into()));
    }

    if keyed && event.content.len() > MAX_EVENT_CONTENT_BYTES {
        return Err(IngestError::Rejected(format!(
            "invalid: content exceeds maximum size of {} bytes (got {})",
            MAX_EVENT_CONTENT_BYTES,
            event.content.len()
        )));
    }

    Ok(kind_u32)
}

fn bind_authenticated_event_author(
    event: &Event,
    auth: &IngestAuth,
    kind_u32: u32,
) -> Result<(), IngestError> {
    let is_gift_wrap = kind_u32 == KIND_GIFT_WRAP;
    if event.pubkey != *auth.pubkey() && !is_gift_wrap {
        return Err(IngestError::AuthFailed(
            "invalid: event pubkey does not match authenticated identity".into(),
        ));
    }
    Ok(())
}

/// Suffix after signature verification: timestamp, unkeyed size, optional
/// pubkey/auth, scope, keyed-kind allowlist, and p-tag cap.
fn validate_ingest_pre_command_suffix(
    event: Event,
    auth: &IngestAuth,
    keyed: bool,
    kind_u32: u32,
    bind_author: bool,
) -> Result<Event, IngestError> {
    let now = chrono::Utc::now().timestamp();
    if timestamp_drift_exceeds_max(event.created_at.as_secs(), now) {
        return Err(IngestError::Rejected(
            "invalid: event timestamp too far from server time".into(),
        ));
    }

    if !keyed && event.content.len() > MAX_EVENT_CONTENT_BYTES {
        return Err(IngestError::Rejected(format!(
            "invalid: content exceeds maximum size of {} bytes (got {})",
            MAX_EVENT_CONTENT_BYTES,
            event.content.len()
        )));
    }
    if bind_author {
        bind_authenticated_event_author(&event, auth, kind_u32)?;
    }

    let required = match required_scope_for_kind(kind_u32, &event) {
        Ok(scope) => scope,
        Err(msg) => return Err(IngestError::Rejected(msg.into())),
    };
    // NIP-43: relay admin commands are global — channel-scoped tokens cannot
    // issue them even if the event has no `h` tag (is_global_only_kind strips
    // channel_id, but we still need to reject the token itself).
    if is_relay_admin_kind(kind_u32) && auth.channel_ids().is_some() {
        return Err(IngestError::AuthFailed(
            "restricted: relay admin commands require a global token, not a channel-scoped token"
                .into(),
        ));
    }
    // NIP-43: leave requests are also global — channel-scoped tokens cannot
    // issue them.
    if kind_u32 == KIND_NIP43_LEAVE_REQUEST && auth.channel_ids().is_some() {
        return Err(IngestError::AuthFailed(
            "restricted: leave requests require a global token".into(),
        ));
    }
    if !auth.scopes().contains(&required) {
        return Err(IngestError::AuthFailed(format!(
            "restricted: insufficient scope (need {})",
            required
        )));
    }

    if keyed && !buzz_core::idempotency::supports_keyed_kind(kind_u32) {
        return Err(IngestError::Rejected(
            "invalid: Idempotency-Key is not supported for this event kind".into(),
        ));
    }
    if buzz_core::idempotency::keyed_p_tag_count(&event) > buzz_core::idempotency::KEYED_MAX_P_TAGS
    {
        if keyed {
            return Err(IngestError::Rejected(
                "invalid: too many p tags for keyed ingest".into(),
            ));
        }
        return Err(IngestError::Rejected("invalid: too many p tags".into()));
    }

    Ok(event)
}

fn keyed_validate_signature_and_author(
    event: Event,
    auth: IngestAuth,
) -> Result<KeyedHttpSignedEvent, IngestError> {
    let kind_u32 = validate_ingest_pre_command_prefix(&event, &auth, true)?;
    let event = keyed_verify_event_joined(event)?;
    bind_authenticated_event_author(&event, &auth, kind_u32)?;
    Ok(KeyedHttpSignedEvent {
        event,
        auth,
        kind_u32,
    })
}

fn keyed_finish_pre_command(
    signed: KeyedHttpSignedEvent,
) -> Result<KeyedHttpValidatedEvent, IngestError> {
    let KeyedHttpSignedEvent {
        event,
        auth,
        kind_u32,
    } = signed;
    let event = validate_ingest_pre_command_suffix(event, &auth, true, kind_u32, false)?;
    Ok(KeyedHttpValidatedEvent { event, auth })
}

#[cfg(test)]
fn keyed_validate_pre_command(
    event: Event,
    auth: IngestAuth,
) -> Result<KeyedHttpValidatedEvent, IngestError> {
    let signed = keyed_validate_signature_and_author(event, auth)?;
    keyed_finish_pre_command(signed)
}

/// Pre-command ingest checks shared by WebSocket, unkeyed HTTP, and keyed HTTP.
///
/// Keyed HTTP runs this before charging `KeyedHttpFresh`. WebSocket and unkeyed
/// HTTP keep calling it from [`ingest_event_inner`] after the serving-state DB
/// fence. Includes the HTTP/keyed-relevant checks performed before
/// command/business/DB work: forbidden AUTH / member-notification / HTTP-only /
/// relay-only kinds, id/signature verification, timestamp window, content bound,
/// authenticated-pubkey match, required/sufficient scope, the actual
/// lowercase `"p"` tag cap for every externally accepted event kind (keyed
/// and unkeyed), and when `keyed` the keyed-kind allowlist. WebSocket and
/// HTTP share this function, so omitting `Idempotency-Key` cannot bypass
/// the p-tag cap.
async fn validate_ingest_pre_command(
    event: Event,
    auth: &IngestAuth,
    keyed: bool,
) -> Result<Event, IngestError> {
    let kind_u32 = validate_ingest_pre_command_prefix(&event, auth, keyed)?;

    let event = if keyed {
        keyed_verify_event_joined(event)?
    } else {
        // Share the event with the verify task via Arc instead of deep-cloning it
        // (tags + up to 256 KB of content). spawn_blocking only needs 'static, not
        // ownership; once it completes its Arc is dropped, so try_unwrap returns
        // the original event without ever having copied it.
        let event = std::sync::Arc::new(event);
        let event_for_verify = std::sync::Arc::clone(&event);
        let verify_result =
            tokio::task::spawn_blocking(move || verify_event(&event_for_verify)).await;
        match verify_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                return Err(IngestError::Rejected(format!("invalid: {e}")));
            }
            Err(e) => return Err(ingest_verify_join_error(e)),
        }
        std::sync::Arc::try_unwrap(event).unwrap_or_else(|arc| (*arc).clone())
    };

    validate_ingest_pre_command_suffix(event, auth, keyed, kind_u32, true)
}

/// HTTP-only keyed ingest outcomes that must not enlarge [`IngestError`].
#[derive(Debug)]
pub(crate) enum KeyedHttpError {
    /// Existing ingest failure.
    Ingest(IngestError),
    /// Same key, different semantic intent — HTTP 409.
    Conflict,
    /// Keyed writer busy — HTTP 503. `retry_after_secs` is the fleet window
    /// reset when the aggregate denied the request, or the conservative
    /// default for stripe/global/SQL timeout and limiter unavailability.
    Busy {
        /// Seconds advertised in `Retry-After`. Fleet quota denial uses the
        /// limiter's `reset_in_secs`; stripe, SQL, and limiter unavailability
        /// use the conservative five-second default.
        retry_after_secs: u64,
    },
    /// Per-principal HTTP API quota — HTTP 429 / 503. Charged only for
    /// genuinely new keyed work after atomic replay/conflict classification.
    Principal(crate::admission::AdmissionError),
}

/// Closed terminal classification for [`ingest_event_inner`].
///
/// Ordinary success is `Ok(IngestResult)`. Every ordinary ingest error and
/// every keyed-only HTTP terminal is a variant of this enum. The returned
/// value is the sole authority for terminal classification — not mutable
/// side state, sentinel `IngestError::Internal` prose, or stored-metric
/// bookkeeping.
#[derive(Debug)]
enum IngestInnerOutcome {
    Rejected(String),
    AuthFailed(String),
    Internal(String),
    Conflict,
    Busy { retry_after_secs: u64 },
    Principal(crate::admission::AdmissionError),
}

impl From<IngestError> for IngestInnerOutcome {
    fn from(error: IngestError) -> Self {
        match error {
            IngestError::Rejected(message) => Self::Rejected(message),
            IngestError::AuthFailed(message) => Self::AuthFailed(message),
            IngestError::Internal(message) => Self::Internal(message),
        }
    }
}

impl From<KeyedHttpError> for IngestInnerOutcome {
    fn from(error: KeyedHttpError) -> Self {
        match error {
            KeyedHttpError::Ingest(error) => Self::from(error),
            KeyedHttpError::Conflict => Self::Conflict,
            KeyedHttpError::Busy { retry_after_secs } => Self::Busy { retry_after_secs },
            KeyedHttpError::Principal(error) => Self::Principal(error),
        }
    }
}

fn keyed_http_error_from_inner(outcome: IngestInnerOutcome) -> KeyedHttpError {
    match outcome {
        IngestInnerOutcome::Rejected(message) => {
            KeyedHttpError::Ingest(IngestError::Rejected(message))
        }
        IngestInnerOutcome::AuthFailed(message) => {
            KeyedHttpError::Ingest(IngestError::AuthFailed(message))
        }
        IngestInnerOutcome::Internal(message) => {
            KeyedHttpError::Ingest(IngestError::Internal(message))
        }
        IngestInnerOutcome::Conflict => KeyedHttpError::Conflict,
        IngestInnerOutcome::Busy { retry_after_secs } => KeyedHttpError::Busy { retry_after_secs },
        IngestInnerOutcome::Principal(error) => KeyedHttpError::Principal(error),
    }
}

fn ingest_error_from_inner(outcome: IngestInnerOutcome) -> IngestError {
    match outcome {
        IngestInnerOutcome::Rejected(message) => IngestError::Rejected(message),
        IngestInnerOutcome::AuthFailed(message) => IngestError::AuthFailed(message),
        IngestInnerOutcome::Internal(message) => IngestError::Internal(message),
        IngestInnerOutcome::Conflict
        | IngestInnerOutcome::Busy { .. }
        | IngestInnerOutcome::Principal(_) => {
            IngestError::Internal("error: internal ingest error".into())
        }
    }
}

/// Explicit keyed persist signal for the HTTP stored-event metric seam.
///
/// Carried from the `KeyedStreamInsert` match to [`ingest_keyed_http_event`]
/// so `buzz_events_stored_total` counts a physical insert only, never a
/// Replay/BoundExisting HTTP-accepted duplicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyedStoredMetric {
    Increment,
    Skip,
}

fn keyed_inserted_stored_metric() -> KeyedStoredMetric {
    KeyedStoredMetric::Increment
}

fn keyed_duplicate_stored_metric() -> KeyedStoredMetric {
    KeyedStoredMetric::Skip
}

fn keyed_http_should_increment_stored(signal: Option<KeyedStoredMetric>) -> bool {
    matches!(signal, Some(KeyedStoredMetric::Increment))
}

fn keyed_accepted_duplicate_result(original_event_id: impl AsRef<[u8]>) -> IngestResult {
    IngestResult {
        event_id: hex::encode(original_event_id),
        accepted: true,
        message: "duplicate:".into(),
    }
}

/// Keyed stored-metric bookkeeping only. Terminal HTTP classification is
/// [`IngestInnerOutcome`]; this signal cannot override the returned outcome.
struct KeyedIngestSignals {
    stored: Option<KeyedStoredMetric>,
}

/// Input-only keyed identity for [`ingest_event_inner`]. `keyed` stays a
/// separate `&mut` so the inner signature stays at seven arguments.
struct IngestInnerKeyedContext<'a> {
    idempotency_key: Option<[u8; 32]>,
    keyed_early: Option<&'a mut KeyedHttpEarlyContext>,
}

const KEYED_STRIPE_COUNT: usize = 1024;
/// Hard cap on concurrent keyed writers. `try_acquire` fail-closes immediately
/// when this many permits are held, so request memory cannot queue without bound.
/// This is the post-admission persist gate. Hashed stripes are best-effort and
/// must not fail closed on unrelated-key collisions; same-key serialization is
/// the DB primary key. Open reservations are bounded separately by
/// [`buzz_db::idempotency::KEYED_RESERVATION_CAPACITY`].
pub(crate) const KEYED_WRITER_WAIT_MAX: usize = 8;
const KEYED_GLOBAL_PERMITS: usize = KEYED_WRITER_WAIT_MAX;
pub(crate) const KEYED_BUSY_RETRY_AFTER_SECS: u64 = 5;

/// Process-global keyed HTTP handler ingress cap. Fail-fast; never queues.
pub(crate) const KEYED_INGRESS_GLOBAL_MAX: usize = 32;
/// Per-authenticated-community ingress cap. Strictly below global and at most
/// half of global so one community cannot occupy every slot.
pub(crate) const KEYED_INGRESS_COMMUNITY_MAX: usize = 16;
pub(crate) const KEYED_EARLY_DEADLINE_SECS: u64 = 5;

const _: () = {
    assert!(KEYED_INGRESS_COMMUNITY_MAX > 0);
    assert!(KEYED_INGRESS_COMMUNITY_MAX < KEYED_INGRESS_GLOBAL_MAX);
    assert!(KEYED_INGRESS_COMMUNITY_MAX * 2 <= KEYED_INGRESS_GLOBAL_MAX);
    assert!(KEYED_INGRESS_GLOBAL_MAX == 32);
    assert!(KEYED_EARLY_DEADLINE_SECS == 5);
};

/// Caller-side wall-clock seconds for principal + paired Redis admission on a
/// keyed persist miss. Runs before reservation capacity or a writer
/// transaction is acquired. Independent of
/// [`buzz_db::idempotency::KEYED_RESERVATION_IDLE_TIMEOUT_SECS`]: this must
/// stay strictly shorter than the idle belt.
pub(crate) const KEYED_RESERVATION_ADMISSION_BUDGET_SECS: u64 = 5;

/// Wall-clock budget for principal + paired Redis admission on a keyed persist
/// miss, before any reservation is opened. Timeout maps to keyed HTTP 503.
/// PostgreSQL `idle_in_transaction_session_timeout` is a longer safety belt
/// for an already-open reservation, not this mapping.
pub(crate) const KEYED_RESERVATION_ADMISSION_BUDGET: Duration =
    Duration::from_secs(KEYED_RESERVATION_ADMISSION_BUDGET_SECS);

/// Caller-side bound for committed classify and begin/reserve.
/// Classify does not hold a reservation; begin does. Complete is not
/// wrapped in an external cancellation deadline: persist statements and
/// post-COMMIT witness recovery are bounded internally. Independent of the
/// idle belt; matches `SET LOCAL statement_timeout = '15s'`.
pub(crate) const KEYED_RESERVATION_PERSIST_BUDGET_SECS: u64 = 15;
pub(crate) const KEYED_RESERVATION_PERSIST_BUDGET: Duration =
    Duration::from_secs(KEYED_RESERVATION_PERSIST_BUDGET_SECS);

const _: () = {
    assert!(
        KEYED_RESERVATION_ADMISSION_BUDGET_SECS
            < buzz_db::idempotency::KEYED_RESERVATION_IDLE_TIMEOUT_SECS
    );
    assert!(
        buzz_db::idempotency::KEYED_RESERVATION_IDLE_TIMEOUT_SECS
            <= KEYED_RESERVATION_PERSIST_BUDGET_SECS
    );
    assert!(
        KEYED_RESERVATION_PERSIST_BUDGET_SECS
            == buzz_db::idempotency::KEYED_RESERVATION_STATEMENT_TIMEOUT_SECS
    );
};

/// Fleet-wide keyed POST /events aggregate. Below the reaper's 1,600/min
/// sustainable delete rate with headroom, and above the documented 600,000/day
/// (~417/min) supported average. One production ceiling, identical on every pod.
pub(crate) const KEYED_EVENTS_FLEET_ADMISSION_PER_MIN: u64 = 1_200;
pub(crate) const KEYED_EVENTS_FLEET_ADMISSION_WINDOW_SECS: u64 = 60;
/// Typed 60-second shared window for persist identity+community+fleet admission.
const KEYED_EVENTS_FLEET_ADMISSION_WINDOW: NonZeroU64 =
    NonZeroU64::MIN.saturating_add(KEYED_EVENTS_FLEET_ADMISSION_WINDOW_SECS - 1);
/// Per-community share of the fleet bucket. Strictly below the aggregate so
/// one tenant cannot exhaust the sentinel and starve every other community.
pub(crate) const KEYED_EVENTS_COMMUNITY_ADMISSION_PER_MIN: u64 = 600;

/// Limited-broadcast IPv4 is never a TCP client source, so this Redis
/// IP-admission bucket cannot collide with a reachable client identity.
pub(crate) const KEYED_EVENTS_FLEET_ADMISSION_SENTINEL: IpAddr = IpAddr::V4(Ipv4Addr::BROADCAST);

/// Tenant-prefixed hierarchical suffix for persist identity and community
/// keys. Identity is the authenticated HTTP principal; community is the
/// reserved persist principal. Fleet remains the operator-global sentinel.
pub(crate) const KEYED_COMMUNITY_ADMISSION_LIMIT_TYPE: LimitType = LimitType::ApiCalls;

/// Protocol-reserved principal for the per-community keyed-events bucket.
/// Not an event author and not used as a real user identity.
pub(crate) fn keyed_community_admission_principal() -> nostr::PublicKey {
    const BYTES: [u8; 32] = {
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        bytes
    };
    nostr::PublicKey::from_byte_array(BYTES)
}

fn keyed_busy_default() -> KeyedHttpError {
    KeyedHttpError::Busy {
        retry_after_secs: KEYED_BUSY_RETRY_AFTER_SECS,
    }
}

pub(crate) fn keyed_http_error_from_fleet(
    error: crate::admission::AdmissionError,
) -> KeyedHttpError {
    match error {
        crate::admission::AdmissionError::Exceeded { reset_in_secs } => KeyedHttpError::Busy {
            retry_after_secs: reset_in_secs,
        },
        crate::admission::AdmissionError::Unavailable => keyed_busy_default(),
    }
}

#[cfg(test)]
pub(crate) async fn enforce_keyed_events_fleet_admission<L: RateLimiter>(
    limiter: &L,
    tenant: &TenantContext,
    principal: &nostr::PublicKey,
    api_calls_per_min: u64,
) -> Result<(), crate::admission::AdmissionError> {
    match limiter
        .check_hierarchical_admission_classified(HierarchicalAdmissionRequest::new(
            tenant,
            principal,
            &keyed_community_admission_principal(),
            KEYED_COMMUNITY_ADMISSION_LIMIT_TYPE,
            KEYED_EVENTS_FLEET_ADMISSION_WINDOW,
            HierarchicalAdmissionLimits::new(
                api_calls_per_min,
                KEYED_EVENTS_COMMUNITY_ADMISSION_PER_MIN,
                KEYED_EVENTS_FLEET_ADMISSION_PER_MIN,
            ),
            &KEYED_EVENTS_FLEET_ADMISSION_SENTINEL,
        ))
        .await
    {
        Ok(HierarchicalAdmissionOutcome::Allowed { .. }) => Ok(()),
        Ok(HierarchicalAdmissionOutcome::IdentityDenied(result)) => {
            Err(crate::admission::AdmissionError::Exceeded {
                reset_in_secs: result.reset_in_secs,
            })
        }
        Ok(
            HierarchicalAdmissionOutcome::CommunityDenied(result)
            | HierarchicalAdmissionOutcome::FleetDenied(result),
        ) => Err(crate::admission::AdmissionError::Exceeded {
            reset_in_secs: result.reset_in_secs,
        }),
        Err(failure) => {
            tracing::warn!(
                class = failure.class().as_str(),
                "shared keyed-event hierarchical persist admission unavailable"
            );
            Err(crate::admission::AdmissionError::Unavailable)
        }
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) async fn maybe_enforce_keyed_events_fleet_admission<L: RateLimiter>(
    limiter: &L,
    tenant: &TenantContext,
    principal: &nostr::PublicKey,
    api_calls_per_min: u64,
    keyed: bool,
) -> Result<(), crate::admission::AdmissionError> {
    if !keyed {
        return Ok(());
    }
    enforce_keyed_events_fleet_admission(limiter, tenant, principal, api_calls_per_min).await
}

/// Absolute five-second early deadline started immediately after authentication.
/// Remaining budget is applied to attempt, replay, validation, committed
/// classification, fresh, and atomic persist. Never reset per await. Never wrap
/// a blocking verification join or a durable DB commit.
#[derive(Clone, Copy, Debug)]
pub(crate) struct KeyedEarlyDeadline {
    start: Instant,
    budget: Duration,
    // Test-only: `expired()` is true while `remaining()` still covers replay
    // I/O, so the pre-spawn verification guard is reachable after parse.
    #[cfg(test)]
    verification_expired: bool,
}

impl KeyedEarlyDeadline {
    pub(crate) fn start() -> Self {
        Self {
            start: Instant::now(),
            budget: Duration::from_secs(KEYED_EARLY_DEADLINE_SECS),
            #[cfg(test)]
            verification_expired: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_budget(budget: Duration) -> Self {
        Self {
            start: Instant::now(),
            budget,
            verification_expired: false,
        }
    }

    /// Already-expired for the pre-spawn verification guard while replay still
    /// observes a live remaining budget. Membership and owner selection run
    /// only after signature verification and authenticated-author binding.
    #[cfg(test)]
    pub(crate) fn already_expired() -> Self {
        Self {
            start: Instant::now(),
            budget: Duration::from_secs(KEYED_EARLY_DEADLINE_SECS),
            verification_expired: true,
        }
    }

    #[cfg(test)]
    pub(crate) fn same_absolute_clock(self, other: Self) -> bool {
        self.start == other.start && self.budget == other.budget
    }

    pub(crate) fn remaining(self) -> Duration {
        self.budget.saturating_sub(self.start.elapsed())
    }

    pub(crate) fn expired(self) -> bool {
        #[cfg(test)]
        if self.verification_expired {
            return true;
        }
        self.remaining().is_zero()
    }

    #[cfg(test)]
    pub(crate) async fn run<T, E, F>(self, fut: F) -> Result<T, E>
    where
        F: Future<Output = Result<T, E>>,
        E: From<KeyedHttpError>,
    {
        let remaining = self.remaining();
        if remaining.is_zero() {
            return Err(E::from(keyed_busy_default()));
        }
        match tokio::time::timeout(remaining, fut).await {
            Ok(result) => result,
            Err(_elapsed) => Err(E::from(keyed_busy_default())),
        }
    }
}

/// Apply the remaining absolute early deadline to a cancellation-safe I/O
/// await. Unkeyed callers pass `None` and are unchanged. Timeout maps to the
/// existing keyed busy/503 contract. The inner result is returned untouched
/// so a DB/auth error is not rewritten as busy.
async fn keyed_early_io<T, F>(
    early: Option<&KeyedHttpEarlyContext>,
    fut: F,
) -> Result<T, KeyedHttpError>
where
    F: Future<Output = T>,
{
    match early {
        None => Ok(fut.await),
        Some(early) => {
            let remaining = early.deadline.remaining();
            if remaining.is_zero() {
                return Err(keyed_busy_default());
            }
            match tokio::time::timeout(remaining, fut).await {
                Ok(value) => Ok(value),
                Err(_elapsed) => Err(keyed_busy_default()),
            }
        }
    }
}

struct KeyedCommunityIngressEntry {
    semaphore: Arc<Semaphore>,
    live_handles: usize,
}

struct KeyedCommunityIngressHandle {
    community: Uuid,
    semaphore: Arc<Semaphore>,
}

impl fmt::Debug for KeyedCommunityIngressHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyedCommunityIngressHandle")
            .field("community", &self.community)
            .field("available_permits", &self.semaphore.available_permits())
            .finish()
    }
}

impl Drop for KeyedCommunityIngressHandle {
    fn drop(&mut self) {
        release_keyed_community_ingress_handle(self.community, &self.semaphore);
    }
}

/// Fail-fast RAII global 32 + community 16 ingress permits. Dropping releases
/// both permits and reclaims an idle community registry entry. Field-take Drop
/// keeps release order independent of layout: community permit, global permit,
/// then registry handle.
pub(crate) struct KeyedIngressGuard {
    community: Option<tokio::sync::OwnedSemaphorePermit>,
    global: Option<SemaphorePermit<'static>>,
    handle: Option<KeyedCommunityIngressHandle>,
}

impl fmt::Debug for KeyedIngressGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyedIngressGuard")
            .field("community_held", &self.community.is_some())
            .field("global_held", &self.global.is_some())
            .field("handle", &self.handle)
            .finish()
    }
}

impl Drop for KeyedIngressGuard {
    fn drop(&mut self) {
        drop(self.community.take());
        drop(self.global.take());
        drop(self.handle.take());
    }
}

fn keyed_ingress_global() -> &'static Semaphore {
    static SEM: OnceLock<Semaphore> = OnceLock::new();
    SEM.get_or_init(|| Semaphore::new(KEYED_INGRESS_GLOBAL_MAX))
}

fn keyed_community_ingress_registry() -> &'static Mutex<HashMap<Uuid, KeyedCommunityIngressEntry>> {
    static REG: OnceLock<Mutex<HashMap<Uuid, KeyedCommunityIngressEntry>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_keyed_community_ingress_registry(
) -> std::sync::MutexGuard<'static, HashMap<Uuid, KeyedCommunityIngressEntry>> {
    keyed_community_ingress_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn checkout_keyed_community_ingress_handle(
    community: Uuid,
) -> Result<KeyedCommunityIngressHandle, KeyedHttpError> {
    let mut tenants = lock_keyed_community_ingress_registry();
    let entry = tenants
        .entry(community)
        .or_insert_with(|| KeyedCommunityIngressEntry {
            semaphore: Arc::new(Semaphore::new(KEYED_INGRESS_COMMUNITY_MAX)),
            live_handles: 0,
        });
    entry.live_handles = entry
        .live_handles
        .checked_add(1)
        .ok_or_else(keyed_busy_default)?;
    Ok(KeyedCommunityIngressHandle {
        community,
        semaphore: Arc::clone(&entry.semaphore),
    })
}

fn release_keyed_community_ingress_handle(community: Uuid, expected: &Arc<Semaphore>) {
    let mut tenants = lock_keyed_community_ingress_registry();
    let Some(entry) = tenants.get_mut(&community) else {
        return;
    };
    if !Arc::ptr_eq(&entry.semaphore, expected) {
        return;
    }
    let Some(live_handles) = entry.live_handles.checked_sub(1) else {
        return;
    };
    entry.live_handles = live_handles;
    if entry.live_handles != 0 {
        return;
    }
    if expected.available_permits() < KEYED_INGRESS_COMMUNITY_MAX {
        return;
    }
    tenants.remove(&community);
}

/// Acquire fail-fast global and community ingress. Never queues waiters.
pub(crate) fn try_acquire_keyed_ingress(
    community: Uuid,
) -> Result<KeyedIngressGuard, KeyedHttpError> {
    let handle = checkout_keyed_community_ingress_handle(community)?;
    let community_permit = match Arc::clone(&handle.semaphore).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return Err(keyed_busy_default()),
    };
    match keyed_ingress_global().try_acquire() {
        Ok(global) => Ok(KeyedIngressGuard {
            community: Some(community_permit),
            global: Some(global),
            handle: Some(handle),
        }),
        Err(_) => Err(keyed_busy_default()),
    }
}

pub(crate) struct KeyedHttpEarlyContext {
    pub ingress: Option<KeyedIngressGuard>,
    pub deadline: KeyedEarlyDeadline,
    pub verified_owner: Option<nostr::PublicKey>,
}

impl KeyedHttpEarlyContext {
    fn release_ingress(&mut self) {
        drop(self.ingress.take());
    }
}

#[cfg(test)]
fn keyed_ingress_global_available() -> usize {
    keyed_ingress_global().available_permits()
}

#[cfg(test)]
fn keyed_ingress_registry_len() -> usize {
    lock_keyed_community_ingress_registry().len()
}

#[cfg(test)]
fn keyed_ingress_registry_contains(community: Uuid) -> bool {
    lock_keyed_community_ingress_registry().contains_key(&community)
}

#[cfg(test)]
fn keyed_ingress_live_handles(community: Uuid) -> Option<usize> {
    lock_keyed_community_ingress_registry()
        .get(&community)
        .map(|entry| entry.live_handles)
}

#[cfg(test)]
fn keyed_ingress_test_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

#[cfg(test)]
pub(crate) fn lock_keyed_ingress_tests() -> tokio::sync::MutexGuard<'static, ()> {
    keyed_ingress_test_lock().blocking_lock()
}

#[cfg(test)]
pub(crate) async fn lock_keyed_ingress_tests_async() -> tokio::sync::MutexGuard<'static, ()> {
    keyed_ingress_test_lock().lock().await
}

#[cfg(test)]
pub(crate) struct KeyedVerifyWatch {
    event_id: nostr::EventId,
    in_flight: std::sync::atomic::AtomicUsize,
    release: std::sync::atomic::AtomicBool,
    panic: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
fn keyed_verify_watcher() -> &'static Mutex<Option<Arc<KeyedVerifyWatch>>> {
    static WATCH: OnceLock<Mutex<Option<Arc<KeyedVerifyWatch>>>> = OnceLock::new();
    WATCH.get_or_init(|| Mutex::new(None))
}

#[cfg(test)]
fn snapshot_keyed_verify_watch(event_id: &nostr::EventId) -> Option<Arc<KeyedVerifyWatch>> {
    let slot = keyed_verify_watcher()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    slot.as_ref().and_then(|watch| {
        if watch.event_id == *event_id {
            Some(Arc::clone(watch))
        } else {
            None
        }
    })
}

#[cfg(test)]
pub(crate) struct KeyedVerifyWatchGuard {
    watch: Arc<KeyedVerifyWatch>,
    join: Option<std::thread::JoinHandle<Result<Event, IngestError>>>,
}

#[cfg(test)]
pub(crate) fn install_keyed_verify_watch(event_id: nostr::EventId) -> KeyedVerifyWatchGuard {
    let watch = Arc::new(KeyedVerifyWatch {
        event_id,
        in_flight: std::sync::atomic::AtomicUsize::new(0),
        release: std::sync::atomic::AtomicBool::new(true),
        panic: std::sync::atomic::AtomicBool::new(false),
    });
    {
        let mut slot = keyed_verify_watcher()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *slot = Some(Arc::clone(&watch));
    }
    KeyedVerifyWatchGuard { watch, join: None }
}

#[cfg(test)]
impl KeyedVerifyWatchGuard {
    pub(crate) fn hold(&self) {
        self.watch
            .release
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) fn release(&self) {
        self.watch
            .release
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) fn arm_panic(&self) {
        self.watch
            .panic
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) fn in_flight(&self) -> usize {
        self.watch
            .in_flight
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn spawn_joined_verify(&mut self, event: Event) {
        self.join = Some(std::thread::spawn(move || keyed_verify_event_joined(event)));
    }

    fn join_verify(&mut self) -> Result<Event, IngestError> {
        self.join
            .take()
            .expect("joined worker")
            .join()
            .expect("verification thread")
    }
}

#[cfg(test)]
impl Drop for KeyedVerifyWatchGuard {
    fn drop(&mut self) {
        self.watch
            .release
            .store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        let mut slot = keyed_verify_watcher()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if slot
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &self.watch))
        {
            *slot = None;
        }
    }
}

fn keyed_verify_event_joined(event: Event) -> Result<Event, IngestError> {
    #[cfg(test)]
    let matched = snapshot_keyed_verify_watch(&event.id);
    #[cfg(test)]
    struct MatchedInFlight(Option<Arc<KeyedVerifyWatch>>);
    #[cfg(test)]
    impl Drop for MatchedInFlight {
        fn drop(&mut self) {
            if let Some(watch) = &self.0 {
                watch
                    .in_flight
                    .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
    }
    #[cfg(test)]
    let _inflight = match &matched {
        Some(watch) => {
            watch
                .in_flight
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            MatchedInFlight(Some(Arc::clone(watch)))
        }
        None => MatchedInFlight(None),
    };
    #[cfg(test)]
    if let Some(watch) = &matched {
        if watch.panic.load(std::sync::atomic::Ordering::SeqCst) {
            panic!("keyed verify test panic");
        }
        while !watch.release.load(std::sync::atomic::Ordering::SeqCst) {
            std::thread::yield_now();
        }
    }
    match verify_event(&event) {
        Ok(()) => Ok(event),
        Err(e) => Err(IngestError::Rejected(format!("invalid: {e}"))),
    }
}

fn keyed_stripes() -> &'static [Semaphore] {
    static STRIPES: OnceLock<Vec<Semaphore>> = OnceLock::new();
    STRIPES.get_or_init(|| (0..KEYED_STRIPE_COUNT).map(|_| Semaphore::new(1)).collect())
}

fn keyed_global() -> &'static Semaphore {
    static GLOBAL: OnceLock<Semaphore> = OnceLock::new();
    GLOBAL.get_or_init(|| Semaphore::new(KEYED_GLOBAL_PERMITS))
}

fn keyed_stripe_index(community: Uuid, author: &[u8; 32], key: &[u8; 32]) -> usize {
    static HASHER: OnceLock<std::collections::hash_map::RandomState> = OnceLock::new();
    let mut hasher = HASHER
        .get_or_init(std::collections::hash_map::RandomState::new)
        .build_hasher();
    community.hash(&mut hasher);
    author.hash(&mut hasher);
    key.hash(&mut hasher);
    (hasher.finish() as usize) % KEYED_STRIPE_COUNT
}

struct KeyedWriterPermits {
    _stripe: Option<SemaphorePermit<'static>>,
    _global: SemaphorePermit<'static>,
}

fn acquire_keyed_writer_permits(
    community: Uuid,
    author: &[u8; 32],
    key: &[u8; 32],
) -> Result<KeyedWriterPermits, KeyedHttpError> {
    let index = keyed_stripe_index(community, author, key);
    // Same-key serialization is the DB primary key. A hashed stripe is only a
    // best-effort local hint: an unrelated-key collision must not abort a
    // valid reservation or synthesize 503.
    let stripe = keyed_stripes()[index].try_acquire().ok();
    let global = keyed_global()
        .try_acquire()
        .map_err(|_| keyed_busy_default())?;
    Ok(KeyedWriterPermits {
        _stripe: stripe,
        _global: global,
    })
}

/// Test-only RAII guard that holds every keyed writer permit so a concurrent
/// keyed persist fails closed as Busy. Permits are released on drop, including
/// panic unwind. Compiles out of production.
#[cfg(test)]
pub(crate) struct KeyedWriterCapacityGuard {
    _permits: Vec<SemaphorePermit<'static>>,
}

#[cfg(test)]
impl KeyedWriterCapacityGuard {
    #[must_use]
    pub(crate) fn hold_all() -> Self {
        let mut permits = Vec::with_capacity(KEYED_GLOBAL_PERMITS);
        for _ in 0..KEYED_GLOBAL_PERMITS {
            permits.push(
                keyed_global()
                    .try_acquire()
                    .expect("test must fill the keyed writer gate"),
            );
        }
        Self { _permits: permits }
    }
}

/// Persist plus lost-COMMIT-ack recovery. Internally bounded by statement
/// timeout and the witness-lookup timeout; never wrapped in an external
/// cancellation deadline that can return 503 after a durable commit.
async fn complete_keyed_reservation(
    reservation: buzz_db::KeyedReservation,
    prepared: &PreparedKeyedIntent,
    event: &Event,
    thread_meta: Option<buzz_db::event::ThreadMetadataParams<'_>>,
) -> Result<buzz_db::KeyedStreamInsert, buzz_db::DbError> {
    reservation.complete(prepared, event, thread_meta).await
}

#[cfg(test)]
async fn keyed_await_admission_for<T, F>(budget: Duration, fut: F) -> Result<T, KeyedHttpError>
where
    F: Future<Output = Result<T, KeyedHttpError>>,
{
    match tokio::time::timeout(budget, fut).await {
        Ok(result) => result,
        Err(_elapsed) => Err(keyed_busy_default()),
    }
}

/// Atomic persist identity+community+fleet admission for a keyed persist miss.
/// Must not run while a PostgreSQL transaction, writer-pool connection, or
/// reservation capacity permit is held. Identity denial maps to the established
/// 429 principal contract; community/fleet denial and backend unavailability
/// map to keyed 503. The caller applies the remaining early deadline.
async fn admit_keyed_persist_miss<L: RateLimiter>(
    limiter: &L,
    tenant: &TenantContext,
    principal: &nostr::PublicKey,
    api_calls_per_min: u64,
) -> Result<(), KeyedHttpError> {
    match limiter
        .check_hierarchical_admission_classified(HierarchicalAdmissionRequest::new(
            tenant,
            principal,
            &keyed_community_admission_principal(),
            KEYED_COMMUNITY_ADMISSION_LIMIT_TYPE,
            KEYED_EVENTS_FLEET_ADMISSION_WINDOW,
            HierarchicalAdmissionLimits::new(
                api_calls_per_min,
                KEYED_EVENTS_COMMUNITY_ADMISSION_PER_MIN,
                KEYED_EVENTS_FLEET_ADMISSION_PER_MIN,
            ),
            &KEYED_EVENTS_FLEET_ADMISSION_SENTINEL,
        ))
        .await
    {
        Ok(HierarchicalAdmissionOutcome::Allowed { .. }) => Ok(()),
        Ok(HierarchicalAdmissionOutcome::IdentityDenied(result)) => Err(KeyedHttpError::Principal(
            crate::admission::AdmissionError::Exceeded {
                reset_in_secs: result.reset_in_secs,
            },
        )),
        Ok(
            HierarchicalAdmissionOutcome::CommunityDenied(result)
            | HierarchicalAdmissionOutcome::FleetDenied(result),
        ) => Err(keyed_http_error_from_fleet(
            crate::admission::AdmissionError::Exceeded {
                reset_in_secs: result.reset_in_secs,
            },
        )),
        Err(failure) => {
            tracing::warn!(
                class = failure.class().as_str(),
                "shared keyed-event hierarchical persist admission unavailable"
            );
            Err(keyed_http_error_from_fleet(
                crate::admission::AdmissionError::Unavailable,
            ))
        }
    }
}

/// Committed replay/conflict skip fresh and persist admission. A committed miss
/// runs fresh then [`admit_keyed_persist_miss`] and returns `Ok(None)` so the
/// caller can open the authoritative reservation afterward.
async fn finish_keyed_committed_classify<L: RateLimiter>(
    committed: Option<buzz_db::idempotency::KeyedCommittedOutcome>,
    limiter: &L,
    tenant: &TenantContext,
    principal: &nostr::PublicKey,
    api_calls_per_min: u64,
) -> Result<Option<buzz_db::idempotency::KeyedCommittedOutcome>, KeyedHttpError> {
    match committed {
        Some(hit) => Ok(Some(hit)),
        None => {
            crate::admission::check_keyed_http_fresh_admission(limiter, tenant, principal)
                .await
                .map_err(keyed_http_error_from_fleet)?;
            admit_keyed_persist_miss(limiter, tenant, principal, api_calls_per_min).await?;
            Ok(None)
        }
    }
}

const KEYED_RESERVATION_ABORT_FAILURES_TOTAL: &str = "buzz_keyed_reservation_abort_failures_total";

fn classify_keyed_reservation_abort_sqlstate(code: Option<&str>) -> &'static str {
    match code {
        Some("55P03") => "lock_not_available",
        Some("57014") => "statement_canceled",
        Some("25P03") => "idle_in_transaction_timeout",
        _ => "sqlx_other",
    }
}

fn classify_keyed_reservation_abort_db_error(error: &buzz_db::DbError) -> &'static str {
    if error.is_idempotency_unavailable() {
        return "idempotency_unavailable";
    }
    match error {
        buzz_db::DbError::Sqlx(sqlx::Error::PoolTimedOut) => "pool_timeout",
        buzz_db::DbError::Sqlx(sqlx::Error::Database(database)) => {
            classify_keyed_reservation_abort_sqlstate(database.code().as_deref())
        }
        buzz_db::DbError::Sqlx(_) => "sqlx_other",
        _ => "database_other",
    }
}

fn record_keyed_reservation_abort_failure(class: &'static str) {
    warn!(class, "keyed reservation abort failed");
    metrics::counter!(KEYED_RESERVATION_ABORT_FAILURES_TOTAL, "class" => class).increment(1);
}

fn finish_keyed_reservation_abort<T, TE>(
    outcome: Result<Result<(), buzz_db::DbError>, TE>,
    passthrough: T,
) -> T {
    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            record_keyed_reservation_abort_failure(classify_keyed_reservation_abort_db_error(
                &error,
            ));
        }
        Err(_) => record_keyed_reservation_abort_failure("deadline_timeout"),
    }
    passthrough
}

async fn abort_keyed_reservation(reservation: buzz_db::KeyedReservation) {
    let outcome = tokio::time::timeout(KEYED_RESERVATION_PERSIST_BUDGET, reservation.abort()).await;
    finish_keyed_reservation_abort(outcome, ());
}

/// Map the durable community write-fence lookup onto the ingest error taxonomy.
///
/// An inactive community is an authorization decision and keeps the exact
/// `restricted:` wire text the ephemeral path uses. A lookup outage is a
/// server fault and fails closed as `error:`/500 — a Postgres blip can
/// neither admit a write past the fence nor read as a client mistake.
fn map_serving_fence_state(active: Result<bool, buzz_db::DbError>) -> Result<(), IngestError> {
    match active {
        Ok(true) => Ok(()),
        Ok(false) => Err(IngestError::Rejected(
            "restricted: community writes are fenced".into(),
        )),
        Err(error) => Err(IngestError::Internal(format!(
            "error: checking community write fence: {error}"
        ))),
    }
}

fn map_relay_admin_error(error: super::relay_admin::RelayAdminError) -> IngestError {
    use super::relay_admin::RelayAdminError;
    match error {
        // Same wire prefix and HTTP status (403) as every other durable
        // restriction refusal — see the write-path gate below and `auth.rs`.
        RelayAdminError::Banned => {
            IngestError::AuthFailed("blocked: you are banned from this community".to_string())
        }
        RelayAdminError::Rejected(reason) => IngestError::Rejected(format!("invalid: {reason}")),
        RelayAdminError::Internal(reason) => IngestError::Internal(format!("error: {reason}")),
    }
}

fn map_push_accept_error(error: super::push_lease::AcceptError) -> IngestError {
    match error {
        super::push_lease::AcceptError::Validation(reason) => {
            IngestError::Rejected(format!("invalid: {reason}"))
        }
        super::push_lease::AcceptError::Internal(reason) => IngestError::Internal(reason),
    }
}

/// Determine the required scope for a given event kind.
///
/// Returns `Err` for unknown kinds — the relay rejects them.
fn required_scope_for_kind(kind: u32, event: &Event) -> Result<Scope, &'static str> {
    match kind {
        KIND_PROFILE => Ok(Scope::UsersWrite),
        KIND_TEXT_NOTE | KIND_LONG_FORM => Ok(Scope::MessagesWrite),
        KIND_CONTACT_LIST | KIND_READ_STATE | KIND_USER_STATUS | KIND_AGENT_ENGRAM
        | KIND_EVENT_REMINDER | KIND_PERSONA | KIND_TEAM | KIND_MANAGED_AGENT
        | KIND_PRIVATE_MANAGED_AGENT | KIND_TEAM_CATALOG | super::push_lease::KIND_PUSH_LEASE => {
            Ok(Scope::UsersWrite)
        }
        // NIP-AM: agent turn metrics are agent-authored global events (encrypted to owner).
        KIND_AGENT_TURN_METRIC => Ok(Scope::MessagesWrite),
        // NIP-56 reports are ordinary member writes into the mod-only queue.
        // Ingest persists them to `moderation_reports` and suppresses public
        // storage/fanout; reports are signals, never enforcement triggers.
        KIND_REPORT | KIND_PRODUCT_FEEDBACK => Ok(Scope::MessagesWrite),
        // Community moderation commands are direct, mod-authz-gated writes.
        // Scope only proves the transport can submit message writes; the
        // command handler owns role/capability authorization.
        k if buzz_core::kind::is_moderation_command_kind(k) => Ok(Scope::MessagesWrite),
        // NIP-51 standard lists and NIP-65 relay list — user-owned global state,
        // same ownership shape as kind:3 (contacts) and kind:0 (profile).
        KIND_MUTE_LIST
        | KIND_PIN_LIST
        | KIND_NIP65_RELAY_LIST_METADATA
        | KIND_BOOKMARK_LIST
        | KIND_FOLLOW_SET
        | KIND_BOOKMARK_SET
        // NIP-30/NIP-51: per-user custom emoji set (30030) and emoji list (10030).
        // User-owned global state, keyed by (pubkey, kind[, d_tag]); the workspace
        // palette is the client-side union of every member's own set.
        | KIND_EMOJI_SET
        | KIND_EMOJI_LIST
        | KIND_AGENT_PROFILE => Ok(Scope::UsersWrite),
        KIND_DELETION
        | KIND_REACTION
        | KIND_GIFT_WRAP
        | KIND_STREAM_MESSAGE
        | KIND_STREAM_MESSAGE_V2
        | KIND_NIP29_DELETE_EVENT
        | KIND_STREAM_MESSAGE_EDIT
        | KIND_STREAM_MESSAGE_PINNED
        | KIND_STREAM_MESSAGE_BOOKMARKED
        | KIND_STREAM_MESSAGE_SCHEDULED
        | KIND_STREAM_REMINDER
        | KIND_STREAM_MESSAGE_DIFF
        | KIND_FORUM_POST
        | KIND_FORUM_VOTE
        | KIND_FORUM_COMMENT => Ok(Scope::MessagesWrite),
        KIND_NIP29_PUT_USER | KIND_NIP29_REMOVE_USER | KIND_NIP29_DELETE_GROUP => {
            Ok(Scope::AdminChannels)
        }
        // NIP-43: relay membership admin commands (9030–9032) + Buzz
        // workspace-profile command (9033).
        k if k == RELAY_ADMIN_ADD_MEMBER
            || k == RELAY_ADMIN_REMOVE_MEMBER
            || k == RELAY_ADMIN_CHANGE_ROLE
            || k == RELAY_ADMIN_SET_WORKSPACE_PROFILE =>
        {
            Ok(Scope::AdminUsers)
        }
        // NIP-IA: identity archive/unarchive requests (9035/9036).
        // Scope is intentionally UsersWrite, not AdminUsers: NIP-IA's self and
        // owner-of-agent paths are open to ordinary users (a user retiring their
        // own key, or an owner archiving their agent). Real authorization is the
        // consent-path check inside handle_identity_archive_event — the relay
        // verifies self / admin-role / owner-via-live-kind:0 there. This gate
        // only ensures the actor can write user-scoped state, which any
        // profile-publishing user already holds.
        KIND_IA_ARCHIVE_REQUEST | KIND_IA_UNARCHIVE_REQUEST => Ok(Scope::UsersWrite),
        KIND_NIP29_EDIT_METADATA => {
            // kind:9002 scope split: archived tag → AdminChannels, else ChannelsWrite
            let has_archived = event
                .tags
                .iter()
                .any(|t| t.kind().to_string() == "archived");
            if has_archived {
                Ok(Scope::AdminChannels)
            } else {
                Ok(Scope::ChannelsWrite)
            }
        }
        KIND_NIP29_CREATE_GROUP | KIND_CANVAS => Ok(Scope::ChannelsWrite),
        KIND_NIP29_JOIN_REQUEST | KIND_NIP29_LEAVE_REQUEST | KIND_NIP43_LEAVE_REQUEST => {
            Ok(Scope::ChannelsRead)
        }
        // Huddle lifecycle events + guidelines
        KIND_HUDDLE_STARTED
        | KIND_HUDDLE_PARTICIPANT_JOINED
        | KIND_HUDDLE_PARTICIPANT_LEFT
        | KIND_HUDDLE_ENDED
        | KIND_HUDDLE_GUIDELINES => Ok(Scope::ChannelsWrite),
        // NIP-34: Git repository events
        KIND_GIT_REPO_ANNOUNCEMENT | KIND_GIT_REPO_STATE => Ok(Scope::ReposWrite),
        // NIP-MP: a project is repository metadata — grouping repositories needs
        // the same scope as announcing them.
        KIND_PROJECT => Ok(Scope::ReposWrite),
        KIND_GIT_PATCH
        | KIND_GIT_PULL_REQUEST
        | KIND_GIT_PR_UPDATE
        | KIND_GIT_ISSUE
        | KIND_GIT_STATUS_OPEN
        | KIND_GIT_STATUS_MERGED
        | KIND_GIT_STATUS_CLOSED
        | KIND_GIT_STATUS_DRAFT => Ok(Scope::MessagesWrite),
        // Command kinds — DM management, workflows, approvals
        KIND_DM_OPEN | KIND_DM_ADD_MEMBER | KIND_DM_HIDE => Ok(Scope::MessagesWrite),
        KIND_WORKFLOW_DEF | KIND_WORKFLOW_TRIGGER => Ok(Scope::MessagesWrite),
        KIND_APPROVAL_GRANT | KIND_APPROVAL_DENY => Ok(Scope::MessagesWrite),
        _ => Err("restricted: unknown event kind"),
    }
}

/// Extract a channel UUID from the `"h"` NIP-29 group tag.
pub(crate) fn extract_channel_id(event: &Event) -> Option<Uuid> {
    for tag in event.tags.iter() {
        if tag.kind().to_string() == "h" {
            if let Some(val) = tag.content() {
                if let Ok(id) = val.parse::<Uuid>() {
                    return Some(id);
                }
            }
        }
    }
    None
}

/// Result of resolving a reaction's target channel.
pub(crate) enum ReactionChannelResult {
    Channel(Uuid),
    NoChannel,
    NotFound,
    NoTarget,
    DbError(String),
}

/// Derive channel_id from the target event for NIP-25 reactions.
pub(crate) async fn derive_reaction_channel(
    community_id: CommunityId,
    db: &buzz_db::Db,
    event: &Event,
) -> ReactionChannelResult {
    let target_hex = match event.tags.iter().rev().find_map(|tag| {
        if tag.kind().to_string() == "e" {
            tag.content().and_then(|v| {
                if v.len() == 64 && v.chars().all(|c| c.is_ascii_hexdigit()) {
                    Some(v.to_string())
                } else {
                    None
                }
            })
        } else {
            None
        }
    }) {
        Some(h) => h,
        None => return ReactionChannelResult::NoTarget,
    };

    let id_bytes = match hex::decode(&target_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return ReactionChannelResult::NoTarget,
    };

    match db
        .get_event_by_id_for_event_write(community_id, &id_bytes)
        .await
    {
        Ok(Some(target)) => match target.channel_id {
            Some(ch_id) => ReactionChannelResult::Channel(ch_id),
            None => ReactionChannelResult::NoChannel,
        },
        Ok(None) => ReactionChannelResult::NotFound,
        Err(e) => ReactionChannelResult::DbError(e.to_string()),
    }
}

/// Kinds that are always global (`channel_id = NULL`).
///
/// If a client includes a stray `h` tag on these kinds, the ingest pipeline
/// sets `channel_id = None` — these events are never channel-scoped.
///
/// Note: the raw `h` tag remains on the stored event (Nostr events are signed,
/// so tags cannot be stripped without invalidating the signature). The read-path
/// filter matching in `filter.rs` treats explicit `h` tags as authoritative,
/// which means a stray `h` tag can still match `#h` queries. This is a known
/// limitation affecting all global-only kinds and should be addressed in the
/// filter layer as a follow-up.
pub(crate) fn is_global_only_kind(kind: u32) -> bool {
    matches!(
        kind,
        KIND_PROFILE
            | KIND_TEXT_NOTE
            | KIND_CONTACT_LIST
            | KIND_LONG_FORM
            | KIND_USER_STATUS
            | KIND_READ_STATE
            // NIP-51 standard lists + sets and NIP-65 relay list — user-owned global state.
            // Same as kind:3 (contacts): keyed by (pubkey, kind) or (pubkey, kind, d_tag),
            // never channel-scoped. A stray `h` tag must not channel-scope them.
            | KIND_MUTE_LIST
            | KIND_PIN_LIST
            | KIND_NIP65_RELAY_LIST_METADATA
            | KIND_BOOKMARK_LIST
            | KIND_FOLLOW_SET
            | KIND_BOOKMARK_SET
            // NIP-30 custom emoji set (30030) + emoji list (10030): user-owned,
            // keyed by (pubkey, kind[, d_tag]). A stray `h` tag must not channel-scope them.
            | KIND_EMOJI_SET
            | KIND_EMOJI_LIST
            // NIP-AE agent engrams are addressed by (pubkey_a, kind, d_tag); never channel-scoped.
            | KIND_AGENT_ENGRAM
            // NIP-ER event reminders are addressed by (pubkey, kind, d_tag); never channel-scoped.
            | KIND_EVENT_REMINDER
            // Agent profile (10100): user-owned replaceable, keyed by pubkey.
            | KIND_AGENT_PROFILE
            // NIP-AP: persona definitions (30175): owner-authored, keyed by (pubkey, kind, d_tag).
            | KIND_PERSONA
            // NIP-AP: team (30176) + managed-agent (30177) definitions and the
            // team-catalog projection (30178): owner-authored, keyed by
            // (pubkey, kind, d_tag). A stray `h` tag must not channel-scope them.
            | KIND_TEAM
            | KIND_MANAGED_AGENT
            | KIND_PRIVATE_MANAGED_AGENT
            | KIND_TEAM_CATALOG
            // NIP-34: git events use `a` tags (repo reference), not `h` tags (channel scope).
            // Parameterized replaceable kinds are keyed by (pubkey, kind, d_tag).
            | KIND_GIT_REPO_ANNOUNCEMENT
            | KIND_GIT_REPO_STATE
            | KIND_GIT_PATCH
            | KIND_GIT_PULL_REQUEST
            | KIND_GIT_PR_UPDATE
            | KIND_GIT_ISSUE
            | KIND_GIT_STATUS_OPEN
            | KIND_GIT_STATUS_MERGED
            | KIND_GIT_STATUS_CLOSED
            | KIND_GIT_STATUS_DRAFT
            // NIP-MP: projects are addressed by (pubkey, kind, d_tag). The
            // `buzz-channel` tag is a metadata reference, not a routing directive,
            // so a project's state is never channel-scoped.
            | KIND_PROJECT
            // Community moderation commands (9040–9044): community-global
            // direct commands, same model as the NIP-43 9030-series. A stray
            // `h` tag must never channel-scope them (pinned contract —
            // handlers/moderation_commands.rs routing docs).
            | KIND_MODERATION_BAN
            | KIND_MODERATION_UNBAN
            | KIND_MODERATION_TIMEOUT
            | KIND_MODERATION_UNTIMEOUT
            | KIND_MODERATION_RESOLVE_REPORT
            // NIP-43: relay admin commands and leave requests are global — they
            // must never be channel-scoped, even if the event carries a stray `h` tag.
            | RELAY_ADMIN_ADD_MEMBER
            | RELAY_ADMIN_REMOVE_MEMBER
            | RELAY_ADMIN_CHANGE_ROLE
            | RELAY_ADMIN_SET_WORKSPACE_PROFILE
            | KIND_NIP43_LEAVE_REQUEST
            // NIP-IA: identity archive/unarchive requests drive relay-global
            // archive state (8002/8003/13535) and are audited as global request
            // events. A stray `h` tag must not channel-scope them.
            | KIND_IA_ARCHIVE_REQUEST
            | KIND_IA_UNARCHIVE_REQUEST
            // NIP-AM: agent turn metrics are owner-scoped global events.
            // Channel identity is encrypted inside the payload — no `h` tag.
            | KIND_AGENT_TURN_METRIC
            // NIP-PL leases are author-owned, addressable global state.
            | super::push_lease::KIND_PUSH_LEASE
    )
}

/// Kinds that require an `h` tag for channel scoping.
pub(crate) fn requires_h_channel_scope(kind: u32) -> bool {
    matches!(
        kind,
        KIND_STREAM_MESSAGE
            | KIND_STREAM_MESSAGE_V2
            | KIND_STREAM_MESSAGE_EDIT
            | KIND_STREAM_MESSAGE_PINNED
            | KIND_STREAM_MESSAGE_BOOKMARKED
            | KIND_STREAM_MESSAGE_SCHEDULED
            | KIND_STREAM_REMINDER
            | KIND_STREAM_MESSAGE_DIFF
            | KIND_CANVAS
            | KIND_FORUM_POST
            | KIND_FORUM_VOTE
            | KIND_FORUM_COMMENT
            // NIP-29 admin kinds (except CREATE_GROUP which creates the channel)
            | KIND_NIP29_PUT_USER
            | KIND_NIP29_REMOVE_USER
            | KIND_NIP29_EDIT_METADATA
            | KIND_NIP29_DELETE_EVENT
            | KIND_NIP29_DELETE_GROUP
            | KIND_NIP29_LEAVE_REQUEST
            // Huddle lifecycle events + guidelines
            | KIND_HUDDLE_STARTED
            | KIND_HUDDLE_PARTICIPANT_JOINED
            | KIND_HUDDLE_PARTICIPANT_LEFT
            | KIND_HUDDLE_ENDED
            | KIND_HUDDLE_GUIDELINES
    )
}

/// Check channel membership: member OR open-visibility channel.
///
/// `channel` is the request's already-fetched channel row, when the caller has
/// one (E1 within-request threading; correctness ruling §4.8). Callers without
/// a row pass `None` and the open-visibility fallback reads the DB directly.
///
/// Returns `Ok(())` if allowed, `Err(reason)` if denied.
pub(crate) async fn check_channel_membership(
    tenant: &TenantContext,
    state: &AppState,
    ch_id: Uuid,
    pubkey_bytes: &[u8],
    channel: Option<&buzz_db::channel::ChannelRecord>,
) -> Result<(), String> {
    match state
        .is_member_cached(tenant.community(), ch_id, pubkey_bytes)
        .await
    {
        Ok(true) => return Ok(()),
        Ok(false) => {}
        Err(e) => return Err(format!("error: database error: {e}")),
    }
    // Not a member — check if channel is open.
    let is_open = match channel {
        Some(ch) => ch.visibility == "open",
        None => state
            .db
            .get_channel_for_event_write(tenant.community(), ch_id)
            .await
            .map(|ch| ch.visibility == "open")
            .unwrap_or(false),
    };
    if is_open {
        Ok(())
    } else {
        Err("restricted: not a channel member".to_string())
    }
}

fn check_token_channel_access(auth: &IngestAuth, channel_id: Uuid) -> Result<(), String> {
    if let Some(allowed) = auth.channel_ids() {
        if !allowed.contains(&channel_id) {
            return Err("restricted: token does not have access to this channel".to_string());
        }
    }
    Ok(())
}

/// Owned thread metadata for the DB insert.
pub(crate) struct ThreadMetadataOwned {
    pub event_id: Vec<u8>,
    pub event_created_at: chrono::DateTime<Utc>,
    pub channel_id: Uuid,
    pub parent_event_id: Vec<u8>,
    pub parent_event_created_at: chrono::DateTime<Utc>,
    pub root_event_id: Vec<u8>,
    pub root_event_created_at: chrono::DateTime<Utc>,
    pub depth: i32,
    pub broadcast: bool,
}

impl ThreadMetadataOwned {
    pub fn as_params(&self) -> buzz_db::event::ThreadMetadataParams<'_> {
        buzz_db::event::ThreadMetadataParams {
            event_id: &self.event_id,
            event_created_at: self.event_created_at,
            channel_id: self.channel_id,
            parent_event_id: Some(&self.parent_event_id),
            parent_event_created_at: Some(self.parent_event_created_at),
            root_event_id: Some(&self.root_event_id),
            root_event_created_at: Some(self.root_event_created_at),
            depth: self.depth,
            broadcast: self.broadcast,
        }
    }
}

/// Resolve NIP-10 thread ancestry from e-tags.
pub(crate) async fn resolve_nip10_thread_meta(
    community_id: CommunityId,
    event: &Event,
    channel_id: Uuid,
    state: &AppState,
) -> Result<Option<ThreadMetadataOwned>, String> {
    let markers = buzz_core::nip10::parse_thread_markers(&event.tags);

    let (root_hex, parent_hex) = match markers.resolve() {
        Some(pair) => pair,
        None => return Ok(None),
    };

    let parent_bytes =
        hex::decode(&parent_hex).map_err(|_| "invalid parent event ID hex".to_string())?;

    let (parent_event_result, parent_meta_result) = tokio::join!(
        state
            .db
            .get_event_by_id_for_event_write(community_id, &parent_bytes),
        state
            .db
            .get_thread_metadata_by_event(community_id, &parent_bytes),
    );

    let parent_event = parent_event_result
        .map_err(|e| format!("db error looking up parent: {e}"))?
        .ok_or_else(|| "reply parent not found".to_string())?;

    match parent_event.channel_id {
        Some(parent_ch) if parent_ch != channel_id => {
            return Err("parent event belongs to a different channel".to_string());
        }
        None => return Err("parent event has no channel association".to_string()),
        _ => {}
    }

    let parent_created =
        chrono::DateTime::from_timestamp(parent_event.event.created_at.as_secs() as i64, 0)
            .unwrap_or_else(Utc::now);

    let client_root_bytes =
        hex::decode(&root_hex).map_err(|_| "invalid root event ID hex".to_string())?;

    let parent_meta =
        parent_meta_result.map_err(|e| format!("db error looking up thread metadata: {e}"))?;

    let (final_root_bytes, root_created, depth) = match parent_meta {
        Some(meta) => {
            let effective_root = meta.root_event_id.unwrap_or_else(|| parent_bytes.clone());
            if client_root_bytes != effective_root {
                return Err("root tag does not match thread ancestry".to_string());
            }
            let root_ts = if let Ok(Some(root_ev)) = state
                .db
                .get_event_by_id_for_event_write(community_id, &effective_root)
                .await
            {
                chrono::DateTime::from_timestamp(root_ev.event.created_at.as_secs() as i64, 0)
                    .unwrap_or(parent_created)
            } else {
                parent_created
            };
            let depth = meta.depth + 1;
            if depth > 100 {
                return Err("thread depth limit exceeded".to_string());
            }
            (effective_root, root_ts, depth)
        }
        None => {
            let (parent_root, root_created, depth) = derive_ancestry_from_parent_tags(
                community_id,
                &parent_event.event,
                &parent_bytes,
                parent_created,
                state,
            )
            .await;

            if client_root_bytes != parent_root {
                return Err("root tag does not match thread ancestry".to_string());
            }
            (parent_root, root_created, depth)
        }
    };

    let broadcast = event.tags.iter().any(|t| {
        let parts = t.as_slice();
        parts.len() >= 2 && parts[0] == "broadcast" && parts[1] == "1"
    });

    let event_created_at = chrono::DateTime::from_timestamp(event.created_at.as_secs() as i64, 0)
        .unwrap_or_else(Utc::now);

    Ok(Some(ThreadMetadataOwned {
        event_id: event.id.as_bytes().to_vec(),
        event_created_at,
        channel_id,
        parent_event_id: parent_bytes,
        parent_event_created_at: parent_created,
        root_event_id: final_root_bytes,
        root_event_created_at: root_created,
        depth,
        broadcast,
    }))
}

/// Recover a reply's thread ancestry from its *parent's* NIP-10 tags when the
/// parent has **no** `thread_metadata` row (legacy or not-yet-indexed events).
///
/// The parent's markers are first collapsed through `ThreadMarkers::resolve()`:
/// a `root`+`reply` parent carries its marked root, a `reply`-only parent carries
/// its reply target as root, and a root-only/malformed/unmarked parent is itself
/// top-level and its own root. Depth is 1 when the parent is the root and 2
/// otherwise — a reply to a nested-but-unindexed parent must not be mistaken for
/// a top-level reply.
///
/// Shared by [`resolve_nip10_thread_meta`] (client path) and
/// [`resolve_relay_reply_thread_meta`] (workflow path) so the two cannot
/// diverge. Returns `(root_event_id, root_event_created_at, depth)`.
async fn derive_ancestry_from_parent_tags(
    community_id: CommunityId,
    parent_event: &Event,
    parent_bytes: &[u8],
    parent_created: chrono::DateTime<Utc>,
    state: &AppState,
) -> (Vec<u8>, chrono::DateTime<Utc>, i32) {
    let marked_ancestor = |id_hex: &str| hex::decode(id_hex).ok().filter(|b| b.len() == 32);
    let markers = buzz_core::nip10::parse_thread_markers(&parent_event.tags);
    let parent_root = markers
        .resolve()
        .map(|(root, _)| root)
        .as_deref()
        .and_then(marked_ancestor)
        .unwrap_or_else(|| parent_bytes.to_vec());

    if parent_root.as_slice() == parent_bytes {
        (parent_root, parent_created, 1)
    } else {
        let root_created = if let Ok(Some(root_ev)) = state
            .db
            .get_event_by_id_for_event_write(community_id, &parent_root)
            .await
        {
            chrono::DateTime::from_timestamp(root_ev.event.created_at.as_secs() as i64, 0)
                .unwrap_or(parent_created)
        } else {
            parent_created
        };
        (parent_root, root_created, 2)
    }
}

/// Resolved thread ancestry for a relay-built reply (workflow path).
///
/// Carries the parent and root identifiers plus the reply's depth, so the
/// caller can both emit matching NIP-10 `root`/`reply` tags and persist thread
/// metadata for the signed reply event.
pub(crate) struct ReplyAncestry {
    pub parent_event_id: Vec<u8>,
    pub parent_event_created_at: chrono::DateTime<Utc>,
    pub root_event_id: Vec<u8>,
    pub root_event_created_at: chrono::DateTime<Utc>,
    pub depth: i32,
}

impl ReplyAncestry {
    /// Root event ID as lowercase hex, for the NIP-10 `root` tag.
    pub fn root_hex(&self) -> String {
        hex::encode(&self.root_event_id)
    }

    /// Parent event ID as lowercase hex, for the NIP-10 `reply` tag.
    pub fn parent_hex(&self) -> String {
        hex::encode(&self.parent_event_id)
    }

    /// Build the DB thread-metadata params for the signed reply event.
    pub fn into_thread_meta(
        self,
        reply_event_id: Vec<u8>,
        reply_created_at: chrono::DateTime<Utc>,
        channel_id: Uuid,
    ) -> ThreadMetadataOwned {
        ThreadMetadataOwned {
            event_id: reply_event_id,
            event_created_at: reply_created_at,
            channel_id,
            parent_event_id: self.parent_event_id,
            parent_event_created_at: self.parent_event_created_at,
            root_event_id: self.root_event_id,
            root_event_created_at: self.root_event_created_at,
            depth: self.depth,
            broadcast: false,
        }
    }
}

/// Resolve thread ancestry for a reply built by the relay (workflow path).
///
/// Unlike [`resolve_nip10_thread_meta`], which validates client-supplied NIP-10
/// `e` tags, this derives ancestry from a known `parent_hex` (the triggering
/// event) and *computes* the correct root and depth. Enforces the same-channel
/// invariant and the depth limit that the ingest path applies.
pub(crate) async fn resolve_relay_reply_thread_meta(
    community_id: CommunityId,
    parent_hex: &str,
    channel_id: Uuid,
    state: &AppState,
) -> Result<ReplyAncestry, String> {
    let parent_bytes =
        hex::decode(parent_hex).map_err(|_| "invalid parent event ID hex".to_string())?;

    let (parent_event_result, parent_meta_result) = tokio::join!(
        state
            .db
            .get_event_by_id_for_event_write(community_id, &parent_bytes),
        state
            .db
            .get_thread_metadata_by_event(community_id, &parent_bytes),
    );

    let parent_event = parent_event_result
        .map_err(|e| format!("db error looking up parent: {e}"))?
        .ok_or_else(|| "reply parent not found".to_string())?;

    match parent_event.channel_id {
        Some(parent_ch) if parent_ch != channel_id => {
            return Err("parent event belongs to a different channel".to_string());
        }
        None => return Err("parent event has no channel association".to_string()),
        _ => {}
    }

    let parent_created =
        chrono::DateTime::from_timestamp(parent_event.event.created_at.as_secs() as i64, 0)
            .unwrap_or_else(Utc::now);

    let parent_meta =
        parent_meta_result.map_err(|e| format!("db error looking up thread metadata: {e}"))?;

    // Root = parent's root if the parent is itself a reply, else the parent.
    // Depth = parent depth + 1 (a direct reply to a top-level message is depth 1).
    let (root_bytes, root_created, depth) = match parent_meta {
        Some(meta) => {
            let effective_root = meta.root_event_id.unwrap_or_else(|| parent_bytes.clone());
            let root_ts = if effective_root == parent_bytes {
                parent_created
            } else if let Ok(Some(root_ev)) = state
                .db
                .get_event_by_id_for_event_write(community_id, &effective_root)
                .await
            {
                chrono::DateTime::from_timestamp(root_ev.event.created_at.as_secs() as i64, 0)
                    .unwrap_or(parent_created)
            } else {
                parent_created
            };
            (effective_root, root_ts, meta.depth + 1)
        }
        // No metadata row ⇒ recover the parent's ancestry from its own NIP-10
        // tags. A marked (but not-yet-indexed) nested parent yields depth 2, not
        // a false top-level depth 1.
        None => {
            derive_ancestry_from_parent_tags(
                community_id,
                &parent_event.event,
                &parent_bytes,
                parent_created,
                state,
            )
            .await
        }
    };

    if depth > 100 {
        return Err("thread depth limit exceeded".to_string());
    }

    Ok(ReplyAncestry {
        parent_event_id: parent_bytes,
        parent_event_created_at: parent_created,
        root_event_id: root_bytes,
        root_event_created_at: root_created,
        depth,
    })
}

/// Count all `e` tags regardless of content validity.
fn count_e_tags(event: &Event) -> usize {
    event
        .tags
        .iter()
        .filter(|t| t.kind().to_string() == "e")
        .count()
}

/// Extract the effective author of a stored event (handles workflow-generated and
/// legacy relay-signed attributed events).
pub(crate) fn effective_message_author(event: &Event, relay_pubkey: &nostr::PublicKey) -> Vec<u8> {
    if event.pubkey == *relay_pubkey {
        // Workflow-generated or legacy relay-signed attributed event — real author
        // in "actor" or "p" tag.
        if let Some(hex) = event.tags.iter().find_map(|t| {
            if t.kind().to_string() == "actor" {
                t.content().map(|s| s.to_string())
            } else {
                None
            }
        }) {
            if let Ok(bytes) = hex::decode(&hex) {
                if bytes.len() == 32 {
                    return bytes;
                }
            }
        }
        for tag in event.tags.iter() {
            if tag.kind().to_string() == "p" {
                if let Some(hex) = tag.content() {
                    if let Ok(bytes) = hex::decode(hex) {
                        if bytes.len() == 32 {
                            return bytes;
                        }
                    }
                }
            }
        }
    }
    event.pubkey.to_bytes().to_vec()
}

/// Validate kind:40003 edit ownership — event.pubkey must match target's effective author,
/// or the actor must be the owning human of the agent that authored the target message.
async fn validate_edit_ownership(
    community_id: CommunityId,
    event: &Event,
    state: &AppState,
) -> Result<(), String> {
    let target_hex = event
        .tags
        .iter()
        .find_map(|t| {
            if t.kind().to_string() == "e" {
                t.content().and_then(|v| {
                    if v.len() == 64 && v.chars().all(|c| c.is_ascii_hexdigit()) {
                        Some(v.to_string())
                    } else {
                        None
                    }
                })
            } else {
                None
            }
        })
        .ok_or_else(|| "missing e tag for edit target".to_string())?;

    let target_bytes =
        hex::decode(&target_hex).map_err(|_| "invalid target event ID".to_string())?;
    let target_event = state
        .db
        .get_event_by_id_for_event_write(community_id, &target_bytes)
        .await
        .map_err(|e| format!("db error: {e}"))?
        .ok_or_else(|| "edit target event not found".to_string())?;

    // Verify target belongs to the same channel as the edit event.
    let edit_channel_id = extract_channel_id(event);
    match (edit_channel_id, target_event.channel_id) {
        (Some(edit_ch), Some(target_ch)) if edit_ch != target_ch => {
            return Err("target event belongs to a different channel".to_string());
        }
        (Some(_), None) => {
            return Err("target event has no channel".to_string());
        }
        _ => {} // Same channel or no channel context — OK
    }

    let author = effective_message_author(&target_event.event, &state.relay_keypair.public_key());
    let actor = event.pubkey.to_bytes().to_vec();
    if author == actor {
        // Author editing their own message: re-gate on membership/open visibility so that
        // a removed private-channel member cannot mutate old messages after access is revoked.
        if let Some(ch_id) = target_event.channel_id {
            let is_member = state
                .is_member_cached(community_id, ch_id, &actor)
                .await
                .map_err(|e| format!("db error checking membership: {e}"))?;
            if !is_member {
                let is_open = state
                    .db
                    .get_channel_for_event_write(community_id, ch_id)
                    .await
                    .map(|ch| ch.visibility == "open")
                    .unwrap_or(false);
                if !is_open {
                    return Err("restricted: not a channel member".to_string());
                }
            }
        }
    } else {
        // Allow the owning human to edit messages authored by their agent.
        let is_owner = state
            .db
            .is_agent_owner(community_id, &author, &actor)
            .await
            .map_err(|e| format!("db error checking agent ownership: {e}"))?;
        if !is_owner {
            return Err("must be event author to edit".to_string());
        }
    }
    Ok(())
}

/// Validate kind:45002 vote targets a forum post (45001) or comment (45003).
async fn validate_forum_vote_target(
    community_id: CommunityId,
    event: &Event,
    state: &AppState,
) -> Result<(), String> {
    let target_hex = event
        .tags
        .iter()
        .find_map(|t| {
            if t.kind().to_string() == "e" {
                t.content().and_then(|v| {
                    if v.len() == 64 && v.chars().all(|c| c.is_ascii_hexdigit()) {
                        Some(v.to_string())
                    } else {
                        None
                    }
                })
            } else {
                None
            }
        })
        .ok_or_else(|| "missing e tag for vote target".to_string())?;

    let target_bytes =
        hex::decode(&target_hex).map_err(|_| "invalid target event ID".to_string())?;
    let target_event = state
        .db
        .get_event_by_id_for_event_write(community_id, &target_bytes)
        .await
        .map_err(|e| format!("db error: {e}"))?
        .ok_or_else(|| "vote target event not found".to_string())?;

    let target_kind = event_kind_u32(&target_event.event);
    if target_kind != KIND_FORUM_POST && target_kind != KIND_FORUM_COMMENT {
        return Err("vote target must be a forum post or comment".to_string());
    }

    // Verify target belongs to the same channel as the vote event.
    let vote_channel_id = extract_channel_id(event);
    match (vote_channel_id, target_event.channel_id) {
        (Some(vote_ch), Some(target_ch)) if vote_ch != target_ch => {
            return Err("target event belongs to a different channel".to_string());
        }
        (Some(_), None) => {
            return Err("target event has no channel".to_string());
        }
        _ => {}
    }
    Ok(())
}

/// Validate kind:40008 diff event metadata tags.
fn validate_diff_event(event: &Event) -> Result<(), String> {
    // Content max 60KB
    if event.content.len() > 61_440 {
        return Err(format!(
            "diff content exceeds 60KB limit (got {} bytes)",
            event.content.len()
        ));
    }

    let mut has_repo = false;
    let mut has_commit = false;

    for tag in event.tags.iter() {
        let parts = tag.as_slice();
        if parts.len() < 2 {
            continue;
        }
        match parts[0].as_str() {
            "repo" => {
                let url = &parts[1];
                if !url.starts_with("http://") && !url.starts_with("https://") {
                    return Err("repo URL must be http or https".to_string());
                }
                has_repo = true;
            }
            "commit" => {
                let sha = &parts[1];
                if sha.len() < 7 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err("commit SHA must be at least 7 hex characters".to_string());
                }
                has_commit = true;
            }
            "parent-commit" => {
                let sha = &parts[1];
                if sha.len() < 7 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err("parent-commit SHA must be at least 7 hex characters".to_string());
                }
            }
            "branch" if (parts.len() < 3 || parts[1].is_empty() || parts[2].is_empty()) => {
                return Err("branch tag requires both source and target".to_string());
            }
            "pr" if parts[1].parse::<u32>().map(|n| n == 0).unwrap_or(true) => {
                return Err("pr number must be a positive integer".to_string());
            }
            _ => {}
        }
    }

    if !has_repo {
        return Err("diff event requires a repo tag".to_string());
    }
    if !has_commit {
        return Err("diff event requires a commit tag".to_string());
    }
    Ok(())
}

/// Validate the public envelope of a NIP-AE `kind:30174` event before it
/// reaches NIP-33 parameterized replacement.
///
/// We deliberately do this here (not in the d-tag length check downstream)
/// because a malformed envelope can otherwise *replace* a valid head in
/// storage and then be invisible to readers querying `#p`. The relay sees
/// no plaintext, but it can — and must — enforce the public tag shape:
///
/// * exactly one `d` tag with a 64-hex value (`d_tag = lower_hex(HMAC...)`),
/// * exactly one `p` tag with a 64-hex pubkey (the owner counterparty).
///
/// Content is opaque NIP-44 ciphertext; we do not parse it.
fn validate_engram_envelope(event: &Event) -> Result<(), String> {
    let mut d_tags: Vec<&str> = Vec::new();
    let mut p_tags: Vec<&str> = Vec::new();
    for tag in event.tags.iter() {
        let parts = tag.as_slice();
        if parts.len() < 2 {
            continue;
        }
        match parts[0].as_str() {
            "d" => d_tags.push(&parts[1]),
            "p" => p_tags.push(&parts[1]),
            _ => {}
        }
    }
    if d_tags.len() != 1 {
        return Err(format!(
            "agent-engram event must have exactly one `d` tag (got {})",
            d_tags.len()
        ));
    }
    if p_tags.len() != 1 {
        return Err(format!(
            "agent-engram event must have exactly one `p` tag (got {})",
            p_tags.len()
        ));
    }
    let d = d_tags[0];
    if d.len() != 64
        || !d
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("agent-engram `d` tag must be 64 lowercase hex chars".to_string());
    }
    let p = p_tags[0];
    // Lowercase-only: readers query `#p` with `owner.to_hex()` (lowercase) and
    // Nostr tag matching is byte-exact. Accepting uppercase here would let a
    // submitter replace the lowercase head with an event that subsequent
    // lowercase-`#p` queries cannot see — silently bricking the slug.
    if p.len() != 64
        || !p
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("agent-engram `p` tag must be 64 lowercase hex chars (pubkey)".to_string());
    }
    // Content must be a syntactically plausible NIP-44 v2 payload. We do not
    // (and cannot) verify the MAC at the relay, but we can reject obvious
    // garbage so a malformed event cannot supersede a valid head via NIP-33
    // replacement and then be silently discarded by readers.
    validate_engram_nip44_content(&event.content)?;
    Ok(())
}

/// Enforce the `shared`-tag shape shared by every kind in
/// [`buzz_core::kind::SHARED_GATED_KINDS`]: at most one `shared` tag, and if
/// present it must be exactly `["shared", "true"]`.
///
/// This ensures no ambiguous heads: either an event has no `shared` tag
/// (author-only) or exactly `["shared", "true"]` (community-readable). Any
/// other value (`"false"`, `"1"`, extra elements, duplicate tags) is rejected
/// at ingest so read-path helpers — including the SQL-level `tags @>
/// '[["shared","true"]]'` containment clause, which would otherwise match a
/// three-element superset — can treat stored events as unambiguously one or the
/// other.
///
/// `label` names the kind in error messages (e.g. `"persona event"`).
fn validate_shared_tag(event: &Event, label: &str) -> Result<(), String> {
    let mut shared_count = 0usize;
    for tag in event.tags.iter() {
        let parts = tag.as_slice();
        if !parts.is_empty() && parts[0].as_str() == "shared" {
            if parts.len() != 2 || parts[1].as_str() != "true" {
                return Err(format!(
                    "{label} `shared` tag must be exactly [\"shared\",\"true\"] (got {:?})",
                    parts.iter().map(|s| s.as_str()).collect::<Vec<_>>()
                ));
            }
            shared_count += 1;
        }
    }
    if shared_count > 1 {
        return Err(format!(
            "{label} must have at most one `shared` tag (got {shared_count})"
        ));
    }
    Ok(())
}

/// Return the event's single `d` tag value, requiring exactly one tag whose
/// value is non-empty, at most 64 characters, and free of Unicode control
/// characters and whitespace.
///
/// Without this check an empty `d` tag collapses every event of the kind into
/// the `(pubkey, kind, "")` slot — last-write-wins data loss. The character
/// bound keeps the value usable as a NIP-33 coordinate (`<kind>:<pubkey>:<d>`)
/// and as a log field: an embedded newline or tab would break line-oriented
/// consumers of both.
///
/// Tags are counted by their first element alone, so a valueless `["d"]`
/// counts. Skipping it would let `["d"]` plus `["d", "team-1"]` pass the
/// exactly-one rule, and a NIP-33 consumer that reads `["d"]` as an
/// empty-valued first `d` tag would then address the event at `""` where this
/// relay addresses it at `"team-1"`.
///
/// `label` names the kind in error messages (e.g. `"persona event"`).
fn single_bounded_d_tag<'a>(event: &'a Event, label: &str) -> Result<&'a str, String> {
    let d_tags: Vec<Option<&str>> = event
        .tags
        .iter()
        .filter_map(|tag| {
            let parts = tag.as_slice();
            (parts.first().map(|name| name.as_str()) == Some("d"))
                .then(|| parts.get(1).map(|value| value.as_str()))
        })
        .collect();
    if d_tags.len() != 1 {
        return Err(format!(
            "{label} must have exactly one `d` tag (got {})",
            d_tags.len()
        ));
    }
    let d = d_tags[0].unwrap_or_default();
    if d.is_empty() {
        return Err(format!("{label} `d` tag must not be empty"));
    }
    let char_count = d.chars().count();
    if char_count > 64 {
        return Err(format!(
            "{label} `d` tag too long ({char_count} chars, max 64)"
        ));
    }
    if d.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(format!(
            "{label} `d` tag must not contain control characters or whitespace"
        ));
    }
    Ok(d)
}

/// Validate the envelope of a kind:30175 persona event.
///
/// Enforces the shared-gated `shared`-tag shape ([`validate_shared_tag`]) plus
/// exactly one `d` tag matching the persona slug grammar
/// `^[a-z0-9][a-z0-9_-]{0,63}$`.
fn validate_persona_envelope(event: &Event) -> Result<(), String> {
    const LABEL: &str = "persona event";
    validate_shared_tag(event, LABEL)?;
    let d = single_bounded_d_tag(event, LABEL)?;
    // Slug grammar: ^[a-z0-9][a-z0-9_-]{0,63}$
    let bytes = d.as_bytes();
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return Err(format!(
            "{LABEL} `d` tag must start with a lowercase letter or digit"
        ));
    }
    if !bytes[1..]
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        return Err(format!(
            "{LABEL} `d` tag must match [a-z0-9_-] after the first character"
        ));
    }
    Ok(())
}

/// Validate the envelope of a kind:30178 team-catalog event.
///
/// Enforces the shared-gated `shared`-tag shape ([`validate_shared_tag`]) plus
/// exactly one non-empty, bounded `d` tag.
///
/// Deliberately NOT the persona slug grammar: a team's `d` tag is its stable
/// local id, which is either a UUID or a built-in identifier such as
/// `builtin-team:welcome` — the colon is not slug-legal, and rewriting ids to
/// fit would break NIP-33 addressing against the team's own kind:30176 head.
fn validate_team_catalog_envelope(event: &Event) -> Result<(), String> {
    const LABEL: &str = "team-catalog event";
    validate_shared_tag(event, LABEL)?;
    single_bounded_d_tag(event, LABEL)?;
    Ok(())
}

/// Maximum number of member `a` tags on a kind:30621 project.
///
/// Counted over raw tags, not distinct coordinates: a duplicate-heavy event
/// naming one coordinate thousands of times would otherwise be bounded only by
/// the relay frame limit (`config.rs`), so the cap must be checked before any
/// set proportional to the tag list is built.
const PROJECT_MEMBER_CAP: usize = 64;

/// Maximum byte length of a project `name` tag value.
const PROJECT_NAME_MAX_LEN: usize = 256;

/// Maximum byte length of a project `description` tag value.
const PROJECT_DESCRIPTION_MAX_LEN: usize = 2048;

/// Maximum byte length of `buzz-channel` and `buzz-visibility` tag values.
///
/// Both are opaque strings at the relay layer; the bound exists only so an
/// unbounded value cannot ride into storage on a tag ingest does not interpret.
const PROJECT_METADATA_TAG_MAX_LEN: usize = 256;

/// Metadata tags a project may carry at most once each.
///
/// Duplicates would make the effective value reader-dependent — one client
/// taking the first, another the last.
const PROJECT_SINGLETON_METADATA_TAGS: [&str; 4] =
    ["name", "description", "buzz-channel", "buzz-visibility"];

/// The kind segment every project member coordinate must carry: a project groups
/// repository *announcements*, so a coordinate naming any other kind (notably
/// kind:30618 repository state) is malformed.
const PROJECT_MEMBER_KIND_SEGMENT: &str = "30617";
const _: () = assert!(KIND_GIT_REPO_ANNOUNCEMENT == 30617);

/// A validation failure from [`validate_project_envelope`] or
/// [`parse_project_member_coordinate`].
///
/// Carries the stable NIP-MP rule identifier alongside the human-readable
/// rejection message. The rule ID allows the fixture oracle and any future
/// cross-implementation conformance test to assert *which* rule fired, not just
/// that rejection occurred — an implementation cannot pass a reject fixture by
/// refusing for an unrelated reason.
///
/// The eight IDs match the `reject_rules` strings in `NIP-MP.fixtures.json`
/// exactly: `d-cardinality`, `d-empty`, `member-cap`, `member-tag-arity`,
/// `member-coordinate-malformed`, `member-duplicate`, `metadata-cardinality`,
/// `metadata-length`.
#[derive(Debug)]
struct ProjectRejection {
    /// Stable rule identifier matching the fixture file's `reject_rules` set.
    rule: &'static str,
    /// Human-readable explanation forwarded to the client's NOTICE/OK message.
    message: String,
}

impl std::fmt::Display for ProjectRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.rule, self.message)
    }
}

impl ProjectRejection {
    fn new(rule: &'static str, message: impl Into<String>) -> Self {
        Self {
            rule,
            message: message.into(),
        }
    }
}

/// Validate the envelope of a kind:30621 NIP-MP project event.
///
/// Enforces the structural contract in `docs/nips/NIP-MP.md` — exactly one
/// non-empty `d` tag, at most [`PROJECT_MEMBER_CAP`] member `a` tags each
/// holding a canonical `30617:<lowercase-64-hex-owner>:<non-empty-d>`
/// coordinate with no duplicates, and bounded metadata.
///
/// Deliberately absent: any membership authorization. The signer may reference
/// any repository coordinate, including another owner's, because membership
/// grants nothing — push policy reads the repository's own kind:30617
/// (`api/git/policy.rs`) and never a project. Owner-only replacement comes free
/// from NIP-33 addressing.
///
/// Duplicates are rejected rather than deduped: a relay cannot rewrite tags
/// inside a signed event without invalidating its id and signature, so the
/// choice is reject or force every consumer to apply a first-wins rule.
fn validate_project_envelope(event: &Event) -> Result<(), ProjectRejection> {
    let mut d_tags: Vec<&str> = Vec::new();
    let mut members: Vec<&str> = Vec::new();
    let mut name: Option<&str> = None;
    let mut description: Option<&str> = None;
    let mut buzz_channel: Option<&str> = None;
    let mut buzz_visibility: Option<&str> = None;
    let mut singleton_counts = [0usize; PROJECT_SINGLETON_METADATA_TAGS.len()];

    for tag in event.tags.iter() {
        let parts = tag.as_slice();
        let Some(tag_name) = parts.first().map(|s| s.as_str()) else {
            continue;
        };
        let value = parts.get(1).map(|s| s.as_str()).unwrap_or("");
        match tag_name {
            "d" => d_tags.push(value),
            "a" => members.push(value),
            _ => {
                if let Some(i) = PROJECT_SINGLETON_METADATA_TAGS
                    .iter()
                    .position(|k| *k == tag_name)
                {
                    singleton_counts[i] += 1;
                    match tag_name {
                        "name" => name = Some(value),
                        "description" => description = Some(value),
                        "buzz-channel" => buzz_channel = Some(value),
                        "buzz-visibility" => buzz_visibility = Some(value),
                        _ => {}
                    }
                }
            }
        }
    }

    // `d-cardinality` / `d-empty`: under NIP-33 a missing `d` is treated as
    // empty, which collapses every such project into the `(pubkey, 30621, "")`
    // slot where unrelated projects silently overwrite each other. Several `d`
    // tags make the address reader-dependent. Length is bounded by the generic
    // `D_TAG_MAX_LEN` check the ingest pipeline already applies.
    if d_tags.len() != 1 {
        return Err(ProjectRejection::new(
            "d-cardinality",
            format!(
                "project event must have exactly one `d` tag (got {})",
                d_tags.len()
            ),
        ));
    }
    if d_tags[0].is_empty() {
        return Err(ProjectRejection::new(
            "d-empty",
            "project event `d` tag must not be empty",
        ));
    }

    // `member-cap` before `member-coordinate-malformed` and `member-duplicate`:
    // refuse on count before doing per-tag work.
    if members.len() > PROJECT_MEMBER_CAP {
        return Err(ProjectRejection::new(
            "member-cap",
            format!(
                "project event must have at most {PROJECT_MEMBER_CAP} member `a` tags (got {})",
                members.len()
            ),
        ));
    }
    // `member-tag-arity`: every member `a` tag has exactly 2 or 3 elements per
    // NIP-01's `a` tag grammar. A one-element tag names no coordinate; a fourth
    // element has no defined meaning, and accepting it would let a writer park
    // unbounded unvalidated data in a position no consumer reads.
    for tag in event.tags.iter() {
        let parts = tag.as_slice();
        if parts.first().map(|s| s.as_str()) == Some("a") && !(2..=3).contains(&parts.len()) {
            return Err(ProjectRejection::new(
                "member-tag-arity",
                format!(
                    "project event member `a` tag must have exactly 2 or 3 elements (got {})",
                    parts.len()
                ),
            ));
        }
    }
    let mut seen = std::collections::HashSet::with_capacity(members.len());
    for member in &members {
        parse_project_member_coordinate(member)?;
        if !seen.insert(*member) {
            return Err(ProjectRejection::new(
                "member-duplicate",
                format!("project event has duplicate member coordinate {member:?}"),
            ));
        }
    }

    for (i, count) in singleton_counts.iter().enumerate() {
        if *count > 1 {
            return Err(ProjectRejection::new(
                "metadata-cardinality",
                format!(
                    "project event must have at most one `{}` tag (got {count})",
                    PROJECT_SINGLETON_METADATA_TAGS[i]
                ),
            ));
        }
    }
    if let Some(name) = name {
        if name.len() > PROJECT_NAME_MAX_LEN {
            return Err(ProjectRejection::new(
                "metadata-length",
                format!(
                    "project event `name` tag too long ({} bytes, max {PROJECT_NAME_MAX_LEN})",
                    name.len()
                ),
            ));
        }
    }
    if let Some(description) = description {
        if description.len() > PROJECT_DESCRIPTION_MAX_LEN {
            return Err(ProjectRejection::new(
                "metadata-length",
                format!(
                    "project event `description` tag too long ({} bytes, max {PROJECT_DESCRIPTION_MAX_LEN})",
                    description.len()
                ),
            ));
        }
    }
    if let Some(buzz_channel) = buzz_channel {
        if buzz_channel.len() > PROJECT_METADATA_TAG_MAX_LEN {
            return Err(ProjectRejection::new(
                "metadata-length",
                format!(
                    "project event `buzz-channel` tag too long ({} bytes, max {PROJECT_METADATA_TAG_MAX_LEN})",
                    buzz_channel.len()
                ),
            ));
        }
    }
    if let Some(buzz_visibility) = buzz_visibility {
        if buzz_visibility.len() > PROJECT_METADATA_TAG_MAX_LEN {
            return Err(ProjectRejection::new(
                "metadata-length",
                format!(
                    "project event `buzz-visibility` tag too long ({} bytes, max {PROJECT_METADATA_TAG_MAX_LEN})",
                    buzz_visibility.len()
                ),
            ));
        }
    }
    Ok(())
}

/// Check that `coordinate` is a canonical repository-announcement address.
///
/// Splits on the first two colons only, matching how NIP-09 deletion handling
/// parses coordinates (`side_effects.rs`), so a repository whose `d` tag
/// contains a colon stays addressable and a project can never disagree with a
/// deletion about where the `d` value begins.
fn parse_project_member_coordinate(coordinate: &str) -> Result<(), ProjectRejection> {
    let malformed = || {
        ProjectRejection::new(
            "member-coordinate-malformed",
            format!(
                "project event member `a` tag must be \
                 `{PROJECT_MEMBER_KIND_SEGMENT}:<lowercase-64-hex-owner>:<repo-d>` (got {coordinate:?})"
            ),
        )
    };
    let mut segments = coordinate.splitn(3, ':');
    let (Some(kind), Some(owner), Some(repo_d)) =
        (segments.next(), segments.next(), segments.next())
    else {
        return Err(malformed());
    };
    if kind != PROJECT_MEMBER_KIND_SEGMENT {
        return Err(malformed());
    }
    // Lowercase-only: `#a` filter matching is byte-exact, so an uppercase-owner
    // head would be invisible to the lowercase-coordinate queries readers issue.
    if owner.len() != 64
        || !owner
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(malformed());
    }
    if repo_d.is_empty() {
        return Err(malformed());
    }
    Ok(())
}

/// Validate that `content` is a syntactically plausible NIP-44 v2 ciphertext.
///
/// Checks:
/// - Non-empty.
/// - Standard base64 alphabet only (A-Z, a-z, 0-9, +, /, =), with padding only
///   at the end and total length a multiple of 4.
/// - Decoded length >= 99 bytes (1 version + 32 nonce + 32 MAC + minimum 34
///   bytes of length-prefixed padded ciphertext required by NIP-44 v2).
/// - First decoded byte is `0x02` (NIP-44 version 2).
///
/// This is an envelope sanity check, not full validation: the MAC and actual
/// decryption happen at the reader. The intent is to refuse obvious junk so a
/// malformed event cannot win NIP-33 replacement against a valid head and then
/// be silently skipped by `validate_and_decrypt`. Mirrors the validator in
/// `buzz-pair-relay::validate_nip44_content`.
fn validate_engram_nip44_content(content: &str) -> Result<(), String> {
    if content.is_empty() {
        return Err("agent-engram content must not be empty (NIP-44 ciphertext)".to_string());
    }
    let bytes = content.as_bytes();
    let len = bytes.len();
    if !len.is_multiple_of(4) {
        return Err("agent-engram content is not valid base64 (length)".to_string());
    }
    let mut pad_count = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' => {
                if pad_count > 0 {
                    return Err("agent-engram content is not valid base64".to_string());
                }
            }
            b'=' => {
                if i < len - 2 {
                    return Err("agent-engram content is not valid base64".to_string());
                }
                pad_count += 1;
                if pad_count > 2 {
                    return Err("agent-engram content is not valid base64".to_string());
                }
            }
            _ => return Err("agent-engram content is not valid base64".to_string()),
        }
    }
    let decoded_len = (len / 4) * 3 - pad_count;
    if decoded_len < 99 {
        return Err("agent-engram content too short for NIP-44 v2".to_string());
    }
    let b64_val = |c: u8| -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let v0 =
        b64_val(bytes[0]).ok_or_else(|| "agent-engram content is not valid base64".to_string())?;
    let v1 =
        b64_val(bytes[1]).ok_or_else(|| "agent-engram content is not valid base64".to_string())?;
    let first_byte = (v0 << 2) | (v1 >> 4);
    if first_byte != 0x02 {
        return Err(
            "agent-engram content is not NIP-44 v2 (expected 0x02 version prefix)".to_string(),
        );
    }
    Ok(())
}

/// Validate the public envelope of a NIP-AM `kind:44200` event.
///
/// Enforces (without touching the encrypted payload):
/// - Exactly one `p` tag: 64 lowercase hex chars (the owner pubkey).
/// - Exactly one `agent` tag: 64 lowercase hex chars equal to `event.pubkey`.
/// - No `h` tag (channel identity belongs inside the encrypted payload).
/// - Content syntactically resembles NIP-44 v2 ciphertext (delegated to
///   `validate_engram_nip44_content`, which does the same length/base64/version check).
///
/// Ownership (`is_agent_owner`) is an async DB check performed separately in
/// `ingest_event_inner` after this synchronous envelope check.
fn validate_agent_turn_metric_envelope(event: &nostr::Event) -> Result<(), String> {
    let event_pubkey_hex = event.pubkey.to_hex();
    let mut p_tags: Vec<&str> = Vec::new();
    let mut agent_tags: Vec<&str> = Vec::new();
    let mut has_h_tag = false;

    for tag in event.tags.iter() {
        let parts = tag.as_slice();
        if parts.len() < 2 {
            continue;
        }
        match parts[0].as_str() {
            "p" => p_tags.push(&parts[1]),
            "agent" => agent_tags.push(&parts[1]),
            "h" => has_h_tag = true,
            _ => {}
        }
    }

    if has_h_tag {
        return Err(
            "agent-turn-metric event must not have an `h` tag (channel identity belongs inside the encrypted payload)".to_string(),
        );
    }

    if p_tags.len() != 1 {
        return Err(format!(
            "agent-turn-metric event must have exactly one `p` tag (got {})",
            p_tags.len()
        ));
    }
    let p = p_tags[0];
    if p.len() != 64
        || !p
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("agent-turn-metric `p` tag must be 64 lowercase hex chars".to_string());
    }

    if agent_tags.len() != 1 {
        return Err(format!(
            "agent-turn-metric event must have exactly one `agent` tag (got {})",
            agent_tags.len()
        ));
    }
    let agent = agent_tags[0];
    if agent.len() != 64
        || !agent
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("agent-turn-metric `agent` tag must be 64 lowercase hex chars".to_string());
    }
    if agent != event_pubkey_hex {
        return Err("agent-turn-metric `agent` tag must equal event pubkey".to_string());
    }

    // Content must look like a NIP-44 v2 ciphertext (length, base64, version prefix).
    validate_engram_nip44_content(&event.content)
        .map_err(|e| e.replace("agent-engram", "agent-turn-metric"))?;

    Ok(())
}

/// Parse a NIP-ER `not_before` tag value into a Unix timestamp.
///
/// The value MUST be a decimal integer string containing only ASCII digits, with
/// no sign, whitespace, decimal point, or leading zero (except the literal `"0"`),
/// and MUST be in the range 0..=9007199254740991 (`Number.MAX_SAFE_INTEGER`, the
/// interoperable JSON integer bound the spec mandates). Parsing is exact integer
/// parsing — never lossy floating-point — so values that overflow are malformed.
fn validate_not_before(tag_value: &str) -> Result<u64, &'static str> {
    const MAX_NOT_BEFORE: u64 = 9_007_199_254_740_991;

    if tag_value.is_empty() || !tag_value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("malformed not_before");
    }
    // Reject leading zeros (e.g. "007") so each timestamp has one canonical form.
    // "0" itself is the only value allowed to begin with '0'.
    if tag_value.len() > 1 && tag_value.starts_with('0') {
        return Err("malformed not_before");
    }
    // Exact integer parse — `u64::from_str` rejects overflow rather than rounding,
    // so values that would lose precision as f64 are caught before the range check.
    let value: u64 = tag_value.parse().map_err(|_| "malformed not_before")?;
    if value > MAX_NOT_BEFORE {
        return Err("malformed not_before");
    }
    Ok(value)
}

/// Validate the public tag envelope of a NIP-ER `kind:30300` event before it
/// reaches NIP-33 parameterized replacement.
///
/// The relay never decrypts the reminder; it only enforces the public schedule
/// tags. A reminder carries at most one `not_before` (omitted on terminal
/// states), and — when both `not_before` and an optional NIP-40 `expiration`
/// are present — `expiration` MUST be strictly after `not_before` (an
/// `expiration <= not_before` window would expire the reminder before it ever
/// became due).
fn validate_event_reminder(event: &Event) -> Result<(), &'static str> {
    let mut not_before: Option<u64> = None;
    let mut expiration: Option<&str> = None;
    let mut d_count = 0u8;
    let mut d_empty = false;

    for tag in event.tags.iter() {
        let parts = tag.as_slice();
        if parts.len() < 2 {
            continue;
        }
        match parts[0].as_str() {
            "not_before" => {
                // Spec (NIP-ER line 60) collapses invalid and duplicate
                // `not_before` into one wire string clients may match on.
                if not_before.is_some() {
                    return Err("malformed not_before");
                }
                not_before = Some(validate_not_before(&parts[1])?);
            }
            "expiration" => expiration = Some(&parts[1]),
            "d" => {
                d_count = d_count.saturating_add(1);
                if parts[1].is_empty() {
                    d_empty = true;
                }
            }
            _ => {}
        }
    }

    // d-tag: must have exactly one, non-empty
    if d_count == 0 {
        return Err("missing d tag");
    }
    if d_count > 1 {
        return Err("duplicate d tag");
    }
    if d_empty {
        return Err("empty d tag");
    }

    // `not_before` is optional — terminal states (done/cancelled) and bookmarks
    // omit it. The ordering check only applies when both are present.
    if let Some(nb) = not_before {
        // Reject reminders scheduled beyond the configured horizon. The same
        // SPROUT_MAX_NOT_BEFORE_DELTA env var is advertised in NIP-11.
        let max_delta: u64 = std::env::var("SPROUT_MAX_NOT_BEFORE_DELTA")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(31_536_000); // 1 year default
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if nb > now + max_delta {
            return Err("not_before too far in future");
        }

        if let Some(exp) = expiration {
            if let Ok(exp) = exp.parse::<u64>() {
                if exp <= nb {
                    return Err("expiration before not_before");
                }
            }
        }
    }

    Ok(())
}

/// Resolve the `author_type` metric label (`"agent"` / `"human"`) for an
/// event author, from `users.agent_owner_pubkey IS NOT NULL` via a
/// per-community cache. Metric-labeling only — never used for authorization.
/// Unknown pubkeys and lookup errors count as "human" (the label must not
/// add a failure path to ingest).
async fn author_type_label(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    author_pubkey_bytes: Vec<u8>,
) -> &'static str {
    let key = (tenant.community(), author_pubkey_bytes);
    let cached = state.author_type_cache.get(&key);
    let is_agent = match cached {
        Some(v) => v,
        None => {
            let v = match state.db.get_agent_channel_policy(key.0, &key.1).await {
                Ok(Some((_, owner))) => owner.is_some(),
                Ok(None) | Err(_) => false,
            };
            state.author_type_cache.insert(key, v);
            v
        }
    };
    if is_agent {
        "agent"
    } else {
        "human"
    }
}

/// Ingest a signed Nostr event through the full validation pipeline.
///
/// Shared by WebSocket and HTTP transports. The caller constructs [`IngestAuth`]
/// from their transport-specific auth mechanism and maps the result to their
/// transport-specific response format.
///
/// Builds a [`crate::conformance::EmitGuard`] around the actual ingest
/// logic so the trace seam has fail-closed coverage: any exit path that
/// doesn't emit a Write*/SanitizedError action will be caught by the
/// guard's Drop → `ImplBug` → CoverageBreach. The wrapper also maps
/// `IngestError` → SanitizedError in one place, sparing every individual
/// `return Err(...)` from having to emit explicitly. See
/// `crates/buzz-relay/src/conformance/mod.rs` and
/// `docs/spec/MultiTenantRelay.tla`.
pub async fn ingest_event(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    event: Event,
    auth: IngestAuth,
) -> Result<IngestResult, IngestError> {
    // Captured before `event` moves into the inner fn: the stored-events
    // counter below is emitted at this shared seam so WebSocket and HTTP
    // transports are counted identically.
    let kind_label = super::event::bounded_kind_label(event_kind_u32(&event));
    // Classify the authenticated principal, not the event envelope signer:
    // NIP-59 gift wraps deliberately use an unrelated ephemeral pubkey.
    let author_pubkey_bytes = auth.principal_pubkey_bytes();

    let abstract_state = state_for_request(tenant, auth.pubkey());
    let (_guard, tracer) = EmitGuard::arm(
        state.tracer.clone(),
        abstract_state.clone(),
        "ingest_event_exited_without_trace",
    );

    let mut keyed = KeyedIngestSignals { stored: None };
    let result = ingest_event_inner(
        state,
        &tracer,
        tenant,
        IngestSource::Raw { event },
        auth,
        IngestInnerKeyedContext {
            idempotency_key: None,
            keyed_early: None,
        },
        &mut keyed,
    )
    .await
    .map_err(ingest_error_from_inner);
    debug_assert!(keyed.stored.is_none());

    // Fleet-wide stored counter: kind + author_type only, no community tag
    // (see the cardinality rationale on buzz_events_received_total —
    // author_type is a 2-value label so it merely doubles the kind series).
    // Emitted here rather than per-transport so HTTP bridge ingests count too.
    if let Ok(r) = &result {
        if r.accepted {
            let author_type = author_type_label(state, tenant, author_pubkey_bytes).await;
            metrics::counter!(
                "buzz_events_stored_total",
                "kind" => kind_label,
                "author_type" => author_type
            )
            .increment(1);
        }
    }

    // Map terminal error variants onto the closed SanitizedReason
    // alphabet (spec line 778). The inner fn's success path emits
    // WriteInsert/WriteInsertGlobal/WriteDuplicate explicitly at its
    // dispatch points — so on Ok we don't emit here.
    if let Err(err) = &result {
        let reason = conf::sanitized_reason_for(err);
        emit(
            &tracer,
            TraceAction::SanitizedError { reason },
            abstract_state.clone(),
        );
    }

    // _guard drops here. If `tracer` received no records during the
    // request (a panic before the first emit, or a future new exit
    // path that forgets to emit), Drop records an ImplBug step on
    // the underlying tracer — the checker treats that as
    // CoverageBreach.
    result
}

/// HTTP-only keyed ingest. WebSocket continues to call [`ingest_event`].
///
/// Requires [`KeyedHttpValidatedEvent`] so signature verification and the other
/// pre-command checks are not repeated, the exact validating [`IngestAuth`] is
/// bound to the event, and an unvalidated event cannot select this skip path.
pub(crate) async fn ingest_keyed_http_event(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    validated: KeyedHttpValidatedEvent,
    key: [u8; 32],
    mut early: KeyedHttpEarlyContext,
) -> Result<IngestResult, KeyedHttpError> {
    let kind_label = super::event::bounded_kind_label(event_kind_u32(validated.event()));
    let (event, auth) = validated.into_event_and_auth();
    let author_pubkey_bytes = auth.principal_pubkey_bytes();
    let verified_owner = early.verified_owner;
    let agent = *auth.pubkey();
    let abstract_state = state_for_request(tenant, auth.pubkey());
    let (_guard, tracer) = EmitGuard::arm(
        state.tracer.clone(),
        abstract_state.clone(),
        "ingest_event_exited_without_trace",
    );
    let mut keyed = KeyedIngestSignals { stored: None };
    let result = ingest_event_inner(
        state,
        &tracer,
        tenant,
        IngestSource::KeyedValidated(event),
        auth,
        IngestInnerKeyedContext {
            idempotency_key: Some(key),
            keyed_early: Some(&mut early),
        },
        &mut keyed,
    )
    .await;
    early.release_ingress();
    match result {
        Ok(ingest_result) => {
            if ingest_result.accepted {
                if let Some(owner) = verified_owner {
                    crate::api::relay_members::materialize_nip_oa_owner(
                        state, tenant, &agent, &owner,
                    )
                    .await;
                }
            }
            if keyed_http_should_increment_stored(keyed.stored) {
                let author_type = author_type_label(state, tenant, author_pubkey_bytes).await;
                metrics::counter!(
                    "buzz_events_stored_total",
                    "kind" => kind_label,
                    "author_type" => author_type
                )
                .increment(1);
            }
            Ok(ingest_result)
        }
        Err(outcome) => {
            let error = keyed_http_error_from_inner(outcome);
            let reason = match &error {
                KeyedHttpError::Conflict => SanitizedReason::Invalid,
                KeyedHttpError::Busy { .. } => SanitizedReason::ServerError,
                KeyedHttpError::Principal(_) => SanitizedReason::ServerError,
                KeyedHttpError::Ingest(err) => conf::sanitized_reason_for(err),
            };
            emit(
                &tracer,
                TraceAction::SanitizedError { reason },
                abstract_state,
            );
            Err(error)
        }
    }
}

async fn ingest_event_inner(
    state: &Arc<AppState>,
    tracer: &Arc<dyn buzz_conformance::Tracer>,
    tenant: &TenantContext,
    source: IngestSource,
    auth: IngestAuth,
    keyed_context: IngestInnerKeyedContext<'_>,
    keyed: &mut KeyedIngestSignals,
) -> Result<IngestResult, IngestInnerOutcome> {
    let IngestInnerKeyedContext {
        idempotency_key,
        mut keyed_early,
    } = keyed_context;
    let preview = match &source {
        IngestSource::Raw { event } => event,
        IngestSource::KeyedValidated(event) => event,
    };
    let event_id_hex = preview.id.to_hex();
    let kind_u32 = event_kind_u32(preview);
    debug!(event_id = %event_id_hex, kind = kind_u32, "ingest_event");

    // Durable community write fence: persistent ingest is a DB write the
    // deletion engine cannot exclude via serving-write leases (those cover
    // external side effects only), so the shared WS/HTTP seam must refuse
    // writes once the community leaves the active lifecycle state. Row churn
    // inside the remaining race window is swept by the destructive DB stage.
    // Kept ahead of keyed fresh-admission only on the unkeyed/WS path; keyed
    // HTTP already ran the cheap pre-command checks before charging fresh.
    // Keyed early I/O still consumes the remaining absolute five-second
    // deadline so a stalled serving-fence lookup cannot run unbounded.
    map_serving_fence_state(
        keyed_early_io(
            keyed_early.as_deref(),
            buzz_deletion::store(&state.db).is_serving_active(tenant.community()),
        )
        .await
        .map_err(IngestInnerOutcome::from)?,
    )?;

    let event = match source {
        IngestSource::KeyedValidated(event) => event,
        IngestSource::Raw { event } => {
            validate_ingest_pre_command(event, &auth, idempotency_key.is_some()).await?
        }
    };
    let kind_u32 = event_kind_u32(&event);
    let is_gift_wrap = kind_u32 == KIND_GIFT_WRAP;
    let now = chrono::Utc::now().timestamp();

    if kind_u32 != KIND_REPORT {
        let proven_owner = auth.moderation_owner().copied().or_else(|| {
            keyed_early
                .as_deref()
                .and_then(|early| early.verified_owner)
        });
        keyed_early_io(
            keyed_early.as_deref(),
            crate::moderation::check_read(
                state,
                tenant.community(),
                auth.pubkey(),
                proven_owner.as_ref(),
            ),
        )
        .await
        .map_err(IngestInnerOutcome::from)?
        .map_err(|reason| {
            if reason == crate::moderation::BANNED {
                IngestError::AuthFailed(reason.into())
            } else {
                IngestError::Internal(reason.into())
            }
        })?;
    }

    // Command kinds are routed AFTER signature verification, timestamp check,
    // pubkey/auth match, and scope validation — never before.
    if buzz_core::kind::is_command_kind(kind_u32) {
        return super::command_executor::handle_command(tenant, state, event, auth)
            .await
            .map_err(IngestInnerOutcome::from);
    }

    // Product feedback is sidecarred directly into its private deployment table.
    // It never enters ordinary event storage or subscription fan-out.
    if kind_u32 == KIND_PRODUCT_FEEDBACK {
        super::product_feedback::handle(tenant, &event, state)
            .await
            .map_err(IngestError::Rejected)?;
        // Feedback is a host-resolved, channel-less write. Although its row is
        // private to operator tooling rather than ordinary event reads, this is
        // the matching modeled success action at the ingest isolation seam.
        emit_product_feedback_success(tracer, tenant, &event, &auth);
        return Ok(IngestResult {
            event_id: event_id_hex,
            accepted: true,
            message: String::new(),
        });
    }

    // NIP-56 reports are persisted only to the mod queue. They are not stored in
    // the public events table and never fan out to subscribers. Reports remain
    // available while timed out so users can signal abuse during a write-block.
    // A banned actor in the rare missed-disconnect window may also submit a
    // report; that is tolerated because reports are non-actioning signals and
    // remain visible only to moderators.
    if kind_u32 == KIND_REPORT {
        super::report::handle_report_event(tenant, &event, state)
            .await
            .map_err(IngestError::Rejected)?;
        return Ok(IngestResult {
            event_id: event_id_hex,
            accepted: true,
            message: String::new(),
        });
    }

    // Community moderation commands (9040–9044) are direct, community-global
    // mutations. They are never stored or fanned out as ordinary events; the
    // handler writes the durable audit/enforcement rows after its own capability
    // authorization. These commands are intentionally routed before the
    // timeout/write-block gate below so a timed-out admin can lift a timeout.
    // The handler independently checks the durable ban state before executing
    // any command, which also covers NIP-98 and missed live disconnects.
    if buzz_core::kind::is_moderation_command_kind(kind_u32) {
        super::moderation_commands::handle_moderation_command(tenant, state, &event)
            .await
            .map_err(IngestError::Rejected)?;
        return Ok(IngestResult {
            event_id: event_id_hex,
            accepted: true,
            message: String::new(),
        });
    }

    // Community ban / timeout write-block (COMMUNITY_MODERATION_PLAN.md §0
    // decision 4). A timeout is a write-block only — the connection stays open,
    // content writes are refused with `restricted: you are timed out until <ts>`
    // so the desktop can render a countdown. A ban is normally enforced at the
    // auth seam, but an already-authenticated connection never re-auths: if the
    // live-disconnect fan-out is missed (fire-and-forget publish, broadcast lag,
    // subscriber reconnect window), a banned member's open socket would keep
    // writing indefinitely. So the ban is re-checked here — this write-path gate
    // is the durable backstop the fan-out's best-effort delivery relies on.
    // Moderation commands enforce bans inside their handler and remain exempt
    // here only so timeouts do not disarm the tool used to lift them. Relay-admin
    // commands (9030–9033) are exempt for the same reason — a timed-out admin
    // must still be able to administer the roster — and likewise enforce the
    // durable ban inside `relay_admin::handle_relay_admin_event`. Any kind added
    // to this exemption owes the same handler-local ban check.
    //
    // Direct timeouts remain write-only and do not cascade from owner to agent.
    // Bans (including trusted owner bans) were checked before command dispatch.
    if !buzz_core::kind::is_moderation_command_kind(kind_u32) && !is_relay_admin_kind(kind_u32) {
        match keyed_early_io(
            keyed_early.as_deref(),
            state
                .db
                .moderation_restriction_state(tenant.community(), auth.pubkey().as_bytes()),
        )
        .await
        .map_err(IngestInnerOutcome::from)?
        {
            Ok(r) => {
                if r.banned {
                    return Err(IngestError::AuthFailed(
                        "blocked: you are banned from this community".to_string(),
                    )
                    .into());
                }
                if let Some(until) = r.muted_until {
                    if until > chrono::Utc::now() {
                        return Err(IngestError::AuthFailed(format!(
                            "restricted: you are timed out until {}",
                            until.timestamp()
                        ))
                        .into());
                    }
                }
            }
            Err(e) => {
                // Fail closed: a DB error must not let a banned/timed-out actor
                // write.
                return Err(IngestError::Internal(format!(
                    "error: internal error checking restriction state: {e}"
                ))
                .into());
            }
        }
    }

    let mut channel_id = if kind_u32 == KIND_REACTION {
        match keyed_early_io(
            keyed_early.as_deref(),
            derive_reaction_channel(tenant.community(), &state.db, &event),
        )
        .await
        .map_err(IngestInnerOutcome::from)?
        {
            ReactionChannelResult::Channel(ch_id) => Some(ch_id),
            ReactionChannelResult::NoChannel => None,
            ReactionChannelResult::NotFound => {
                return Err(IngestError::Rejected(
                    "invalid: reaction target event not found".into(),
                )
                .into());
            }
            ReactionChannelResult::NoTarget => {
                return Err(IngestError::Rejected(
                    "invalid: reaction must reference a target event via e tag".into(),
                )
                .into());
            }
            ReactionChannelResult::DbError(e) => {
                return Err(IngestError::Internal(format!(
                    "error: internal error looking up reaction target: {e}"
                ))
                .into());
            }
        }
    } else if is_gift_wrap {
        None
    } else if kind_u32 == KIND_DELETION {
        // Standard deletion (kind:5): derive channel from the target event.
        // kind:5 events don't carry an h-tag, so we look up the target event
        // and use its channel_id. This ensures token-channel, membership, and
        // archived checks run against the correct channel.
        let target_hex = event.tags.iter().find_map(|t| {
            if t.kind().to_string() == "e" {
                t.content().and_then(|v| {
                    if v.len() == 64 && v.chars().all(|c| c.is_ascii_hexdigit()) {
                        Some(v.to_string())
                    } else {
                        None
                    }
                })
            } else {
                None
            }
        });
        match target_hex {
            Some(hex) => {
                let target_bytes = hex::decode(&hex).map_err(|_| {
                    IngestError::Rejected("invalid: malformed deletion target id".into())
                })?;
                match keyed_early_io(
                    keyed_early.as_deref(),
                    state
                        .db
                        .get_event_by_id_for_event_write(tenant.community(), &target_bytes),
                )
                .await
                .map_err(IngestInnerOutcome::from)?
                {
                    Ok(Some(target)) => target.channel_id,
                    Ok(None) => None, // target not found — validate_standard_deletion will catch this
                    Err(e) => {
                        return Err(IngestError::Internal(format!(
                            "error: looking up deletion target: {e}"
                        ))
                        .into());
                    }
                }
            }
            None => None, // no e-tag — will be caught by single-target enforcement (step 12)
        }
    } else {
        extract_channel_id(&event)
    };

    if is_global_only_kind(kind_u32) {
        channel_id = None;
    }

    if requires_h_channel_scope(kind_u32) && channel_id.is_none() {
        return Err(IngestError::Rejected(
            "invalid: channel-scoped events must include an h tag".into(),
        )
        .into());
    }

    if let Some(ch_id) = channel_id {
        check_token_channel_access(&auth, ch_id).map_err(IngestError::AuthFailed)?;
    } else if auth.channel_ids().is_some() {
        // Channel-scoped tokens cannot publish global events — that would bypass
        // the token's channel restriction. This covers kind:1 (global text notes),
        // kind:3 (contact lists), kind:0 (profiles), and kind:9007 (create-group
        // without an h-tag, which would auto-assign a server UUID).
        return Err(IngestError::AuthFailed(
            "restricted: channel-scoped tokens cannot publish global events".into(),
        )
        .into());
    }

    // Successful commands are immutable receipts. Classify an exact signed
    // replay after signature, principal, scopes and token-channel validation,
    // before membership/archive checks that this command may itself change.
    // Community lookup and full envelope/channel equality prevent a receipt
    // from another tenant or a mismatched stored row from authorizing a retry.
    if matches!(kind_u32, 9000..=9002) {
        if let Some(existing) = state
            .db
            .get_event_by_id_for_event_write(tenant.community(), event.id.as_bytes())
            .await
            .map_err(|e| IngestError::Internal(format!("error: command receipt lookup: {e}")))?
        {
            if existing.event != event || existing.channel_id != channel_id {
                return Err(IngestError::Internal(
                    "error: command receipt does not match signed source".into(),
                )
                .into());
            }
            if let Some(channel) = channel_id {
                emit(
                    tracer,
                    TraceAction::WriteDuplicate {
                        msg_id: msg_id_label(event.id.as_bytes()),
                        channel: channel_label(channel),
                        claimed_community: claimed_community_from_event(&event),
                    },
                    state_for_request(tenant, auth.pubkey()),
                );
            }
            return Ok(IngestResult {
                event_id: event_id_hex,
                accepted: true,
                message: "duplicate:".into(),
            });
        }
    }

    let pubkey_bytes = auth.pubkey().to_bytes().to_vec();
    // E1 (§4.8): fetch the community-scoped channel row once per request and
    // thread it through the gates below (membership open-fallback, archived
    // check, join visibility) instead of re-SELECTing it at each. `None` when
    // the event is global or the channel doesn't exist yet (kind:9007 creates
    // it later in this request); each gate keeps its existing missing-row
    // behavior.
    let channel_row = match channel_id {
        Some(ch_id) => keyed_early_io(
            keyed_early.as_deref(),
            state
                .db
                .get_channel_for_event_write(tenant.community(), ch_id),
        )
        .await
        .map_err(IngestInnerOutcome::from)?
        .ok(),
        None => None,
    };
    // E1 phase-2 (§4.8 phase-2 addendum): resolve the fan-out visibility once,
    // here, through the same `channel_visibility_cached` gate fan-out uses
    // (fence 2: cached `private` wins over the prefetched row; a `private`
    // read still populates the cache). The value travels to fan-out bundled
    // with the (community, channel) it was resolved under (fence 3). When the
    // row is missing (global event, kind:9007 pre-create) this is `None` and
    // fan-out performs its own fresh fail-closed lookup — `None` is never
    // "assume open" (fence 1).
    let threaded_visibility = match (channel_id, &channel_row) {
        (Some(ch_id), Some(row)) => keyed_early_io(
            keyed_early.as_deref(),
            state.channel_visibility_cached(tenant.community(), ch_id, Some(row)),
        )
        .await
        .map_err(IngestInnerOutcome::from)?
        .ok()
        .map(|visibility| crate::state::ThreadedChannelVisibility {
            community_id: tenant.community(),
            channel_id: ch_id,
            visibility,
        }),
        _ => None,
    };
    if let Some(ch_id) = channel_id {
        // kind:9021 (join) doesn't require prior membership.
        // kind:9007 (create) — channel doesn't exist yet; creator becomes owner in step 16.
        // kind:40003/9002/9005/9008 — per-kind validators are the authority; they
        // individually enforce authorization and fail closed. Bypassing the generic
        // member/open gate here lets the owning human act on private agent channels
        // without being a member (OQ1 decision; see validate_edit_ownership /
        // validate_admin_event for per-kind enforcement).
        let skip_membership = matches!(kind_u32, 9000..=9002)
            || kind_u32 == KIND_NIP29_JOIN_REQUEST
            || kind_u32 == KIND_NIP29_CREATE_GROUP
            || kind_u32 == KIND_STREAM_MESSAGE_EDIT
            || kind_u32 == KIND_NIP29_EDIT_METADATA
            || kind_u32 == KIND_NIP29_DELETE_EVENT
            || kind_u32 == KIND_NIP29_DELETE_GROUP;
        if !skip_membership {
            // Spec AuthCheck (line 794): emit the verdict at the actual
            // call site. claimed_community comes from the event's h tag
            // (recorded separately to bite M2 / M8 — claim or A-host
            // driving a B-channel verdict — at the checker). The verdict
            // basis is `tenant.community()` server-resolved, confirmed
            // at `check_channel_membership`'s `is_member_cached(tenant
            // .community(), …)` call (see crates/buzz-relay/src/handlers
            // /ingest.rs:424).
            let auth_result = keyed_early_io(
                keyed_early.as_deref(),
                check_channel_membership(tenant, state, ch_id, &pubkey_bytes, channel_row.as_ref()),
            )
            .await
            .map_err(IngestInnerOutcome::from)?;
            let claimed = claimed_community_from_event(&event);
            let verdict = if auth_result.is_ok() {
                Verdict::Allow
            } else {
                Verdict::Deny
            };
            emit(
                tracer,
                TraceAction::AuthCheck {
                    channel: channel_label(ch_id),
                    claimed_community: claimed,
                    verdict,
                },
                state_for_request(tenant, auth.pubkey()),
            );
            auth_result.map_err(IngestError::Rejected)?;
        }
    }

    // Handled directly — these mutate relay_members and do NOT get stored.
    // The handler enforces the durable community ban itself: the write-path
    // gate above exempts relay-admin kinds so timed-out admins keep their
    // administrative capability, which leaves bans to the handler.
    if is_relay_admin_kind(event.kind.as_u16() as u32) {
        crate::handlers::relay_admin::handle_relay_admin_event(tenant, state, &event)
            .await
            .map_err(map_relay_admin_error)?;
        return Ok(IngestResult {
            event_id: event_id_hex,
            accepted: true,
            message: String::new(),
        });
    }

    // Handled directly — removes the sender from relay_members. NOT stored.
    if kind_u32 == KIND_NIP43_LEAVE_REQUEST {
        if !state.config.require_relay_membership {
            return Err(
                IngestError::Rejected("invalid: relay membership is not enabled".into()).into(),
            );
        }

        // Freshness check: reject events outside ±120s of now (same as admin commands).
        {
            let event_ts = event.created_at.as_secs() as i64;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            if (event_ts - now).abs() > 120 {
                return Err(IngestError::Rejected(format!(
                    "invalid: leave request timestamp out of range (delta={}s, max ±120s)",
                    event_ts - now
                ))
                .into());
            }
        }

        // NIP-43 spec: "This event MUST include a NIP-70 `-` tag."
        let has_protected_tag = event
            .tags
            .iter()
            .any(|t| t.as_slice().first().map(|s| s.as_str()) == Some("-"));
        if !has_protected_tag {
            return Err(IngestError::Rejected(
                "invalid: leave request must include NIP-70 protected event tag [\"-\"]".into(),
            )
            .into());
        }

        let sender_hex = event.pubkey.to_hex();

        // remove_relay_member handles both the NotFound and IsOwner cases atomically.
        let remove_result = state
            .db
            .remove_relay_member(tenant.community(), &sender_hex)
            .await
            .map_err(|e| IngestError::Internal(format!("database error: {e}")))?;

        match remove_result {
            buzz_db::relay_members::RemoveResult::Removed => {}
            buzz_db::relay_members::RemoveResult::NotFound => {
                return Err(
                    IngestError::Rejected("invalid: you are not a relay member".into()).into(),
                );
            }
            buzz_db::relay_members::RemoveResult::IsOwner => {
                return Err(
                    IngestError::Rejected("invalid: relay owner cannot leave".into()).into(),
                );
            }
            buzz_db::relay_members::RemoveResult::RoleMismatch => {
                // remove_relay_member (no role filter) never returns RoleMismatch —
                // this arm is unreachable but exhaustiveness requires it.
                return Err(IngestError::Internal(
                    "unexpected RoleMismatch from remove_relay_member".into(),
                )
                .into());
            }
        }

        // Publish NIP-43 announcements — fire-and-forget.
        if let Err(e) =
            crate::handlers::side_effects::publish_nip43_member_removed(tenant, state, &sender_hex)
                .await
        {
            warn!(error = %e, "failed to publish NIP-43 member removed event");
        }
        if let Err(e) =
            crate::handlers::side_effects::publish_nip43_membership_list(tenant, state).await
        {
            warn!(error = %e, "failed to publish NIP-43 membership list");
        }

        info!(pubkey = %sender_hex, "relay member left via NIP-43 leave request");

        return Ok(IngestResult {
            event_id: event_id_hex,
            accepted: true,
            message: "info: you have left this relay".into(),
        });
    }

    keyed_early_io(
        keyed_early.as_deref(),
        validate_huddle_lifecycle_event(tenant, state, &event, kind_u32),
    )
    .await
    .map_err(IngestInnerOutcome::from)??;

    // Canonical commands perform complete current policy under their held
    // transaction. An unlocked preflight here can reject a concurrent exact
    // retry after its first request removes membership or archives the channel.
    if crate::handlers::side_effects::is_admin_kind(kind_u32) && !matches!(kind_u32, 9000..=9002) {
        keyed_early_io(
            keyed_early.as_deref(),
            crate::handlers::side_effects::validate_admin_event(tenant, kind_u32, &event, state),
        )
        .await
        .map_err(IngestInnerOutcome::from)?
        .map_err(|e| IngestError::Rejected(format!("invalid: {e}")))?;
    }

    // Processed here (verify consent, mutate archived_identities, emit the
    // relay-signed 8002/8003 delta + 13535 snapshot), then — unlike the
    // NIP-43 admin commands above — the request itself falls through to normal
    // storage so the delta's `["e", request_id]` audit reference resolves.
    if is_identity_archive_request_kind(kind_u32) {
        crate::handlers::identity_archive::handle_identity_archive_event(tenant, state, &event)
            .await
            .map_err(|e| IngestError::Rejected(format!("invalid: {e}")))?;
    }

    if kind_u32 == KIND_DELETION {
        keyed_early_io(
            keyed_early.as_deref(),
            crate::handlers::side_effects::validate_standard_deletion_event(tenant, &event, state),
        )
        .await
        .map_err(IngestInnerOutcome::from)?
        .map_err(|e| IngestError::Rejected(format!("invalid: {e}")))?;
    }

    if channel_id.is_some() && !matches!(kind_u32, 9000..=9002) {
        // Allow kind:9002 with archived=false (unarchive operation)
        let is_unarchive = kind_u32 == KIND_NIP29_EDIT_METADATA
            && event.tags.iter().any(|t| {
                let parts = t.as_slice();
                parts.len() >= 2 && parts[0] == "archived" && parts[1] == "false"
            });

        if !is_unarchive {
            if let Some(channel) = &channel_row {
                if channel.archived_at.is_some() {
                    return Err(IngestError::Rejected("invalid: channel is archived".into()).into());
                }
            }
        }
    }

    // NIP-09: kind:5 may reference targets via `e` tag (regular events) OR
    // `a` tag (addressable/parameterized-replaceable events like kind:30620).
    if kind_u32 == KIND_NIP29_DELETE_EVENT || kind_u32 == KIND_DELETION {
        let e_count = count_e_tags(&event);
        let a_count = event
            .tags
            .iter()
            .filter(|t| t.kind().to_string() == "a")
            .count();
        if (e_count + a_count) != 1 {
            return Err(IngestError::Rejected(format!(
                "invalid: deletion events must reference exactly one target via e or a tag (got e={e_count}, a={a_count})"
            ))
            .into());
        }
    }

    if kind_u32 == KIND_STREAM_MESSAGE_EDIT {
        keyed_early_io(
            keyed_early.as_deref(),
            validate_edit_ownership(tenant.community(), &event, state),
        )
        .await
        .map_err(IngestInnerOutcome::from)?
        .map_err(|e| IngestError::Rejected(format!("invalid: {e}")))?;
    }

    if kind_u32 == KIND_FORUM_VOTE {
        keyed_early_io(
            keyed_early.as_deref(),
            validate_forum_vote_target(tenant.community(), &event, state),
        )
        .await
        .map_err(IngestInnerOutcome::from)?
        .map_err(|e| IngestError::Rejected(format!("invalid: {e}")))?;
    }

    if kind_u32 == KIND_STREAM_MESSAGE_DIFF {
        validate_diff_event(&event).map_err(|e| IngestError::Rejected(format!("invalid: {e}")))?;
    }

    if kind_u32 == KIND_AGENT_ENGRAM {
        validate_engram_envelope(&event)
            .map_err(|e| IngestError::Rejected(format!("invalid: {e}")))?;
    }

    if kind_u32 == KIND_AGENT_TURN_METRIC {
        validate_agent_turn_metric_envelope(&event)
            .map_err(|e| IngestError::Rejected(format!("invalid: {e}")))?;

        // Ownership check: `p` tag must be the registered owner of `event.pubkey`.
        // Tag shape is already verified above; these extractions are infallible.
        let owner_hex = event
            .tags
            .iter()
            .find_map(|t| {
                let parts = t.as_slice();
                if parts.len() >= 2 && parts[0].as_str() == "p" {
                    Some(parts[1].as_str())
                } else {
                    None
                }
            })
            .expect("p tag present (validated above)");
        let agent_bytes = event.pubkey.to_bytes().to_vec();
        let owner_bytes = hex::decode(owner_hex).expect("hex validated above");
        let is_owner = keyed_early_io(
            keyed_early.as_deref(),
            state
                .db
                .is_agent_owner(tenant.community(), &agent_bytes, &owner_bytes),
        )
        .await
        .map_err(IngestInnerOutcome::from)?
        .map_err(|e| {
            IngestError::Internal(format!(
                "error: db error checking agent-turn-metric ownership: {e}"
            ))
        })?;
        if !is_owner {
            return Err(IngestError::AuthFailed(
                "restricted: agent-turn-metric `p` tag must be the registered owner of this agent"
                    .into(),
            )
            .into());
        }
    }

    if kind_u32 == KIND_EVENT_REMINDER {
        validate_event_reminder(&event)
            .map_err(|e| IngestError::Rejected(format!("invalid: {e}")))?;
    }

    if kind_u32 == KIND_PERSONA {
        validate_persona_envelope(&event)
            .map_err(|e| IngestError::Rejected(format!("invalid: {e}")))?;
    }

    if kind_u32 == KIND_TEAM_CATALOG {
        validate_team_catalog_envelope(&event)
            .map_err(|e| IngestError::Rejected(format!("invalid: {e}")))?;
    }

    if kind_u32 == KIND_PROJECT {
        validate_project_envelope(&event)
            .map_err(|e| IngestError::Rejected(format!("invalid: {e}")))?;
    }

    // Track pre-created channel UUID for compensation on insert failure.
    let mut pre_created_channel: Option<Uuid> = None;

    if kind_u32 == KIND_NIP29_CREATE_GROUP {
        // Validate name tag is present and non-empty before any DB work.
        let create_name = event.tags.iter().find_map(|t| {
            if t.kind().to_string() == "name" {
                t.content().map(|s| s.to_string())
            } else {
                None
            }
        });
        if create_name
            .as_ref()
            .map(|n| {
                buzz_core::channel::canonical_channel_name(n)
                    .trim()
                    .is_empty()
            })
            .unwrap_or(true)
        {
            return Err(IngestError::Rejected("invalid: channel name is required".into()).into());
        }

        // Validate visibility/channel_type for ALL kind:9007 events (with or without h-tag).
        // This runs pre-storage so invalid enums are rejected before the event is persisted.
        let visibility_str = event
            .tags
            .iter()
            .find_map(|t| {
                if t.kind().to_string() == "visibility" {
                    t.content().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "open".to_string());
        let channel_type_str = event
            .tags
            .iter()
            .find_map(|t| {
                if t.kind().to_string() == "channel_type" {
                    t.content().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "stream".to_string());

        let visibility: buzz_db::channel::ChannelVisibility = visibility_str
            .parse()
            .map_err(|_| IngestError::Rejected(format!("invalid visibility: {visibility_str}")))?;
        let channel_type: buzz_db::channel::ChannelType =
            channel_type_str.parse().map_err(|_| {
                IngestError::Rejected(format!("invalid channel_type: {channel_type_str}"))
            })?;

        if let Some(client_uuid) = channel_id {
            let name = create_name.unwrap_or_default();
            let name = buzz_core::channel::canonical_channel_name(&name);

            let description = event.tags.iter().find_map(|t| {
                if t.kind().to_string() == "about" {
                    t.content().map(|s| s.to_string())
                } else {
                    None
                }
            });

            let ttl_seconds = super::resolve_ttl(&event, state.config.ephemeral_ttl_override);

            let actor_bytes = event.pubkey.to_bytes().to_vec();
            let (_, was_created) = state
                .db
                .create_channel_with_id(
                    tenant.community(),
                    client_uuid,
                    name,
                    channel_type,
                    visibility,
                    description.as_deref(),
                    &actor_bytes,
                    ttl_seconds,
                )
                .await
                .map_err(|e| IngestError::Internal(format!("error: {e}")))?;

            if !was_created {
                return Ok(IngestResult {
                    event_id: event_id_hex,
                    accepted: false,
                    message: "duplicate: channel already exists".into(),
                });
            }
            pre_created_channel = Some(client_uuid);
            metrics::counter!(
                "buzz_channels_created_total",
                "community" => tenant.host().to_owned(),
                "type" => channel_type.to_string()
            )
            .increment(1);
        }
    }

    if kind_u32 == KIND_NIP29_JOIN_REQUEST {
        // A join without an h-tag is meaningless — reject early.
        if channel_id.is_none() {
            return Err(IngestError::Rejected(
                "invalid: join request must include an h tag".into(),
            )
            .into());
        }
        if channel_id.is_some() {
            match &channel_row {
                Some(ch) if ch.visibility == "private" => {
                    return Err(
                        IngestError::Rejected("restricted: channel is private".into()).into(),
                    );
                }
                None => {
                    return Err(IngestError::Rejected("invalid: channel not found".into()).into());
                }
                _ => {} // open — OK
            }
        }
    }

    if kind_u32 == super::push_lease::KIND_PUSH_LEASE {
        let outcome = super::push_lease::accept(tenant, state, &event, now)
            .await
            .map_err(map_push_accept_error)?;
        match outcome {
            buzz_db::push::AcceptLeaseOutcome::Accepted => {}
            buzz_db::push::AcceptLeaseOutcome::StaleEvent => {
                return Err(IngestError::Rejected("invalid: stale replacement".into()).into());
            }
            buzz_db::push::AcceptLeaseOutcome::StaleGeneration => {
                return Err(IngestError::Rejected("invalid: stale generation".into()).into());
            }
            buzz_db::push::AcceptLeaseOutcome::EndpointAlreadyLeased => {
                return Err(
                    IngestError::Rejected("invalid: endpoint already leased".into()).into(),
                );
            }
            buzz_db::push::AcceptLeaseOutcome::LeaseQuotaExceeded => {
                return Err(IngestError::Rejected("invalid: lease quota exceeded".into()).into());
            }
            buzz_db::push::AcceptLeaseOutcome::SourceEventCollision => {
                return Err(IngestError::Rejected("invalid: source event collision".into()).into());
            }
            buzz_db::push::AcceptLeaseOutcome::ConstraintViolation => {
                return Err(
                    IngestError::Rejected("invalid: lease constraint violation".into()).into(),
                );
            }
        };
        emit(
            tracer,
            TraceAction::WriteInsertGlobal {
                msg_id: msg_id_label(event.id.as_bytes()),
                claimed_community: claimed_community_from_event(&event),
            },
            state_for_request(tenant, auth.pubkey()),
        );
        return Ok(IngestResult {
            event_id: event_id_hex,
            accepted: true,
            message: String::new(),
        });
    }

    let tenant_media_base =
        crate::api::media::media_base_url_for_tenant(&state.config.relay_url, tenant.host());
    if kind_u32 == KIND_STREAM_MESSAGE {
        validate_link_preview_tags(&event, &tenant_media_base)
            .map_err(|e| IngestError::Rejected(format!("invalid: {e}")))?;
    }

    let imeta_tags: Vec<Vec<String>> = event
        .tags
        .iter()
        .filter(|t| t.kind().to_string() == "imeta")
        .map(|t| t.as_slice().iter().map(|s| s.to_string()).collect())
        .collect();
    if !imeta_tags.is_empty() {
        crate::api::validate_imeta_tags(&imeta_tags, &tenant_media_base)
            .map_err(|e| IngestError::Rejected(format!("invalid: {e}")))?;
        keyed_early_io(
            keyed_early.as_deref(),
            crate::api::verify_imeta_blobs(tenant, &imeta_tags, &state.media_storage),
        )
        .await
        .map_err(IngestInnerOutcome::from)?
        .map_err(|e| IngestError::Rejected(format!("invalid: {e}")))?;
    }

    let thread_meta = if requires_h_channel_scope(kind_u32) {
        if let Some(ch_id) = channel_id {
            keyed_early_io(
                keyed_early.as_deref(),
                resolve_nip10_thread_meta(tenant.community(), &event, ch_id, state),
            )
            .await
            .map_err(IngestInnerOutcome::from)?
            .map_err(|msg| IngestError::Rejected(format!("invalid: {msg}")))?
        } else {
            None
        }
    } else {
        None
    };

    let profile = if kind_u32 == KIND_PROFILE {
        Some(
            super::profile::prepare(tenant, &event)
                .map_err(|message| IngestError::Rejected(format!("invalid: {message}")))?,
        )
    } else {
        None
    };

    if kind_u32 == KIND_EMOJI_SET || kind_u32 == KIND_EMOJI_LIST {
        validate_custom_emoji_tags(&event)?;
    }

    // Resolve the target reference, then use one DB transaction to upsert the
    // reaction row (dedup via ON CONFLICT) with reaction_event_id already set and
    // store the kind:7 event. This replaces the post-storage side-effect handler.
    if kind_u32 == KIND_REACTION {
        // Extract target event hex from last e-tag (NIP-25).
        let target_hex = event
            .tags
            .iter()
            .rev()
            .find_map(|tag| {
                if tag.kind().to_string() == "e" {
                    tag.content().and_then(|v| {
                        if v.len() == 64 && v.chars().all(|c| c.is_ascii_hexdigit()) {
                            Some(v.to_string())
                        } else {
                            None
                        }
                    })
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                IngestError::Rejected(
                    "invalid: reaction must reference a target event via e tag".into(),
                )
            })?;

        let target_id = hex::decode(&target_hex)
            .map_err(|_| IngestError::Rejected("invalid: malformed reaction target id".into()))?;

        let actor_bytes = effective_message_author(&event, &state.relay_keypair.public_key());
        let emoji = if event.content.is_empty() {
            "+"
        } else {
            &event.content
        };

        validate_reaction_emoji(&event, emoji)?;

        // Atomically upsert the reaction row with this kind:7 event id, then store
        // the event in the same transaction. Ordering is load-bearing: active
        // duplicate reactions must return before storing a duplicate kind:7 event.
        let thread_params = thread_meta.as_ref().map(|m| m.as_params());
        let (stored_event, was_inserted) = match state
            .db
            .insert_reaction_event_with_thread_metadata(
                tenant.community(),
                &event,
                channel_id,
                thread_params,
                &target_id,
                &actor_bytes,
                emoji,
            )
            .await
            .map_err(|e| IngestError::Internal(format!("error: {e}")))?
        {
            buzz_db::ReactionEventInsertOutcome::TargetMissing => {
                return Err(IngestError::Rejected(
                    "invalid: reaction target event not found".into(),
                )
                .into());
            }
            buzz_db::ReactionEventInsertOutcome::Duplicate => {
                return Ok(IngestResult {
                    event_id: event_id_hex,
                    accepted: false,
                    message: "duplicate: reaction already exists".into(),
                });
            }
            buzz_db::ReactionEventInsertOutcome::Inserted {
                stored_event,
                was_inserted,
            } => (stored_event, was_inserted),
        };

        let pubkey_hex = auth.pubkey().to_hex();
        // Spec WriteInsert (line 514) / WriteDuplicate (line 606) /
        // WriteInsertGlobal (line 559): emit the abstract write action. The
        // persist API returns `was_inserted` (true → Insert/Global, false →
        // Duplicate). Reactions on project events (issue/PR roots and their
        // comments) carry no `h` tag, so `channel_id` can be `None` here —
        // mirror the message write's three-way split instead of asserting a
        // channel, which panicked the ingest worker on those events.
        let claimed = claimed_community_from_event(&event);
        let action = match (channel_id, was_inserted) {
            (Some(ch), true) => TraceAction::WriteInsert {
                msg_id: msg_id_label(event.id.as_bytes()),
                channel: channel_label(ch),
                claimed_community: claimed,
            },
            (Some(ch), false) => TraceAction::WriteDuplicate {
                msg_id: msg_id_label(event.id.as_bytes()),
                channel: channel_label(ch),
                claimed_community: claimed,
            },
            (None, _) => TraceAction::WriteInsertGlobal {
                msg_id: msg_id_label(event.id.as_bytes()),
                claimed_community: claimed,
            },
        };
        emit(tracer, action, state_for_request(tenant, auth.pubkey()));
        dispatch_persistent_event(
            tenant,
            state,
            &stored_event,
            kind_u32,
            &pubkey_hex,
            threaded_visibility.clone(),
        )
        .await;

        info!(event_id = %event_id_hex, kind = kind_u32, "Event ingested via pipeline");
        return Ok(IngestResult {
            event_id: event_id_hex,
            accepted: true,
            message: String::new(),
        });
    }

    let mut atomic_channel_notices = None;
    let (stored_event, was_inserted) = if matches!(kind_u32, 9000..=9002) {
        let channel =
            channel_id.ok_or_else(|| IngestError::Rejected("invalid: missing channel".into()))?;
        let committed = super::channel_commands::persist(
            tenant,
            state,
            &event,
            channel,
            auth.moderation_owner(),
            thread_meta.as_ref().map(|meta| meta.as_params()),
        )
        .await
        .map_err(|error| match error.downcast_ref::<buzz_db::DbError>() {
            Some(buzz_db::DbError::AccessDenied(reason)) => {
                IngestError::Rejected(format!("restricted: {reason}"))
            }
            Some(buzz_db::DbError::InvalidData(reason)) => {
                IngestError::Rejected(format!("invalid: {reason}"))
            }
            Some(buzz_db::DbError::ChannelNotFound(_) | buzz_db::DbError::MemberNotFound(_)) => {
                IngestError::Rejected(format!("invalid: {error}"))
            }
            _ => IngestError::Internal(format!("error: channel command transaction: {error}")),
        })?;
        atomic_channel_notices = Some(committed.notices);
        (committed.source, committed.inserted)
    } else if let Some(profile) = profile.as_ref() {
        let (stored, inserted, user_created) = state
            .db
            .replace_profile_event(tenant.community(), &event, profile)
            .await
            .map_err(|e| IngestError::Internal(format!("error: {e}")))?;
        if user_created {
            metrics::counter!("buzz_users_created_total", "community" => tenant.host().to_owned())
                .increment(1);
        }
        (stored, inserted)
    } else if buzz_core::kind::is_replaceable(kind_u32) {
        // NIP-16 replaceable event — atomic replace with stale-write protection.
        // channel_id is None for global kinds (0, 1, 3) due to step 5b above.
        state
            .db
            .replace_addressable_event(tenant.community(), &event, channel_id)
            .await
            .map_err(|e| IngestError::Internal(format!("error: {e}")))?
    } else if is_parameterized_replaceable(kind_u32) {
        // NIP-33 parameterized replaceable — keyed by (kind, pubkey, d_tag).
        let d_tag = buzz_db::event::extract_d_tag(&event).unwrap_or_default();
        if d_tag.len() > buzz_db::event::D_TAG_MAX_LEN {
            return Err(IngestError::Rejected(format!(
                "invalid: d tag too long ({} bytes, max {})",
                d_tag.len(),
                buzz_db::event::D_TAG_MAX_LEN,
            ))
            .into());
        }
        state
            .db
            .replace_parameterized_event(tenant.community(), &event, &d_tag, channel_id)
            .await
            .map_err(|e| IngestError::Internal(format!("error: {e}")))?
    } else {
        let thread_params = thread_meta.as_ref().map(|m| m.as_params());
        if let Some(key) = idempotency_key {
            let author = event.pubkey.to_bytes();
            let prepared = match buzz_db::Db::prepare_keyed_stream_intent(key, &event) {
                Ok(prepared) => prepared,
                Err(error) => {
                    return Err(
                        IngestError::Internal(format!("error: database error: {error}")).into(),
                    );
                }
            };
            let classify_budget = keyed_early
                .as_ref()
                .map(|early| early.deadline.remaining())
                .filter(|remaining| !remaining.is_zero())
                .unwrap_or(if keyed_early.is_some() {
                    Duration::from_secs(0)
                } else {
                    KEYED_RESERVATION_PERSIST_BUDGET
                });
            if keyed_early.is_some() && classify_budget.is_zero() {
                return Err(IngestInnerOutcome::from(keyed_busy_default()));
            }
            let committed = match tokio::time::timeout(
                classify_budget,
                state.db.classify_keyed_stream_before_admission(
                    tenant.community(),
                    &prepared,
                    &event,
                    channel_id,
                    thread_params.as_ref(),
                ),
            )
            .await
            {
                Err(_elapsed) => {
                    return Err(IngestInnerOutcome::from(keyed_busy_default()));
                }
                Ok(Ok(committed)) => committed,
                Ok(Err(error)) if error.is_idempotency_unavailable() => {
                    return Err(IngestInnerOutcome::from(keyed_busy_default()));
                }
                Ok(Err(error)) if error.is_idempotency_unsupported_kind() => {
                    return Err(IngestError::Rejected(
                        "invalid: Idempotency-Key is not supported for this event kind".into(),
                    )
                    .into());
                }
                Ok(Err(error)) if error.is_idempotency_too_many_mentions() => {
                    return Err(IngestError::Rejected(
                        "invalid: too many p tags for keyed ingest".into(),
                    )
                    .into());
                }
                Ok(Err(e)) => {
                    if let Some(ch_id) = pre_created_channel {
                        if let Err(re) = state
                            .db
                            .soft_delete_channel(tenant.community(), ch_id)
                            .await
                        {
                            warn!(event_id = %event_id_hex, "channel compensation failed: {re}");
                        }
                        state.invalidate_channel_deleted(tenant);
                    }
                    return Err(IngestInnerOutcome::from(match e {
                        buzz_db::DbError::AuthEventRejected => {
                            IngestError::Rejected("invalid: AUTH events cannot be stored".into())
                        }
                        other => IngestError::Internal(format!("error: database error: {other}")),
                    }));
                }
            };
            let admit_budget = keyed_early
                .as_ref()
                .map(|early| early.deadline.remaining())
                .filter(|remaining| !remaining.is_zero())
                .unwrap_or(if keyed_early.is_some() {
                    Duration::from_secs(0)
                } else {
                    KEYED_RESERVATION_ADMISSION_BUDGET
                });
            if keyed_early.is_some() && admit_budget.is_zero() {
                return Err(IngestInnerOutcome::from(keyed_busy_default()));
            }
            match tokio::time::timeout(
                admit_budget,
                finish_keyed_committed_classify(
                    committed,
                    state.admission_rate_limiter.as_ref(),
                    tenant,
                    auth.pubkey(),
                    state.auth.config().rate_limits.human_api_calls_per_min,
                ),
            )
            .await
            {
                Err(_elapsed) => {
                    return Err(IngestInnerOutcome::from(keyed_busy_default()));
                }
                Ok(classified) => match classified {
                    Ok(Some(buzz_db::idempotency::KeyedCommittedOutcome::Replay {
                        original_event_id,
                    })) => {
                        keyed.stored = Some(keyed_duplicate_stored_metric());
                        let claimed = claimed_community_from_event(&event);
                        let action = match channel_id {
                            Some(ch) => TraceAction::WriteDuplicate {
                                msg_id: msg_id_label(&original_event_id),
                                channel: channel_label(ch),
                                claimed_community: claimed,
                            },
                            None => TraceAction::WriteInsertGlobal {
                                msg_id: msg_id_label(&original_event_id),
                                claimed_community: claimed,
                            },
                        };
                        emit(tracer, action, state_for_request(tenant, auth.pubkey()));
                        return Ok(keyed_accepted_duplicate_result(original_event_id));
                    }
                    Ok(Some(buzz_db::idempotency::KeyedCommittedOutcome::Conflict { .. })) => {
                        return Err(IngestInnerOutcome::Conflict);
                    }
                    Ok(None) => {}
                    Err(error) => {
                        return Err(IngestInnerOutcome::from(error));
                    }
                },
            }
            if let Some(early) = keyed_early.as_mut() {
                early.release_ingress();
            }
            let reservation = match tokio::time::timeout(
                KEYED_RESERVATION_PERSIST_BUDGET,
                state.db.begin_keyed_stream_reservation(
                    tenant.community(),
                    &prepared,
                    &event,
                    channel_id,
                    thread_params.as_ref(),
                ),
            )
            .await
            {
                Err(_elapsed) => {
                    return Err(IngestInnerOutcome::from(keyed_busy_default()));
                }
                Ok(Ok(buzz_db::idempotency::KeyedReserveOutcome::Replay { original_event_id })) => {
                    keyed.stored = Some(keyed_duplicate_stored_metric());
                    let claimed = claimed_community_from_event(&event);
                    let action = match channel_id {
                        Some(ch) => TraceAction::WriteDuplicate {
                            msg_id: msg_id_label(&original_event_id),
                            channel: channel_label(ch),
                            claimed_community: claimed,
                        },
                        None => TraceAction::WriteInsertGlobal {
                            msg_id: msg_id_label(&original_event_id),
                            claimed_community: claimed,
                        },
                    };
                    emit(tracer, action, state_for_request(tenant, auth.pubkey()));
                    return Ok(keyed_accepted_duplicate_result(original_event_id));
                }
                Ok(Ok(buzz_db::idempotency::KeyedReserveOutcome::Conflict { .. })) => {
                    return Err(IngestInnerOutcome::Conflict);
                }
                Ok(Ok(buzz_db::idempotency::KeyedReserveOutcome::Reserved(reservation))) => {
                    *reservation
                }
                Ok(Err(error)) if error.is_idempotency_unavailable() => {
                    return Err(IngestInnerOutcome::from(keyed_busy_default()));
                }
                Ok(Err(error)) if error.is_idempotency_unsupported_kind() => {
                    return Err(IngestError::Rejected(
                        "invalid: Idempotency-Key is not supported for this event kind".into(),
                    )
                    .into());
                }
                Ok(Err(error)) if error.is_idempotency_too_many_mentions() => {
                    return Err(IngestError::Rejected(
                        "invalid: too many p tags for keyed ingest".into(),
                    )
                    .into());
                }
                Ok(Err(e)) => {
                    if let Some(ch_id) = pre_created_channel {
                        if let Err(re) = state
                            .db
                            .soft_delete_channel(tenant.community(), ch_id)
                            .await
                        {
                            warn!(event_id = %event_id_hex, "channel compensation failed: {re}");
                        }
                        state.invalidate_channel_deleted(tenant);
                    }
                    return Err(IngestInnerOutcome::from(match e {
                        buzz_db::DbError::AuthEventRejected => {
                            IngestError::Rejected("invalid: AUTH events cannot be stored".into())
                        }
                        other => IngestError::Internal(format!("error: database error: {other}")),
                    }));
                }
            };
            let permits =
                match acquire_keyed_writer_permits(*tenant.community().as_uuid(), &author, &key) {
                    Ok(permits) => permits,
                    Err(busy) => {
                        abort_keyed_reservation(reservation).await;
                        return Err(IngestInnerOutcome::from(busy));
                    }
                };
            let outcome =
                complete_keyed_reservation(reservation, &prepared, &event, thread_params).await;
            drop(permits);
            match outcome {
                Ok(insert) => match insert.into_fresh_stored_event() {
                    Ok(stored_event) => {
                        keyed.stored = Some(keyed_inserted_stored_metric());
                        (*stored_event, true)
                    }
                    Err(buzz_db::KeyedStreamInsert::BoundExisting { event_id })
                    | Err(buzz_db::KeyedStreamInsert::Replay {
                        original_event_id: event_id,
                    }) => {
                        keyed.stored = Some(keyed_duplicate_stored_metric());
                        let claimed = claimed_community_from_event(&event);
                        let action = match channel_id {
                            Some(ch) => TraceAction::WriteDuplicate {
                                msg_id: msg_id_label(&event_id),
                                channel: channel_label(ch),
                                claimed_community: claimed,
                            },
                            None => TraceAction::WriteInsertGlobal {
                                msg_id: msg_id_label(&event_id),
                                claimed_community: claimed,
                            },
                        };
                        emit(tracer, action, state_for_request(tenant, auth.pubkey()));
                        return Ok(keyed_accepted_duplicate_result(event_id));
                    }
                    Err(buzz_db::KeyedStreamInsert::Conflict { .. }) => {
                        return Err(IngestInnerOutcome::Conflict);
                    }
                    Err(
                        buzz_db::KeyedStreamInsert::Inserted { .. }
                        | buzz_db::KeyedStreamInsert::RecoveredFresh { .. },
                    ) => {
                        return Err(IngestError::Internal(
                            "error: keyed persist classification".into(),
                        )
                        .into());
                    }
                },
                Err(error) if error.is_idempotency_unavailable() => {
                    return Err(IngestInnerOutcome::from(keyed_busy_default()));
                }
                Err(error) if error.is_idempotency_unsupported_kind() => {
                    return Err(IngestError::Rejected(
                        "invalid: Idempotency-Key is not supported for this event kind".into(),
                    )
                    .into());
                }
                Err(error) if error.is_idempotency_too_many_mentions() => {
                    return Err(IngestError::Rejected(
                        "invalid: too many p tags for keyed ingest".into(),
                    )
                    .into());
                }
                Err(e) => {
                    if let Some(ch_id) = pre_created_channel {
                        if let Err(re) = state
                            .db
                            .soft_delete_channel(tenant.community(), ch_id)
                            .await
                        {
                            warn!(event_id = %event_id_hex, "channel compensation failed: {re}");
                        }
                        state.invalidate_channel_deleted(tenant);
                    }
                    return Err(IngestInnerOutcome::from(match e {
                        buzz_db::DbError::AuthEventRejected => {
                            IngestError::Rejected("invalid: AUTH events cannot be stored".into())
                        }
                        other => IngestError::Internal(format!("error: database error: {other}")),
                    }));
                }
            }
        } else {
            match state
                .db
                .insert_event_with_thread_metadata(
                    tenant.community(),
                    &event,
                    channel_id,
                    thread_params,
                )
                .await
            {
                Ok(result) => result,
                Err(e) => {
                    // Compensate: if we pre-created a channel for kind:9007,
                    // soft-delete it so no orphaned channel row remains.
                    if let Some(ch_id) = pre_created_channel {
                        if let Err(re) = state
                            .db
                            .soft_delete_channel(tenant.community(), ch_id)
                            .await
                        {
                            warn!(event_id = %event_id_hex, "channel compensation failed: {re}");
                        }
                        state.invalidate_channel_deleted(tenant);
                    }
                    return Err(IngestInnerOutcome::from(match e {
                        buzz_db::DbError::AuthEventRejected => {
                            IngestError::Rejected("invalid: AUTH events cannot be stored".into())
                        }
                        other => IngestError::Internal(format!("error: database error: {other}")),
                    }));
                }
            }
        }
    };

    if !was_inserted {
        return Ok(IngestResult {
            event_id: event_id_hex,
            accepted: true,
            message: "duplicate:".into(),
        });
    }

    if let Some(notices) = atomic_channel_notices.as_ref() {
        super::side_effects::after_atomic_channel_command(tenant, &event, state).await;
        super::side_effects::dispatch_atomic_channel_notices(tenant, state, notices).await;
    } else if crate::handlers::side_effects::is_side_effect_kind(kind_u32) {
        if let Err(e) =
            crate::handlers::side_effects::handle_side_effects(tenant, kind_u32, &event, state)
                .await
        {
            // error!, not warn!: the event was accepted but its side effects
            // (channel creation, git repo seeding, …) did not run — the relay
            // is now in a state the client believes it isn't. Production runs
            // RUST_LOG=error, so warn! made these failures invisible during
            // the #3527 triage.
            error!(event_id = %event_id_hex, kind = kind_u32, "Side effect failed: {e}");
        }
    }

    // A freshly inserted reply changed its thread's counters (updated in the
    // same transaction as the insert) — push a fresh relay-signed 39005 so
    // subscribed clients can update badge counts without refetching the head
    // window. Page responses recompute summaries independently, so this is
    // fan-out-only and best-effort.
    if let Some(meta) = &thread_meta {
        crate::handlers::side_effects::emit_live_thread_summary(
            tenant,
            state,
            meta.channel_id,
            meta.root_event_id.clone(),
        );
    }

    let pubkey_hex = auth.pubkey().to_hex();
    // Spec WriteInsert (line 514) / WriteInsertGlobal (line 559) /
    // WriteDuplicate (line 606): emit the abstract write at the trailing
    // dispatch site. `channel_id.is_some()` distinguishes channel-bearing
    // (Insert/Duplicate) from channel-less (InsertGlobal); `was_inserted`
    // distinguishes accepted-new (Insert/Global) from no-op-on-conflict
    // (Duplicate). The WriteInsertGlobal duplicate case is not modeled
    // separately in the spec (channel-less duplicates collapse to the
    // same observation shape as channel-less inserts at this seam);
    // see docs/spec/MultiTenantRelay.tla lines 559-595.
    {
        let claimed = claimed_community_from_event(&event);
        let action = match (channel_id, was_inserted) {
            (Some(ch), true) => TraceAction::WriteInsert {
                msg_id: msg_id_label(event.id.as_bytes()),
                channel: channel_label(ch),
                claimed_community: claimed,
            },
            (Some(ch), false) => TraceAction::WriteDuplicate {
                msg_id: msg_id_label(event.id.as_bytes()),
                channel: channel_label(ch),
                claimed_community: claimed,
            },
            (None, _) => TraceAction::WriteInsertGlobal {
                msg_id: msg_id_label(event.id.as_bytes()),
                claimed_community: claimed,
            },
        };
        emit(tracer, action, state_for_request(tenant, auth.pubkey()));
    }
    dispatch_persistent_event(
        tenant,
        state,
        &stored_event,
        kind_u32,
        &pubkey_hex,
        if atomic_channel_notices.is_some() {
            None
        } else {
            threaded_visibility.clone()
        },
    )
    .await;

    info!(event_id = %event_id_hex, kind = kind_u32, "Event ingested via pipeline");

    Ok(IngestResult {
        event_id: event_id_hex,
        accepted: true,
        message: String::new(),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use buzz_auth::rate_limit::{PairedAdmissionOutcome, PairedAdmissionRequest};
    use buzz_auth::RateLimiter;
    use buzz_conformance::{TraceStep, Tracer};
    use buzz_core::kind::{
        KIND_CANVAS, KIND_FORUM_COMMENT, KIND_FORUM_POST, KIND_FORUM_VOTE, KIND_LONG_FORM,
        KIND_MANAGED_AGENT, KIND_PERSONA, KIND_PRESENCE_UPDATE, KIND_STREAM_MESSAGE,
        KIND_STREAM_MESSAGE_DIFF, KIND_TEAM, KIND_USER_STATUS,
    };
    use buzz_core::{CommunityId, TenantContext};
    use nostr::{EventBuilder, Kind, Tag, Timestamp};

    #[test]
    fn missing_huddle_backing_channel_is_a_client_rejection() {
        let channel_id = Uuid::new_v4();
        assert!(matches!(
            map_huddle_backing_channel_error(buzz_db::DbError::ChannelNotFound(channel_id)),
            IngestError::Rejected(message) if message.contains("backing channel not found")
        ));
    }

    #[test]
    fn huddle_backing_channel_lookup_outage_is_internal() {
        let error = sqlx::Error::Io(std::io::Error::other("database unavailable"));
        assert!(matches!(
            map_huddle_backing_channel_error(buzz_db::DbError::Sqlx(error)),
            IngestError::Internal(message) if message.contains("loading Huddle backing channel")
        ));
    }

    #[test]
    fn huddle_backing_ttl_honors_the_ephemeral_override() {
        assert_eq!(expected_huddle_backing_ttl(None), 3600);
        assert_eq!(expected_huddle_backing_ttl(Some(60)), 60);
    }

    #[test]
    fn huddle_lifecycle_requires_a_uuid_backing_channel() {
        let event = EventBuilder::new(
            Kind::Custom(KIND_HUDDLE_STARTED as u16),
            r#"{"ephemeral_channel_id":"not-a-uuid"}"#,
        )
        .sign_with_keys(&nostr::Keys::generate())
        .expect("sign Huddle event");

        assert!(matches!(
            huddle_backing_channel_id(&event),
            Err(IngestError::Rejected(message)) if message.contains("must be a UUID")
        ));
    }

    #[test]
    fn huddle_lifecycle_extracts_the_backing_channel() {
        let channel_id = Uuid::new_v4();
        let event = EventBuilder::new(
            Kind::Custom(KIND_HUDDLE_ENDED as u16),
            serde_json::json!({"ephemeral_channel_id": channel_id}).to_string(),
        )
        .sign_with_keys(&nostr::Keys::generate())
        .expect("sign Huddle event");

        assert_eq!(
            huddle_backing_channel_id(&event).expect("channel id"),
            channel_id
        );
    }

    #[test]
    fn reaction_validation_accepts_wrapped_max_shortcode() {
        let shortcode = "a".repeat(buzz_sdk::MAX_CUSTOM_EMOJI_SHORTCODE_LEN);
        let event = EventBuilder::new(Kind::Custom(KIND_REACTION as u16), format!(":{shortcode}:"))
            .tags([
                nostr::Tag::parse(["emoji", &shortcode, "https://example.com/max.png"])
                    .expect("emoji tag"),
            ])
            .sign_with_keys(&nostr::Keys::generate())
            .expect("sign reaction");

        assert!(validate_reaction_emoji(&event, &event.content).is_ok());
    }

    #[test]
    fn reaction_validation_rejects_mixed_case_max_shortcode() {
        let shortcode = "Ab".repeat(buzz_sdk::MAX_CUSTOM_EMOJI_SHORTCODE_LEN / 2);
        let event = EventBuilder::new(Kind::Custom(KIND_REACTION as u16), format!(":{shortcode}:"))
            .tags([
                nostr::Tag::parse(["emoji", &shortcode, "https://example.com/max.png"])
                    .expect("emoji tag"),
            ])
            .sign_with_keys(&nostr::Keys::generate())
            .expect("sign reaction");

        assert!(matches!(
            validate_reaction_emoji(&event, &event.content),
            Err(IngestError::Rejected(_))
        ));
    }

    #[test]
    fn reaction_validation_rejects_case_mismatched_tag() {
        let shortcode = "a".repeat(buzz_sdk::MAX_CUSTOM_EMOJI_SHORTCODE_LEN);
        let uppercase_shortcode = shortcode.to_uppercase();
        let event = EventBuilder::new(Kind::Custom(KIND_REACTION as u16), format!(":{shortcode}:"))
            .tags([nostr::Tag::parse([
                "emoji",
                &uppercase_shortcode,
                "https://example.com/max.png",
            ])
            .expect("emoji tag")])
            .sign_with_keys(&nostr::Keys::generate())
            .expect("sign reaction");

        assert!(matches!(
            validate_reaction_emoji(&event, &event.content),
            Err(IngestError::Rejected(_))
        ));
    }

    #[test]
    fn emoji_set_validation_enforces_shortcode_boundary() {
        let max_shortcode = "a".repeat(buzz_sdk::MAX_CUSTOM_EMOJI_SHORTCODE_LEN);
        let valid_event = EventBuilder::new(Kind::Custom(KIND_EMOJI_SET as u16), "")
            .tags([
                nostr::Tag::parse(["emoji", &max_shortcode, "https://example.com/max.png"])
                    .expect("emoji tag"),
            ])
            .sign_with_keys(&nostr::Keys::generate())
            .expect("sign valid emoji set");
        assert!(validate_custom_emoji_tags(&valid_event).is_ok());

        let shortcode = "a".repeat(buzz_sdk::MAX_CUSTOM_EMOJI_SHORTCODE_LEN + 1);
        let event = EventBuilder::new(Kind::Custom(KIND_EMOJI_SET as u16), "")
            .tags([
                nostr::Tag::parse(["emoji", &shortcode, "https://example.com/long.png"])
                    .expect("emoji tag"),
            ])
            .sign_with_keys(&nostr::Keys::generate())
            .expect("sign emoji set");

        assert!(matches!(
            validate_custom_emoji_tags(&event),
            Err(IngestError::Rejected(message)) if message.contains("exceeds 64 bytes")
        ));
    }

    /// A banned relay admin must be refused with the same wire prefix and
    /// transport status as every other durable-restriction refusal:
    /// `blocked:` and (via `bridge.rs`'s `AuthFailed` arm) HTTP 403 — never
    /// `invalid:`/400, which reads as "your request was malformed" and lets a
    /// client retry-loop against an authorization decision.
    #[test]
    fn relay_admin_ban_maps_to_blocked_auth_failure() {
        let mapped = map_relay_admin_error(super::super::relay_admin::RelayAdminError::Banned);
        match mapped {
            IngestError::AuthFailed(msg) => {
                assert_eq!(msg, "blocked: you are banned from this community");
            }
            other => panic!("banned admin must map to AuthFailed (HTTP 403), got {other:?}"),
        }
    }

    /// Validation/authorization failures keep the pre-existing `invalid:`
    /// prefix and 400 status — this is the arm the whole 9030-series relied on
    /// before the ban category existed, so it must not regress.
    #[test]
    fn relay_admin_rejection_keeps_invalid_prefix() {
        let mapped = map_relay_admin_error(super::super::relay_admin::RelayAdminError::Rejected(
            "actor not authorized: must be admin or owner".to_string(),
        ));
        match mapped {
            IngestError::Rejected(msg) => {
                assert_eq!(
                    msg, "invalid: actor not authorized: must be admin or owner",
                    "existing relay-admin rejections must keep their exact wire text"
                );
            }
            other => panic!("validation failure must map to Rejected, got {other:?}"),
        }
    }

    /// A restriction-lookup outage is a server fault, not a client one. It
    /// must fail closed as `error:`/500 so a Postgres blip can neither admit a
    /// banned admin nor be reported to an innocent one as a bad request.
    #[test]
    fn relay_admin_internal_maps_to_error_not_client_fault() {
        let mapped = map_relay_admin_error(super::super::relay_admin::RelayAdminError::Internal(
            "internal error checking restriction state: pool timed out".to_string(),
        ));
        match mapped {
            IngestError::Internal(msg) => {
                assert!(
                    msg.starts_with("error: "),
                    "internal failures need the `error:` NIP-01 prefix, got {msg:?}"
                );
            }
            other => {
                panic!("restriction DB failure must map to Internal (HTTP 500), got {other:?}")
            }
        }
    }

    /// An active community passes the durable write fence untouched.
    #[test]
    fn serving_fence_active_community_admits_write() {
        assert!(map_serving_fence_state(Ok(true)).is_ok());
    }

    /// A fenced/tombstoned/archived community is an authorization decision:
    /// `restricted:` and (via `bridge.rs`) HTTP 400 — with the exact wire text
    /// the ephemeral WS path uses, so clients see one refusal vocabulary.
    #[test]
    fn serving_fence_inactive_community_maps_to_restricted() {
        match map_serving_fence_state(Ok(false)) {
            Err(IngestError::Rejected(msg)) => {
                assert_eq!(msg, "restricted: community writes are fenced");
            }
            other => panic!("fenced community must map to Rejected, got {other:?}"),
        }
    }

    /// A fence-lookup outage is a server fault and must fail closed as
    /// `error:`/500 — a Postgres blip can neither admit a write past the
    /// fence nor be reported to an innocent client as a bad request.
    #[test]
    fn serving_fence_lookup_outage_fails_closed_as_internal() {
        let outage = buzz_db::DbError::Sqlx(sqlx::Error::PoolTimedOut);
        match map_serving_fence_state(Err(outage)) {
            Err(IngestError::Internal(msg)) => {
                assert!(
                    msg.starts_with("error: "),
                    "fence outages need the `error:` NIP-01 prefix, got {msg:?}"
                );
            }
            other => panic!("fence lookup failure must map to Internal, got {other:?}"),
        }
    }

    /// Production-path regression: the exact predicate `ingest_event_inner`
    /// consults must admit writes while a community is active and refuse them
    /// once the community deletion lifecycle fences it.
    pub(crate) async fn ingest_write_fence_follows_community_deletion_lifecycle() {
        use buzz_db::deletion::{
            FrozenInventory, KeyStreamDigest, PrefixManifest, StorageManifest,
            DEFAULT_LEASE_DURATION,
        };

        let url = crate::test_support::database_url();
        let pool = sqlx::PgPool::connect(&url).await.expect("connect test DB");
        let db = buzz_db::Db::from_pool(pool);
        if std::env::var("BUZZ_TEST_SCHEMA_MODE").as_deref() != Ok("desired") {
            db.migrate().await.expect("migrate test DB");
        }
        let store = buzz_deletion::store(&db);

        let host = format!("lane3-fence-{}.example", Uuid::new_v4().simple());
        let community = db
            .ensure_configured_community(&host)
            .await
            .expect("community")
            .id;

        assert!(
            map_serving_fence_state(store.is_serving_active(community).await).is_ok(),
            "active community must admit persistent ingest"
        );

        let submitted = store
            .submit(
                &host,
                "test-operator",
                Some("lane3 ingest fence regression"),
            )
            .await
            .expect("submit");
        let inventory = FrozenInventory {
            schema: store
                .inventory_schema(community)
                .await
                .expect("schema inventory"),
            storage: StorageManifest {
                version: 4,
                prefixes: buzz_media::tenant_prefixes(*community.as_uuid())
                    .into_iter()
                    .map(|prefix| PrefixManifest {
                        prefix,
                        object_count: 0,
                        total_bytes: 0,
                        keys_digest: KeyStreamDigest::new().finish().0,
                    })
                    .collect(),
            },
        };
        let request = store
            .freeze_inventory(submitted.id, &inventory)
            .await
            .expect("freeze inventory");
        store
            .approve(request.id, "approver", None)
            .await
            .expect("approve");
        let claim = store
            .claim_specific(request.id, "executor", DEFAULT_LEASE_DURATION)
            .await
            .expect("claim")
            .expect("won claim");
        store.begin_quiescing(&claim.lease).await.expect("quiesce");
        store.fence(&claim.lease).await.expect("fence");

        match map_serving_fence_state(store.is_serving_active(community).await) {
            Err(IngestError::Rejected(msg)) => {
                assert_eq!(msg, "restricted: community writes are fenced");
            }
            other => panic!("fenced community must refuse persistent ingest, got {other:?}"),
        }
    }

    #[derive(Debug, Default)]
    struct VecTracer {
        steps: Mutex<Vec<TraceStep>>,
    }

    impl Tracer for VecTracer {
        fn record(&self, step: TraceStep) {
            self.steps.lock().expect("trace lock").push(step);
        }
    }

    #[test]
    fn feedback_success_action_satisfies_ingest_emit_guard() {
        let community = buzz_core::CommunityId::from_uuid(Uuid::new_v4());
        let tenant = TenantContext::resolved(community, "feedback.test");
        let keys = nostr::Keys::generate();
        let event = EventBuilder::new(
            Kind::Custom(KIND_PRODUCT_FEEDBACK as u16),
            "Useful feedback",
        )
        .sign_with_keys(&keys)
        .expect("sign feedback");
        let auth = IngestAuth::Http {
            moderation_owner: None,
            pubkey: keys.public_key(),
            scopes: vec![Scope::MessagesWrite],
            auth_method: HttpAuthMethod::Nip98,
        };
        let tracer = Arc::new(VecTracer::default());
        let abstract_state = state_for_request(&tenant, auth.pubkey());

        {
            let (guard, counting) = EmitGuard::arm(
                tracer.clone(),
                abstract_state.clone(),
                "ingest_event_exited_without_trace",
            );
            emit_product_feedback_success(&counting, &tenant, &event, &auth);
            drop(guard);
        }

        let steps = tracer.steps.lock().expect("trace lock");
        assert_eq!(steps.len(), 1);
        assert!(matches!(
            steps[0].action,
            TraceAction::WriteInsertGlobal { .. }
        ));
    }

    #[test]
    fn nip_ia_requests_are_global_only() {
        // NIP-IA requests drive relay-global archive state; a stray `h` tag
        // must not channel-scope them, or the global audit trail breaks.
        for kind in [KIND_IA_ARCHIVE_REQUEST, KIND_IA_UNARCHIVE_REQUEST] {
            assert!(is_global_only_kind(kind), "kind {kind} must be global-only");
            assert!(
                !requires_h_channel_scope(kind),
                "kind {kind} must not require an h tag"
            );
        }
    }

    #[test]
    fn channel_scoped_content_kinds_require_h_tags() {
        for kind in [
            KIND_STREAM_MESSAGE,
            KIND_STREAM_MESSAGE_DIFF,
            KIND_CANVAS,
            KIND_FORUM_POST,
            KIND_FORUM_VOTE,
            KIND_FORUM_COMMENT,
        ] {
            assert!(
                requires_h_channel_scope(kind),
                "kind {kind} should require h"
            );
        }
    }

    #[test]
    fn nip29_admin_kinds_require_h_tags() {
        for kind in [
            KIND_NIP29_PUT_USER,
            KIND_NIP29_REMOVE_USER,
            KIND_NIP29_EDIT_METADATA,
            KIND_NIP29_DELETE_EVENT,
            KIND_NIP29_DELETE_GROUP,
            KIND_NIP29_LEAVE_REQUEST,
        ] {
            assert!(
                requires_h_channel_scope(kind),
                "kind {kind} should require h"
            );
        }
    }

    #[test]
    fn create_group_does_not_require_h_tag() {
        // kind:9007 creates the channel — h-tag is optional (client-chosen UUID)
        assert!(!requires_h_channel_scope(KIND_NIP29_CREATE_GROUP));
    }

    #[test]
    fn join_request_does_not_require_h_tag_via_requires_h() {
        // kind:9021 uses h-tag for channel reference but doesn't go through
        // requires_h_channel_scope — it's handled separately in the pipeline
        // because it needs special "open-only" validation
        assert!(!requires_h_channel_scope(KIND_NIP29_JOIN_REQUEST));
    }

    #[test]
    fn reactions_do_not_require_h_tag() {
        assert!(!requires_h_channel_scope(KIND_REACTION));
    }

    #[test]
    fn long_form_is_in_scope_allowlist() {
        let dummy = make_dummy_event();
        assert!(
            required_scope_for_kind(KIND_LONG_FORM, &dummy).is_ok(),
            "KIND_LONG_FORM (30023) should be accepted"
        );
    }

    #[test]
    fn long_form_requires_messages_write_scope() {
        let dummy = make_dummy_event();
        assert_eq!(
            required_scope_for_kind(KIND_LONG_FORM, &dummy).unwrap(),
            Scope::MessagesWrite,
        );
    }

    #[test]
    fn long_form_does_not_require_h_tag() {
        // kind:30023 is global (author-owned, not channel-scoped)
        assert!(!requires_h_channel_scope(KIND_LONG_FORM));
    }

    #[test]
    fn long_form_is_global_only() {
        // kind:30023 is always global — ingest nulls channel_id even if an h-tag is present
        assert!(is_global_only_kind(KIND_LONG_FORM));
    }

    #[test]
    fn user_status_requires_users_write_scope() {
        let dummy = make_dummy_event();
        assert_eq!(
            required_scope_for_kind(KIND_USER_STATUS, &dummy).unwrap(),
            Scope::UsersWrite,
        );
    }

    #[test]
    fn user_status_is_global_only() {
        assert!(is_global_only_kind(KIND_USER_STATUS));
    }

    #[test]
    fn user_status_does_not_require_h_tag() {
        assert!(!requires_h_channel_scope(KIND_USER_STATUS));
    }

    #[test]
    fn private_sidecars_and_moderation_commands_require_messages_write_scope() {
        let dummy = make_dummy_event();
        for kind in [
            KIND_REPORT,
            KIND_PRODUCT_FEEDBACK,
            KIND_MODERATION_BAN,
            KIND_MODERATION_UNBAN,
            KIND_MODERATION_TIMEOUT,
            KIND_MODERATION_UNTIMEOUT,
            KIND_MODERATION_RESOLVE_REPORT,
        ] {
            assert_eq!(
                required_scope_for_kind(kind, &dummy).unwrap(),
                Scope::MessagesWrite,
                "kind {kind} should require MessagesWrite scope"
            );
        }
    }

    #[test]
    fn moderation_commands_are_global_only() {
        for kind in [
            KIND_MODERATION_BAN,
            KIND_MODERATION_UNBAN,
            KIND_MODERATION_TIMEOUT,
            KIND_MODERATION_UNTIMEOUT,
            KIND_MODERATION_RESOLVE_REPORT,
        ] {
            assert!(is_global_only_kind(kind), "kind {kind} must be global-only");
            assert!(
                !requires_h_channel_scope(kind),
                "kind {kind} must not require an h tag"
            );
        }
    }

    #[test]
    fn moderation_command_rejection_from_ingest_preserves_prefix() {
        let rejection = "restricted: moderator access required".to_string();
        let map_rejection = IngestError::Rejected;
        let result: Result<(), String> = Err(rejection.clone());

        match result.map_err(map_rejection).unwrap_err() {
            IngestError::Rejected(message) => assert_eq!(message, rejection),
            _ => panic!("expected rejected ingest error"),
        }
    }

    #[test]
    fn push_infrastructure_failures_are_internal_not_protocol_invalid() {
        match map_push_accept_error(crate::handlers::push_lease::AcceptError::Internal(
            "gateway unavailable".to_string(),
        )) {
            IngestError::Internal(message) => {
                assert_eq!(message, "gateway unavailable");
                assert!(!message.starts_with("invalid:"));
            }
            _ => panic!("infrastructure failure became a protocol rejection"),
        }
        match map_push_accept_error(crate::handlers::push_lease::AcceptError::Validation(
            "unknown executor key".to_string(),
        )) {
            IngestError::Rejected(message) => {
                assert_eq!(message, "invalid: unknown executor key")
            }
            _ => panic!("validation failure did not become a protocol rejection"),
        }
    }

    #[test]
    fn global_only_and_channel_scoped_are_disjoint() {
        // A kind cannot be both global-only and channel-scoped
        for kind in 0..=65535u32 {
            assert!(
                !(is_global_only_kind(kind) && requires_h_channel_scope(kind)),
                "kind {kind} is both global-only and channel-scoped"
            );
        }
    }

    #[test]
    fn private_managed_agent_kind_is_owner_scoped_global_user_data() {
        let event = make_dummy_event();
        assert_eq!(
            required_scope_for_kind(KIND_PRIVATE_MANAGED_AGENT, &event),
            Ok(Scope::UsersWrite)
        );
        assert!(is_global_only_kind(KIND_PRIVATE_MANAGED_AGENT));
        assert!(!requires_h_channel_scope(KIND_PRIVATE_MANAGED_AGENT));
    }

    #[test]
    fn ephemeral_kinds_not_in_scope_allowlist() {
        assert!(required_scope_for_kind(KIND_PRESENCE_UPDATE, &make_dummy_event()).is_err());
    }

    #[test]
    fn per_kind_scope_allowlist_covers_all_migrated_kinds() {
        let dummy = make_dummy_event();
        let migrated = [
            KIND_PROFILE,
            KIND_DELETION,
            KIND_REACTION,
            KIND_REPORT,
            KIND_PRODUCT_FEEDBACK,
            KIND_MODERATION_BAN,
            KIND_MODERATION_UNBAN,
            KIND_MODERATION_TIMEOUT,
            KIND_MODERATION_UNTIMEOUT,
            KIND_MODERATION_RESOLVE_REPORT,
            KIND_STREAM_MESSAGE,
            KIND_NIP29_PUT_USER,
            KIND_NIP29_REMOVE_USER,
            KIND_NIP29_EDIT_METADATA,
            KIND_NIP29_DELETE_EVENT,
            KIND_NIP29_CREATE_GROUP,
            KIND_NIP29_DELETE_GROUP,
            KIND_NIP29_JOIN_REQUEST,
            KIND_NIP29_LEAVE_REQUEST,
            KIND_STREAM_MESSAGE_EDIT,
            KIND_STREAM_MESSAGE_DIFF,
            KIND_CANVAS,
            KIND_FORUM_POST,
            KIND_FORUM_VOTE,
            KIND_FORUM_COMMENT,
            KIND_LONG_FORM,
            KIND_USER_STATUS,
            // NIP-51 lists + sets, NIP-65 relay list
            KIND_MUTE_LIST,
            KIND_PIN_LIST,
            KIND_NIP65_RELAY_LIST_METADATA,
            KIND_BOOKMARK_LIST,
            KIND_FOLLOW_SET,
            KIND_BOOKMARK_SET,
            KIND_EMOJI_SET,
            KIND_EMOJI_LIST,
            KIND_AGENT_ENGRAM,
            KIND_AGENT_PROFILE,
            KIND_PERSONA,
            KIND_TEAM,
            KIND_MANAGED_AGENT,
            KIND_AGENT_TURN_METRIC,
        ];
        for kind in migrated {
            assert!(
                required_scope_for_kind(kind, &dummy).is_ok(),
                "kind {kind} should be in the allowlist"
            );
        }
    }

    #[test]
    fn nip51_and_nip65_lists_require_users_write() {
        let dummy = make_dummy_event();
        for kind in [
            KIND_MUTE_LIST,
            KIND_PIN_LIST,
            KIND_NIP65_RELAY_LIST_METADATA,
            KIND_BOOKMARK_LIST,
            KIND_FOLLOW_SET,
            KIND_BOOKMARK_SET,
        ] {
            assert_eq!(
                required_scope_for_kind(kind, &dummy).ok(),
                Some(Scope::UsersWrite),
                "kind {kind} should require UsersWrite scope"
            );
        }
    }

    #[test]
    fn agent_turn_metric_is_global_only_and_in_scope_allowlist() {
        let dummy = make_dummy_event();
        assert!(
            is_global_only_kind(KIND_AGENT_TURN_METRIC),
            "kind:44200 must be global-only (no h tag)"
        );
        assert!(
            !requires_h_channel_scope(KIND_AGENT_TURN_METRIC),
            "kind:44200 must not require an h-tag"
        );
        assert_eq!(
            required_scope_for_kind(KIND_AGENT_TURN_METRIC, &dummy).unwrap(),
            Scope::MessagesWrite,
            "kind:44200 requires MessagesWrite scope"
        );
    }

    #[test]
    fn nip51_and_nip65_lists_are_global_only() {
        for kind in [
            KIND_MUTE_LIST,
            KIND_PIN_LIST,
            KIND_NIP65_RELAY_LIST_METADATA,
            KIND_BOOKMARK_LIST,
            KIND_FOLLOW_SET,
            KIND_BOOKMARK_SET,
        ] {
            assert!(
                is_global_only_kind(kind),
                "kind {kind} should be global-only (never channel-scoped)"
            );
            assert!(
                !requires_h_channel_scope(kind),
                "kind {kind} must not require an h-tag channel scope"
            );
        }
    }

    #[test]
    fn persona_is_in_scope_allowlist() {
        let dummy = make_dummy_event();
        assert_eq!(
            required_scope_for_kind(KIND_PERSONA, &dummy).unwrap(),
            Scope::UsersWrite,
        );
    }

    #[test]
    fn persona_is_global_only() {
        assert!(is_global_only_kind(KIND_PERSONA));
        assert!(!requires_h_channel_scope(KIND_PERSONA));
    }

    #[test]
    fn team_and_managed_agent_are_in_scope_allowlist() {
        let dummy = make_dummy_event();
        for kind in [KIND_TEAM, KIND_MANAGED_AGENT] {
            assert_eq!(
                required_scope_for_kind(kind, &dummy).unwrap(),
                Scope::UsersWrite,
                "kind {kind} should require UsersWrite scope"
            );
        }
    }

    #[test]
    fn team_and_managed_agent_are_global_only() {
        for kind in [KIND_TEAM, KIND_MANAGED_AGENT] {
            assert!(
                is_global_only_kind(kind),
                "kind {kind} should be global-only (never channel-scoped)"
            );
            assert!(
                !requires_h_channel_scope(kind),
                "kind {kind} must not require an h-tag channel scope"
            );
        }
    }

    #[test]
    fn unknown_kind_rejected() {
        let dummy = make_dummy_event();
        assert!(required_scope_for_kind(99999, &dummy).is_err());
    }

    #[test]
    fn gift_wrap_is_in_scope_allowlist() {
        // KIND_GIFT_WRAP is still in the per-kind scope allowlist.
        // The HTTP block is transport-level (is_http gate), not scope-level.
        let dummy = make_dummy_event();
        assert!(
            required_scope_for_kind(KIND_GIFT_WRAP, &dummy).is_ok(),
            "KIND_GIFT_WRAP should be in the scope allowlist"
        );
    }

    #[test]
    fn accounting_uses_authenticated_principal_pubkey() {
        let principal = nostr::Keys::generate();
        let envelope_signer = nostr::Keys::generate();
        let auth = IngestAuth::Nip42 {
            moderation_owner: None,
            pubkey: principal.public_key(),
            scopes: vec![],
            channel_ids: None,
            conn_id: Uuid::new_v4(),
        };

        assert_ne!(principal.public_key(), envelope_signer.public_key());
        assert_eq!(
            auth.principal_pubkey_bytes(),
            principal.public_key().to_bytes().to_vec()
        );
    }

    #[test]
    fn ingest_auth_is_http_returns_true_for_http_variant() {
        use crate::handlers::ingest::{HttpAuthMethod, IngestAuth};
        let keys = nostr::Keys::generate();
        let http_auth = IngestAuth::Http {
            moderation_owner: None,
            pubkey: keys.public_key(),
            scopes: vec![],
            auth_method: HttpAuthMethod::Nip98,
        };
        assert!(
            http_auth.is_http(),
            "Http variant should return true for is_http()"
        );
    }

    #[test]
    fn ingest_auth_is_http_returns_false_for_nip42_variant() {
        use crate::handlers::ingest::IngestAuth;
        let keys = nostr::Keys::generate();
        let ws_auth = IngestAuth::Nip42 {
            moderation_owner: None,
            pubkey: keys.public_key(),
            scopes: vec![],
            channel_ids: None,
            conn_id: uuid::Uuid::new_v4(),
        };
        assert!(
            !ws_auth.is_http(),
            "Nip42 variant should return false for is_http()"
        );
    }

    #[test]
    fn keyed_inserted_increments_stored_metric() {
        assert!(keyed_http_should_increment_stored(Some(
            keyed_inserted_stored_metric()
        )));
        assert_eq!(keyed_inserted_stored_metric(), KeyedStoredMetric::Increment);
    }

    #[test]
    fn keyed_recovered_fresh_classification_reaches_the_same_fresh_branch() {
        // Ingest persist classifies through `into_fresh_stored_event`: Ok is
        // the fresh branch for both Inserted and RecoveredFresh (dispatch,
        // side effects, WriteInsert, stored metric, accepted). Replay and
        // BoundExisting stay duplicate; Conflict stays failure.
        let replay = buzz_db::KeyedStreamInsert::Replay {
            original_event_id: [0x11; 32],
        };
        let bound = buzz_db::KeyedStreamInsert::BoundExisting {
            event_id: [0x22; 32],
        };
        let conflict = buzz_db::KeyedStreamInsert::Conflict {
            existing_event_id: [0x33; 32],
        };
        assert!(!replay.should_dispatch());
        assert!(!bound.should_dispatch());
        assert!(!conflict.should_dispatch());

        let replay = replay
            .into_fresh_stored_event()
            .expect_err("replay is not fresh");
        let bound = bound
            .into_fresh_stored_event()
            .expect_err("bound-existing is not fresh");
        let conflict = conflict
            .into_fresh_stored_event()
            .expect_err("conflict is not fresh");
        assert!(matches!(
            replay,
            buzz_db::KeyedStreamInsert::Replay {
                original_event_id
            } if original_event_id == [0x11; 32]
        ));
        assert!(matches!(
            bound,
            buzz_db::KeyedStreamInsert::BoundExisting { event_id }
                if event_id == [0x22; 32]
        ));
        assert!(matches!(
            conflict,
            buzz_db::KeyedStreamInsert::Conflict { .. }
        ));
        assert!(!replay.should_dispatch());
        assert!(!bound.should_dispatch());
        assert!(!conflict.should_dispatch());
        assert!(keyed_http_should_increment_stored(Some(
            keyed_inserted_stored_metric()
        )));
        assert!(!keyed_http_should_increment_stored(Some(
            keyed_duplicate_stored_metric()
        )));
    }

    #[test]
    fn keyed_replay_and_bound_existing_do_not_increment_stored_metric() {
        let skip = keyed_duplicate_stored_metric();
        assert_eq!(skip, KeyedStoredMetric::Skip);
        assert!(!keyed_http_should_increment_stored(Some(skip)));
        assert!(!keyed_http_should_increment_stored(None));
    }

    #[test]
    fn keyed_duplicate_response_stays_accepted_with_original_event_id() {
        let original = [0xab; 32];
        let result = keyed_accepted_duplicate_result(original);
        assert!(result.accepted);
        assert_eq!(result.event_id, hex::encode(original));
        assert_eq!(result.message, "duplicate:");
        assert!(!keyed_http_should_increment_stored(Some(
            keyed_duplicate_stored_metric()
        )));
    }

    #[test]
    fn keyed_kind_and_p_tag_gates_reject_before_fleet_persist() {
        assert!(
            !buzz_core::idempotency::supports_keyed_kind(1),
            "unsupported kinds fail before the keyed persist/fleet branch"
        );
        assert!(buzz_core::idempotency::supports_keyed_kind(
            KIND_STREAM_MESSAGE
        ));
        assert_eq!(buzz_core::idempotency::KEYED_MAX_P_TAGS, 64);
    }

    fn keyed_http_auth(pubkey: nostr::PublicKey) -> IngestAuth {
        IngestAuth::Http {
            moderation_owner: None,
            pubkey,
            scopes: Scope::all_known(),
            auth_method: HttpAuthMethod::Nip98,
        }
    }

    fn signed_kind9(keys: &nostr::Keys, content: &str, extra_tags: Vec<Tag>) -> Event {
        let expected_tag_count = extra_tags.len();
        let event = EventBuilder::new(Kind::Custom(KIND_STREAM_MESSAGE as u16), content)
            .tags(extra_tags)
            .allow_self_tagging()
            .sign_with_keys(keys)
            .expect("sign kind 9");
        assert_eq!(event.tags.len(), expected_tag_count);
        event
    }

    fn repeated_p_tags(count: usize, value: &str) -> Vec<Tag> {
        (0..count)
            .map(|_| Tag::parse(["p", value]).expect("p tag"))
            .collect()
    }

    fn assert_too_many_keyed_p_tags(err: IngestError) {
        assert!(
            matches!(
                err,
                IngestError::Rejected(ref msg)
                    if msg == "invalid: too many p tags for keyed ingest"
            ),
            "expected keyed p-tag cap rejection, got {err:?}"
        );
    }

    fn assert_too_many_unkeyed_p_tags(err: IngestError) {
        assert!(
            matches!(
                err,
                IngestError::Rejected(ref msg) if msg == "invalid: too many p tags"
            ),
            "expected unkeyed p-tag cap rejection, got {err:?}"
        );
    }

    fn signed_kind1(keys: &nostr::Keys, content: &str, extra_tags: Vec<Tag>) -> Event {
        let expected_tag_count = extra_tags.len();
        let event = EventBuilder::new(Kind::TextNote, content)
            .tags(extra_tags)
            .allow_self_tagging()
            .sign_with_keys(keys)
            .expect("sign kind 1");
        assert_eq!(event.tags.len(), expected_tag_count);
        event
    }

    fn http_auth_for(keys: &nostr::Keys) -> IngestAuth {
        keyed_http_auth(keys.public_key())
    }

    #[tokio::test]
    async fn keyed_pre_command_validation_rejects_unsupported_kind() {
        let keys = nostr::Keys::generate();
        let event = EventBuilder::new(Kind::TextNote, "fresh")
            .sign_with_keys(&keys)
            .expect("sign");
        let err = KeyedHttpValidatedEvent::validate(event, http_auth_for(&keys))
            .await
            .expect_err("kind 1 is not keyed");
        assert!(matches!(
            err,
            IngestError::Rejected(ref msg)
                if msg == "invalid: Idempotency-Key is not supported for this event kind"
        ));
    }

    #[tokio::test]
    async fn keyed_pre_command_validation_rejects_invalid_id_and_signature() {
        let keys = nostr::Keys::generate();
        let event = signed_kind9(&keys, "fresh", Vec::new());
        let mut value = serde_json::to_value(&event).expect("json");
        let sig = value
            .get("sig")
            .and_then(|v| v.as_str())
            .expect("sig")
            .to_owned();
        let flipped = format!(
            "{}{}",
            if sig.as_bytes()[0] == b'0' { '1' } else { '0' },
            &sig[1..]
        );
        value["sig"] = serde_json::Value::String(flipped);
        let forged: Event = serde_json::from_value(value).expect("forged event");
        let err = KeyedHttpValidatedEvent::validate(forged, http_auth_for(&keys))
            .await
            .expect_err("forged sig");
        assert!(matches!(err, IngestError::Rejected(ref msg) if msg.starts_with("invalid:")));
    }

    #[tokio::test]
    async fn keyed_pre_command_validation_rejects_stale_timestamp() {
        let keys = nostr::Keys::generate();
        let event = EventBuilder::new(Kind::Custom(KIND_STREAM_MESSAGE as u16), "fresh")
            .custom_created_at(Timestamp::from(1u64))
            .sign_with_keys(&keys)
            .expect("sign");
        let err = KeyedHttpValidatedEvent::validate(event, http_auth_for(&keys))
            .await
            .expect_err("stale");
        assert!(matches!(
            err,
            IngestError::Rejected(ref msg)
                if msg == "invalid: event timestamp too far from server time"
        ));
    }

    #[tokio::test]
    async fn keyed_pre_command_validation_rejects_oversized_content() {
        let keys = nostr::Keys::generate();
        let content = "x".repeat(MAX_EVENT_CONTENT_BYTES + 1);
        let event = signed_kind9(&keys, &content, Vec::new());
        let err = KeyedHttpValidatedEvent::validate(event, http_auth_for(&keys))
            .await
            .expect_err("oversized");
        assert!(matches!(
            err,
            IngestError::Rejected(ref msg)
                if msg.starts_with("invalid: content exceeds maximum size of")
        ));
    }

    #[tokio::test]
    async fn keyed_pre_command_validation_rejects_pubkey_mismatch() {
        let author = nostr::Keys::generate();
        let caller = nostr::Keys::generate();
        let event = signed_kind9(&author, "fresh", Vec::new());
        let err = KeyedHttpValidatedEvent::validate(event, http_auth_for(&caller))
            .await
            .expect_err("mismatch");
        assert!(matches!(
            err,
            IngestError::AuthFailed(ref msg)
                if msg == "invalid: event pubkey does not match authenticated identity"
        ));
    }

    #[tokio::test]
    async fn keyed_pre_command_validation_rejects_excessive_p_tags() {
        let keys = nostr::Keys::generate();
        let hex = keys.public_key().to_hex();
        let tags: Vec<Tag> = (0..=buzz_core::idempotency::KEYED_MAX_P_TAGS)
            .map(|_| Tag::parse(["p", &hex]).expect("p tag"))
            .collect();
        let event = signed_kind9(&keys, "fresh", tags);
        let err = KeyedHttpValidatedEvent::validate(event, http_auth_for(&keys))
            .await
            .expect_err("p-tag bound");
        assert!(matches!(
            err,
            IngestError::Rejected(ref msg) if msg == "invalid: too many p tags for keyed ingest"
        ));
    }

    #[tokio::test]
    async fn keyed_pre_command_validation_accepts_supported_kind9() {
        let keys = nostr::Keys::generate();
        let event = signed_kind9(&keys, "fresh", Vec::new());
        let validated = KeyedHttpValidatedEvent::validate(event, http_auth_for(&keys))
            .await
            .expect("kind 9 must pass pre-command checks");
        assert_eq!(validated.event().pubkey, keys.public_key());
        assert_eq!(event_kind_u32(validated.event()), KIND_STREAM_MESSAGE);
    }

    #[test]
    fn keyed_timestamp_drift_accepts_inclusive_900_rejects_901_and_extreme_u64() {
        let fixed_now: i64 = 1_700_000_000;
        let plus_900 = (fixed_now + MAX_TIMESTAMP_DRIFT_SECS) as u64;
        let minus_900 = (fixed_now - MAX_TIMESTAMP_DRIFT_SECS) as u64;
        let plus_901 = (fixed_now + MAX_TIMESTAMP_DRIFT_SECS + 1) as u64;
        let minus_901 = (fixed_now - MAX_TIMESTAMP_DRIFT_SECS - 1) as u64;
        let extreme = (fixed_now as u64).wrapping_add(1u64 << 63);

        assert!(!timestamp_drift_exceeds_max(plus_900, fixed_now));
        assert!(!timestamp_drift_exceeds_max(minus_900, fixed_now));
        assert!(timestamp_drift_exceeds_max(plus_901, fixed_now));
        assert!(timestamp_drift_exceeds_max(minus_901, fixed_now));
        assert!(timestamp_drift_exceeds_max(extreme, fixed_now));
        assert!(timestamp_drift_exceeds_max(u64::MAX, fixed_now));
    }

    #[tokio::test]
    async fn keyed_pre_command_validation_rejects_extreme_signed_timestamp() {
        let keys = nostr::Keys::generate();
        let fixed_now: i64 = 1_700_000_000;
        let extreme = (fixed_now as u64).wrapping_add(1u64 << 63);
        let event = EventBuilder::new(Kind::Custom(KIND_STREAM_MESSAGE as u16), "fresh")
            .custom_created_at(Timestamp::from(extreme))
            .sign_with_keys(&keys)
            .expect("sign");
        let err = KeyedHttpValidatedEvent::validate(event, http_auth_for(&keys))
            .await
            .expect_err("extreme timestamp");
        assert!(matches!(
            err,
            IngestError::Rejected(ref msg)
                if msg == "invalid: event timestamp too far from server time"
        ));
    }

    #[tokio::test]
    async fn keyed_validated_event_retains_exact_auth_variant_and_scopes() {
        let keys = nostr::Keys::generate();
        let event = signed_kind9(&keys, "fresh", Vec::new());

        let http_auth = IngestAuth::Http {
            moderation_owner: None,
            pubkey: keys.public_key(),
            scopes: vec![Scope::MessagesWrite],
            auth_method: HttpAuthMethod::DevPubkey,
        };
        let http_proof = KeyedHttpValidatedEvent::validate(event.clone(), http_auth)
            .await
            .expect("http MessagesWrite");
        assert!(matches!(
            http_proof.auth(),
            IngestAuth::Http {
                moderation_owner: None,
                pubkey,
                scopes,
                auth_method: HttpAuthMethod::DevPubkey,
            } if *pubkey == keys.public_key()
                && scopes.as_slice() == [Scope::MessagesWrite].as_slice()
        ));

        let channel_ids = vec![Uuid::from_u128(7)];
        let conn_id = Uuid::from_u128(11);
        let ws_auth = IngestAuth::Nip42 {
            moderation_owner: None,
            pubkey: keys.public_key(),
            scopes: vec![Scope::MessagesWrite],
            channel_ids: Some(channel_ids.clone()),
            conn_id,
        };
        let ws_proof = KeyedHttpValidatedEvent::validate(event, ws_auth)
            .await
            .expect("nip42 MessagesWrite");
        assert!(matches!(
            ws_proof.auth(),
            IngestAuth::Nip42 {
                moderation_owner: None,
                pubkey,
                scopes,
                channel_ids: Some(ids),
                conn_id: retained_conn,
            } if *pubkey == keys.public_key()
                && scopes.as_slice() == [Scope::MessagesWrite].as_slice()
                && ids.as_slice() == channel_ids.as_slice()
                && *retained_conn == conn_id
        ));
        assert_eq!(ws_proof.auth().channel_ids(), Some(channel_ids.as_slice()));
        assert!(!ws_proof.auth().is_http());
    }

    #[tokio::test]
    async fn keyed_unsupported_kind_rejection_precedes_p_tag_cap() {
        let keys = nostr::Keys::generate();
        let hex = keys.public_key().to_hex();
        let tags = repeated_p_tags(buzz_core::idempotency::KEYED_MAX_P_TAGS + 1, &hex);
        let event = signed_kind1(&keys, "fresh", tags);
        let err = KeyedHttpValidatedEvent::validate(event, http_auth_for(&keys))
            .await
            .expect_err("kind 1 is not keyed");
        assert!(matches!(
            err,
            IngestError::Rejected(ref msg)
                if msg == "invalid: Idempotency-Key is not supported for this event kind"
        ));
    }

    #[tokio::test]
    async fn keyed_refactor_preserves_unkeyed_kind1_without_p_tag_cap_bypass() {
        let keys = nostr::Keys::generate();
        let http_auth = http_auth_for(&keys);
        let ws_auth = IngestAuth::Nip42 {
            moderation_owner: None,
            pubkey: keys.public_key(),
            scopes: Scope::all_known(),
            channel_ids: None,
            conn_id: Uuid::new_v4(),
        };
        let kind1 = EventBuilder::new(Kind::TextNote, "fresh")
            .sign_with_keys(&keys)
            .expect("sign");
        validate_ingest_pre_command(kind1.clone(), &http_auth, false)
            .await
            .expect("unkeyed HTTP kind 1 remains valid");
        validate_ingest_pre_command(kind1, &ws_auth, false)
            .await
            .expect("WebSocket kind 1 remains valid");
    }

    #[tokio::test]
    async fn unkeyed_kind1_pre_command_accepts_sixty_four_actual_p_tags() {
        let keys = nostr::Keys::generate();
        let hex = keys.public_key().to_hex();
        let tags = repeated_p_tags(buzz_core::idempotency::KEYED_MAX_P_TAGS, &hex);
        let event = signed_kind1(&keys, "fresh", tags);
        assert_eq!(
            buzz_core::idempotency::keyed_p_tag_count(&event),
            buzz_core::idempotency::KEYED_MAX_P_TAGS
        );
        let http_auth = http_auth_for(&keys);
        let ws_auth = IngestAuth::Nip42 {
            moderation_owner: None,
            pubkey: keys.public_key(),
            scopes: Scope::all_known(),
            channel_ids: None,
            conn_id: Uuid::new_v4(),
        };
        validate_ingest_pre_command(event.clone(), &http_auth, false)
            .await
            .expect("unkeyed HTTP kind 1 with 64 p tags");
        validate_ingest_pre_command(event, &ws_auth, false)
            .await
            .expect("unkeyed WebSocket kind 1 with 64 p tags");
    }

    #[tokio::test]
    async fn unkeyed_kind1_pre_command_rejects_sixty_five_actual_p_tags() {
        let keys = nostr::Keys::generate();
        let hex = keys.public_key().to_hex();
        let tags = repeated_p_tags(buzz_core::idempotency::KEYED_MAX_P_TAGS + 1, &hex);
        let event = signed_kind1(&keys, "fresh", tags);
        assert_eq!(
            buzz_core::idempotency::keyed_p_tag_count(&event),
            buzz_core::idempotency::KEYED_MAX_P_TAGS + 1
        );
        let http_auth = http_auth_for(&keys);
        let ws_auth = IngestAuth::Nip42 {
            moderation_owner: None,
            pubkey: keys.public_key(),
            scopes: Scope::all_known(),
            channel_ids: None,
            conn_id: Uuid::new_v4(),
        };
        assert_too_many_unkeyed_p_tags(
            validate_ingest_pre_command(event.clone(), &http_auth, false)
                .await
                .expect_err("unkeyed HTTP kind 1 with 65 p tags"),
        );
        assert_too_many_unkeyed_p_tags(
            validate_ingest_pre_command(event, &ws_auth, false)
                .await
                .expect_err("unkeyed WebSocket kind 1 with 65 p tags"),
        );
    }

    #[tokio::test]
    async fn unkeyed_kind9_pre_command_accepts_sixty_four_actual_p_tags() {
        let keys = nostr::Keys::generate();
        let hex = keys.public_key().to_hex();
        let tags = repeated_p_tags(buzz_core::idempotency::KEYED_MAX_P_TAGS, &hex);
        let event = signed_kind9(&keys, "fresh", tags);
        assert_eq!(
            buzz_core::idempotency::keyed_p_tag_count(&event),
            buzz_core::idempotency::KEYED_MAX_P_TAGS
        );
        let http_auth = http_auth_for(&keys);
        let ws_auth = IngestAuth::Nip42 {
            moderation_owner: None,
            pubkey: keys.public_key(),
            scopes: Scope::all_known(),
            channel_ids: None,
            conn_id: Uuid::new_v4(),
        };
        validate_ingest_pre_command(event.clone(), &http_auth, false)
            .await
            .expect("unkeyed HTTP kind 9 with 64 p tags");
        validate_ingest_pre_command(event.clone(), &ws_auth, false)
            .await
            .expect("unkeyed WebSocket kind 9 with 64 p tags");
        KeyedHttpValidatedEvent::validate(event, http_auth)
            .await
            .expect("keyed kind 9 with 64 p tags remains accepted");
    }

    #[tokio::test]
    async fn unkeyed_kind9_pre_command_rejects_sixty_five_actual_p_tags() {
        let keys = nostr::Keys::generate();
        let hex = keys.public_key().to_hex();
        let tags = repeated_p_tags(buzz_core::idempotency::KEYED_MAX_P_TAGS + 1, &hex);
        let event = signed_kind9(&keys, "fresh", tags);
        assert_eq!(
            buzz_core::idempotency::keyed_p_tag_count(&event),
            buzz_core::idempotency::KEYED_MAX_P_TAGS + 1
        );
        let http_auth = http_auth_for(&keys);
        let ws_auth = IngestAuth::Nip42 {
            moderation_owner: None,
            pubkey: keys.public_key(),
            scopes: Scope::all_known(),
            channel_ids: None,
            conn_id: Uuid::new_v4(),
        };
        assert_too_many_unkeyed_p_tags(
            validate_ingest_pre_command(event.clone(), &http_auth, false)
                .await
                .expect_err("unkeyed HTTP kind 9 with 65 p tags"),
        );
        assert_too_many_unkeyed_p_tags(
            validate_ingest_pre_command(event.clone(), &ws_auth, false)
                .await
                .expect_err("unkeyed WebSocket kind 9 with 65 p tags"),
        );
        assert_too_many_keyed_p_tags(
            KeyedHttpValidatedEvent::validate(event, http_auth)
                .await
                .expect_err("keyed kind 9 with 65 p tags stays rejected"),
        );
    }

    #[tokio::test]
    async fn unkeyed_kind9_pre_command_counts_malformed_and_duplicate_actual_p_tags() {
        let keys = nostr::Keys::generate();
        let hex = keys.public_key().to_hex();
        let mut tags = repeated_p_tags(buzz_core::idempotency::KEYED_MAX_P_TAGS, &hex);
        tags.push(Tag::parse(["p", "not-a-hex-pubkey"]).expect("malformed p"));
        let event = signed_kind9(&keys, "fresh", tags);
        assert_eq!(
            buzz_core::idempotency::keyed_p_tag_count(&event),
            buzz_core::idempotency::KEYED_MAX_P_TAGS + 1
        );
        assert_too_many_unkeyed_p_tags(
            validate_ingest_pre_command(event.clone(), &http_auth_for(&keys), false)
                .await
                .expect_err("malformed actual p tags count toward the cap"),
        );
        assert_too_many_keyed_p_tags(
            KeyedHttpValidatedEvent::validate(event, http_auth_for(&keys))
                .await
                .expect_err("keyed malformed actual p tags count toward the cap"),
        );
    }

    #[tokio::test]
    async fn unkeyed_kind9_pre_command_ignores_uppercase_p_and_non_p_tags() {
        let keys = nostr::Keys::generate();
        let hex = keys.public_key().to_hex();
        let mut tags = repeated_p_tags(buzz_core::idempotency::KEYED_MAX_P_TAGS, &hex);
        tags.extend(
            (0..=buzz_core::idempotency::KEYED_MAX_P_TAGS)
                .map(|_| Tag::parse(["P", &hex]).expect("uppercase P")),
        );
        tags.extend(
            (0..=buzz_core::idempotency::KEYED_MAX_P_TAGS)
                .map(|_| Tag::parse(["e", &hex]).expect("e tag")),
        );
        let event = signed_kind9(&keys, "fresh", tags);
        assert_eq!(
            buzz_core::idempotency::keyed_p_tag_count(&event),
            buzz_core::idempotency::KEYED_MAX_P_TAGS
        );
        validate_ingest_pre_command(event.clone(), &http_auth_for(&keys), false)
            .await
            .expect("uppercase P and non-p tags must not count");
        KeyedHttpValidatedEvent::validate(event, http_auth_for(&keys))
            .await
            .expect("keyed uppercase P and non-p tags must not count");
    }

    #[test]
    fn fleet_exceeded_preserves_reset_other_than_five() {
        match keyed_http_error_from_fleet(crate::admission::AdmissionError::Exceeded {
            reset_in_secs: 59,
        }) {
            KeyedHttpError::Busy { retry_after_secs } => {
                assert_eq!(retry_after_secs, 59);
                assert_ne!(retry_after_secs, KEYED_BUSY_RETRY_AFTER_SECS);
            }
            other => panic!("Exceeded must not collapse to default Busy, got {other:?}"),
        }
    }

    #[test]
    fn fleet_unavailable_and_local_busy_use_explicit_default() {
        match keyed_http_error_from_fleet(crate::admission::AdmissionError::Unavailable) {
            KeyedHttpError::Busy { retry_after_secs } => {
                assert_eq!(retry_after_secs, KEYED_BUSY_RETRY_AFTER_SECS);
            }
            other => panic!("Unavailable must map to default Busy, got {other:?}"),
        }
        match keyed_busy_default() {
            KeyedHttpError::Busy { retry_after_secs } => {
                assert_eq!(retry_after_secs, 5);
            }
            other => panic!("local/SQL busy must use the five-second default, got {other:?}"),
        }
    }

    #[test]
    fn keyed_terminals_are_typed_outcomes_not_internal_sentinels() {
        match keyed_http_error_from_inner(IngestInnerOutcome::Conflict) {
            KeyedHttpError::Conflict => {}
            KeyedHttpError::Ingest(IngestError::Internal(message)) => {
                panic!("conflict must not be an Internal sentinel, got {message}")
            }
            KeyedHttpError::Ingest(_)
            | KeyedHttpError::Busy { .. }
            | KeyedHttpError::Principal(_) => {
                panic!("conflict must stay Conflict")
            }
        }
        match keyed_http_error_from_inner(IngestInnerOutcome::Busy {
            retry_after_secs: KEYED_BUSY_RETRY_AFTER_SECS,
        }) {
            KeyedHttpError::Busy { retry_after_secs } => {
                assert_eq!(retry_after_secs, KEYED_BUSY_RETRY_AFTER_SECS);
            }
            KeyedHttpError::Ingest(IngestError::Internal(message)) => {
                panic!("busy must not be an Internal sentinel, got {message}")
            }
            KeyedHttpError::Ingest(_) | KeyedHttpError::Conflict | KeyedHttpError::Principal(_) => {
                panic!("busy must stay Busy")
            }
        }
        match keyed_http_error_from_inner(IngestInnerOutcome::Principal(
            crate::admission::AdmissionError::Exceeded { reset_in_secs: 11 },
        )) {
            KeyedHttpError::Principal(crate::admission::AdmissionError::Exceeded {
                reset_in_secs: 11,
            }) => {}
            KeyedHttpError::Ingest(IngestError::Internal(message)) => {
                panic!("principal must not be an Internal sentinel, got {message}")
            }
            KeyedHttpError::Ingest(_) | KeyedHttpError::Conflict | KeyedHttpError::Busy { .. } => {
                panic!("principal must stay Principal")
            }
            KeyedHttpError::Principal(_) => panic!("principal Exceeded must keep reset_in_secs 11"),
        }
        match keyed_http_error_from_inner(IngestInnerOutcome::Rejected("invalid: x".into())) {
            KeyedHttpError::Ingest(IngestError::Rejected(message)) => {
                assert_eq!(message, "invalid: x");
            }
            KeyedHttpError::Ingest(_)
            | KeyedHttpError::Conflict
            | KeyedHttpError::Busy { .. }
            | KeyedHttpError::Principal(_) => {
                panic!("ordinary reject must stay Ingest(Rejected)")
            }
        }

        let sentinel_conflict =
            IngestInnerOutcome::from(IngestError::Internal("error: keyed conflict".into()));
        match keyed_http_error_from_inner(sentinel_conflict) {
            KeyedHttpError::Ingest(IngestError::Internal(message)) => {
                assert_eq!(message, "error: keyed conflict");
            }
            KeyedHttpError::Conflict => {
                panic!("Internal sentinel strings must not be reclassified as Conflict")
            }
            KeyedHttpError::Ingest(_)
            | KeyedHttpError::Busy { .. }
            | KeyedHttpError::Principal(_) => {
                panic!("Internal(\"error: keyed conflict\") must stay Ingest(Internal)")
            }
        }
        let sentinel_busy =
            IngestInnerOutcome::from(IngestError::Internal("error: keyed writer busy".into()));
        match keyed_http_error_from_inner(sentinel_busy) {
            KeyedHttpError::Ingest(IngestError::Internal(message)) => {
                assert_eq!(message, "error: keyed writer busy");
            }
            KeyedHttpError::Busy { .. } => {
                panic!("Internal sentinel strings must not be reclassified as Busy")
            }
            KeyedHttpError::Ingest(_) | KeyedHttpError::Conflict | KeyedHttpError::Principal(_) => {
                panic!("Internal(\"error: keyed writer busy\") must stay Ingest(Internal)")
            }
        }
        let sentinel_principal = IngestInnerOutcome::from(IngestError::Internal(
            "error: keyed principal admission".into(),
        ));
        match keyed_http_error_from_inner(sentinel_principal) {
            KeyedHttpError::Ingest(IngestError::Internal(message)) => {
                assert_eq!(message, "error: keyed principal admission");
            }
            KeyedHttpError::Principal(_) => {
                panic!("Internal sentinel strings must not be reclassified as Principal")
            }
            KeyedHttpError::Ingest(_) | KeyedHttpError::Conflict | KeyedHttpError::Busy { .. } => {
                panic!("Internal(\"error: keyed principal admission\") must stay Ingest(Internal)")
            }
        }
    }

    #[test]
    fn stored_metric_cannot_override_typed_terminal() {
        let stored = Some(keyed_inserted_stored_metric());
        let outcome: Result<IngestResult, IngestInnerOutcome> = Err(IngestInnerOutcome::Conflict);
        let classified = match outcome {
            Ok(_) => "ok",
            Err(IngestInnerOutcome::Rejected(_)) => "rejected",
            Err(IngestInnerOutcome::AuthFailed(_)) => "auth",
            Err(IngestInnerOutcome::Internal(_)) => "internal",
            Err(IngestInnerOutcome::Conflict) => "conflict",
            Err(IngestInnerOutcome::Busy { .. }) => "busy",
            Err(IngestInnerOutcome::Principal(_)) => "principal",
        };
        assert_eq!(classified, "conflict");
        assert!(
            keyed_http_should_increment_stored(stored),
            "stored bookkeeping may still say increment"
        );
        assert!(
            !matches!(
                keyed_http_error_from_inner(IngestInnerOutcome::Conflict),
                KeyedHttpError::Ingest(_)
            ),
            "the HTTP wrapper classifies from the returned outcome, never from stored"
        );
    }

    #[test]
    fn miss_path_admission_keeps_principal_distinct_from_busy() {
        let exceeded = IngestInnerOutcome::from(KeyedHttpError::Principal(
            crate::admission::AdmissionError::Exceeded { reset_in_secs: 11 },
        ));
        match exceeded {
            IngestInnerOutcome::Principal(crate::admission::AdmissionError::Exceeded {
                reset_in_secs: 11,
            }) => {}
            IngestInnerOutcome::Rejected(_)
            | IngestInnerOutcome::AuthFailed(_)
            | IngestInnerOutcome::Internal(_)
            | IngestInnerOutcome::Conflict
            | IngestInnerOutcome::Busy { .. }
            | IngestInnerOutcome::Principal(_) => {
                panic!("principal Exceeded must stay Principal with reset 11")
            }
        }
        let unavailable = IngestInnerOutcome::from(KeyedHttpError::Principal(
            crate::admission::AdmissionError::Unavailable,
        ));
        match unavailable {
            IngestInnerOutcome::Principal(crate::admission::AdmissionError::Unavailable) => {}
            IngestInnerOutcome::Busy { .. } => {
                panic!("principal Unavailable must not collapse into keyed Busy")
            }
            IngestInnerOutcome::Rejected(_)
            | IngestInnerOutcome::AuthFailed(_)
            | IngestInnerOutcome::Internal(_)
            | IngestInnerOutcome::Conflict
            | IngestInnerOutcome::Principal(_) => {
                panic!("principal Unavailable must stay Principal")
            }
        }
        let fleet_busy = IngestInnerOutcome::from(keyed_http_error_from_fleet(
            crate::admission::AdmissionError::Unavailable,
        ));
        match fleet_busy {
            IngestInnerOutcome::Busy { retry_after_secs } => {
                assert_eq!(retry_after_secs, KEYED_BUSY_RETRY_AFTER_SECS);
            }
            IngestInnerOutcome::Principal(_) => {
                panic!("fleet unavailability must stay keyed Busy, not Principal")
            }
            IngestInnerOutcome::Rejected(_)
            | IngestInnerOutcome::AuthFailed(_)
            | IngestInnerOutcome::Internal(_)
            | IngestInnerOutcome::Conflict => {
                panic!("fleet unavailability must stay keyed Busy")
            }
        }
    }

    struct ImmediateDenyLimiter;

    impl RateLimiter for ImmediateDenyLimiter {
        async fn check_and_increment(
            &self,
            _ctx: &TenantContext,
            _pubkey: &nostr::PublicKey,
            _limit_type: LimitType,
            _window_secs: u64,
            _limit: u64,
        ) -> Result<buzz_auth::RateLimitResult, buzz_auth::AuthError> {
            Ok(buzz_auth::RateLimitResult::denied(2, 1, 59))
        }

        async fn check_ip_connection(
            &self,
            _ip: &IpAddr,
            _window_secs: u64,
            _limit: u64,
        ) -> Result<buzz_auth::RateLimitResult, buzz_auth::AuthError> {
            Ok(buzz_auth::RateLimitResult::denied(2, 1, 59))
        }

        async fn check_paired_admission(
            &self,
            request: PairedAdmissionRequest<'_>,
        ) -> Result<PairedAdmissionOutcome, buzz_auth::AuthError> {
            Ok(PairedAdmissionOutcome::FleetDenied(
                buzz_auth::RateLimitResult::denied(
                    request.fleet_limit + 1,
                    request.fleet_limit,
                    59,
                ),
            ))
        }

        async fn check_hierarchical_admission(
            &self,
            request: HierarchicalAdmissionRequest<'_>,
        ) -> Result<HierarchicalAdmissionOutcome, buzz_auth::AuthError> {
            Ok(HierarchicalAdmissionOutcome::IdentityDenied(
                buzz_auth::RateLimitResult::denied(
                    request.limits.identity + 1,
                    request.limits.identity,
                    59,
                ),
            ))
        }
    }

    #[tokio::test]
    async fn held_writer_gate_denies_fleet_immediately_and_queue_stays_bounded() {
        assert_eq!(KEYED_WRITER_WAIT_MAX, KEYED_GLOBAL_PERMITS);
        assert_eq!(KEYED_WRITER_WAIT_MAX, 8);
        let held = KeyedWriterCapacityGuard::hold_all();
        assert_eq!(keyed_global().available_permits(), 0);

        let tenant = TenantContext::resolved(
            CommunityId::from_uuid(Uuid::from_u128(7)),
            "keyed-writer-gate.test",
        );
        let started = std::time::Instant::now();
        let denied = enforce_keyed_events_fleet_admission(
            &ImmediateDenyLimiter,
            &tenant,
            &nostr::Keys::generate().public_key(),
            120,
        )
        .await;
        assert!(
            started.elapsed() < std::time::Duration::from_millis(50),
            "fleet denial must not wait on the local writer gate"
        );
        assert!(
            matches!(
                denied,
                Err(crate::admission::AdmissionError::Exceeded { reset_in_secs: 59 })
            ),
            "got {denied:?}"
        );

        let started = std::time::Instant::now();
        let acquire = acquire_keyed_writer_permits(Uuid::from_u128(7), &[1u8; 32], &[2u8; 32]);
        assert!(
            started.elapsed() < std::time::Duration::from_millis(20),
            "a full writer gate must fail closed immediately"
        );
        let busy = match acquire {
            Err(error) => error,
            Ok(_) => panic!("a full writer gate must fail closed immediately"),
        };
        match IngestInnerOutcome::from(busy) {
            IngestInnerOutcome::Busy { retry_after_secs } => {
                assert_eq!(retry_after_secs, KEYED_BUSY_RETRY_AFTER_SECS);
            }
            IngestInnerOutcome::Internal(message) => {
                panic!("writer exhaustion must not be an Internal sentinel, got {message}")
            }
            IngestInnerOutcome::Rejected(_)
            | IngestInnerOutcome::AuthFailed(_)
            | IngestInnerOutcome::Conflict
            | IngestInnerOutcome::Principal(_) => {
                panic!("writer exhaustion must be typed Busy")
            }
        }
        assert_eq!(
            keyed_global().available_permits(),
            0,
            "try_acquire must not enqueue waiters past {KEYED_WRITER_WAIT_MAX}"
        );
        drop(held);
        assert_eq!(keyed_global().available_permits(), KEYED_GLOBAL_PERMITS);
        let recovered = acquire_keyed_writer_permits(Uuid::from_u128(7), &[1u8; 32], &[2u8; 32]);
        assert!(
            recovered.is_ok(),
            "dropping the capacity guard must release every writer permit"
        );
    }

    struct NeverResolvesLimiter;

    impl RateLimiter for NeverResolvesLimiter {
        async fn check_and_increment(
            &self,
            _ctx: &TenantContext,
            _pubkey: &nostr::PublicKey,
            _limit_type: LimitType,
            _window_secs: u64,
            _limit: u64,
        ) -> Result<buzz_auth::RateLimitResult, buzz_auth::AuthError> {
            std::future::pending::<Result<buzz_auth::RateLimitResult, buzz_auth::AuthError>>().await
        }

        async fn check_ip_connection(
            &self,
            _ip: &IpAddr,
            _window_secs: u64,
            _limit: u64,
        ) -> Result<buzz_auth::RateLimitResult, buzz_auth::AuthError> {
            std::future::pending::<Result<buzz_auth::RateLimitResult, buzz_auth::AuthError>>().await
        }

        async fn check_paired_admission(
            &self,
            _request: PairedAdmissionRequest<'_>,
        ) -> Result<PairedAdmissionOutcome, buzz_auth::AuthError> {
            std::future::pending::<Result<PairedAdmissionOutcome, buzz_auth::AuthError>>().await
        }

        async fn check_hierarchical_admission(
            &self,
            _request: HierarchicalAdmissionRequest<'_>,
        ) -> Result<HierarchicalAdmissionOutcome, buzz_auth::AuthError> {
            std::future::pending::<Result<HierarchicalAdmissionOutcome, buzz_auth::AuthError>>()
                .await
        }
    }

    #[test]
    fn keyed_reservation_abort_classifies_failures_without_exposing_errors() {
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let (success, database, timeout) = metrics::with_local_recorder(&recorder, || {
            (
                finish_keyed_reservation_abort(
                    Ok::<Result<(), buzz_db::DbError>, ()>(Ok(())),
                    "ok-pass",
                ),
                finish_keyed_reservation_abort(
                    Ok::<Result<(), buzz_db::DbError>, ()>(Err(buzz_db::DbError::InvalidData(
                        "db".into(),
                    ))),
                    "db-pass",
                ),
                finish_keyed_reservation_abort(
                    Err::<Result<(), buzz_db::DbError>, ()>(()),
                    "to-pass",
                ),
            )
        });
        assert_eq!(success, "ok-pass");
        assert_eq!(database, "db-pass");
        assert_eq!(timeout, "to-pass");

        let snapshot = snapshotter.snapshot().into_vec();
        assert_eq!(snapshot.len(), 2);
        let mut classes = Vec::new();
        for (key, _unit, _desc, value) in snapshot {
            let key = key.key();
            assert_eq!(key.name(), KEYED_RESERVATION_ABORT_FAILURES_TOTAL);
            let labels: Vec<_> = key.labels().collect();
            assert_eq!(labels.len(), 1);
            assert_eq!(labels[0].key(), "class");
            classes.push(labels[0].value().to_string());
            match value {
                metrics_util::debugging::DebugValue::Counter(count) => assert_eq!(count, 1),
                other => panic!("expected counter, got {other:?}"),
            }
        }
        classes.sort();
        assert_eq!(
            classes,
            ["database_other".to_string(), "deadline_timeout".to_string()]
        );
    }

    #[test]
    fn keyed_reservation_abort_sqlstate_classes_are_allowlisted() {
        assert_eq!(
            classify_keyed_reservation_abort_sqlstate(Some("55P03")),
            "lock_not_available"
        );
        assert_eq!(
            classify_keyed_reservation_abort_sqlstate(Some("57014")),
            "statement_canceled"
        );
        assert_eq!(
            classify_keyed_reservation_abort_sqlstate(Some("25P03")),
            "idle_in_transaction_timeout"
        );
        assert_eq!(
            classify_keyed_reservation_abort_sqlstate(Some("08006")),
            "sqlx_other"
        );
        assert_eq!(
            classify_keyed_reservation_abort_sqlstate(None),
            "sqlx_other"
        );
    }

    #[test]
    fn keyed_reservation_abort_db_error_classes_are_finite() {
        assert_eq!(
            classify_keyed_reservation_abort_db_error(&buzz_db::DbError::Sqlx(
                sqlx::Error::PoolTimedOut
            )),
            "pool_timeout"
        );
        assert_eq!(
            classify_keyed_reservation_abort_db_error(&buzz_db::DbError::Sqlx(sqlx::Error::Io(
                std::io::Error::other("database unavailable")
            ))),
            "sqlx_other"
        );
        assert_eq!(
            classify_keyed_reservation_abort_db_error(&buzz_db::DbError::InvalidData("n".into())),
            "database_other"
        );
        let unavailable = buzz_db::DbError::InvalidData("idempotency writer is busy".into());
        assert!(unavailable.is_idempotency_unavailable());
        assert_eq!(
            classify_keyed_reservation_abort_db_error(&unavailable),
            "idempotency_unavailable"
        );
    }

    #[test]
    fn keyed_reservation_abort_pool_timeout_increments_bounded_class() {
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let passthrough = metrics::with_local_recorder(&recorder, || {
            finish_keyed_reservation_abort(
                Ok::<Result<(), buzz_db::DbError>, ()>(Err(buzz_db::DbError::Sqlx(
                    sqlx::Error::PoolTimedOut,
                ))),
                "pool-pass",
            )
        });
        assert_eq!(passthrough, "pool-pass");
        let snapshot = snapshotter.snapshot().into_vec();
        assert_eq!(snapshot.len(), 1);
        let (key, _unit, _desc, value) = &snapshot[0];
        let key = key.key();
        assert_eq!(key.name(), KEYED_RESERVATION_ABORT_FAILURES_TOTAL);
        let labels: Vec<_> = key.labels().collect();
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].key(), "class");
        assert_eq!(labels[0].value(), "pool_timeout");
        match value {
            metrics_util::debugging::DebugValue::Counter(count) => assert_eq!(*count, 1),
            other => panic!("expected counter, got {other:?}"),
        }
    }

    #[test]
    fn reservation_admission_and_persist_budgets_are_documented() {
        const {
            assert!(
                KEYED_RESERVATION_ADMISSION_BUDGET_SECS
                    < buzz_db::idempotency::KEYED_RESERVATION_IDLE_TIMEOUT_SECS
            );
            assert!(
                buzz_db::idempotency::KEYED_RESERVATION_IDLE_TIMEOUT_SECS
                    <= KEYED_RESERVATION_PERSIST_BUDGET_SECS
            );
            assert!(
                KEYED_RESERVATION_PERSIST_BUDGET_SECS
                    == buzz_db::idempotency::KEYED_RESERVATION_STATEMENT_TIMEOUT_SECS
            );
        }
        assert_eq!(
            buzz_db::idempotency::KEYED_RESERVATION_CAPACITY,
            KEYED_WRITER_WAIT_MAX
        );
        assert_eq!(
            KEYED_RESERVATION_ADMISSION_BUDGET_SECS,
            KEYED_BUSY_RETRY_AFTER_SECS
        );
        assert_eq!(KEYED_RESERVATION_ADMISSION_BUDGET, Duration::from_secs(5));
        assert_eq!(
            buzz_db::idempotency::KEYED_RESERVATION_IDLE_TIMEOUT_SECS,
            10
        );
        assert_eq!(KEYED_RESERVATION_PERSIST_BUDGET, Duration::from_secs(15));
        assert!(
            KEYED_RESERVATION_ADMISSION_BUDGET.as_secs()
                < buzz_db::idempotency::KEYED_RESERVATION_IDLE_TIMEOUT_SECS
        );
        assert!(
            buzz_db::idempotency::KEYED_RESERVATION_IDLE_TIMEOUT_SECS
                <= KEYED_RESERVATION_PERSIST_BUDGET.as_secs()
        );
        assert_ne!(
            KEYED_RESERVATION_ADMISSION_BUDGET_SECS,
            buzz_db::idempotency::KEYED_RESERVATION_IDLE_TIMEOUT_SECS,
            "admission budget must not be derived from or equal to the idle belt"
        );
    }

    #[test]
    fn old_complete_deadline_cannot_cancel_witness_recovery() {
        const OLD_GUESSED_OUTER_SECS: u64 = 31;
        const MIN_PERSIST_STATEMENTS: u64 = 2;
        const {
            assert!(
                KEYED_RESERVATION_PERSIST_BUDGET_SECS
                    == buzz_db::idempotency::KEYED_RESERVATION_STATEMENT_TIMEOUT_SECS
            );
            assert!(buzz_db::idempotency::KEYED_COMMIT_RECOVERY_LOOKUP_TIMEOUT_SECS > 0);
        }
        assert_eq!(
            buzz_db::idempotency::KEYED_COMMIT_RECOVERY_LOOKUP_TIMEOUT_SECS,
            15
        );
        assert_eq!(KEYED_RESERVATION_PERSIST_BUDGET, Duration::from_secs(15));
        let phased = MIN_PERSIST_STATEMENTS * KEYED_RESERVATION_PERSIST_BUDGET_SECS
            + buzz_db::idempotency::KEYED_COMMIT_RECOVERY_LOOKUP_TIMEOUT_SECS;
        assert!(
            phased > OLD_GUESSED_OUTER_SECS,
            "the old 31s outer complete deadline can fire during internally bounded recovery"
        );
    }

    #[test]
    fn lost_ack_recovery_is_one_accepted_dispatch_then_replay() {
        let replay = buzz_db::KeyedStreamInsert::Replay {
            original_event_id: [0xaa; 32],
        };
        assert!(
            !replay.should_dispatch(),
            "retry after durable commit classifies Replay and must not dispatch again"
        );
        assert!(replay.into_fresh_stored_event().is_err());
        assert!(keyed_http_should_increment_stored(Some(
            keyed_inserted_stored_metric()
        )));
        assert!(!keyed_http_should_increment_stored(Some(
            keyed_duplicate_stored_metric()
        )));
        assert_eq!(
            keyed_accepted_duplicate_result([0xaa; 32]).message,
            "duplicate:"
        );
    }

    #[test]
    fn unrelated_key_hash_collision_does_not_fail_closed() {
        let community = Uuid::from_u128(42);
        let author = [3u8; 32];
        let key_a = [1u8; 32];
        let index = keyed_stripe_index(community, &author, &key_a);
        let held = keyed_stripes()[index]
            .try_acquire()
            .expect("hold the colliding stripe");
        let mut colliding = None;
        'search: for b0 in 0u8..=255 {
            for b1 in 0u8..=255 {
                let mut key_b = [0u8; 32];
                key_b[0] = b0;
                key_b[1] = b1;
                if key_b == key_a {
                    continue;
                }
                if keyed_stripe_index(community, &author, &key_b) == index {
                    colliding = Some(key_b);
                    break 'search;
                }
            }
        }
        let key_b = colliding.expect("two unrelated keys must be able to share a stripe");
        let acquired = acquire_keyed_writer_permits(community, &author, &key_b);
        drop(held);
        assert!(
            acquired.is_ok(),
            "an unrelated-key stripe collision must not synthesize 503"
        );
    }

    #[tokio::test]
    async fn never_resolving_admission_times_out_as_busy() {
        let tenant = TenantContext::resolved(
            CommunityId::from_uuid(Uuid::from_u128(11)),
            "keyed-admission-timeout.test",
        );
        let started = std::time::Instant::now();
        let result = keyed_await_admission_for(Duration::from_millis(25), async {
            admit_keyed_persist_miss(
                &NeverResolvesLimiter,
                &tenant,
                &nostr::Keys::generate().public_key(),
                120,
            )
            .await?;
            Ok::<(), KeyedHttpError>(())
        })
        .await;
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "a never-resolving admission future must fail closed inside the wall-clock budget"
        );
        assert!(
            matches!(
                result,
                Err(KeyedHttpError::Busy {
                    retry_after_secs: 5
                })
            ),
            "got {result:?}"
        );
    }

    #[tokio::test]
    async fn never_resolving_pending_future_times_out_as_busy() {
        let started = std::time::Instant::now();
        let result = keyed_await_admission_for(
            Duration::from_millis(20),
            std::future::pending::<Result<(), KeyedHttpError>>(),
        )
        .await;
        assert!(started.elapsed() < Duration::from_millis(200));
        assert!(
            matches!(
                result,
                Err(KeyedHttpError::Busy {
                    retry_after_secs: 5
                })
            ),
            "got {result:?}"
        );
    }

    #[test]
    fn replay_and_conflict_classification_does_not_join_the_writer_gate() {
        let replay = buzz_db::idempotency::KeyedReserveOutcome::Replay {
            original_event_id: [9u8; 32],
        };
        let conflict = buzz_db::idempotency::KeyedReserveOutcome::Conflict {
            existing_event_id: [8u8; 32],
        };
        assert!(!matches!(
            replay,
            buzz_db::idempotency::KeyedReserveOutcome::Reserved(_)
        ));
        assert!(!matches!(
            conflict,
            buzz_db::idempotency::KeyedReserveOutcome::Reserved(_)
        ));
        assert!(
            !matches!(
                replay,
                buzz_db::idempotency::KeyedReserveOutcome::Reserved(_)
            ) && !matches!(
                conflict,
                buzz_db::idempotency::KeyedReserveOutcome::Reserved(_)
            ),
            "replay/conflict return before principal, community, or fleet charge"
        );
    }

    struct PanicOnAdmissionLimiter;

    impl RateLimiter for PanicOnAdmissionLimiter {
        async fn check_and_increment(
            &self,
            _ctx: &TenantContext,
            _pubkey: &nostr::PublicKey,
            _limit_type: LimitType,
            _window_secs: u64,
            _limit: u64,
        ) -> Result<buzz_auth::RateLimitResult, buzz_auth::AuthError> {
            panic!("committed classification must not charge principal admission");
        }

        async fn check_ip_connection(
            &self,
            _ip: &IpAddr,
            _window_secs: u64,
            _limit: u64,
        ) -> Result<buzz_auth::RateLimitResult, buzz_auth::AuthError> {
            panic!("committed classification must not charge IP admission");
        }

        async fn check_paired_admission(
            &self,
            _request: PairedAdmissionRequest<'_>,
        ) -> Result<PairedAdmissionOutcome, buzz_auth::AuthError> {
            panic!("committed classification must not charge paired admission");
        }

        async fn check_hierarchical_admission(
            &self,
            _request: HierarchicalAdmissionRequest<'_>,
        ) -> Result<HierarchicalAdmissionOutcome, buzz_auth::AuthError> {
            panic!("committed classification must not charge hierarchical admission");
        }
    }

    struct RecordingLimiter {
        principal: std::sync::atomic::AtomicUsize,
        paired: std::sync::atomic::AtomicUsize,
        hierarchical: std::sync::atomic::AtomicUsize,
        identity_charged: std::sync::atomic::AtomicUsize,
        community_charged: std::sync::atomic::AtomicUsize,
        fleet_charged: std::sync::atomic::AtomicUsize,
        limit_types: Mutex<Vec<LimitType>>,
    }

    impl RecordingLimiter {
        fn new() -> Self {
            Self {
                principal: std::sync::atomic::AtomicUsize::new(0),
                paired: std::sync::atomic::AtomicUsize::new(0),
                hierarchical: std::sync::atomic::AtomicUsize::new(0),
                identity_charged: std::sync::atomic::AtomicUsize::new(0),
                community_charged: std::sync::atomic::AtomicUsize::new(0),
                fleet_charged: std::sync::atomic::AtomicUsize::new(0),
                limit_types: Mutex::new(Vec::new()),
            }
        }
    }

    impl RateLimiter for RecordingLimiter {
        async fn check_and_increment(
            &self,
            _ctx: &TenantContext,
            _pubkey: &nostr::PublicKey,
            _limit_type: LimitType,
            window_secs: u64,
            limit: u64,
        ) -> Result<buzz_auth::RateLimitResult, buzz_auth::AuthError> {
            self.principal
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(buzz_auth::RateLimitResult::allowed(1, limit, window_secs))
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
            self.paired
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let window_secs = request.window_secs();
            Ok(PairedAdmissionOutcome::Allowed {
                tenant: buzz_auth::RateLimitResult::allowed(1, request.tenant_limit, window_secs),
                fleet: buzz_auth::RateLimitResult::allowed(1, request.fleet_limit, window_secs),
            })
        }

        async fn check_hierarchical_admission(
            &self,
            request: HierarchicalAdmissionRequest<'_>,
        ) -> Result<HierarchicalAdmissionOutcome, buzz_auth::AuthError> {
            self.hierarchical
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.identity_charged
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.community_charged
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.fleet_charged
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.limit_types
                .lock()
                .unwrap()
                .push(request.limit_type.clone());
            let window_secs = request.window_secs();
            Ok(HierarchicalAdmissionOutcome::Allowed {
                identity: buzz_auth::RateLimitResult::allowed(
                    1,
                    request.limits.identity,
                    window_secs,
                ),
                community: buzz_auth::RateLimitResult::allowed(
                    1,
                    request.limits.community,
                    window_secs,
                ),
                fleet: buzz_auth::RateLimitResult::allowed(1, request.limits.fleet, window_secs),
            })
        }
    }

    struct PersistIdentityDenyLimiter;

    impl RateLimiter for PersistIdentityDenyLimiter {
        async fn check_and_increment(
            &self,
            _ctx: &TenantContext,
            _pubkey: &nostr::PublicKey,
            _limit_type: LimitType,
            window_secs: u64,
            limit: u64,
        ) -> Result<buzz_auth::RateLimitResult, buzz_auth::AuthError> {
            Ok(buzz_auth::RateLimitResult::allowed(1, limit, window_secs))
        }

        async fn check_ip_connection(
            &self,
            _ip: &IpAddr,
            window_secs: u64,
            limit: u64,
        ) -> Result<buzz_auth::RateLimitResult, buzz_auth::AuthError> {
            Ok(buzz_auth::RateLimitResult::allowed(1, limit, window_secs))
        }

        async fn check_hierarchical_admission(
            &self,
            request: HierarchicalAdmissionRequest<'_>,
        ) -> Result<HierarchicalAdmissionOutcome, buzz_auth::AuthError> {
            let window_secs = request.window_secs();
            if request.limit_type == LimitType::KeyedHttpFresh {
                return Ok(HierarchicalAdmissionOutcome::Allowed {
                    identity: buzz_auth::RateLimitResult::allowed(
                        1,
                        request.limits.identity,
                        window_secs,
                    ),
                    community: buzz_auth::RateLimitResult::allowed(
                        1,
                        request.limits.community,
                        window_secs,
                    ),
                    fleet: buzz_auth::RateLimitResult::allowed(
                        1,
                        request.limits.fleet,
                        window_secs,
                    ),
                });
            }
            Ok(HierarchicalAdmissionOutcome::IdentityDenied(
                buzz_auth::RateLimitResult::denied(
                    request.limits.identity + 1,
                    request.limits.identity,
                    11,
                ),
            ))
        }
    }

    fn keyed_admission_tenant() -> TenantContext {
        TenantContext::resolved(
            CommunityId::from_uuid(Uuid::from_u128(13)),
            "keyed-classify-admit.test",
        )
    }

    #[tokio::test]
    async fn committed_replay_and_conflict_skip_redis_admission() {
        let tenant = keyed_admission_tenant();
        let principal = nostr::Keys::generate().public_key();
        let replay = finish_keyed_committed_classify(
            Some(buzz_db::idempotency::KeyedCommittedOutcome::Replay {
                original_event_id: [9u8; 32],
            }),
            &PanicOnAdmissionLimiter,
            &tenant,
            &principal,
            120,
        )
        .await
        .expect("replay must skip admission");
        match replay {
            Some(buzz_db::idempotency::KeyedCommittedOutcome::Replay { original_event_id }) => {
                assert_eq!(original_event_id, [9u8; 32]);
            }
            _other => panic!("expected replay"),
        }

        let conflict = finish_keyed_committed_classify(
            Some(buzz_db::idempotency::KeyedCommittedOutcome::Conflict {
                existing_event_id: [8u8; 32],
            }),
            &PanicOnAdmissionLimiter,
            &tenant,
            &principal,
            120,
        )
        .await
        .expect("conflict must skip admission");
        match conflict {
            Some(buzz_db::idempotency::KeyedCommittedOutcome::Conflict { existing_event_id }) => {
                assert_eq!(existing_event_id, [8u8; 32]);
            }
            _other => panic!("expected conflict"),
        }
    }

    #[test]
    fn classify_miss_reserve_replay_race_is_honest_after_fresh_persist() {
        // finish_keyed_committed_classify(None) is the only path that charges
        // fresh then persist. begin_keyed_stream_reservation may still return
        // Replay for the same key. Those counters are not rolled back.
        let replay = buzz_db::idempotency::KeyedReserveOutcome::Replay {
            original_event_id: [0x11; 32],
        };
        assert!(matches!(
            &replay,
            buzz_db::idempotency::KeyedReserveOutcome::Replay { .. }
        ));
        assert!(!matches!(
            &replay,
            buzz_db::idempotency::KeyedReserveOutcome::Reserved(_)
        ));
        let duplicate = keyed_accepted_duplicate_result([0x11; 32]);
        assert!(duplicate.accepted);
        assert_eq!(duplicate.message, "duplicate:");
    }

    #[tokio::test]
    async fn committed_miss_admits_before_any_reservation() {
        let tenant = keyed_admission_tenant();
        let principal = nostr::Keys::generate().public_key();
        let limiter = RecordingLimiter::new();
        let admitted = finish_keyed_committed_classify(None, &limiter, &tenant, &principal, 120)
            .await
            .expect("miss must run admission");
        assert!(
            admitted.is_none(),
            "an admitted miss must not open a reservation"
        );
        assert_eq!(
            limiter.principal.load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(limiter.paired.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(
            limiter
                .hierarchical
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        assert_eq!(
            limiter
                .identity_charged
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        assert_eq!(
            limiter
                .community_charged
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        assert_eq!(
            limiter
                .fleet_charged
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        assert_eq!(
            limiter.limit_types.lock().unwrap().clone(),
            vec![LimitType::KeyedHttpFresh, LimitType::ApiCalls]
        );
    }

    #[tokio::test]
    async fn redis_denial_cannot_retain_a_reservation() {
        let tenant = keyed_admission_tenant();
        let principal = nostr::Keys::generate().public_key();
        let denied = finish_keyed_committed_classify(
            None,
            &PersistIdentityDenyLimiter,
            &tenant,
            &principal,
            120,
        )
        .await;
        let denied = match denied {
            Err(error) => error,
            Ok(other) => {
                panic!("principal denial must fail before a reservation exists, got {other:?}")
            }
        };
        match IngestInnerOutcome::from(denied) {
            IngestInnerOutcome::Principal(_) => {}
            IngestInnerOutcome::Internal(message) => {
                panic!("principal denial must not be an Internal sentinel, got {message}")
            }
            IngestInnerOutcome::Busy { .. } => {
                panic!("principal denial must not collapse into keyed Busy")
            }
            IngestInnerOutcome::Rejected(_)
            | IngestInnerOutcome::AuthFailed(_)
            | IngestInnerOutcome::Conflict => {
                panic!("principal denial must stay Principal")
            }
        }
    }

    #[tokio::test]
    async fn redis_timeout_cannot_retain_a_reservation() {
        let tenant = keyed_admission_tenant();
        let principal = nostr::Keys::generate().public_key();
        let started = std::time::Instant::now();
        let timed_out = keyed_await_admission_for(Duration::from_millis(25), async {
            admit_keyed_persist_miss(&NeverResolvesLimiter, &tenant, &principal, 120).await
        })
        .await;
        assert!(started.elapsed() < Duration::from_millis(200));
        assert!(
            matches!(
                timed_out,
                Err(KeyedHttpError::Busy {
                    retry_after_secs: 5
                })
            ),
            "admission timeout must fail closed with no reservation to abort, got {timed_out:?}"
        );
    }

    #[derive(Clone, Copy)]
    enum PersistStub {
        Allow,
        DenyIdentity,
        DenyCommunity,
        DenyFleet,
        PreMutation,
        AmbiguousCharged,
        AmbiguousUncharged,
    }

    struct PersistMatrixLimiter {
        outcome: PersistStub,
        calls: std::sync::atomic::AtomicUsize,
        identity_charged: std::sync::atomic::AtomicUsize,
        community_charged: std::sync::atomic::AtomicUsize,
        fleet_charged: std::sync::atomic::AtomicUsize,
    }

    impl PersistMatrixLimiter {
        fn new(outcome: PersistStub) -> Self {
            Self {
                outcome,
                calls: std::sync::atomic::AtomicUsize::new(0),
                identity_charged: std::sync::atomic::AtomicUsize::new(0),
                community_charged: std::sync::atomic::AtomicUsize::new(0),
                fleet_charged: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn charges(&self) -> (usize, usize, usize, usize) {
            (
                self.calls.load(std::sync::atomic::Ordering::Relaxed),
                self.identity_charged
                    .load(std::sync::atomic::Ordering::Relaxed),
                self.community_charged
                    .load(std::sync::atomic::Ordering::Relaxed),
                self.fleet_charged
                    .load(std::sync::atomic::Ordering::Relaxed),
            )
        }
    }

    impl RateLimiter for PersistMatrixLimiter {
        async fn check_and_increment(
            &self,
            _ctx: &TenantContext,
            _pubkey: &nostr::PublicKey,
            _limit_type: LimitType,
            window_secs: u64,
            limit: u64,
        ) -> Result<buzz_auth::RateLimitResult, buzz_auth::AuthError> {
            Ok(buzz_auth::RateLimitResult::allowed(1, limit, window_secs))
        }

        async fn check_ip_connection(
            &self,
            _ip: &IpAddr,
            window_secs: u64,
            limit: u64,
        ) -> Result<buzz_auth::RateLimitResult, buzz_auth::AuthError> {
            Ok(buzz_auth::RateLimitResult::allowed(1, limit, window_secs))
        }

        async fn check_hierarchical_admission(
            &self,
            request: HierarchicalAdmissionRequest<'_>,
        ) -> Result<HierarchicalAdmissionOutcome, buzz_auth::AuthError> {
            let prior = self
                .calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if matches!(
                self.outcome,
                PersistStub::AmbiguousCharged | PersistStub::AmbiguousUncharged
            ) {
                assert_eq!(prior, 0, "ambiguous persist must not be blindly retried");
            }
            let window_secs = request.window_secs();
            match self.outcome {
                PersistStub::Allow => {
                    self.identity_charged
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    self.community_charged
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    self.fleet_charged
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    Ok(HierarchicalAdmissionOutcome::Allowed {
                        identity: buzz_auth::RateLimitResult::allowed(
                            1,
                            request.limits.identity,
                            window_secs,
                        ),
                        community: buzz_auth::RateLimitResult::allowed(
                            1,
                            request.limits.community,
                            window_secs,
                        ),
                        fleet: buzz_auth::RateLimitResult::allowed(
                            1,
                            request.limits.fleet,
                            window_secs,
                        ),
                    })
                }
                PersistStub::DenyIdentity => Ok(HierarchicalAdmissionOutcome::IdentityDenied(
                    buzz_auth::RateLimitResult::denied(
                        request.limits.identity + 1,
                        request.limits.identity,
                        11,
                    ),
                )),
                PersistStub::DenyCommunity => Ok(HierarchicalAdmissionOutcome::CommunityDenied(
                    buzz_auth::RateLimitResult::denied(
                        request.limits.community + 1,
                        request.limits.community,
                        17,
                    ),
                )),
                PersistStub::DenyFleet => Ok(HierarchicalAdmissionOutcome::FleetDenied(
                    buzz_auth::RateLimitResult::denied(
                        request.limits.fleet + 1,
                        request.limits.fleet,
                        23,
                    ),
                )),
                PersistStub::PreMutation => Err(buzz_auth::AuthError::Internal(
                    "hierarchical admission counter is corrupt".into(),
                )),
                PersistStub::AmbiguousCharged => {
                    self.identity_charged
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    self.community_charged
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    self.fleet_charged
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    Err(buzz_auth::AuthError::Internal(
                        "hierarchical persist reply lost".into(),
                    ))
                }
                PersistStub::AmbiguousUncharged => Err(buzz_auth::AuthError::Internal(
                    "hierarchical persist reply lost".into(),
                )),
            }
        }
    }

    #[tokio::test]
    async fn atomic_persist_outcome_matrix_never_charges_a_subset() {
        let tenant = keyed_admission_tenant();
        let principal = nostr::Keys::generate().public_key();

        let allow = PersistMatrixLimiter::new(PersistStub::Allow);
        admit_keyed_persist_miss(&allow, &tenant, &principal, 300)
            .await
            .expect("allow");
        assert_eq!(allow.charges(), (1, 1, 1, 1));

        let identity = PersistMatrixLimiter::new(PersistStub::DenyIdentity);
        match admit_keyed_persist_miss(&identity, &tenant, &principal, 300).await {
            Err(KeyedHttpError::Principal(crate::admission::AdmissionError::Exceeded {
                reset_in_secs: 11,
            })) => {}
            other => panic!("identity deny must stay Principal, got {other:?}"),
        }
        assert_eq!(identity.charges(), (1, 0, 0, 0));

        let community = PersistMatrixLimiter::new(PersistStub::DenyCommunity);
        match admit_keyed_persist_miss(&community, &tenant, &principal, 300).await {
            Err(KeyedHttpError::Busy {
                retry_after_secs: 17,
            }) => {}
            other => panic!("community deny must stay Busy, got {other:?}"),
        }
        assert_eq!(community.charges(), (1, 0, 0, 0));

        let fleet = PersistMatrixLimiter::new(PersistStub::DenyFleet);
        match admit_keyed_persist_miss(&fleet, &tenant, &principal, 300).await {
            Err(KeyedHttpError::Busy {
                retry_after_secs: 23,
            }) => {}
            other => panic!("fleet deny must stay Busy, got {other:?}"),
        }
        assert_eq!(fleet.charges(), (1, 0, 0, 0));

        let pre = PersistMatrixLimiter::new(PersistStub::PreMutation);
        match admit_keyed_persist_miss(&pre, &tenant, &principal, 300).await {
            Err(KeyedHttpError::Busy { retry_after_secs }) => {
                assert_eq!(retry_after_secs, KEYED_BUSY_RETRY_AFTER_SECS);
            }
            other => panic!("pre-mutation must fail closed Busy, got {other:?}"),
        }
        assert_eq!(pre.charges(), (1, 0, 0, 0));

        for stub in [
            PersistStub::AmbiguousCharged,
            PersistStub::AmbiguousUncharged,
        ] {
            let limiter = PersistMatrixLimiter::new(stub);
            match admit_keyed_persist_miss(&limiter, &tenant, &principal, 300).await {
                Err(KeyedHttpError::Busy { .. }) => {}
                other => panic!("ambiguous persist must fail closed, got {other:?}"),
            }
            let (calls, identity_c, community_c, fleet_c) = limiter.charges();
            assert_eq!(calls, 1);
            assert_eq!(identity_c, community_c);
            assert_eq!(community_c, fleet_c);
            if matches!(stub, PersistStub::AmbiguousCharged) {
                assert_eq!(identity_c, 1);
            } else {
                assert_eq!(identity_c, 0);
            }
        }
    }

    #[tokio::test]
    async fn concurrent_persist_boundary_still_all_or_none() {
        let tenant = keyed_admission_tenant();
        let principal = nostr::Keys::generate().public_key();
        let limiter = std::sync::Arc::new(PersistMatrixLimiter::new(PersistStub::Allow));
        let a = admit_keyed_persist_miss(limiter.as_ref(), &tenant, &principal, 300);
        let b = admit_keyed_persist_miss(limiter.as_ref(), &tenant, &principal, 300);
        let (ra, rb) = tokio::join!(a, b);
        ra.expect("first concurrent persist");
        rb.expect("second concurrent persist");
        let (calls, identity_c, community_c, fleet_c) = limiter.charges();
        assert_eq!(calls, 2);
        assert_eq!(identity_c, 2);
        assert_eq!(community_c, 2);
        assert_eq!(fleet_c, 2);
    }

    #[test]
    fn reserved_keyed_community_principal_bytes_and_paired_window_are_exact() {
        let mut reserved = [0u8; 32];
        reserved[31] = 1;
        assert_eq!(keyed_community_admission_principal().to_bytes(), reserved);
        assert_eq!(KEYED_EVENTS_FLEET_ADMISSION_WINDOW_SECS, 60);
        assert_eq!(KEYED_EVENTS_FLEET_ADMISSION_WINDOW.get(), 60);
    }

    #[test]
    fn keyed_fleet_admission_is_tenant_fair_under_the_aggregate_ceiling() {
        const {
            assert!(KEYED_EVENTS_COMMUNITY_ADMISSION_PER_MIN < KEYED_EVENTS_FLEET_ADMISSION_PER_MIN)
        };
        let community_a = Uuid::from_u128(1);
        let community_b = Uuid::from_u128(2);
        assert_ne!(community_a, community_b);
        let principal = keyed_community_admission_principal();
        let user = nostr::Keys::generate().public_key();
        assert_ne!(principal, user);
        assert_eq!(KEYED_COMMUNITY_ADMISSION_LIMIT_TYPE, LimitType::ApiCalls);
        let mut community_used: std::collections::HashMap<Uuid, u64> =
            std::collections::HashMap::new();
        let mut fleet_used = 0u64;
        let mut admit = |community: Uuid| -> bool {
            let count = community_used.entry(community).or_insert(0);
            if *count >= KEYED_EVENTS_COMMUNITY_ADMISSION_PER_MIN {
                return false;
            }
            if fleet_used >= KEYED_EVENTS_FLEET_ADMISSION_PER_MIN {
                return false;
            }
            *count += 1;
            fleet_used += 1;
            true
        };
        for _ in 0..KEYED_EVENTS_COMMUNITY_ADMISSION_PER_MIN {
            assert!(
                admit(community_a),
                "community A must be admitted up to its per-tenant share"
            );
        }
        assert!(
            !admit(community_a),
            "an exhausted community must not keep charging the fleet sentinel"
        );
        assert!(
            admit(community_b),
            "a distinct community must still admit while fleet capacity remains"
        );
        assert_eq!(fleet_used, KEYED_EVENTS_COMMUNITY_ADMISSION_PER_MIN + 1);
        assert!(
            fleet_used < KEYED_EVENTS_FLEET_ADMISSION_PER_MIN,
            "protected fleet capacity must remain after one community is exhausted"
        );
    }

    #[test]
    fn keyed_ingress_caps_are_compile_time_isolated() {
        const {
            assert!(KEYED_INGRESS_COMMUNITY_MAX > 0);
            assert!(KEYED_INGRESS_COMMUNITY_MAX < KEYED_INGRESS_GLOBAL_MAX);
            assert!(KEYED_INGRESS_COMMUNITY_MAX * 2 <= KEYED_INGRESS_GLOBAL_MAX);
        }
        assert_eq!(KEYED_INGRESS_GLOBAL_MAX, 32);
        assert_eq!(KEYED_INGRESS_COMMUNITY_MAX, 16);
        assert_eq!(KEYED_EARLY_DEADLINE_SECS, 5);
    }

    #[test]
    fn keyed_ingress_community_saturation_isolates_and_reclaims() {
        let _lock = lock_keyed_ingress_tests();
        let community_a = Uuid::from_u128(0xA11);
        let community_b = Uuid::from_u128(0xB22);
        let global_before = keyed_ingress_global_available();
        let mut held_a = Vec::new();
        for _ in 0..KEYED_INGRESS_COMMUNITY_MAX {
            held_a.push(try_acquire_keyed_ingress(community_a).expect("community A permit"));
        }
        match try_acquire_keyed_ingress(community_a) {
            Err(KeyedHttpError::Busy { retry_after_secs }) => {
                assert_eq!(retry_after_secs, KEYED_BUSY_RETRY_AFTER_SECS);
            }
            other => panic!("community A at 16 must fail fast, got {other:?}"),
        }
        let b = try_acquire_keyed_ingress(community_b).expect("community B still admits");
        assert!(keyed_ingress_registry_contains(community_a));
        assert!(keyed_ingress_registry_contains(community_b));
        assert_eq!(
            keyed_ingress_live_handles(community_a),
            Some(KEYED_INGRESS_COMMUNITY_MAX)
        );
        drop(held_a);
        drop(b);
        assert_eq!(keyed_ingress_global_available(), global_before);
        assert!(!keyed_ingress_registry_contains(community_a));
        assert!(!keyed_ingress_registry_contains(community_b));
        assert_eq!(keyed_ingress_registry_len(), 0);
    }

    #[test]
    fn keyed_ingress_global_saturation_fails_fast() {
        let _lock = lock_keyed_ingress_tests();
        let community_a = Uuid::from_u128(0xC33);
        let community_b = Uuid::from_u128(0xD44);
        let community_c = Uuid::from_u128(0xE55);
        let mut held = Vec::new();
        for _ in 0..KEYED_INGRESS_COMMUNITY_MAX {
            held.push(try_acquire_keyed_ingress(community_a).expect("A"));
        }
        for _ in 0..KEYED_INGRESS_COMMUNITY_MAX {
            held.push(try_acquire_keyed_ingress(community_b).expect("B"));
        }
        assert_eq!(keyed_ingress_global_available(), 0);
        match try_acquire_keyed_ingress(community_c) {
            Err(KeyedHttpError::Busy { .. }) => {}
            other => panic!("global 32 must fail fast, got {other:?}"),
        }
        drop(held);
        assert_eq!(keyed_ingress_global_available(), KEYED_INGRESS_GLOBAL_MAX);
        assert_eq!(keyed_ingress_registry_len(), 0);
    }

    #[test]
    fn keyed_ingress_releases_on_panic() {
        let _lock = lock_keyed_ingress_tests();
        let community = Uuid::from_u128(0xF66);
        let before = keyed_ingress_global_available();
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = try_acquire_keyed_ingress(community).expect("permit");
            panic!("ingress must drop on unwind");
        }));
        assert!(panicked.is_err());
        assert_eq!(keyed_ingress_global_available(), before);
        assert!(!keyed_ingress_registry_contains(community));
    }

    #[tokio::test]
    async fn keyed_ingress_releases_on_cancellation() {
        let _lock = lock_keyed_ingress_tests_async().await;
        let community = Uuid::from_u128(0xCA11);
        let before = keyed_ingress_global_available();
        let (acquired_tx, acquired_rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            let _guard = try_acquire_keyed_ingress(community).expect("permit");
            let _ = acquired_tx.send(());
            std::future::pending::<()>().await;
        });
        acquired_rx.await.expect("acquired");
        assert_eq!(keyed_ingress_global_available(), before - 1);
        handle.abort();
        let _ = handle.await;
        assert_eq!(keyed_ingress_global_available(), before);
        assert!(!keyed_ingress_registry_contains(community));
    }

    #[test]
    fn keyed_ingress_releases_on_error_return() {
        let _lock = lock_keyed_ingress_tests();
        let community = Uuid::from_u128(0xE77);
        let before = keyed_ingress_global_available();
        let result: Result<(), KeyedHttpError> = (|| {
            let _guard = try_acquire_keyed_ingress(community)?;
            Err(keyed_busy_default())
        })();
        assert!(result.is_err());
        assert_eq!(keyed_ingress_global_available(), before);
        assert!(!keyed_ingress_registry_contains(community));
        assert_eq!(keyed_ingress_live_handles(community), None);
    }

    #[test]
    fn keyed_ingress_reclaim_does_not_alias_across_aba() {
        let _lock = lock_keyed_ingress_tests();
        let community = Uuid::from_u128(0xABA1);
        let first = try_acquire_keyed_ingress(community).expect("first generation");
        assert_eq!(keyed_ingress_live_handles(community), Some(1));
        drop(first);
        assert!(!keyed_ingress_registry_contains(community));
        let second = try_acquire_keyed_ingress(community).expect("reclaimed generation");
        assert_eq!(keyed_ingress_live_handles(community), Some(1));
        assert!(keyed_ingress_registry_contains(community));
        drop(second);
        assert!(!keyed_ingress_registry_contains(community));
        assert_eq!(keyed_ingress_registry_len(), 0);
    }

    #[tokio::test]
    async fn pending_early_future_hits_shared_five_second_deadline() {
        let deadline = KeyedEarlyDeadline::from_budget(Duration::from_millis(20));
        let started = Instant::now();
        let result = deadline
            .run(std::future::pending::<Result<(), KeyedHttpError>>())
            .await;
        assert!(started.elapsed() < Duration::from_millis(200));
        assert!(
            matches!(
                result,
                Err(KeyedHttpError::Busy {
                    retry_after_secs: 5
                })
            ),
            "got {result:?}"
        );
    }

    fn wait_watch_in_flight_sync(guard: &KeyedVerifyWatchGuard, expected: usize) {
        let started = Instant::now();
        while guard.in_flight() != expected {
            if started.elapsed() > Duration::from_secs(1) {
                panic!(
                    "watched verification in-flight {}, expected {expected}",
                    guard.in_flight()
                );
            }
            std::thread::yield_now();
        }
    }

    async fn wait_watch_in_flight(guard: &KeyedVerifyWatchGuard, expected: usize) {
        let started = Instant::now();
        while guard.in_flight() != expected {
            if started.elapsed() > Duration::from_secs(1) {
                panic!(
                    "watched verification in-flight {}, expected {expected}",
                    guard.in_flight()
                );
            }
            tokio::task::yield_now().await;
        }
    }

    #[test]
    fn keyed_verification_leaves_no_detached_work() {
        let _lock = lock_keyed_ingress_tests();
        let keys = nostr::Keys::generate();
        let event = EventBuilder::new(Kind::Custom(KIND_STREAM_MESSAGE as u16), "fresh")
            .sign_with_keys(&keys)
            .expect("sign");
        let mut guard = install_keyed_verify_watch(event.id);
        guard.hold();
        guard.spawn_joined_verify(event);
        wait_watch_in_flight_sync(&guard, 1);
        assert_eq!(guard.in_flight(), 1);
        guard.release();
        guard.join_verify().expect("verified");
        assert_eq!(guard.in_flight(), 0);
    }

    #[tokio::test]
    async fn keyed_verification_cancellation_keeps_ingress_until_cpu_completes() {
        let _lock = lock_keyed_ingress_tests_async().await;
        let keys = nostr::Keys::generate();
        let event = signed_kind9(&keys, "fresh", Vec::new());
        let guard = install_keyed_verify_watch(event.id);
        guard.hold();
        let community = Uuid::from_u128(0xCA17);
        let before = keyed_ingress_global_available();
        let ingress = try_acquire_keyed_ingress(community).expect("permit");
        assert_eq!(keyed_ingress_global_available(), before - 1);
        let early = KeyedHttpEarlyContext {
            ingress: Some(ingress),
            deadline: KeyedEarlyDeadline::start(),
            verified_owner: None,
        };
        let auth = http_auth_for(&keys);
        let handle = tokio::spawn(async move {
            KeyedHttpValidatedEvent::validate_with_early(event, auth, early).await
        });
        wait_watch_in_flight(&guard, 1).await;
        handle.abort();
        let _ = handle.await;
        assert_eq!(
            keyed_ingress_global_available(),
            before - 1,
            "ingress must stay held while watched CPU is blocked"
        );
        guard.release();
        wait_watch_in_flight(&guard, 0).await;
        let released = Instant::now();
        while keyed_ingress_global_available() != before {
            if released.elapsed() > Duration::from_secs(1) {
                panic!("ingress must release only after watched CPU completion");
            }
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn keyed_validate_with_early_returns_the_same_live_context() {
        let _lock = lock_keyed_ingress_tests_async().await;
        let keys = nostr::Keys::generate();
        let event = signed_kind9(&keys, "fresh", Vec::new());
        let community = Uuid::from_u128(0xCA18);
        let before = keyed_ingress_global_available();
        let ingress = try_acquire_keyed_ingress(community).expect("permit");
        let deadline = KeyedEarlyDeadline::start();
        let early = KeyedHttpEarlyContext {
            ingress: Some(ingress),
            deadline,
            verified_owner: None,
        };
        let (validated, early) =
            KeyedHttpValidatedEvent::validate_with_early(event, http_auth_for(&keys), early)
                .await
                .expect("validated");
        assert_eq!(event_kind_u32(validated.event()), KIND_STREAM_MESSAGE);
        assert!(early.ingress.is_some());
        assert!(early.deadline.same_absolute_clock(deadline));
        assert_eq!(keyed_ingress_global_available(), before - 1);
        drop(early);
        assert_eq!(keyed_ingress_global_available(), before);
    }

    #[tokio::test]
    async fn keyed_validate_with_early_join_error_maps_internal_and_releases_after_unwind() {
        let _lock = lock_keyed_ingress_tests_async().await;
        let keys = nostr::Keys::generate();
        let event = signed_kind9(&keys, "fresh", Vec::new());
        let guard = install_keyed_verify_watch(event.id);
        guard.arm_panic();
        let community = Uuid::from_u128(0xCA19);
        let before = keyed_ingress_global_available();
        let ingress = try_acquire_keyed_ingress(community).expect("permit");
        let early = KeyedHttpEarlyContext {
            ingress: Some(ingress),
            deadline: KeyedEarlyDeadline::start(),
            verified_owner: None,
        };
        let err = KeyedHttpValidatedEvent::validate_with_early(event, http_auth_for(&keys), early)
            .await
            .err()
            .expect("join error");
        assert!(matches!(
            err,
            IngestError::Internal(ref msg) if msg == "error: internal verification error"
        ));
        assert_eq!(keyed_ingress_global_available(), before);
        assert_eq!(guard.in_flight(), 0);
    }

    #[tokio::test]
    async fn keyed_validate_with_early_invalid_signature_keeps_rejected_mapping() {
        let _lock = lock_keyed_ingress_tests_async().await;
        let keys = nostr::Keys::generate();
        let event = signed_kind9(&keys, "fresh", Vec::new());
        let mut value = serde_json::to_value(&event).expect("json");
        let sig = value
            .get("sig")
            .and_then(|v| v.as_str())
            .expect("sig")
            .to_owned();
        let flipped = format!(
            "{}{}",
            if sig.as_bytes()[0] == b'0' { '1' } else { '0' },
            &sig[1..]
        );
        value["sig"] = serde_json::Value::String(flipped);
        let forged: Event = serde_json::from_value(value).expect("forged event");
        let community = Uuid::from_u128(0xCA1A);
        let before = keyed_ingress_global_available();
        let ingress = try_acquire_keyed_ingress(community).expect("permit");
        let early = KeyedHttpEarlyContext {
            ingress: Some(ingress),
            deadline: KeyedEarlyDeadline::start(),
            verified_owner: None,
        };
        let err = KeyedHttpValidatedEvent::validate_with_early(forged, http_auth_for(&keys), early)
            .await
            .err()
            .expect("forged sig");
        assert!(matches!(err, IngestError::Rejected(ref msg) if msg.starts_with("invalid:")));
        assert_eq!(keyed_ingress_global_available(), before);
    }

    #[test]
    fn presence_update_not_in_scope_allowlist() {
        // KIND_PRESENCE_UPDATE is ephemeral — not in the allowlist regardless of transport.
        let dummy = make_dummy_event();
        assert!(
            required_scope_for_kind(KIND_PRESENCE_UPDATE, &dummy).is_err(),
            "KIND_PRESENCE_UPDATE should not be in the scope allowlist"
        );
    }

    #[test]
    fn diff_validation_rejects_missing_repo() {
        let event = make_event_with_tags(
            KIND_STREAM_MESSAGE_DIFF,
            "diff content",
            &[&["commit", "abc1234"]],
        );
        assert!(validate_diff_event(&event).is_err());
    }

    #[test]
    fn diff_validation_rejects_missing_commit() {
        let event = make_event_with_tags(
            KIND_STREAM_MESSAGE_DIFF,
            "diff content",
            &[&["repo", "https://github.com/example/repo"]],
        );
        assert!(validate_diff_event(&event).is_err());
    }

    #[test]
    fn diff_validation_accepts_valid() {
        let event = make_event_with_tags(
            KIND_STREAM_MESSAGE_DIFF,
            "diff content",
            &[
                &["repo", "https://github.com/example/repo"],
                &["commit", "abc1234"],
            ],
        );
        assert!(validate_diff_event(&event).is_ok());
    }

    #[test]
    fn diff_validation_rejects_oversized_content() {
        let big = "x".repeat(61_441);
        let event = make_event_with_tags(
            KIND_STREAM_MESSAGE_DIFF,
            &big,
            &[
                &["repo", "https://github.com/example/repo"],
                &["commit", "abc1234"],
            ],
        );
        assert!(validate_diff_event(&event).is_err());
    }

    #[test]
    fn link_preview_suppression_accepts_blanket_marker() {
        let event = make_event_with_tags(
            KIND_STREAM_MESSAGE,
            "https://example.com",
            &[&["link-preview", "none"]],
        );

        assert!(validate_link_preview_tags(&event, "https://media.example.com").is_ok());
    }

    #[test]
    fn link_preview_suppression_rejects_duplicate_marker() {
        let event = make_event_with_tags(
            KIND_STREAM_MESSAGE,
            "https://example.com",
            &[&["link-preview", "none"], &["link-preview", "none"]],
        );

        assert_eq!(
            validate_link_preview_tags(&event, "https://media.example.com"),
            Err("link-preview suppression cannot include snapshots".into())
        );
    }

    #[test]
    fn link_preview_suppression_rejects_mixed_snapshot_tags_in_either_order() {
        let snapshot = [
            "link-preview",
            "snapshot",
            "1",
            "https://example.com",
            "Example",
            "Example",
            "Description",
            "",
            "",
            "",
            "",
        ];
        for tags in [
            vec![&["link-preview", "none"][..], &snapshot[..]],
            vec![&snapshot[..], &["link-preview", "none"][..]],
        ] {
            let event = make_event_with_tags(KIND_STREAM_MESSAGE, "https://example.com", &tags);
            assert!(validate_link_preview_tags(&event, "https://media.example.com").is_err());
        }
    }

    fn make_link_preview_event(title: &str, site: &str, description: &str) -> Event {
        make_event_with_tags(
            KIND_STREAM_MESSAGE,
            "https://example.com",
            &[&[
                "link-preview",
                "snapshot",
                "1",
                "https://example.com",
                title,
                site,
                description,
                "",
                "",
                "",
                "",
            ]],
        )
    }

    #[test]
    fn link_preview_snapshot_accepts_description_newlines() {
        let event = make_link_preview_event(
            "Example title",
            "Example site",
            "First paragraph\n\nSecond paragraph",
        );

        assert!(validate_link_preview_tags(&event, "https://media.example.com").is_ok());
    }

    #[test]
    fn link_preview_snapshot_rejects_title_and_site_newlines() {
        for (title, site) in [
            ("Example\ntitle", "Example site"),
            ("Example title", "Example\nsite"),
        ] {
            let event = make_link_preview_event(title, site, "Description");
            assert!(validate_link_preview_tags(&event, "https://media.example.com").is_err());
        }
    }

    #[test]
    fn link_preview_snapshot_rejects_non_newline_controls_in_all_text_fields() {
        for (title, site, description) in [
            ("Example\ttitle", "Example site", "Description"),
            ("Example title", "Example\rsite", "Description"),
            ("Example title", "Example site", "Unsafe\tdescription"),
        ] {
            let event = make_link_preview_event(title, site, description);
            assert!(validate_link_preview_tags(&event, "https://media.example.com").is_err());
        }
    }

    fn make_dummy_event() -> Event {
        let keys = nostr::Keys::generate();
        nostr::EventBuilder::new(nostr::Kind::Custom(9), "")
            .tags([])
            .sign_with_keys(&keys)
            .unwrap()
    }

    fn make_event_with_tags(kind: u32, content: &str, tags: &[&[&str]]) -> Event {
        let keys = nostr::Keys::generate();
        let nostr_tags: Vec<nostr::Tag> = tags
            .iter()
            .map(|t| nostr::Tag::parse(t.iter().copied()).unwrap())
            .collect();
        nostr::EventBuilder::new(nostr::Kind::Custom(kind as u16), content)
            .tags(nostr_tags)
            .sign_with_keys(&keys)
            .unwrap()
    }

    #[test]
    fn count_e_tags_includes_malformed() {
        // A deletion event with one valid e-tag and one malformed e-tag
        // should count as 2 e-tags (and be rejected by the "exactly 1" check).
        let event = make_event_with_tags(
            5, // kind:5 deletion
            "",
            &[&["e", "a".repeat(64).as_str()], &["e", "not-valid-hex"]],
        );
        assert_eq!(count_e_tags(&event), 2);
    }

    #[test]
    fn count_e_tags_single_valid() {
        let event = make_event_with_tags(5, "", &[&["e", "a".repeat(64).as_str()]]);
        assert_eq!(count_e_tags(&event), 1);
    }

    fn make_engram(tags: &[&[&str]], content: &str) -> Event {
        make_event_with_tags(KIND_AGENT_ENGRAM, content, tags)
    }

    /// Minimal syntactically-plausible NIP-44 v2 payload (99 zero-filled bytes
    /// with the 0x02 version prefix). Real ciphertexts are larger and have real
    /// MACs; the relay only checks shape, not authenticity.
    fn fake_nip44_v2() -> String {
        // base64(b"\x02" + b"\x00" * 98) — 132 chars, decoded length 99,
        // first byte 0x02.
        let mut s = String::from("Ag");
        s.push_str(&"A".repeat(130));
        s
    }

    #[test]
    fn engram_envelope_accepts_canonical() {
        let d = "a".repeat(64);
        let p = "b".repeat(64);
        let ev = make_engram(&[&["d", &d], &["p", &p]], &fake_nip44_v2());
        assert!(validate_engram_envelope(&ev).is_ok());
    }

    #[test]
    fn engram_envelope_rejects_missing_p() {
        let d = "a".repeat(64);
        let ev = make_engram(&[&["d", &d]], &fake_nip44_v2());
        let err = validate_engram_envelope(&ev).unwrap_err();
        assert!(err.contains("`p` tag"), "got: {err}");
    }

    #[test]
    fn engram_envelope_rejects_duplicate_p() {
        let d = "a".repeat(64);
        let p = "b".repeat(64);
        let ev = make_engram(&[&["d", &d], &["p", &p], &["p", &p]], &fake_nip44_v2());
        let err = validate_engram_envelope(&ev).unwrap_err();
        assert!(err.contains("`p` tag"), "got: {err}");
    }

    #[test]
    fn engram_envelope_rejects_short_d() {
        let p = "b".repeat(64);
        let ev = make_engram(&[&["d", "abcd"], &["p", &p]], &fake_nip44_v2());
        let err = validate_engram_envelope(&ev).unwrap_err();
        assert!(err.contains("`d` tag"), "got: {err}");
    }

    #[test]
    fn engram_envelope_rejects_uppercase_d() {
        let p = "b".repeat(64);
        // 64 chars but uppercase — spec mandates lowercase hex.
        let d = "A".repeat(64);
        let ev = make_engram(&[&["d", &d], &["p", &p]], &fake_nip44_v2());
        let err = validate_engram_envelope(&ev).unwrap_err();
        assert!(err.contains("`d` tag"), "got: {err}");
    }

    /// Regression: uppercase `p` tag must be rejected at ingest. Readers query
    /// `#p` lowercase; an uppercase-tagged event that wins NIP-33 replacement
    /// becomes invisible to readers, silently bricking the slug.
    #[test]
    fn engram_envelope_rejects_uppercase_p() {
        let d = "a".repeat(64);
        let p = "B".repeat(64);
        let ev = make_engram(&[&["d", &d], &["p", &p]], &fake_nip44_v2());
        let err = validate_engram_envelope(&ev).unwrap_err();
        assert!(err.contains("`p` tag"), "got: {err}");
    }

    #[test]
    fn engram_envelope_rejects_short_p() {
        let d = "a".repeat(64);
        let ev = make_engram(&[&["d", &d], &["p", "abcd"]], &fake_nip44_v2());
        let err = validate_engram_envelope(&ev).unwrap_err();
        assert!(err.contains("`p` tag"), "got: {err}");
    }

    #[test]
    fn engram_envelope_rejects_empty_content() {
        let d = "a".repeat(64);
        let p = "b".repeat(64);
        let ev = make_engram(&[&["d", &d], &["p", &p]], "");
        let err = validate_engram_envelope(&ev).unwrap_err();
        assert!(err.contains("content"), "got: {err}");
    }

    /// Regression: non-base64 content must be rejected. Otherwise a signed
    /// event with `content="x"` wins NIP-33 replacement against a valid head,
    /// and the new head is then skipped by `validate_and_decrypt` — making the
    /// slug appear absent to readers.
    #[test]
    fn engram_envelope_rejects_non_base64_content() {
        let d = "a".repeat(64);
        let p = "b".repeat(64);
        let ev = make_engram(&[&["d", &d], &["p", &p]], "x");
        let err = validate_engram_envelope(&ev).unwrap_err();
        assert!(
            err.contains("base64") || err.contains("too short"),
            "got: {err}"
        );
    }

    #[test]
    fn engram_envelope_rejects_wrong_nip44_version() {
        // 99 bytes of valid base64 alphabet, but first byte decodes to 0x00,
        // not the NIP-44 v2 prefix 0x02. Length OK (132 chars / 99 decoded).
        let d = "a".repeat(64);
        let p = "b".repeat(64);
        let bad = "A".repeat(132);
        let ev = make_engram(&[&["d", &d], &["p", &p]], &bad);
        let err = validate_engram_envelope(&ev).unwrap_err();
        assert!(
            err.contains("NIP-44 v2") || err.contains("0x02"),
            "got: {err}"
        );
    }

    #[test]
    fn engram_envelope_rejects_short_content() {
        // Base64 of "Ag==" decodes to 1 byte — version prefix correct but
        // way under the 99-byte floor.
        let d = "a".repeat(64);
        let p = "b".repeat(64);
        let ev = make_engram(&[&["d", &d], &["p", &p]], "Ag==");
        let err = validate_engram_envelope(&ev).unwrap_err();
        assert!(err.contains("too short"), "got: {err}");
    }

    #[test]
    fn engram_envelope_rejects_bad_base64_alphabet() {
        let d = "a".repeat(64);
        let p = "b".repeat(64);
        // Contains '!' which is not in the standard base64 alphabet. Length is
        // a multiple of 4 to defeat the length check.
        let bad = format!("Ag!!{}", "A".repeat(128));
        let ev = make_engram(&[&["d", &d], &["p", &p]], &bad);
        let err = validate_engram_envelope(&ev).unwrap_err();
        assert!(err.contains("base64"), "got: {err}");
    }

    #[test]
    fn not_before_accepts_zero() {
        assert_eq!(validate_not_before("0"), Ok(0));
    }

    #[test]
    fn not_before_accepts_typical_timestamp() {
        assert_eq!(validate_not_before("1717000000"), Ok(1_717_000_000));
    }

    #[test]
    fn not_before_accepts_max_safe_integer() {
        assert_eq!(
            validate_not_before("9007199254740991"),
            Ok(9_007_199_254_740_991)
        );
    }

    #[test]
    fn not_before_rejects_above_max_safe_integer() {
        assert_eq!(
            validate_not_before("9007199254740992"),
            Err("malformed not_before")
        );
    }

    #[test]
    fn not_before_rejects_leading_zero() {
        assert_eq!(validate_not_before("007"), Err("malformed not_before"));
    }

    #[test]
    fn not_before_rejects_empty() {
        assert_eq!(validate_not_before(""), Err("malformed not_before"));
    }

    #[test]
    fn not_before_rejects_non_digits() {
        // Sign, whitespace, decimal point, and non-decimal forms are all
        // rejected — only ASCII decimal digits are valid.
        for value in ["-1", "+1", " 1", "1 ", "1.0", "1e3", "0x10", "abc"] {
            assert_eq!(
                validate_not_before(value),
                Err("malformed not_before"),
                "value {value:?} should be malformed"
            );
        }
    }

    #[test]
    fn not_before_rejects_u64_overflow() {
        // Exceeds u64::MAX — `from_str` errors rather than wrapping, so the
        // value is malformed (not a lossy round-trip).
        assert_eq!(
            validate_not_before("99999999999999999999999999"),
            Err("malformed not_before")
        );
    }

    fn make_reminder(tags: &[&[&str]]) -> Event {
        make_event_with_tags(KIND_EVENT_REMINDER, "ciphertext", tags)
    }

    #[test]
    fn reminder_accepts_single_valid_not_before() {
        let ev = make_reminder(&[&["d", "abc"], &["not_before", "1717000000"]]);
        assert!(validate_event_reminder(&ev).is_ok());
    }

    #[test]
    fn reminder_accepts_expiration_after_not_before() {
        let ev = make_reminder(&[
            &["d", "abc"],
            &["not_before", "1717000000"],
            &["expiration", "1717000001"],
        ]);
        assert!(validate_event_reminder(&ev).is_ok());
    }

    #[test]
    fn reminder_accepts_missing_not_before() {
        // Terminal states (done/cancelled) and bookmarks omit not_before
        let ev = make_reminder(&[&["d", "abc"]]);
        assert!(validate_event_reminder(&ev).is_ok());
    }

    #[test]
    fn reminder_rejects_not_before_too_far_in_future() {
        // `not_before` beyond the max horizon (default 1 year) is rejected.
        let far_future = (chrono::Utc::now().timestamp() as u64) + 63_072_000; // ~2 years
        let ev = make_reminder(&[&["d", "abc"], &["not_before", &far_future.to_string()]]);
        assert_eq!(
            validate_event_reminder(&ev),
            Err("not_before too far in future")
        );
    }

    #[test]
    fn reminder_rejects_duplicate_not_before() {
        let ev = make_reminder(&[
            &["d", "abc"],
            &["not_before", "1717000000"],
            &["not_before", "1717000005"],
        ]);
        assert_eq!(validate_event_reminder(&ev), Err("malformed not_before"));
    }

    #[test]
    fn reminder_rejects_malformed_not_before() {
        let ev = make_reminder(&[&["d", "abc"], &["not_before", "007"]]);
        assert_eq!(validate_event_reminder(&ev), Err("malformed not_before"));
    }

    #[test]
    fn reminder_rejects_expiration_equal_to_not_before() {
        let ev = make_reminder(&[
            &["d", "abc"],
            &["not_before", "1717000000"],
            &["expiration", "1717000000"],
        ]);
        assert_eq!(
            validate_event_reminder(&ev),
            Err("expiration before not_before")
        );
    }

    #[test]
    fn reminder_rejects_expiration_before_not_before() {
        let ev = make_reminder(&[
            &["d", "abc"],
            &["not_before", "1717000000"],
            &["expiration", "1716000000"],
        ]);
        assert_eq!(
            validate_event_reminder(&ev),
            Err("expiration before not_before")
        );
    }

    #[test]
    fn reminder_ignores_malformed_expiration() {
        // A malformed `expiration` is NIP-40's concern, not this validator's:
        // the ordering check runs only when `expiration` parses, so a valid
        // `not_before` with an unparseable expiration is accepted here.
        let ev = make_reminder(&[
            &["d", "abc"],
            &["not_before", "1717000000"],
            &["expiration", "notanumber"],
        ]);
        assert!(validate_event_reminder(&ev).is_ok());
    }

    #[test]
    fn event_reminder_is_global_only_and_param_replaceable() {
        assert!(is_global_only_kind(KIND_EVENT_REMINDER));
        assert!(!requires_h_channel_scope(KIND_EVENT_REMINDER));
        assert!(is_parameterized_replaceable(KIND_EVENT_REMINDER));
    }

    #[test]
    fn reminder_accepts_expiration_without_not_before() {
        // A terminal/bookmark with expiration but no not_before is valid —
        // no ordering check applies when not_before is absent.
        let ev = make_reminder(&[&["d", "abc"], &["expiration", "1777542730"]]);
        assert!(validate_event_reminder(&ev).is_ok());
    }

    #[test]
    fn reminder_rejects_missing_d_tag() {
        let ev = make_event_with_tags(
            KIND_EVENT_REMINDER,
            "ciphertext",
            &[&["not_before", "1717000000"]],
        );
        assert_eq!(validate_event_reminder(&ev), Err("missing d tag"));
    }

    #[test]
    fn reminder_rejects_empty_d_tag() {
        let ev = make_event_with_tags(
            KIND_EVENT_REMINDER,
            "ciphertext",
            &[&["d", ""], &["not_before", "1717000000"]],
        );
        assert_eq!(validate_event_reminder(&ev), Err("empty d tag"));
    }

    #[test]
    fn reminder_rejects_duplicate_d_tag() {
        let ev = make_event_with_tags(
            KIND_EVENT_REMINDER,
            "ciphertext",
            &[&["d", "abc"], &["d", "def"], &["not_before", "1717000000"]],
        );
        assert_eq!(validate_event_reminder(&ev), Err("duplicate d tag"));
    }

    fn make_persona(tags: &[&[&str]]) -> Event {
        make_event_with_tags(
            KIND_PERSONA,
            r#"{"display_name":"x","system_prompt":"y"}"#,
            tags,
        )
    }

    #[test]
    fn persona_envelope_accepts_valid_slug() {
        let ev = make_persona(&[&["d", "my-persona-1"]]);
        assert!(validate_persona_envelope(&ev).is_ok());
    }

    #[test]
    fn persona_envelope_accepts_promptless_content() {
        // Unified agent model: system_prompt is optional — a definition can be
        // pure configuration. The relay validates only the envelope, so a
        // prompt-less body must ingest identically to a full one.
        let ev = make_event_with_tags(
            KIND_PERSONA,
            r#"{"display_name":"config-only"}"#,
            &[&["d", "config-only"]],
        );
        assert!(validate_persona_envelope(&ev).is_ok());
    }

    #[test]
    fn persona_envelope_accepts_behavioral_fields() {
        // Unknown legacy fields in persona content remain relay-opaque;
        // unknown-field tolerance is the contract.
        let ev = make_event_with_tags(
            KIND_PERSONA,
            r#"{"display_name":"x","respond_to":"owner-only","respond_to_allowlist":[],"mcp_toolsets":"default","parallelism":2}"#,
            &[&["d", "behavioral"]],
        );
        assert!(validate_persona_envelope(&ev).is_ok());
    }

    #[test]
    fn persona_envelope_accepts_single_char() {
        let ev = make_persona(&[&["d", "a"]]);
        assert!(validate_persona_envelope(&ev).is_ok());
    }

    #[test]
    fn persona_envelope_accepts_max_length() {
        let slug = "a".repeat(64);
        let ev = make_persona(&[&["d", &slug]]);
        assert!(validate_persona_envelope(&ev).is_ok());
    }

    #[test]
    fn persona_envelope_rejects_missing_d_tag() {
        let ev = make_persona(&[]);
        let err = validate_persona_envelope(&ev).unwrap_err();
        assert!(err.contains("`d` tag"), "got: {err}");
    }

    #[test]
    fn persona_envelope_rejects_empty_d_tag() {
        let ev = make_persona(&[&["d", ""]]);
        let err = validate_persona_envelope(&ev).unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn persona_envelope_rejects_duplicate_d_tags() {
        let ev = make_persona(&[&["d", "slug-a"], &["d", "slug-b"]]);
        let err = validate_persona_envelope(&ev).unwrap_err();
        assert!(err.contains("`d` tag"), "got: {err}");
    }

    #[test]
    fn persona_envelope_rejects_valueless_d_tag() {
        // A lone ["d"] carries no value; it must fail as a missing value, not
        // be skipped as though the event had no `d` tag at all.
        let ev = make_persona(&[&["d"]]);
        let err = validate_persona_envelope(&ev).unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn persona_envelope_rejects_valueless_plus_valued_d_tags() {
        // Counting only tags with a value would see one `d` here and accept the
        // event, breaking the exactly-one rule.
        let ev = make_persona(&[&["d"], &["d", "slug-a"]]);
        let err = validate_persona_envelope(&ev).unwrap_err();
        assert!(err.contains("exactly one `d` tag"), "got: {err}");
    }

    #[test]
    fn persona_envelope_rejects_too_long() {
        let slug = "a".repeat(65);
        let ev = make_persona(&[&["d", &slug]]);
        let err = validate_persona_envelope(&ev).unwrap_err();
        assert!(err.contains("too long"), "got: {err}");
    }

    #[test]
    fn persona_envelope_rejects_uppercase() {
        let ev = make_persona(&[&["d", "My-Persona"]]);
        let err = validate_persona_envelope(&ev).unwrap_err();
        assert!(err.contains("`d` tag"), "got: {err}");
    }

    #[test]
    fn persona_envelope_rejects_leading_underscore() {
        let ev = make_persona(&[&["d", "_invalid"]]);
        let err = validate_persona_envelope(&ev).unwrap_err();
        assert!(err.contains("start with"), "got: {err}");
    }

    #[test]
    fn persona_envelope_rejects_leading_hyphen() {
        let ev = make_persona(&[&["d", "-invalid"]]);
        let err = validate_persona_envelope(&ev).unwrap_err();
        assert!(err.contains("start with"), "got: {err}");
    }

    #[test]
    fn persona_envelope_rejects_spaces() {
        let ev = make_persona(&[&["d", "has space"]]);
        let err = validate_persona_envelope(&ev).unwrap_err();
        assert!(err.contains("`d` tag"), "got: {err}");
    }

    #[test]
    fn persona_envelope_rejects_dots() {
        let ev = make_persona(&[&["d", "has.dot"]]);
        let err = validate_persona_envelope(&ev).unwrap_err();
        assert!(err.contains("`d` tag"), "got: {err}");
    }

    // ─── persona shared-tag envelope tests ───────────────────────────────────

    #[test]
    fn persona_envelope_accepts_shared_true() {
        // A persona event with exactly one ["shared","true"] tag must be accepted.
        let ev = make_persona(&[&["d", "my-persona"], &["shared", "true"]]);
        assert!(validate_persona_envelope(&ev).is_ok());
    }

    #[test]
    fn persona_envelope_accepts_no_shared_tag() {
        // The shared tag is optional; omitting it is the author-only default.
        let ev = make_persona(&[&["d", "my-persona"]]);
        assert!(validate_persona_envelope(&ev).is_ok());
    }

    #[test]
    fn persona_envelope_rejects_shared_false() {
        let ev = make_persona(&[&["d", "my-persona"], &["shared", "false"]]);
        let err = validate_persona_envelope(&ev).unwrap_err();
        assert!(
            err.contains("\"true\""),
            "expected 'true' in error, got: {err}"
        );
    }

    #[test]
    fn persona_envelope_rejects_shared_wrong_value() {
        let ev = make_persona(&[&["d", "my-persona"], &["shared", "yes"]]);
        let err = validate_persona_envelope(&ev).unwrap_err();
        assert!(
            err.contains("\"true\""),
            "expected 'true' in error, got: {err}"
        );
    }

    #[test]
    fn persona_envelope_rejects_shared_missing_value() {
        // A "shared" tag with no value argument must be rejected.
        let ev = make_event_with_tags(
            KIND_PERSONA,
            r#"{"display_name":"x"}"#,
            &[&["d", "slug"], &["shared"]],
        );
        let err = validate_persona_envelope(&ev).unwrap_err();
        assert!(
            err.contains("\"true\""),
            "expected 'true' in error, got: {err}"
        );
    }

    #[test]
    fn persona_envelope_rejects_duplicate_shared_tags() {
        // More than one shared tag, even if both are "true", must be rejected.
        let ev = make_persona(&[
            &["d", "my-persona"],
            &["shared", "true"],
            &["shared", "true"],
        ]);
        let err = validate_persona_envelope(&ev).unwrap_err();
        assert!(
            err.contains("at most one"),
            "expected 'at most one' in error, got: {err}"
        );
    }

    #[test]
    fn persona_envelope_rejects_shared_three_elements() {
        // ["shared","true","extra"] must be rejected — only exactly two elements
        // are valid so the SQL containment check tags @> '[["shared","true"]]'
        // cannot match a three-element stored tag.
        let ev = make_event_with_tags(
            KIND_PERSONA,
            r#"{"display_name":"x"}"#,
            &[&["d", "slug"], &["shared", "true", "extra"]],
        );
        let err = validate_persona_envelope(&ev).unwrap_err();
        assert!(
            err.contains("[\"shared\",\"true\"]"),
            "expected exact-shape error, got: {err}"
        );
    }

    // ─── team-catalog (30178) envelope tests ─────────────────────────────────

    fn make_team_catalog(tags: &[&[&str]]) -> Event {
        make_event_with_tags(
            KIND_TEAM_CATALOG,
            r#"{"v":1,"name":"Team","members":[]}"#,
            tags,
        )
    }

    #[test]
    fn team_catalog_envelope_accepts_uuid_d_tag() {
        let ev = make_team_catalog(&[&["d", "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"]]);
        assert!(validate_team_catalog_envelope(&ev).is_ok());
    }

    #[test]
    fn team_catalog_envelope_accepts_builtin_colon_d_tag() {
        // Built-in team ids carry a colon (`builtin-team:welcome`), which the
        // persona slug grammar forbids. The catalog `d` tag must accept them so
        // a built-in team can be shared under its real local id.
        let ev = make_team_catalog(&[&["d", "builtin-team:welcome"]]);
        assert!(validate_team_catalog_envelope(&ev).is_ok());
    }

    #[test]
    fn team_catalog_envelope_accepts_shared_true() {
        let ev = make_team_catalog(&[&["d", "team-1"], &["shared", "true"]]);
        assert!(validate_team_catalog_envelope(&ev).is_ok());
    }

    #[test]
    fn team_catalog_envelope_rejects_missing_d_tag() {
        let ev = make_team_catalog(&[]);
        let err = validate_team_catalog_envelope(&ev).unwrap_err();
        assert!(err.contains("exactly one `d` tag"), "got: {err}");
    }

    #[test]
    fn team_catalog_envelope_rejects_empty_d_tag() {
        // An empty d-tag collapses every team into the (pubkey, 30178, "") slot.
        let ev = make_team_catalog(&[&["d", ""]]);
        let err = validate_team_catalog_envelope(&ev).unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn team_catalog_envelope_rejects_duplicate_d_tags() {
        let ev = make_team_catalog(&[&["d", "team-1"], &["d", "team-2"]]);
        let err = validate_team_catalog_envelope(&ev).unwrap_err();
        assert!(err.contains("exactly one `d` tag"), "got: {err}");
    }

    #[test]
    fn team_catalog_envelope_rejects_valueless_d_tag() {
        // A lone ["d"] carries no value; it must fail as a missing value, not
        // be skipped as though the event had no `d` tag at all.
        let ev = make_team_catalog(&[&["d"]]);
        let err = validate_team_catalog_envelope(&ev).unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn team_catalog_envelope_rejects_valueless_plus_valued_d_tags() {
        // Counting only tags with a value would see one `d` here and accept the
        // event. A NIP-33 consumer that reads ["d"] as an empty-valued first
        // `d` tag would then address this event at "" where we address it at
        // "team-1".
        let ev = make_team_catalog(&[&["d"], &["d", "team-1"]]);
        let err = validate_team_catalog_envelope(&ev).unwrap_err();
        assert!(err.contains("exactly one `d` tag"), "got: {err}");
    }

    #[test]
    fn team_catalog_envelope_bounds_d_tag_by_chars_not_bytes() {
        // 64 multi-byte characters is 192 bytes; the documented bound is
        // characters, so this must be accepted.
        let d = "é".repeat(64);
        assert!(d.len() > 64, "fixture must exceed the bound in bytes");
        let ev = make_team_catalog(&[&["d", &d]]);
        assert!(validate_team_catalog_envelope(&ev).is_ok());
    }

    #[test]
    fn team_catalog_envelope_rejects_too_long_d_tag() {
        let d = "a".repeat(65);
        let ev = make_team_catalog(&[&["d", &d]]);
        let err = validate_team_catalog_envelope(&ev).unwrap_err();
        assert!(err.contains("too long"), "got: {err}");
    }

    #[test]
    fn team_catalog_envelope_accepts_max_length_d_tag() {
        let d = "a".repeat(64);
        let ev = make_team_catalog(&[&["d", &d]]);
        assert!(validate_team_catalog_envelope(&ev).is_ok());
    }

    #[test]
    fn team_catalog_envelope_rejects_whitespace_d_tag() {
        // A newline in the d-tag would break the NIP-33 coordinate and any
        // line-oriented log consumer.
        let ev = make_team_catalog(&[&["d", "team\n1"]]);
        let err = validate_team_catalog_envelope(&ev).unwrap_err();
        assert!(err.contains("control characters"), "got: {err}");
    }

    #[test]
    fn team_catalog_envelope_rejects_shared_false() {
        let ev = make_team_catalog(&[&["d", "team-1"], &["shared", "false"]]);
        let err = validate_team_catalog_envelope(&ev).unwrap_err();
        assert!(err.contains("\"true\""), "got: {err}");
    }

    #[test]
    fn team_catalog_envelope_rejects_shared_three_elements() {
        // Same exact-shape rule as personas: a three-element tag would match the
        // SQL containment clause `tags @> '[["shared","true"]]'` as a superset.
        let ev = make_team_catalog(&[&["d", "team-1"], &["shared", "true", "extra"]]);
        let err = validate_team_catalog_envelope(&ev).unwrap_err();
        assert!(err.contains("[\"shared\",\"true\"]"), "got: {err}");
    }

    #[test]
    fn team_catalog_envelope_rejects_duplicate_shared_tags() {
        let ev = make_team_catalog(&[&["d", "team-1"], &["shared", "true"], &["shared", "true"]]);
        let err = validate_team_catalog_envelope(&ev).unwrap_err();
        assert!(err.contains("at most one"), "got: {err}");
    }

    #[test]
    fn team_catalog_is_in_scope_allowlist() {
        let dummy = make_dummy_event();
        assert_eq!(
            required_scope_for_kind(KIND_TEAM_CATALOG, &dummy).unwrap(),
            Scope::UsersWrite,
        );
    }

    #[test]
    fn team_catalog_is_global_only() {
        assert!(is_global_only_kind(KIND_TEAM_CATALOG));
        assert!(!requires_h_channel_scope(KIND_TEAM_CATALOG));
    }

    // ─── project (NIP-MP kind:30621) envelope tests ──────────────────────────

    const OWNER_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OWNER_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn make_project(tags: &[&[&str]]) -> Event {
        make_event_with_tags(KIND_PROJECT, "", tags)
    }

    fn member_coord(owner: &str, repo_d: &str) -> String {
        format!("30617:{owner}:{repo_d}")
    }

    #[test]
    fn project_envelope_accepts_minimal() {
        let ev = make_project(&[&["d", "platform"]]);
        assert!(validate_project_envelope(&ev).is_ok());
    }

    #[test]
    fn project_envelope_accepts_full_cross_owner_membership() {
        // The motivating case: one project spanning two owners' repositories.
        let a = member_coord(OWNER_A, "buzz");
        let b = member_coord(OWNER_B, "buzz-infra");
        let ev = make_project(&[
            &["d", "platform"],
            &["name", "Platform"],
            &["description", "Relay, desktop, and mobile."],
            &["a", &a],
            &["a", &b],
            &["buzz-channel", "3580ca9b-47b4-4af9-b22a-1068778f26c6"],
            &["buzz-visibility", "listed"],
        ]);
        assert!(validate_project_envelope(&ev).is_ok());
    }

    #[test]
    fn project_envelope_accepts_zero_members() {
        // Legal at the protocol layer: the natural state after removing a final
        // member. The create UI requires >= 1; the relay must not.
        let ev = make_project(&[&["d", "empty"], &["name", "Empty"]]);
        assert!(validate_project_envelope(&ev).is_ok());
    }

    #[test]
    fn project_envelope_accepts_same_repo_d_under_two_owners() {
        // The NIP-34 fork case. Identity is the whole coordinate, so these are
        // two distinct members, not a duplicate.
        let a = member_coord(OWNER_A, "buzz");
        let b = member_coord(OWNER_B, "buzz");
        let ev = make_project(&[&["d", "forks"], &["a", &a], &["a", &b]]);
        assert!(validate_project_envelope(&ev).is_ok());
    }

    #[test]
    fn project_envelope_accepts_member_repo_d_containing_colon() {
        // Coordinates split on the first two colons only, matching NIP-09
        // deletion parsing, so a colon-bearing repository `d` stays addressable.
        let coord = member_coord(OWNER_A, "group:repo");
        let ev = make_project(&[&["d", "external"], &["a", &coord]]);
        assert!(validate_project_envelope(&ev).is_ok());
    }

    #[test]
    fn project_envelope_accepts_member_cap_boundary() {
        let coords: Vec<String> = (0..PROJECT_MEMBER_CAP)
            .map(|i| member_coord(OWNER_A, &format!("repo-{i}")))
            .collect();
        let mut tags: Vec<Vec<&str>> = vec![vec!["d", "wide"]];
        tags.extend(coords.iter().map(|c| vec!["a", c.as_str()]));
        let tag_refs: Vec<&[&str]> = tags.iter().map(|t| t.as_slice()).collect();
        let ev = make_project(&tag_refs);
        assert!(
            validate_project_envelope(&ev).is_ok(),
            "exactly {PROJECT_MEMBER_CAP} members must be accepted"
        );
    }

    #[test]
    fn project_envelope_ignores_unknown_tags() {
        // Forward compatibility: a newer writer's extra metadata must not
        // invalidate the event for this relay.
        let ev = make_project(&[&["d", "platform"], &["future-field", "whatever"]]);
        assert!(validate_project_envelope(&ev).is_ok());
    }

    #[test]
    fn project_envelope_rejects_missing_d_tag() {
        let ev = make_project(&[&["name", "No Identity"]]);
        let err = validate_project_envelope(&ev).unwrap_err();
        assert!(
            err.to_string().contains("exactly one `d` tag"),
            "got: {err}"
        );
    }

    #[test]
    fn project_envelope_rejects_multiple_d_tags() {
        let ev = make_project(&[&["d", "one"], &["d", "two"]]);
        let err = validate_project_envelope(&ev).unwrap_err();
        assert!(
            err.to_string().contains("exactly one `d` tag"),
            "got: {err}"
        );
    }

    #[test]
    fn project_envelope_rejects_empty_d_tag() {
        // An empty `d` collapses every such project into the (pubkey, 30621, "")
        // slot, where unrelated projects silently overwrite each other.
        let ev = make_project(&[&["d", ""]]);
        let err = validate_project_envelope(&ev).unwrap_err();
        assert!(err.to_string().contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn project_envelope_rejects_valueless_d_tag() {
        // `["d"]` with no value is treated as empty, not as absent.
        let ev = make_project(&[&["d"]]);
        let err = validate_project_envelope(&ev).unwrap_err();
        assert!(err.to_string().contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn project_envelope_rejects_duplicate_member_coordinate() {
        let coord = member_coord(OWNER_A, "buzz");
        let ev = make_project(&[&["d", "platform"], &["a", &coord], &["a", &coord]]);
        let err = validate_project_envelope(&ev).unwrap_err();
        assert!(
            err.to_string().contains("duplicate member coordinate"),
            "got: {err}"
        );
    }

    #[test]
    fn project_envelope_rejects_member_cap_exceeded() {
        let coords: Vec<String> = (0..=PROJECT_MEMBER_CAP)
            .map(|i| member_coord(OWNER_A, &format!("repo-{i}")))
            .collect();
        let mut tags: Vec<Vec<&str>> = vec![vec!["d", "wide"]];
        tags.extend(coords.iter().map(|c| vec!["a", c.as_str()]));
        let tag_refs: Vec<&[&str]> = tags.iter().map(|t| t.as_slice()).collect();
        let ev = make_project(&tag_refs);
        let err = validate_project_envelope(&ev).unwrap_err();
        assert!(err.to_string().contains("at most 64 member"), "got: {err}");
    }

    #[test]
    fn project_envelope_rejects_duplicate_heavy_list_on_cap_not_duplicate() {
        // The cap counts raw `a` tags, so a duplicate-heavy list is refused on
        // count — parse volume is never bounded only by the frame limit.
        let coord = member_coord(OWNER_A, "buzz");
        let mut tags: Vec<Vec<&str>> = vec![vec!["d", "wide"]];
        for _ in 0..=PROJECT_MEMBER_CAP {
            tags.push(vec!["a", coord.as_str()]);
        }
        let tag_refs: Vec<&[&str]> = tags.iter().map(|t| t.as_slice()).collect();
        let ev = make_project(&tag_refs);
        let err = validate_project_envelope(&ev).unwrap_err();
        assert!(
            err.to_string().contains("at most 64 member"),
            "cap must be evaluated before the duplicate set is built, got: {err}"
        );
    }

    #[test]
    fn project_envelope_rejects_member_wrong_kind_prefix() {
        // kind:30618 is repository *state*; a project groups announcements.
        let coord = format!("30618:{OWNER_A}:buzz");
        let ev = make_project(&[&["d", "platform"], &["a", &coord]]);
        let err = validate_project_envelope(&ev).unwrap_err();
        assert!(
            err.to_string().contains("member `a` tag must be"),
            "got: {err}"
        );
    }

    #[test]
    fn project_envelope_rejects_member_owner_not_hex() {
        let coord = member_coord(&"z".repeat(64), "buzz");
        let ev = make_project(&[&["d", "platform"], &["a", &coord]]);
        let err = validate_project_envelope(&ev).unwrap_err();
        assert!(
            err.to_string().contains("member `a` tag must be"),
            "got: {err}"
        );
    }

    #[test]
    fn project_envelope_rejects_member_owner_uppercase_hex() {
        // `#a` filter matching is byte-exact: an uppercase-owner head would be
        // invisible to the lowercase-coordinate queries every reader issues.
        let coord = member_coord(&"A".repeat(64), "buzz");
        let ev = make_project(&[&["d", "platform"], &["a", &coord]]);
        let err = validate_project_envelope(&ev).unwrap_err();
        assert!(
            err.to_string().contains("member `a` tag must be"),
            "got: {err}"
        );
    }

    #[test]
    fn project_envelope_rejects_member_owner_wrong_length() {
        let coord = member_coord(&"a".repeat(63), "buzz");
        let ev = make_project(&[&["d", "platform"], &["a", &coord]]);
        let err = validate_project_envelope(&ev).unwrap_err();
        assert!(
            err.to_string().contains("member `a` tag must be"),
            "got: {err}"
        );
    }

    #[test]
    fn project_envelope_rejects_member_empty_repo_d() {
        let coord = member_coord(OWNER_A, "");
        let ev = make_project(&[&["d", "platform"], &["a", &coord]]);
        let err = validate_project_envelope(&ev).unwrap_err();
        assert!(
            err.to_string().contains("member `a` tag must be"),
            "got: {err}"
        );
    }

    #[test]
    fn project_envelope_rejects_member_missing_segment() {
        let coord = format!("30617:{OWNER_A}");
        let ev = make_project(&[&["d", "platform"], &["a", &coord]]);
        let err = validate_project_envelope(&ev).unwrap_err();
        assert!(
            err.to_string().contains("member `a` tag must be"),
            "got: {err}"
        );
    }

    #[test]
    fn project_envelope_rejects_valueless_member_tag() {
        // A one-element `a` tag names no coordinate — caught by the arity check
        // (rule 4) before the coordinate parse (rule 5) even runs.
        let ev = make_project(&[&["d", "platform"], &["a"]]);
        let err = validate_project_envelope(&ev).unwrap_err();
        assert!(
            err.to_string().contains("exactly 2 or 3 elements"),
            "got: {err}"
        );
    }

    #[test]
    fn project_envelope_rejects_duplicate_metadata_tags() {
        // Every singleton metadata tag is bounded: a duplicate would make the
        // effective value reader-dependent.
        for tag_name in PROJECT_SINGLETON_METADATA_TAGS {
            let ev = make_project(&[&["d", "platform"], &[tag_name, "x"], &[tag_name, "y"]]);
            let err = validate_project_envelope(&ev).unwrap_err();
            assert!(
                err.to_string()
                    .contains(&format!("at most one `{tag_name}` tag")),
                "duplicate `{tag_name}` must be rejected, got: {err}"
            );
        }
    }

    #[test]
    fn project_envelope_rejects_name_too_long() {
        let name = "x".repeat(PROJECT_NAME_MAX_LEN + 1);
        let ev = make_project(&[&["d", "platform"], &["name", &name]]);
        let err = validate_project_envelope(&ev).unwrap_err();
        assert!(
            err.to_string().contains("`name` tag too long"),
            "got: {err}"
        );
    }

    #[test]
    fn project_envelope_accepts_name_at_max_length() {
        let name = "x".repeat(PROJECT_NAME_MAX_LEN);
        let ev = make_project(&[&["d", "platform"], &["name", &name]]);
        assert!(validate_project_envelope(&ev).is_ok());
    }

    #[test]
    fn project_envelope_rejects_description_too_long() {
        let description = "x".repeat(PROJECT_DESCRIPTION_MAX_LEN + 1);
        let ev = make_project(&[&["d", "platform"], &["description", &description]]);
        let err = validate_project_envelope(&ev).unwrap_err();
        assert!(
            err.to_string().contains("`description` tag too long"),
            "got: {err}"
        );
    }

    #[test]
    fn project_envelope_accepts_description_at_max_length() {
        let description = "x".repeat(PROJECT_DESCRIPTION_MAX_LEN);
        let ev = make_project(&[&["d", "platform"], &["description", &description]]);
        assert!(validate_project_envelope(&ev).is_ok());
    }

    /// Membership is an assertion, not a permission grant: the relay must accept
    /// a project naming a repository the signer does not own. Cross-owner
    /// grouping is the entire point of the kind, and it is safe precisely because
    /// membership confers nothing.
    #[test]
    fn project_envelope_accepts_member_owned_by_another_pubkey() {
        let stranger = member_coord(OWNER_B, "not-mine");
        let ev = make_project(&[&["d", "collection"], &["a", &stranger]]);
        assert!(validate_project_envelope(&ev).is_ok());
    }

    #[test]
    fn project_is_in_scope_allowlist() {
        let dummy = make_dummy_event();
        assert_eq!(
            required_scope_for_kind(KIND_PROJECT, &dummy).unwrap(),
            Scope::ReposWrite,
            "a project is repository metadata — same scope as announcing a repo"
        );
    }

    #[test]
    fn project_is_global_only() {
        // `buzz-channel` is a metadata reference, not a routing directive.
        assert!(is_global_only_kind(KIND_PROJECT));
        assert!(!requires_h_channel_scope(KIND_PROJECT));
    }

    #[test]
    fn project_is_parameterized_replaceable() {
        // Owner-only editing comes free from NIP-33 addressing: replacement is
        // keyed by (pubkey, kind, d), so one signer can never overwrite another's
        // project. No relay-side permission check exists or is needed.
        assert!(is_parameterized_replaceable(KIND_PROJECT));
    }

    /// Drive every case in the shared NIP-MP fixture file against
    /// `validate_project_envelope`. All 11 accept cases must pass; all 20
    /// reject cases must return an error whose rule is in the case's allowed
    /// `reject_rules` set — an implementation cannot pass by rejecting for an
    /// unrelated reason. This is the machine-readable oracle the spec promises.
    #[test]
    fn project_envelope_validates_all_shared_fixtures() {
        #[derive(serde::Deserialize)]
        struct FixtureFile {
            cases: Vec<Case>,
        }
        #[derive(serde::Deserialize)]
        struct Case {
            name: String,
            expect: String,
            #[serde(default)]
            reject_rules: Vec<String>,
            template: Template,
        }
        #[derive(serde::Deserialize)]
        struct Template {
            content: String,
            tags: Vec<Vec<String>>,
        }

        let raw = include_str!("../../../../docs/nips/NIP-MP.fixtures.json");
        let file: FixtureFile = serde_json::from_str(raw).expect("fixture file must parse");

        for case in &file.cases {
            let tag_strs: Vec<Vec<&str>> = case
                .template
                .tags
                .iter()
                .map(|t| t.iter().map(|s| s.as_str()).collect())
                .collect();
            let tag_refs: Vec<&[&str]> = tag_strs.iter().map(|t| t.as_slice()).collect();
            let ev = make_event_with_tags(KIND_PROJECT, &case.template.content, &tag_refs);
            let result = validate_project_envelope(&ev);
            match case.expect.as_str() {
                "accept" => assert!(
                    result.is_ok(),
                    "fixture {:?} expected accept, got err: {:?}",
                    case.name,
                    result.unwrap_err()
                ),
                "reject" => {
                    let rejection = match result {
                        Err(r) => r,
                        Ok(()) => {
                            panic!("fixture {:?} expected reject, but was accepted", case.name)
                        }
                    };
                    assert!(
                        case.reject_rules.iter().any(|r| r == rejection.rule),
                        "fixture {:?} fired rule {:?}, which is not in allowed set {:?}",
                        case.name,
                        rejection.rule,
                        case.reject_rules,
                    );
                }
                other => panic!(
                    "unknown expect value {:?} in fixture {:?}",
                    other, case.name
                ),
            }
        }
    }

    // ─── agent_turn_metric envelope tests ────────────────────────────────────

    /// Build an event for kind:44200 with the given tags and content.
    /// The signing key IS the agent key, so `event.pubkey` matches the agent.
    fn make_agent_turn_metric(
        agent_keys: &nostr::Keys,
        tags: &[&[&str]],
        content: &str,
    ) -> nostr::Event {
        let nostr_tags: Vec<nostr::Tag> = tags
            .iter()
            .map(|t| nostr::Tag::parse(t.iter().copied()).unwrap())
            .collect();
        nostr::EventBuilder::new(
            nostr::Kind::Custom(buzz_core::kind::KIND_AGENT_TURN_METRIC as u16),
            content,
        )
        .tags(nostr_tags)
        .sign_with_keys(agent_keys)
        .unwrap()
    }

    #[test]
    fn agent_turn_metric_envelope_accepts_canonical() {
        let agent = nostr::Keys::generate();
        let owner_hex = "b".repeat(64);
        let agent_hex = agent.public_key().to_hex();
        let ev = make_agent_turn_metric(
            &agent,
            &[&["p", &owner_hex], &["agent", &agent_hex]],
            &fake_nip44_v2(),
        );
        assert!(validate_agent_turn_metric_envelope(&ev).is_ok());
    }

    #[test]
    fn agent_turn_metric_envelope_rejects_h_tag() {
        let agent = nostr::Keys::generate();
        let owner_hex = "b".repeat(64);
        let agent_hex = agent.public_key().to_hex();
        let ev = make_agent_turn_metric(
            &agent,
            &[
                &["p", &owner_hex],
                &["agent", &agent_hex],
                &["h", "some-channel-uuid"],
            ],
            &fake_nip44_v2(),
        );
        let err = validate_agent_turn_metric_envelope(&ev).unwrap_err();
        assert!(err.contains("`h` tag"), "got: {err}");
    }

    #[test]
    fn agent_turn_metric_envelope_rejects_missing_p() {
        let agent = nostr::Keys::generate();
        let agent_hex = agent.public_key().to_hex();
        let ev = make_agent_turn_metric(&agent, &[&["agent", &agent_hex]], &fake_nip44_v2());
        let err = validate_agent_turn_metric_envelope(&ev).unwrap_err();
        assert!(err.contains("`p` tag"), "got: {err}");
    }

    #[test]
    fn agent_turn_metric_envelope_rejects_missing_agent() {
        let agent = nostr::Keys::generate();
        let owner_hex = "b".repeat(64);
        let ev = make_agent_turn_metric(&agent, &[&["p", &owner_hex]], &fake_nip44_v2());
        let err = validate_agent_turn_metric_envelope(&ev).unwrap_err();
        assert!(err.contains("`agent` tag"), "got: {err}");
    }

    #[test]
    fn agent_turn_metric_envelope_rejects_agent_mismatch() {
        let agent = nostr::Keys::generate();
        let owner_hex = "b".repeat(64);
        let wrong_agent_hex = "c".repeat(64); // not event.pubkey
        let ev = make_agent_turn_metric(
            &agent,
            &[&["p", &owner_hex], &["agent", &wrong_agent_hex]],
            &fake_nip44_v2(),
        );
        let err = validate_agent_turn_metric_envelope(&ev).unwrap_err();
        assert!(err.contains("equal event pubkey"), "got: {err}");
    }

    #[test]
    fn agent_turn_metric_envelope_rejects_bad_content() {
        let agent = nostr::Keys::generate();
        let owner_hex = "b".repeat(64);
        let agent_hex = agent.public_key().to_hex();
        let ev = make_agent_turn_metric(
            &agent,
            &[&["p", &owner_hex], &["agent", &agent_hex]],
            "not-a-ciphertext",
        );
        let err = validate_agent_turn_metric_envelope(&ev).unwrap_err();
        // error comes from validate_engram_nip44_content with label replaced
        assert!(err.contains("agent-turn-metric"), "got: {err}");
    }

    /// The HTTP bridge's `submit_event` 400 arm and the WS `EVENT` handler's
    /// reject path must land on the same counter, distinguished only by the
    /// `transport` label — this is what lets a dashboard tell "server got
    /// hammered with bad HTTP requests" apart from "a WS client is
    /// misbehaving" without losing the combined total.
    #[test]
    fn reject_with_transport_labels_http_and_ws_as_separate_series() {
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        metrics::with_local_recorder(&recorder, || {
            reject_with_transport("http", "invalid");
            reject_with_transport("ws", "invalid");
            reject_with_transport("http", "invalid");
        });

        let counts: std::collections::HashMap<(String, String), u64> = snapshotter
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
            .collect();

        assert_eq!(
            counts.get(&("http".to_owned(), "invalid".to_owned())),
            Some(&2)
        );
        assert_eq!(
            counts.get(&("ws".to_owned(), "invalid".to_owned())),
            Some(&1)
        );
    }
}

#[cfg(test)]
mod postgres_tests {
    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn ingest_write_fence_follows_community_deletion_lifecycle() {
        super::tests::ingest_write_fence_follows_community_deletion_lifecycle().await;
    }
}
