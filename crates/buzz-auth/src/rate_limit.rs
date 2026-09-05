//! Rate limiting types and interface.
//!
//! Defines the [`RateLimiter`] trait. The Redis-backed implementation lives in
//! `buzz-relay` / `buzz-pubsub`. Fixed-window counter algorithm.
//!
//! ⚠️ Fixed windows allow up to 2× burst at boundaries. Upgrade to sliding
//! window or token bucket for strict limiting.

use std::net::IpAddr;
use std::num::NonZeroU64;

use buzz_core::TenantContext;
use nostr::PublicKey;
use serde::{Deserialize, Serialize};

use crate::error::AuthError;

/// The outcome of a rate-limit check, including counter state for response headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitResult {
    /// Whether the request is permitted (`true`) or should be rejected (`false`).
    pub allowed: bool,
    /// Current counter value after this increment.
    pub current: u64,
    /// The configured limit for this window.
    pub limit: u64,
    /// Seconds until the current window resets.
    pub reset_in_secs: u64,
}

impl RateLimitResult {
    /// Construct an **allowed** result.
    pub fn allowed(current: u64, limit: u64, reset_in_secs: u64) -> Self {
        Self {
            allowed: true,
            current,
            limit,
            reset_in_secs,
        }
    }

    /// Construct a **denied** result.
    pub fn denied(current: u64, limit: u64, reset_in_secs: u64) -> Self {
        Self {
            allowed: false,
            current,
            limit,
            reset_in_secs,
        }
    }
}

/// The category of operation being rate-limited.
///
/// Each variant maps to a distinct Redis key suffix so limits are tracked
/// independently per operation type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitType {
    /// Nostr message events (kind:1 etc.) sent via WebSocket.
    Messages,
    /// HTTP REST API calls.
    ApiCalls,
    /// Relay-proxied GIF metadata searches.
    GifSearches,
    /// All WebSocket events (broader than `Messages`).
    WsEvents,
    /// Concurrent WebSocket connections from a single IP address.
    IpConnections,
    /// Keyed HTTP `POST /events` authenticated-attempt hierarchy. Charged
    /// exactly once after host binding and cryptographic NIP-98 signer
    /// authentication, before local ingress, replay-marker write, parse,
    /// membership, validation, or fresh work. Identity, community, and fleet
    /// keys of one admission are charged together.
    KeyedHttpAttempts,
    /// Keyed HTTP `POST /events` legitimate fresh-request lane. Charged only
    /// after replay defense, parse, membership, validation, and a committed
    /// miss. Replay and conflict do not charge this lane.
    KeyedHttpFresh,
}

impl LimitType {
    /// Short suffix used in Redis key construction (e.g. `"msg"`, `"api"`).
    pub fn key_suffix(&self) -> &'static str {
        match self {
            Self::Messages => "msg",
            Self::ApiCalls => "api",
            Self::GifSearches => "gif",
            Self::WsEvents => "ws",
            Self::IpConnections => "conn",
            Self::KeyedHttpAttempts => "katt",
            Self::KeyedHttpFresh => "kfsh",
        }
    }
}

/// Per-tier rate limit thresholds.
///
/// All values are counts per the relevant time window (per-minute or per-second).
/// Loaded from the relay config file; sensible defaults are provided for all fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum messages per minute for human users. Default: 60.
    #[serde(default = "default_human_msg")]
    pub human_messages_per_min: u64,
    /// Maximum relay-proxied GIF searches per minute for each pubkey.
    /// Default: 30.
    #[serde(default = "default_gif_searches")]
    pub gif_searches_per_min: u64,
    /// Maximum HTTP API calls per minute for human users. Default: 300.
    #[serde(default = "default_human_api")]
    pub human_api_calls_per_min: u64,
    /// Maximum WebSocket events per second for human users. Default: 10.
    #[serde(default = "default_human_ws")]
    pub human_ws_events_per_sec: u64,
    /// Maximum messages per minute for standard-tier agent tokens. Default: 120.
    #[serde(default = "default_agent_std_msg")]
    pub agent_standard_messages_per_min: u64,
    /// Maximum HTTP API calls per minute for standard-tier agent tokens. Default: 600.
    #[serde(default = "default_agent_std_api")]
    pub agent_standard_api_calls_per_min: u64,
    /// Maximum messages per minute for elevated-tier agent tokens. Default: 300.
    #[serde(default = "default_agent_elev_msg")]
    pub agent_elevated_messages_per_min: u64,
    /// Maximum messages per minute for platform-tier agent tokens. Default: 600.
    #[serde(default = "default_agent_plat_msg")]
    pub agent_platform_messages_per_min: u64,
}

fn default_human_msg() -> u64 {
    60
}
fn default_gif_searches() -> u64 {
    30
}
fn default_human_api() -> u64 {
    300
}
fn default_human_ws() -> u64 {
    10
}
fn default_agent_std_msg() -> u64 {
    120
}
fn default_agent_std_api() -> u64 {
    600
}
fn default_agent_elev_msg() -> u64 {
    300
}
fn default_agent_plat_msg() -> u64 {
    600
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            human_messages_per_min: default_human_msg(),
            gif_searches_per_min: default_gif_searches(),
            human_api_calls_per_min: default_human_api(),
            human_ws_events_per_sec: default_human_ws(),
            agent_standard_messages_per_min: default_agent_std_msg(),
            agent_standard_api_calls_per_min: default_agent_std_api(),
            agent_elevated_messages_per_min: default_agent_elev_msg(),
            agent_platform_messages_per_min: default_agent_plat_msg(),
        }
    }
}

/// Finite telemetry class for keyed hierarchical-admission and
/// identity-denial-peek failures.
///
/// The only external labels are the static strings returned by [`Self::as_str`].
/// Mapping from variant to label is centralized and exhaustive there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyedAdmissionErrorClass {
    /// Backend wait or command timeout.
    BackendTimeout,
    /// Explicit corrupt-counter response code.
    CounterCorrupt,
    /// Other typed pool or Redis failure.
    BackendUnavailable,
    /// Local precondition, response-shape, or unknown-code failure.
    Contract,
    /// Untyped/legacy failure with no producer-assigned class.
    Unknown,
}

impl KeyedAdmissionErrorClass {
    /// Static telemetry label for this class. The only external labels are
    /// `backend_timeout`, `counter_corrupt`, `backend_unavailable`,
    /// `contract`, and `unknown`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BackendTimeout => "backend_timeout",
            Self::CounterCorrupt => "counter_corrupt",
            Self::BackendUnavailable => "backend_unavailable",
            Self::Contract => "contract",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for KeyedAdmissionErrorClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Producer-assigned [`KeyedAdmissionErrorClass`] plus the legacy [`AuthError`].
///
/// The class is assigned at the failure origin. Log [`Self::class`] via
/// [`KeyedAdmissionErrorClass::as_str`]; do not use [`AuthError`] prose as a
/// telemetry label.
#[derive(Debug)]
pub struct KeyedAdmissionFailure {
    error: AuthError,
    class: KeyedAdmissionErrorClass,
}

impl KeyedAdmissionFailure {
    /// Pair a legacy [`AuthError`] with a producer-assigned class.
    pub fn new(error: AuthError, class: KeyedAdmissionErrorClass) -> Self {
        Self { error, class }
    }

    /// Wrap an untyped [`AuthError`] as [`KeyedAdmissionErrorClass::Unknown`].
    ///
    /// Used by the default classified trait methods. Does not inspect error
    /// prose.
    pub fn unknown(error: AuthError) -> Self {
        Self::new(error, KeyedAdmissionErrorClass::Unknown)
    }

    /// Producer-assigned telemetry class.
    pub const fn class(&self) -> KeyedAdmissionErrorClass {
        self.class
    }

    /// Legacy [`AuthError`] retained for diagnostics and untyped APIs.
    pub fn error(&self) -> &AuthError {
        &self.error
    }

    /// Unwrap the legacy [`AuthError`].
    pub fn into_error(self) -> AuthError {
        self.error
    }
}

impl std::fmt::Display for KeyedAdmissionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

impl From<KeyedAdmissionFailure> for AuthError {
    fn from(failure: KeyedAdmissionFailure) -> Self {
        failure.into_error()
    }
}

/// Async rate-limiting interface.
///
/// The Redis-backed production implementation lives in `buzz-relay` / `buzz-pubsub`.
/// A no-op `AlwaysAllowRateLimiter` is provided for unit tests.
///
/// ## Tenant scoping
///
/// Pubkey-keyed limits ([`check_and_increment`]) take `&TenantContext` and the Redis
/// key is community-prefixed (`buzz:{community}:ratelimit:{pubkey}:{suffix}`). The
/// same pubkey active in two communities consumes two independent quotas — that is
/// the correct behavior under multi-tenant isolation (S1 cross-community fence).
///
/// IP-keyed limits ([`check_ip_connection`]) are **operator-global** by design. They
/// gate connection acceptance at the network edge, before host→community resolution
/// has completed (or, on resolve failure, instead of it). Threading `&TenantContext`
/// through the connection-rate fence would invert the order of operations. If
/// per-(community, IP) caps are ever needed as a tenant-fairness signal, that
/// belongs in an additive `LimitType` keyed on `(community, ip)`, not in this trait.
///
/// ⚠️ The fixed-window algorithm used by the Redis implementation allows up to 2×
/// burst at window boundaries. Upgrade to a sliding window or token bucket if strict
/// per-second limiting is required.
///
/// A downstream crate that implemented only the base-era required methods
/// continues to compile. The inherited [`Self::check_paired_admission`] default
/// fails closed without touching any key:
///
/// ```no_run
/// use buzz_auth::rate_limit::{RateLimitResult, RateLimiter};
/// use buzz_auth::{AuthError, LimitType};
/// use buzz_core::TenantContext;
/// use nostr::PublicKey;
/// use std::net::IpAddr;
///
/// struct LegacyExternalLimiter;
///
/// impl RateLimiter for LegacyExternalLimiter {
///     async fn check_and_increment(
///         &self,
///         _ctx: &TenantContext,
///         _pubkey: &PublicKey,
///         _limit_type: LimitType,
///         window_secs: u64,
///         limit: u64,
///     ) -> Result<RateLimitResult, AuthError> {
///         Ok(RateLimitResult::allowed(1, limit, window_secs))
///     }
///
///     async fn check_ip_connection(
///         &self,
///         _ip: &IpAddr,
///         window_secs: u64,
///         limit: u64,
///     ) -> Result<RateLimitResult, AuthError> {
///         Ok(RateLimitResult::allowed(1, limit, window_secs))
///     }
/// }
/// ```
pub trait RateLimiter: Send + Sync {
    /// Increment the per-(community, pubkey) counter for `limit_type` and return
    /// whether the request is within `limit` for the given `window_secs`.
    ///
    /// `ctx` scopes the counter to the resolved community; the same pubkey in two
    /// communities is two independent quotas.
    fn check_and_increment(
        &self,
        ctx: &TenantContext,
        pubkey: &PublicKey,
        limit_type: LimitType,
        window_secs: u64,
        limit: u64,
    ) -> impl std::future::Future<Output = Result<RateLimitResult, AuthError>> + Send;

    /// Increment the per-IP connection counter and return whether the connection
    /// is within `limit` for the given `window_secs`.
    ///
    /// Operator-global — see trait docs. This fence runs before / outside of host
    /// resolution and intentionally does not take a `TenantContext`.
    fn check_ip_connection(
        &self,
        ip: &IpAddr,
        window_secs: u64,
        limit: u64,
    ) -> impl std::future::Future<Output = Result<RateLimitResult, AuthError>> + Send;

    /// Atomically admit against a tenant-prefixed key and an operator-global
    /// fleet IP key in one implementation-defined operation.
    ///
    /// Implementations MUST NOT sequence [`check_and_increment`] and
    /// [`check_ip_connection`]. A tenant or fleet denial MUST leave both
    /// counter values unchanged (no charge and no partial charge). A denial
    /// MAY repair or align tenant expiry to a still-live fleet window so a
    /// positive tenant counter cannot expire and reopen inside that window.
    /// Success MUST increment both keys once and establish or repair their
    /// fixed-window TTLs together. Redis errors fail closed.
    ///
    /// [`PairedAdmissionRequest`] carries exactly one shared nonzero window;
    /// implementations MUST apply that window to both charged keys.
    ///
    /// The default implementation fails closed without touching any key.
    /// Never default to allow.
    fn check_paired_admission(
        &self,
        _request: PairedAdmissionRequest<'_>,
    ) -> impl std::future::Future<Output = Result<PairedAdmissionOutcome, AuthError>> + Send {
        async {
            Err(AuthError::Internal(
                "paired admission is unavailable".into(),
            ))
        }
    }

    /// Atomically admit against an identity key, a community aggregate key,
    /// and an operator-global fleet key in one implementation-defined operation.
    ///
    /// Implementations MUST NOT sequence [`check_and_increment`] and
    /// [`check_paired_admission`]. An identity, community, or fleet denial
    /// MUST leave all three counter values unchanged and MUST NOT create a
    /// previously missing identity key. A denial MAY repair or align identity
    /// and community expiry to a still-live fleet window so a positive
    /// counter cannot expire and reopen inside that window, and MUST NOT
    /// extend that authoritative window. Success MUST increment all three
    /// keys once and establish or repair one shared absolute deadline.
    /// Backend errors and corrupt or ambiguous counter/TTL state fail closed.
    ///
    /// Identity keys may use the authenticated signer because a missing
    /// identity key is created only by a successful admission that also
    /// consumes the finite community and fleet aggregates; identity-key
    /// cardinality in a window is therefore bounded by those successes.
    ///
    /// The default implementation fails closed without touching any key.
    /// [`HierarchicalAdmissionRequest`] carries exactly one shared nonzero
    /// window; implementations MUST apply that window to all three charged keys.
    fn check_hierarchical_admission(
        &self,
        _request: HierarchicalAdmissionRequest<'_>,
    ) -> impl std::future::Future<Output = Result<HierarchicalAdmissionOutcome, AuthError>> + Send
    {
        async {
            Err(AuthError::Internal(
                "hierarchical admission is unavailable".into(),
            ))
        }
    }

    /// Read-only peek for a proven hierarchical identity denial.
    ///
    /// Implementations MUST NOT write, MUST NOT read the community key, and
    /// MUST NOT create a key or move a deadline. Proven denial is allowed
    /// only when the identity counter is a canonical nonnegative Redis-INCR
    /// integer at or above the request's nonzero identity limit, identity
    /// `PTTL` and `PEXPIRETIME` describe a live finite key, the fleet
    /// sentinel is a canonical nonnegative integer with a live finite TTL
    /// and the same absolute expiry as the identity, and the identity and
    /// fleet keys are distinct. Missing, under-limit, stale, persistent,
    /// misaligned, or semantically corrupt state MUST return the non-denied
    /// outcome so callers can fall through to
    /// [`check_hierarchical_admission`]. Backend and response-contract
    /// errors fail closed.
    ///
    /// The default implementation fails closed without touching any key.
    fn peek_hierarchical_identity_denial(
        &self,
        _request: HierarchicalIdentityDenialPeekRequest<'_>,
    ) -> impl std::future::Future<Output = Result<HierarchicalIdentityDenialPeekOutcome, AuthError>> + Send
    {
        async {
            Err(AuthError::Internal(
                "hierarchical identity denial peek is unavailable".into(),
            ))
        }
    }

    /// Typed variant of [`Self::check_hierarchical_admission`].
    ///
    /// The default implementation calls [`Self::check_hierarchical_admission`]
    /// exactly once and classifies an untyped [`AuthError`] as
    /// [`KeyedAdmissionErrorClass::Unknown`] without inspecting its prose.
    fn check_hierarchical_admission_classified(
        &self,
        request: HierarchicalAdmissionRequest<'_>,
    ) -> impl std::future::Future<Output = Result<HierarchicalAdmissionOutcome, KeyedAdmissionFailure>>
           + Send {
        async {
            self.check_hierarchical_admission(request)
                .await
                .map_err(KeyedAdmissionFailure::unknown)
        }
    }

    /// Typed variant of [`Self::peek_hierarchical_identity_denial`].
    ///
    /// The default implementation calls [`Self::peek_hierarchical_identity_denial`]
    /// exactly once and classifies an untyped [`AuthError`] as
    /// [`KeyedAdmissionErrorClass::Unknown`] without inspecting its prose.
    fn peek_hierarchical_identity_denial_classified(
        &self,
        request: HierarchicalIdentityDenialPeekRequest<'_>,
    ) -> impl std::future::Future<
        Output = Result<HierarchicalIdentityDenialPeekOutcome, KeyedAdmissionFailure>,
    > + Send {
        async {
            self.peek_hierarchical_identity_denial(request)
                .await
                .map_err(KeyedAdmissionFailure::unknown)
        }
    }
}

/// Inputs for [`RateLimiter::check_paired_admission`].
///
/// Tenant and fleet counters share one nonzero window. The window is a
/// [`NonZeroU64`], so a zero or split clock cannot be constructed.
#[derive(Debug, Clone)]
pub struct PairedAdmissionRequest<'a> {
    /// Community that owns the tenant-prefixed counter.
    pub tenant: &'a TenantContext,
    /// Protocol principal for the tenant-prefixed counter.
    pub pubkey: &'a PublicKey,
    /// Limit-type suffix for the tenant-prefixed counter.
    pub limit_type: LimitType,
    /// Maximum tenant-prefixed admissions in the window.
    pub tenant_limit: u64,
    /// Operator-global fleet IP key.
    pub fleet_ip: &'a IpAddr,
    /// Maximum fleet admissions in the window.
    pub fleet_limit: u64,
    window_secs: NonZeroU64,
}

impl<'a> PairedAdmissionRequest<'a> {
    /// Build a paired admission request with one shared nonzero window.
    pub fn new(
        tenant: &'a TenantContext,
        pubkey: &'a PublicKey,
        limit_type: LimitType,
        window_secs: NonZeroU64,
        tenant_limit: u64,
        fleet_ip: &'a IpAddr,
        fleet_limit: u64,
    ) -> Self {
        Self {
            tenant,
            pubkey,
            limit_type,
            tenant_limit,
            fleet_ip,
            fleet_limit,
            window_secs,
        }
    }

    /// Shared fixed window, in seconds, applied to both charged keys.
    pub fn window_secs(&self) -> u64 {
        self.window_secs.get()
    }
}

/// Outcome of [`RateLimiter::check_paired_admission`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairedAdmissionOutcome {
    /// Both counters had room and were incremented together.
    Allowed {
        /// Tenant-prefixed counter after the increment.
        tenant: RateLimitResult,
        /// Fleet counter after the increment.
        fleet: RateLimitResult,
    },
    /// Tenant counter was already at or above its limit. Neither counter
    /// value was charged. Tenant expiry may be aligned to a live fleet window.
    TenantDenied(RateLimitResult),
    /// Fleet counter was already at or above its limit. Neither counter
    /// value was charged. Tenant expiry may be aligned to a live fleet window.
    FleetDenied(RateLimitResult),
}

/// Per-dimension counts for [`HierarchicalAdmissionRequest`].
///
/// Identity, community, and fleet share one nonzero window on the request;
/// this value groups only those three limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HierarchicalAdmissionLimits {
    /// Maximum identity/fair-share admissions in the window.
    pub identity: u64,
    /// Maximum community-aggregate admissions in the window.
    pub community: u64,
    /// Maximum fleet admissions in the window.
    pub fleet: u64,
}

impl HierarchicalAdmissionLimits {
    /// Group the identity, community, and fleet limits for one admission.
    pub const fn new(identity: u64, community: u64, fleet: u64) -> Self {
        Self {
            identity,
            community,
            fleet,
        }
    }
}

/// Inputs for [`RateLimiter::check_hierarchical_admission`].
///
/// Identity, community, and fleet counters share one nonzero window. The
/// window is a [`NonZeroU64`], so a zero or split clock cannot be constructed.
#[derive(Debug, Clone)]
pub struct HierarchicalAdmissionRequest<'a> {
    /// Community that owns the identity and community-prefixed counters.
    pub tenant: &'a TenantContext,
    /// Authenticated signer for the identity/fair-share counter.
    pub identity: &'a PublicKey,
    /// Reserved principal for the per-community aggregate counter.
    pub community: &'a PublicKey,
    /// Limit-type suffix for the identity and community-prefixed counters.
    pub limit_type: LimitType,
    /// Identity, community, and fleet counts for this shared window.
    pub limits: HierarchicalAdmissionLimits,
    /// Operator-global fleet IP key.
    pub fleet_ip: &'a IpAddr,
    window_secs: NonZeroU64,
}

impl<'a> HierarchicalAdmissionRequest<'a> {
    /// Build a hierarchical admission request with one shared nonzero window.
    pub fn new(
        tenant: &'a TenantContext,
        identity: &'a PublicKey,
        community: &'a PublicKey,
        limit_type: LimitType,
        window_secs: NonZeroU64,
        limits: HierarchicalAdmissionLimits,
        fleet_ip: &'a IpAddr,
    ) -> Self {
        Self {
            tenant,
            identity,
            community,
            limit_type,
            limits,
            fleet_ip,
            window_secs,
        }
    }

    /// Shared fixed window, in seconds, applied to all three charged keys.
    pub fn window_secs(&self) -> u64 {
        self.window_secs.get()
    }
}

/// Outcome of [`RateLimiter::check_hierarchical_admission`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HierarchicalAdmissionOutcome {
    /// All three counters had room and were incremented together.
    Allowed {
        /// Identity/fair-share counter after the increment.
        identity: RateLimitResult,
        /// Community aggregate after the increment.
        community: RateLimitResult,
        /// Fleet counter after the increment.
        fleet: RateLimitResult,
    },
    /// Identity counter was already at or above its limit. No counter value
    /// was charged and no missing identity key was created. Existing identity
    /// and community expiry may be aligned to a live fleet window.
    IdentityDenied(RateLimitResult),
    /// Community counter was already at or above its limit. No counter value
    /// was charged and no missing identity key was created. Existing identity
    /// and community expiry may be aligned to a live fleet window.
    CommunityDenied(RateLimitResult),
    /// Fleet counter was already at or above its limit. No counter value was
    /// charged and no missing identity key was created. Existing identity and
    /// community expiry may be aligned to a live fleet window.
    FleetDenied(RateLimitResult),
}

/// Inputs for [`RateLimiter::peek_hierarchical_identity_denial`].
///
/// Identity and fleet keys must be distinct. The identity limit is a
/// [`NonZeroU64`], so a zero limit cannot be constructed.
#[derive(Debug, Clone)]
pub struct HierarchicalIdentityDenialPeekRequest<'a> {
    /// Community that owns the identity counter.
    pub tenant: &'a TenantContext,
    /// Authenticated signer for the identity/fair-share counter.
    pub identity: &'a PublicKey,
    /// Limit-type suffix for the identity counter.
    pub limit_type: LimitType,
    /// Operator-global fleet IP key.
    pub fleet_ip: &'a IpAddr,
    identity_limit: NonZeroU64,
}

impl<'a> HierarchicalIdentityDenialPeekRequest<'a> {
    /// Build a read-only identity-denial peek request with a nonzero identity limit.
    pub fn new(
        tenant: &'a TenantContext,
        identity: &'a PublicKey,
        limit_type: LimitType,
        identity_limit: NonZeroU64,
        fleet_ip: &'a IpAddr,
    ) -> Self {
        Self {
            tenant,
            identity,
            limit_type,
            fleet_ip,
            identity_limit,
        }
    }

    /// Nonzero identity/fair-share limit used for the peek comparison.
    pub fn identity_limit(&self) -> u64 {
        self.identity_limit.get()
    }
}

/// Outcome of [`RateLimiter::peek_hierarchical_identity_denial`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HierarchicalIdentityDenialPeekOutcome {
    /// Identity is a proven live-window denial. No key was written, created,
    /// or moved, and the community key was not read.
    Denied(RateLimitResult),
    /// Not a proven identity denial. Callers must fall through to
    /// [`RateLimiter::check_hierarchical_admission`].
    NotDenied,
}

/// Redis key for pubkey-based rate limit:
/// `buzz:{community}:ratelimit:{pubkey_hex}:{suffix}`.
///
/// Community-prefixed: the same pubkey in two communities maps to two distinct
/// keys, so quotas don't bleed across the tenancy fence.
pub fn rate_limit_key(ctx: &TenantContext, pubkey: &PublicKey, limit_type: &LimitType) -> String {
    format!(
        "buzz:{}:ratelimit:{}:{}",
        ctx.community(),
        pubkey.to_hex(),
        limit_type.key_suffix()
    )
}

/// Redis key for IP-based rate limit: `buzz:ratelimit:ip:{ip}:conn`.
///
/// Operator-global by design — see [`RateLimiter`] docs.
pub fn ip_rate_limit_key(ip: &IpAddr) -> String {
    format!("buzz:ratelimit:ip:{}:conn", ip)
}

/// Always-allow rate limiter for unit tests.
#[cfg(any(test, feature = "test-utils"))]
pub struct AlwaysAllowRateLimiter;

#[cfg(any(test, feature = "test-utils"))]
impl RateLimiter for AlwaysAllowRateLimiter {
    async fn check_and_increment(
        &self,
        _ctx: &TenantContext,
        _pubkey: &PublicKey,
        _limit_type: LimitType,
        window_secs: u64,
        limit: u64,
    ) -> Result<RateLimitResult, AuthError> {
        Ok(RateLimitResult::allowed(1, limit, window_secs))
    }

    async fn check_ip_connection(
        &self,
        _ip: &IpAddr,
        window_secs: u64,
        limit: u64,
    ) -> Result<RateLimitResult, AuthError> {
        Ok(RateLimitResult::allowed(1, limit, window_secs))
    }

    async fn check_paired_admission(
        &self,
        request: PairedAdmissionRequest<'_>,
    ) -> Result<PairedAdmissionOutcome, AuthError> {
        let window_secs = request.window_secs();
        Ok(PairedAdmissionOutcome::Allowed {
            tenant: RateLimitResult::allowed(1, request.tenant_limit, window_secs),
            fleet: RateLimitResult::allowed(1, request.fleet_limit, window_secs),
        })
    }

    async fn check_hierarchical_admission(
        &self,
        request: HierarchicalAdmissionRequest<'_>,
    ) -> Result<HierarchicalAdmissionOutcome, AuthError> {
        let window_secs = request.window_secs();
        Ok(HierarchicalAdmissionOutcome::Allowed {
            identity: RateLimitResult::allowed(1, request.limits.identity, window_secs),
            community: RateLimitResult::allowed(1, request.limits.community, window_secs),
            fleet: RateLimitResult::allowed(1, request.limits.fleet, window_secs),
        })
    }

    async fn peek_hierarchical_identity_denial(
        &self,
        _request: HierarchicalIdentityDenialPeekRequest<'_>,
    ) -> Result<HierarchicalIdentityDenialPeekOutcome, AuthError> {
        Ok(HierarchicalIdentityDenialPeekOutcome::NotDenied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_core::CommunityId;
    use nostr::Keys;
    use sha2::Digest;
    use std::net::Ipv4Addr;
    use std::num::NonZeroU64;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use uuid::Uuid;

    fn fixture_ctx(host: &str) -> TenantContext {
        // Deterministic community id from host so test assertions can name the prefix.
        let bytes = sha2::Sha256::digest(host.as_bytes());
        let mut uuid_bytes = [0u8; 16];
        uuid_bytes.copy_from_slice(&bytes[..16]);
        let id = CommunityId::from_uuid(Uuid::from_bytes(uuid_bytes));
        TenantContext::resolved(id, host)
    }

    #[test]
    fn rate_limit_key_includes_community_prefix() {
        let ctx = fixture_ctx("relay-a.example");
        let keys = Keys::generate();
        let key = rate_limit_key(&ctx, &keys.public_key(), &LimitType::Messages);
        let expected_prefix = format!("buzz:{}:ratelimit:", ctx.community());
        assert!(
            key.starts_with(&expected_prefix),
            "key {key} should start with {expected_prefix}"
        );
        assert!(key.ends_with(":msg"));
    }

    #[test]
    fn keyed_http_attempts_suffix_is_distinct_and_stable() {
        assert_eq!(LimitType::KeyedHttpAttempts.key_suffix(), "katt");
        assert_eq!(LimitType::KeyedHttpFresh.key_suffix(), "kfsh");
        assert_eq!(
            serde_json::to_value(&LimitType::KeyedHttpAttempts).unwrap(),
            serde_json::json!("keyed_http_attempts")
        );
        assert_eq!(
            serde_json::to_value(&LimitType::KeyedHttpFresh).unwrap(),
            serde_json::json!("keyed_http_fresh")
        );
        assert_eq!(
            serde_json::to_value(&LimitType::Messages).unwrap(),
            serde_json::json!("messages")
        );
        assert_eq!(
            serde_json::to_value(&LimitType::ApiCalls).unwrap(),
            serde_json::json!("api_calls")
        );
        assert_eq!(
            serde_json::to_value(&LimitType::GifSearches).unwrap(),
            serde_json::json!("gif_searches")
        );
        assert_eq!(
            serde_json::to_value(&LimitType::WsEvents).unwrap(),
            serde_json::json!("ws_events")
        );
        assert_eq!(
            serde_json::to_value(&LimitType::IpConnections).unwrap(),
            serde_json::json!("ip_connections")
        );
        let existing = [
            LimitType::Messages.key_suffix(),
            LimitType::ApiCalls.key_suffix(),
            LimitType::GifSearches.key_suffix(),
            LimitType::WsEvents.key_suffix(),
            LimitType::IpConnections.key_suffix(),
        ];
        assert_eq!(existing, ["msg", "api", "gif", "ws", "conn"]);
        assert!(!existing.contains(&LimitType::KeyedHttpAttempts.key_suffix()));
        assert!(!existing.contains(&LimitType::KeyedHttpFresh.key_suffix()));
        assert_ne!(
            LimitType::KeyedHttpAttempts.key_suffix(),
            LimitType::KeyedHttpFresh.key_suffix()
        );
    }

    #[test]
    fn keyed_preauth_and_fresh_tenant_keys_do_not_alias() {
        let ctx = fixture_ctx("relay-a.example");
        let keys = Keys::generate();
        let preauth = rate_limit_key(&ctx, &keys.public_key(), &LimitType::KeyedHttpAttempts);
        let fresh = rate_limit_key(&ctx, &keys.public_key(), &LimitType::KeyedHttpFresh);
        assert!(preauth.ends_with(":katt"));
        assert!(fresh.ends_with(":kfsh"));
        assert_ne!(preauth, fresh);
        assert!(preauth.starts_with(&format!("buzz:{}:ratelimit:", ctx.community())));
        assert!(fresh.starts_with(&format!("buzz:{}:ratelimit:", ctx.community())));
    }

    #[test]
    fn gif_searches_have_an_independent_quota_key() {
        let ctx = fixture_ctx("relay-a.example");
        let keys = Keys::generate();
        let gif_key = rate_limit_key(&ctx, &keys.public_key(), &LimitType::GifSearches);
        let api_key = rate_limit_key(&ctx, &keys.public_key(), &LimitType::ApiCalls);

        assert!(gif_key.ends_with(":gif"));
        assert_ne!(gif_key, api_key);
    }

    #[test]
    fn rate_limit_key_isolates_communities_for_same_pubkey() {
        // The S1 cross-community isolation fence at the rate-limit key layer:
        // same pubkey, two communities -> two distinct Redis keys -> independent quotas.
        let keys = Keys::generate();
        let ctx_a = fixture_ctx("relay-a.example");
        let ctx_b = fixture_ctx("relay-b.example");
        let key_a = rate_limit_key(&ctx_a, &keys.public_key(), &LimitType::Messages);
        let key_b = rate_limit_key(&ctx_b, &keys.public_key(), &LimitType::Messages);
        assert_ne!(
            key_a, key_b,
            "same pubkey in two communities must not share a rate-limit key"
        );
    }

    #[test]
    fn rate_limit_key_components_are_lowercase() {
        // Stability/idempotence invariant: if pubkey hex or community Display
        // ever started emitting uppercase, the same (community, pubkey) would
        // produce two distinct Redis keys → effective 2× quota. Pin the
        // lowercase property here so the regression surfaces in unit tests,
        // not in production traffic.
        let ctx = fixture_ctx("relay-a.example");
        let keys = Keys::generate();
        let key = rate_limit_key(&ctx, &keys.public_key(), &LimitType::Messages);
        for c in key.chars() {
            assert!(
                !c.is_ascii_uppercase(),
                "rate-limit key {key} must be all-lowercase ASCII"
            );
        }
    }

    #[test]
    fn ip_rate_limit_key_format() {
        // IP fence stays operator-global — no community in the key.
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(ip_rate_limit_key(&ip), "buzz:ratelimit:ip:192.168.1.1:conn");
    }

    #[tokio::test]
    async fn always_allow_limiter() {
        let limiter = AlwaysAllowRateLimiter;
        let ctx = fixture_ctx("relay-a.example");
        let keys = Keys::generate();
        let result = limiter
            .check_and_increment(&ctx, &keys.public_key(), LimitType::Messages, 60, 60)
            .await
            .unwrap();
        assert!(result.allowed);
    }

    #[tokio::test]
    async fn always_allow_paired_admission_increments_neither_real_key() {
        let limiter = AlwaysAllowRateLimiter;
        let ctx = fixture_ctx("relay-a.example");
        let keys = Keys::generate();
        let ip = IpAddr::V4(Ipv4Addr::BROADCAST);
        let window = NonZeroU64::new(60).expect("shared live window");
        let outcome = limiter
            .check_paired_admission(PairedAdmissionRequest::new(
                &ctx,
                &keys.public_key(),
                LimitType::IpConnections,
                window,
                600,
                &ip,
                1_200,
            ))
            .await
            .unwrap();
        match outcome {
            PairedAdmissionOutcome::Allowed { tenant, fleet } => {
                assert!(tenant.allowed);
                assert!(fleet.allowed);
                assert_eq!(tenant.limit, 600);
                assert_eq!(fleet.limit, 1_200);
                assert_eq!(tenant.reset_in_secs, window.get());
                assert_eq!(fleet.reset_in_secs, window.get());
                assert_eq!(tenant.reset_in_secs, fleet.reset_in_secs);
            }
            other => panic!("always-allow paired admission must succeed, got {other:?}"),
        }
    }

    #[test]
    fn paired_admission_request_requires_one_nonzero_shared_window() {
        assert!(
            NonZeroU64::new(0).is_none(),
            "a zero window is not a NonZeroU64, so it cannot be stored"
        );
        let ctx = fixture_ctx("relay-a.example");
        let keys = Keys::generate();
        let ip = IpAddr::V4(Ipv4Addr::BROADCAST);
        let window = NonZeroU64::new(60).expect("live keyed window");
        let pubkey = keys.public_key();
        let request = PairedAdmissionRequest::new(
            &ctx,
            &pubkey,
            LimitType::IpConnections,
            window,
            600,
            &ip,
            1_200,
        );
        assert_eq!(request.window_secs(), 60);
        assert_eq!(request.tenant_limit, 600);
        assert_eq!(request.fleet_limit, 1_200);
        assert_eq!(
            request.window_secs(),
            window.get(),
            "tenant and fleet share the same stored window"
        );
    }

    #[tokio::test]
    async fn always_allow_hierarchical_admission_increments_neither_real_key() {
        let limiter = AlwaysAllowRateLimiter;
        let ctx = fixture_ctx("relay-a.example");
        let identity = Keys::generate();
        let community = Keys::generate();
        let ip = IpAddr::V4(Ipv4Addr::BROADCAST);
        let window = NonZeroU64::new(60).expect("shared live window");
        let outcome = limiter
            .check_hierarchical_admission(HierarchicalAdmissionRequest::new(
                &ctx,
                &identity.public_key(),
                &community.public_key(),
                LimitType::KeyedHttpAttempts,
                window,
                HierarchicalAdmissionLimits::new(300, 1_200, 2_400),
                &ip,
            ))
            .await
            .unwrap();
        match outcome {
            HierarchicalAdmissionOutcome::Allowed {
                identity,
                community,
                fleet,
            } => {
                assert!(identity.allowed && community.allowed && fleet.allowed);
                assert_eq!(identity.limit, 300);
                assert_eq!(community.limit, 1_200);
                assert_eq!(fleet.limit, 2_400);
                assert_eq!(identity.reset_in_secs, window.get());
                assert_eq!(community.reset_in_secs, identity.reset_in_secs);
                assert_eq!(fleet.reset_in_secs, identity.reset_in_secs);
            }
            other => panic!("always-allow hierarchical admission must succeed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn always_allow_identity_denial_peek_returns_not_denied_without_mutation() {
        let limiter = AlwaysAllowRateLimiter;
        let ctx = fixture_ctx("relay-a.example");
        let identity = Keys::generate();
        let ip = IpAddr::V4(Ipv4Addr::BROADCAST);
        let outcome = limiter
            .peek_hierarchical_identity_denial(HierarchicalIdentityDenialPeekRequest::new(
                &ctx,
                &identity.public_key(),
                LimitType::KeyedHttpAttempts,
                NonZeroU64::new(300).expect("nonzero identity limit"),
                &ip,
            ))
            .await
            .unwrap();
        assert_eq!(
            outcome,
            HierarchicalIdentityDenialPeekOutcome::NotDenied,
            "always-allow peek must return the non-denied outcome without mutation"
        );
    }

    struct DefaultHierarchicalLimiter;

    impl RateLimiter for DefaultHierarchicalLimiter {
        async fn check_and_increment(
            &self,
            _ctx: &TenantContext,
            _pubkey: &PublicKey,
            _limit_type: LimitType,
            window_secs: u64,
            limit: u64,
        ) -> Result<RateLimitResult, AuthError> {
            Ok(RateLimitResult::allowed(1, limit, window_secs))
        }

        async fn check_ip_connection(
            &self,
            _ip: &IpAddr,
            window_secs: u64,
            limit: u64,
        ) -> Result<RateLimitResult, AuthError> {
            Ok(RateLimitResult::allowed(1, limit, window_secs))
        }

        async fn check_paired_admission(
            &self,
            request: PairedAdmissionRequest<'_>,
        ) -> Result<PairedAdmissionOutcome, AuthError> {
            let window_secs = request.window_secs();
            Ok(PairedAdmissionOutcome::Allowed {
                tenant: RateLimitResult::allowed(1, request.tenant_limit, window_secs),
                fleet: RateLimitResult::allowed(1, request.fleet_limit, window_secs),
            })
        }
    }

    /// Base-era implementor: required methods only. Intentionally omits
    /// [`RateLimiter::check_paired_admission`] so the inherited default is used.
    struct LegacyBaseLimiter {
        increment_calls: AtomicUsize,
        ip_calls: AtomicUsize,
    }

    impl LegacyBaseLimiter {
        fn new() -> Self {
            Self {
                increment_calls: AtomicUsize::new(0),
                ip_calls: AtomicUsize::new(0),
            }
        }
    }

    impl RateLimiter for LegacyBaseLimiter {
        async fn check_and_increment(
            &self,
            _ctx: &TenantContext,
            _pubkey: &PublicKey,
            _limit_type: LimitType,
            window_secs: u64,
            limit: u64,
        ) -> Result<RateLimitResult, AuthError> {
            self.increment_calls.fetch_add(1, Ordering::Relaxed);
            Ok(RateLimitResult::allowed(1, limit, window_secs))
        }

        async fn check_ip_connection(
            &self,
            _ip: &IpAddr,
            window_secs: u64,
            limit: u64,
        ) -> Result<RateLimitResult, AuthError> {
            self.ip_calls.fetch_add(1, Ordering::Relaxed);
            Ok(RateLimitResult::allowed(1, limit, window_secs))
        }
    }

    #[tokio::test]
    async fn paired_trait_default_fails_closed_without_touching_keys() {
        let limiter = LegacyBaseLimiter::new();
        let ctx = fixture_ctx("relay-a.example");
        let keys = Keys::generate();
        let ip = IpAddr::V4(Ipv4Addr::BROADCAST);
        let window = NonZeroU64::new(60).expect("shared live window");
        let err = limiter
            .check_paired_admission(PairedAdmissionRequest::new(
                &ctx,
                &keys.public_key(),
                LimitType::ApiCalls,
                window,
                600,
                &ip,
                1_200,
            ))
            .await
            .expect_err("inherited paired admission must fail closed");
        assert!(
            err.to_string().contains("unavailable"),
            "default must fail closed, got {err}"
        );
        assert_eq!(limiter.increment_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.ip_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn hierarchical_trait_default_fails_closed_without_an_outcome() {
        let limiter = DefaultHierarchicalLimiter;
        let ctx = fixture_ctx("relay-a.example");
        let identity = Keys::generate();
        let community = Keys::generate();
        let ip = IpAddr::V4(Ipv4Addr::BROADCAST);
        let window = NonZeroU64::new(60).expect("shared live window");
        let err = limiter
            .check_hierarchical_admission(HierarchicalAdmissionRequest::new(
                &ctx,
                &identity.public_key(),
                &community.public_key(),
                LimitType::KeyedHttpAttempts,
                window,
                HierarchicalAdmissionLimits::new(300, 1_200, 2_400),
                &ip,
            ))
            .await
            .expect_err("default hierarchical admission must fail closed");
        assert!(
            err.to_string().contains("unavailable"),
            "default must fail closed, got {err}"
        );
    }

    #[tokio::test]
    async fn identity_denial_peek_trait_default_fails_closed_without_an_outcome() {
        let limiter = DefaultHierarchicalLimiter;
        let ctx = fixture_ctx("relay-a.example");
        let identity = Keys::generate();
        let ip = IpAddr::V4(Ipv4Addr::BROADCAST);
        let err = limiter
            .peek_hierarchical_identity_denial(HierarchicalIdentityDenialPeekRequest::new(
                &ctx,
                &identity.public_key(),
                LimitType::KeyedHttpAttempts,
                NonZeroU64::new(300).expect("nonzero identity limit"),
                &ip,
            ))
            .await
            .expect_err("default identity denial peek must fail closed");
        assert!(
            err.to_string().contains("unavailable"),
            "default must fail closed, got {err}"
        );
    }

    #[test]
    fn hierarchical_admission_request_requires_one_nonzero_shared_window() {
        assert!(
            NonZeroU64::new(0).is_none(),
            "a zero window is not a NonZeroU64, so it cannot be stored"
        );
        let ctx = fixture_ctx("relay-a.example");
        let identity = Keys::generate();
        let community = Keys::generate();
        let ip = IpAddr::V4(Ipv4Addr::BROADCAST);
        let window = NonZeroU64::new(60).expect("live keyed window");
        let identity_pk = identity.public_key();
        let community_pk = community.public_key();
        let request = HierarchicalAdmissionRequest::new(
            &ctx,
            &identity_pk,
            &community_pk,
            LimitType::KeyedHttpFresh,
            window,
            HierarchicalAdmissionLimits::new(300, 1_200, 2_400),
            &ip,
        );
        assert_eq!(request.window_secs(), 60);
        assert_eq!(request.limits.identity, 300);
        assert_eq!(request.limits.community, 1_200);
        assert_eq!(request.limits.fleet, 2_400);
        assert_eq!(
            request.window_secs(),
            window.get(),
            "identity, community, and fleet share the same stored window"
        );
        assert_ne!(request.identity, request.community);
        assert_eq!(request.limit_type, LimitType::KeyedHttpFresh);
    }

    #[test]
    fn identity_denial_peek_request_requires_nonzero_identity_limit() {
        assert!(
            NonZeroU64::new(0).is_none(),
            "a zero identity limit is not a NonZeroU64, so it cannot be stored"
        );
        let ctx = fixture_ctx("relay-a.example");
        let identity = Keys::generate();
        let ip = IpAddr::V4(Ipv4Addr::BROADCAST);
        let identity_pk = identity.public_key();
        let request = HierarchicalIdentityDenialPeekRequest::new(
            &ctx,
            &identity_pk,
            LimitType::KeyedHttpAttempts,
            NonZeroU64::new(300).expect("nonzero identity limit"),
            &ip,
        );
        assert_eq!(request.identity_limit(), 300);
        assert_eq!(request.limit_type, LimitType::KeyedHttpAttempts);
        assert_eq!(request.identity, &identity_pk);
        assert_eq!(request.fleet_ip, &ip);
    }

    #[test]
    fn hierarchical_identity_and_community_keys_are_distinct_for_distinct_principals() {
        let ctx = fixture_ctx("relay-a.example");
        let identity = Keys::generate();
        let community = Keys::generate();
        let identity_key =
            rate_limit_key(&ctx, &identity.public_key(), &LimitType::KeyedHttpAttempts);
        let community_key =
            rate_limit_key(&ctx, &community.public_key(), &LimitType::KeyedHttpAttempts);
        let fresh_identity =
            rate_limit_key(&ctx, &identity.public_key(), &LimitType::KeyedHttpFresh);
        assert_ne!(identity_key, community_key);
        assert_ne!(identity_key, fresh_identity);
        assert!(identity_key.contains(&identity.public_key().to_hex()));
        assert!(!identity_key.contains(&community.public_key().to_hex()));
    }

    #[test]
    fn keyed_admission_error_class_labels_are_finite_static_and_exhaustive() {
        let classes = [
            KeyedAdmissionErrorClass::BackendTimeout,
            KeyedAdmissionErrorClass::CounterCorrupt,
            KeyedAdmissionErrorClass::BackendUnavailable,
            KeyedAdmissionErrorClass::Contract,
            KeyedAdmissionErrorClass::Unknown,
        ];
        let labels = [
            "backend_timeout",
            "counter_corrupt",
            "backend_unavailable",
            "contract",
            "unknown",
        ];
        let mapped: [&str; 5] = classes.map(KeyedAdmissionErrorClass::as_str);
        assert_eq!(mapped, labels);
        for (class, label) in classes.into_iter().zip(labels) {
            assert_eq!(class.as_str(), label);
            assert_eq!(class.to_string(), label);
        }
    }

    struct UntypedOnlyLimiter {
        message: &'static str,
        hierarchical_calls: AtomicUsize,
        peek_calls: AtomicUsize,
    }

    impl UntypedOnlyLimiter {
        fn poison(message: &'static str) -> Self {
            Self {
                message,
                hierarchical_calls: AtomicUsize::new(0),
                peek_calls: AtomicUsize::new(0),
            }
        }
    }

    impl RateLimiter for UntypedOnlyLimiter {
        async fn check_and_increment(
            &self,
            _ctx: &TenantContext,
            _pubkey: &PublicKey,
            _limit_type: LimitType,
            window_secs: u64,
            limit: u64,
        ) -> Result<RateLimitResult, AuthError> {
            Ok(RateLimitResult::allowed(1, limit, window_secs))
        }

        async fn check_ip_connection(
            &self,
            _ip: &IpAddr,
            window_secs: u64,
            limit: u64,
        ) -> Result<RateLimitResult, AuthError> {
            Ok(RateLimitResult::allowed(1, limit, window_secs))
        }

        async fn check_paired_admission(
            &self,
            request: PairedAdmissionRequest<'_>,
        ) -> Result<PairedAdmissionOutcome, AuthError> {
            let window_secs = request.window_secs();
            Ok(PairedAdmissionOutcome::Allowed {
                tenant: RateLimitResult::allowed(1, request.tenant_limit, window_secs),
                fleet: RateLimitResult::allowed(1, request.fleet_limit, window_secs),
            })
        }

        async fn check_hierarchical_admission(
            &self,
            _request: HierarchicalAdmissionRequest<'_>,
        ) -> Result<HierarchicalAdmissionOutcome, AuthError> {
            self.hierarchical_calls.fetch_add(1, Ordering::Relaxed);
            Err(AuthError::Internal(self.message.to_owned()))
        }

        async fn peek_hierarchical_identity_denial(
            &self,
            _request: HierarchicalIdentityDenialPeekRequest<'_>,
        ) -> Result<HierarchicalIdentityDenialPeekOutcome, AuthError> {
            self.peek_calls.fetch_add(1, Ordering::Relaxed);
            Err(AuthError::Internal(self.message.to_owned()))
        }
    }

    #[tokio::test]
    async fn classified_default_yields_unknown_without_parsing_internal_prose() {
        let ctx = fixture_ctx("relay-a.example");
        let identity = Keys::generate();
        let community = Keys::generate();
        let ip = IpAddr::V4(Ipv4Addr::BROADCAST);
        let window = NonZeroU64::new(60).expect("shared live window");
        let poisons = [
            "Redis pool: connection timed out",
            "Redis hierarchical admission script: timed-out",
            "Redis identity denial peek script: timed out",
            "hierarchical admission counter is corrupt",
            "paired admission counter is corrupt",
            "hierarchical admission requires a shared identity/community/fleet window",
            "hierarchical admission is unavailable",
            "hierarchical identity denial peek is unavailable",
            "timeout",
            "arbitrarily reworded internal failure",
        ];
        for message in poisons {
            let limiter = UntypedOnlyLimiter::poison(message);
            let hierarchical = limiter
                .check_hierarchical_admission_classified(HierarchicalAdmissionRequest::new(
                    &ctx,
                    &identity.public_key(),
                    &community.public_key(),
                    LimitType::KeyedHttpAttempts,
                    window,
                    HierarchicalAdmissionLimits::new(300, 1_200, 2_400),
                    &ip,
                ))
                .await
                .expect_err("default classified hierarchical must fail closed");
            assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 1);
            assert_eq!(hierarchical.class().as_str(), "unknown");
            assert_eq!(
                hierarchical.error().to_string(),
                AuthError::Internal(message.to_owned()).to_string()
            );

            let peek = limiter
                .peek_hierarchical_identity_denial_classified(
                    HierarchicalIdentityDenialPeekRequest::new(
                        &ctx,
                        &identity.public_key(),
                        LimitType::KeyedHttpAttempts,
                        NonZeroU64::new(300).expect("nonzero identity limit"),
                        &ip,
                    ),
                )
                .await
                .expect_err("default classified peek must fail closed");
            assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 1);
            assert_eq!(peek.class().as_str(), "unknown");
            assert_eq!(
                peek.error().to_string(),
                AuthError::Internal(message.to_owned()).to_string()
            );
        }

        let limiter = DefaultHierarchicalLimiter;
        let hierarchical = limiter
            .check_hierarchical_admission_classified(HierarchicalAdmissionRequest::new(
                &ctx,
                &identity.public_key(),
                &community.public_key(),
                LimitType::KeyedHttpAttempts,
                window,
                HierarchicalAdmissionLimits::new(300, 1_200, 2_400),
                &ip,
            ))
            .await
            .expect_err("trait-default classified hierarchical must fail closed");
        assert_eq!(hierarchical.class().as_str(), "unknown");
        assert!(
            hierarchical.error().to_string().contains("unavailable"),
            "legacy AuthError must be preserved, got {}",
            hierarchical.error()
        );
        let peek = limiter
            .peek_hierarchical_identity_denial_classified(
                HierarchicalIdentityDenialPeekRequest::new(
                    &ctx,
                    &identity.public_key(),
                    LimitType::KeyedHttpAttempts,
                    NonZeroU64::new(300).expect("nonzero identity limit"),
                    &ip,
                ),
            )
            .await
            .expect_err("trait-default classified peek must fail closed");
        assert_eq!(peek.class().as_str(), "unknown");
        assert!(
            peek.error().to_string().contains("unavailable"),
            "legacy AuthError must be preserved, got {}",
            peek.error()
        );
    }
}
