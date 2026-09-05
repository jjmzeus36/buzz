use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroU64;

use buzz_auth::rate_limit::{
    HierarchicalAdmissionLimits, HierarchicalAdmissionOutcome, HierarchicalAdmissionRequest,
    KeyedAdmissionFailure,
};
use buzz_auth::{LimitType, RateLimiter};
use buzz_core::TenantContext;
use nostr::PublicKey;

// Desktop startup establishes several independent live subscriptions at once.
// Preserve the configured average rate while allowing that bounded burst. This
// is still a fixed-window limiter, so a Redis-backed token bucket would be a
// better long-term fit for smoother refill behavior.
const WS_BURST_WINDOW_SECS: u64 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionError {
    Exceeded { reset_in_secs: u64 },
    Unavailable,
}

pub(crate) async fn check_principal<L: RateLimiter>(
    limiter: &L,
    tenant: &TenantContext,
    pubkey: &PublicKey,
    limit_type: LimitType,
    window_secs: u64,
    limit: u64,
) -> Result<(), AdmissionError> {
    match limiter
        .check_and_increment(tenant, pubkey, limit_type, window_secs, limit)
        .await
    {
        Ok(result) if result.allowed => Ok(()),
        Ok(result) => Err(AdmissionError::Exceeded {
            reset_in_secs: result.reset_in_secs,
        }),
        Err(error) => {
            tracing::warn!(error = %error, "shared rate-limit admission unavailable");
            Err(AdmissionError::Unavailable)
        }
    }
}

/// Shared 60-second window for keyed HTTP attempt and fresh hierarchies.
pub(crate) const KEYED_HTTP_ATTEMPT_WINDOW_SECS: u64 = 60;
const KEYED_HTTP_ATTEMPT_WINDOW: NonZeroU64 =
    NonZeroU64::MIN.saturating_add(KEYED_HTTP_ATTEMPT_WINDOW_SECS - 1);

/// Fleet-wide keyed HTTP attempt aggregate. Charged once per authenticated
/// keyed request before local ingress, replay, parse, or fresh work.
pub(crate) const KEYED_HTTP_ATTEMPT_FLEET_PER_MIN: u64 = 2_400;
/// Per-community share of the keyed HTTP attempt fleet.
pub(crate) const KEYED_HTTP_ATTEMPT_COMMUNITY_PER_MIN: u64 = 1_200;

/// Legitimate fresh keyed-request community/fleet. Distinct keys from the
/// attempt hierarchy so malformed, exact NIP-98 replay, and rejected
/// non-member traffic that already paid attempt cannot consume this lane.
/// Fresh admission is the sole writer of this hierarchy and runs only after
/// a committed miss.
pub(crate) const KEYED_HTTP_FRESH_COMMUNITY_PER_MIN: u64 = 1_200;
pub(crate) const KEYED_HTTP_FRESH_FLEET_PER_MIN: u64 = 2_400;

/// Per-signer fair share. Strictly below every community and fleet aggregate
/// so one principal saturating this bound cannot exhaust a shared lane.
/// Attempt and fresh each charge identity, community, and fleet together in
/// one hierarchical operation; denial leaves all three values unchanged.
pub(crate) const KEYED_HTTP_FAIR_SHARE_PER_MIN: u64 = 300;
const KEYED_HTTP_FAIR_SHARE_LIMIT: NonZeroU64 =
    NonZeroU64::MIN.saturating_add(KEYED_HTTP_FAIR_SHARE_PER_MIN - 1);

/// Bound on newly created attempt-lane identity keys in one window: a missing
/// identity key is created only on an all-three Allowed decision, so cardinality
/// cannot exceed successful community charges.
pub(crate) const KEYED_HTTP_PREAUTH_IDENTITY_CARDINALITY_BOUND: u64 =
    KEYED_HTTP_ATTEMPT_COMMUNITY_PER_MIN;

/// Per-community bound on newly created fresh-lane identity keys in one window.
pub(crate) const KEYED_HTTP_FRESH_IDENTITY_CARDINALITY_BOUND: u64 =
    KEYED_HTTP_FRESH_COMMUNITY_PER_MIN;

const _: () = {
    assert!(KEYED_HTTP_ATTEMPT_COMMUNITY_PER_MIN < KEYED_HTTP_ATTEMPT_FLEET_PER_MIN);
    assert!(KEYED_HTTP_ATTEMPT_FLEET_PER_MIN > 417);
    assert!(KEYED_HTTP_ATTEMPT_WINDOW_SECS == 60);
    assert!(KEYED_HTTP_FRESH_COMMUNITY_PER_MIN < KEYED_HTTP_FRESH_FLEET_PER_MIN);
    assert!(KEYED_HTTP_FRESH_FLEET_PER_MIN > 417);
    assert!(KEYED_HTTP_FAIR_SHARE_PER_MIN < KEYED_HTTP_ATTEMPT_COMMUNITY_PER_MIN);
    assert!(KEYED_HTTP_FAIR_SHARE_PER_MIN < KEYED_HTTP_ATTEMPT_FLEET_PER_MIN);
    assert!(KEYED_HTTP_FAIR_SHARE_PER_MIN < KEYED_HTTP_FRESH_COMMUNITY_PER_MIN);
    assert!(KEYED_HTTP_FAIR_SHARE_PER_MIN < KEYED_HTTP_FRESH_FLEET_PER_MIN);
    assert!(KEYED_HTTP_PREAUTH_IDENTITY_CARDINALITY_BOUND == KEYED_HTTP_ATTEMPT_COMMUNITY_PER_MIN);
    assert!(KEYED_HTTP_FRESH_IDENTITY_CARDINALITY_BOUND == KEYED_HTTP_FRESH_COMMUNITY_PER_MIN);
    assert!(KEYED_HTTP_FAIR_SHARE_LIMIT.get() == KEYED_HTTP_FAIR_SHARE_PER_MIN);
};

/// Tenant-prefixed suffix for the authenticated keyed HTTP attempt hierarchy.
pub(crate) const KEYED_HTTP_ATTEMPT_LIMIT_TYPE: LimitType = LimitType::KeyedHttpAttempts;

/// Tenant-prefixed suffix for the legitimate fresh keyed-request lane.
pub(crate) const KEYED_HTTP_FRESH_LIMIT_TYPE: LimitType = LimitType::KeyedHttpFresh;

/// Unreachable attempt fleet sentinel.
///
/// Unspecified IPv6 is never a reachable TCP client source and is distinct
/// from the persist fleet broadcast sentinel (`255.255.255.255`) and from
/// the UDS/no-`ConnectInfo` IPv4 fallback (`0.0.0.0`).
pub(crate) const KEYED_HTTP_ATTEMPT_FLEET_SENTINEL: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);

/// IPv6 link-local all-nodes multicast is never a TCP client source. Distinct
/// from persist IPv4 broadcast, attempt IPv6 unspecified, and `0.0.0.0`.
pub(crate) const KEYED_HTTP_FRESH_FLEET_SENTINEL: IpAddr =
    IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));

/// Protocol-reserved principal for the per-community keyed attempt aggregate.
/// Distinct from the persist reserved principal (`bytes[31] = 1`) and not a
/// reachable event author. Identity keys use the authenticated signer.
pub(crate) fn keyed_http_attempt_admission_principal() -> PublicKey {
    const BYTES: [u8; 32] = {
        let mut bytes = [0u8; 32];
        bytes[31] = 2;
        bytes
    };
    PublicKey::from_byte_array(BYTES)
}

/// Protocol-reserved principal for the per-community legitimate fresh lane.
/// Distinct from persist (`1`) and the historical attempt community (`2`).
/// Identity keys use the authenticated signer, not a reserved principal.
pub(crate) fn keyed_http_fresh_admission_principal() -> PublicKey {
    const BYTES: [u8; 32] = {
        let mut bytes = [0u8; 32];
        bytes[31] = 4;
        bytes
    };
    PublicKey::from_byte_array(BYTES)
}

fn keyed_error_class_label(failure: &KeyedAdmissionFailure) -> &'static str {
    failure.class().as_str()
}

async fn check_hierarchical_lane<L: RateLimiter>(
    limiter: &L,
    request: HierarchicalAdmissionRequest<'_>,
    unavailable_msg: &'static str,
) -> Result<(), AdmissionError> {
    match limiter
        .check_hierarchical_admission_classified(request)
        .await
    {
        Ok(HierarchicalAdmissionOutcome::Allowed { .. }) => Ok(()),
        Ok(
            HierarchicalAdmissionOutcome::IdentityDenied(result)
            | HierarchicalAdmissionOutcome::CommunityDenied(result)
            | HierarchicalAdmissionOutcome::FleetDenied(result),
        ) => Err(AdmissionError::Exceeded {
            reset_in_secs: result.reset_in_secs,
        }),
        Err(failure) => {
            tracing::warn!(
                class = keyed_error_class_label(&failure),
                "{unavailable_msg}"
            );
            Err(AdmissionError::Unavailable)
        }
    }
}

/// Authenticated keyed HTTP attempt lane. Invoke exactly once after host
/// binding and cryptographic NIP-98 signer authentication, before local
/// ingress, replay-marker write, parse, membership, validation, or fresh
/// work. Identity is the authenticated signer; community uses the reserved
/// attempt principal; fleet uses the unreachable attempt sentinel. Allowed
/// increments all three once. Explicit denial and known pre-mutation failure
/// increment none. Ambiguous transport timeout may leave all three changed or
/// all three unchanged, never a subset, and must not be blindly retried.
pub(crate) async fn check_keyed_http_attempt_admission<L: RateLimiter>(
    limiter: &L,
    tenant: &TenantContext,
    pubkey: &PublicKey,
) -> Result<(), AdmissionError> {
    check_hierarchical_lane(
        limiter,
        HierarchicalAdmissionRequest::new(
            tenant,
            pubkey,
            &keyed_http_attempt_admission_principal(),
            KEYED_HTTP_ATTEMPT_LIMIT_TYPE,
            KEYED_HTTP_ATTEMPT_WINDOW,
            HierarchicalAdmissionLimits::new(
                KEYED_HTTP_FAIR_SHARE_PER_MIN,
                KEYED_HTTP_ATTEMPT_COMMUNITY_PER_MIN,
                KEYED_HTTP_ATTEMPT_FLEET_PER_MIN,
            ),
            &KEYED_HTTP_ATTEMPT_FLEET_SENTINEL,
        ),
        "shared keyed-attempt hierarchical admission unavailable",
    )
    .await
}

/// Legitimate fresh-request lane. Call only after replay defense, parse,
/// membership, validation, and a committed miss so identity-specific keys are
/// not created for unaffiliated, malformed, replayed, or conflicting traffic.
/// This is the sole writer/charger of the legitimate identity + community +
/// fleet hierarchy. Uses the distinct `KeyedHttpFresh` suffix and reserved
/// community/fleet keys. Denial charges none of the three counters.
pub(crate) async fn check_keyed_http_fresh_admission<L: RateLimiter>(
    limiter: &L,
    tenant: &TenantContext,
    pubkey: &PublicKey,
) -> Result<(), AdmissionError> {
    check_hierarchical_lane(
        limiter,
        HierarchicalAdmissionRequest::new(
            tenant,
            pubkey,
            &keyed_http_fresh_admission_principal(),
            KEYED_HTTP_FRESH_LIMIT_TYPE,
            KEYED_HTTP_ATTEMPT_WINDOW,
            HierarchicalAdmissionLimits::new(
                KEYED_HTTP_FAIR_SHARE_PER_MIN,
                KEYED_HTTP_FRESH_COMMUNITY_PER_MIN,
                KEYED_HTTP_FRESH_FLEET_PER_MIN,
            ),
            &KEYED_HTTP_FRESH_FLEET_SENTINEL,
        ),
        "shared keyed-fresh hierarchical admission unavailable",
    )
    .await
}

pub(crate) fn ws_admission_budget(per_second_limit: u64) -> (u64, u64) {
    (
        WS_BURST_WINDOW_SECS,
        per_second_limit.saturating_mul(WS_BURST_WINDOW_SECS),
    )
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use buzz_auth::rate_limit::{
        HierarchicalAdmissionOutcome, HierarchicalAdmissionRequest,
        HierarchicalIdentityDenialPeekOutcome, HierarchicalIdentityDenialPeekRequest,
        KeyedAdmissionErrorClass, KeyedAdmissionFailure, PairedAdmissionOutcome,
        PairedAdmissionRequest,
    };
    use buzz_auth::{AuthError, RateLimitResult, RateLimiter};
    use buzz_core::CommunityId;
    use nostr::Keys;
    use uuid::Uuid;

    use super::*;

    enum StubOutcome {
        Denied,
        Failed,
    }

    struct StubLimiter {
        outcome: StubOutcome,
        calls: AtomicUsize,
    }

    impl RateLimiter for StubLimiter {
        async fn check_and_increment(
            &self,
            _ctx: &TenantContext,
            _pubkey: &PublicKey,
            _limit_type: LimitType,
            _window_secs: u64,
            _limit: u64,
        ) -> Result<RateLimitResult, AuthError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            match self.outcome {
                StubOutcome::Denied => Ok(RateLimitResult::denied(11, 10, 1)),
                StubOutcome::Failed => Err(AuthError::Internal("redis unavailable".to_owned())),
            }
        }

        async fn check_ip_connection(
            &self,
            _ip: &IpAddr,
            _window_secs: u64,
            _limit: u64,
        ) -> Result<RateLimitResult, AuthError> {
            match self.outcome {
                StubOutcome::Denied => Ok(RateLimitResult::denied(11, 10, 1)),
                StubOutcome::Failed => Err(AuthError::Internal("redis unavailable".to_owned())),
            }
        }

        async fn check_paired_admission(
            &self,
            request: PairedAdmissionRequest<'_>,
        ) -> Result<PairedAdmissionOutcome, AuthError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            match self.outcome {
                StubOutcome::Denied => Ok(PairedAdmissionOutcome::TenantDenied(
                    RateLimitResult::denied(request.tenant_limit + 1, request.tenant_limit, 1),
                )),
                StubOutcome::Failed => Err(AuthError::Internal("redis unavailable".to_owned())),
            }
        }
    }

    fn tenant() -> TenantContext {
        TenantContext::resolved(
            CommunityId::from_uuid(Uuid::from_u128(1)),
            "relay.example.com",
        )
    }

    #[test]
    fn websocket_budget_preserves_rate_with_a_bounded_burst() {
        assert_eq!(ws_admission_budget(10), (5, 50));
    }

    #[test]
    fn websocket_budget_saturates_on_overflow() {
        assert_eq!(ws_admission_budget(u64::MAX), (5, u64::MAX));
    }

    #[tokio::test]
    async fn denied_shared_counter_rejects_admission() {
        let limiter = StubLimiter {
            outcome: StubOutcome::Denied,
            calls: AtomicUsize::new(0),
        };
        let keys = Keys::generate();

        let result = check_principal(
            &limiter,
            &tenant(),
            &keys.public_key(),
            LimitType::WsEvents,
            1,
            10,
        )
        .await;

        assert_eq!(result, Err(AdmissionError::Exceeded { reset_in_secs: 1 }));
        assert_eq!(limiter.calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn shared_counter_failure_rejects_admission() {
        let limiter = StubLimiter {
            outcome: StubOutcome::Failed,
            calls: AtomicUsize::new(0),
        };
        let keys = Keys::generate();

        let result = check_principal(
            &limiter,
            &tenant(),
            &keys.public_key(),
            LimitType::ApiCalls,
            60,
            300,
        )
        .await;

        assert_eq!(result, Err(AdmissionError::Unavailable));
        assert_eq!(limiter.calls.load(Ordering::Relaxed), 1);
    }

    #[derive(Clone, Copy)]
    enum PairedStubOutcome {
        Allow,
        DenyTenant,
        DenyFleet,
        Fail,
    }

    #[derive(Clone, Copy)]
    enum HierarchicalStubOutcome {
        Allow,
        DenyIdentity,
        DenyCommunity,
        DenyFleet,
        Fail,
    }

    #[derive(Clone, Copy)]
    enum IdentityPeekStubOutcome {
        Fail,
    }

    struct RecordingPairedLimiter {
        paired_outcome: PairedStubOutcome,
        hierarchical_outcome: HierarchicalStubOutcome,
        peek_outcome: IdentityPeekStubOutcome,
        identity_charged: AtomicUsize,
        tenant_charged: AtomicUsize,
        fleet_charged: AtomicUsize,
        identity_created: AtomicUsize,
        principal_calls: AtomicUsize,
        paired_calls: AtomicUsize,
        hierarchical_calls: AtomicUsize,
        peek_calls: AtomicUsize,
        last_identity_pubkey: std::sync::Mutex<Option<[u8; 32]>>,
        last_community_pubkey: std::sync::Mutex<Option<[u8; 32]>>,
        last_identity_limit: std::sync::Mutex<Option<u64>>,
        last_limit_type: std::sync::Mutex<Option<LimitType>>,
        last_pubkey: std::sync::Mutex<Option<[u8; 32]>>,
        last_fleet_ip: std::sync::Mutex<Option<IpAddr>>,
        last_window: std::sync::Mutex<Option<u64>>,
        last_tenant_limit: std::sync::Mutex<Option<u64>>,
        last_fleet_limit: std::sync::Mutex<Option<u64>>,
        last_peek_identity: std::sync::Mutex<Option<[u8; 32]>>,
        last_peek_limit_type: std::sync::Mutex<Option<LimitType>>,
        last_peek_fleet_ip: std::sync::Mutex<Option<IpAddr>>,
        last_peek_identity_limit: std::sync::Mutex<Option<u64>>,
    }

    impl RecordingPairedLimiter {
        fn new(paired_outcome: PairedStubOutcome) -> Self {
            Self::hierarchical(match paired_outcome {
                PairedStubOutcome::Allow => HierarchicalStubOutcome::Allow,
                PairedStubOutcome::DenyTenant => HierarchicalStubOutcome::DenyCommunity,
                PairedStubOutcome::DenyFleet => HierarchicalStubOutcome::DenyFleet,
                PairedStubOutcome::Fail => HierarchicalStubOutcome::Fail,
            })
        }

        fn hierarchical(hierarchical_outcome: HierarchicalStubOutcome) -> Self {
            Self::with_peek(hierarchical_outcome, IdentityPeekStubOutcome::Fail)
        }

        fn with_peek(
            hierarchical_outcome: HierarchicalStubOutcome,
            peek_outcome: IdentityPeekStubOutcome,
        ) -> Self {
            Self {
                paired_outcome: match hierarchical_outcome {
                    HierarchicalStubOutcome::Allow => PairedStubOutcome::Allow,
                    HierarchicalStubOutcome::DenyCommunity => PairedStubOutcome::DenyTenant,
                    HierarchicalStubOutcome::DenyFleet => PairedStubOutcome::DenyFleet,
                    HierarchicalStubOutcome::Fail | HierarchicalStubOutcome::DenyIdentity => {
                        PairedStubOutcome::Fail
                    }
                },
                hierarchical_outcome,
                peek_outcome,
                identity_charged: AtomicUsize::new(0),
                tenant_charged: AtomicUsize::new(0),
                fleet_charged: AtomicUsize::new(0),
                identity_created: AtomicUsize::new(0),
                principal_calls: AtomicUsize::new(0),
                paired_calls: AtomicUsize::new(0),
                hierarchical_calls: AtomicUsize::new(0),
                peek_calls: AtomicUsize::new(0),
                last_identity_pubkey: std::sync::Mutex::new(None),
                last_community_pubkey: std::sync::Mutex::new(None),
                last_identity_limit: std::sync::Mutex::new(None),
                last_limit_type: std::sync::Mutex::new(None),
                last_pubkey: std::sync::Mutex::new(None),
                last_fleet_ip: std::sync::Mutex::new(None),
                last_window: std::sync::Mutex::new(None),
                last_tenant_limit: std::sync::Mutex::new(None),
                last_fleet_limit: std::sync::Mutex::new(None),
                last_peek_identity: std::sync::Mutex::new(None),
                last_peek_limit_type: std::sync::Mutex::new(None),
                last_peek_fleet_ip: std::sync::Mutex::new(None),
                last_peek_identity_limit: std::sync::Mutex::new(None),
            }
        }
    }

    impl RateLimiter for RecordingPairedLimiter {
        async fn check_and_increment(
            &self,
            _ctx: &TenantContext,
            _pubkey: &PublicKey,
            _limit_type: LimitType,
            window_secs: u64,
            limit: u64,
        ) -> Result<RateLimitResult, AuthError> {
            self.principal_calls.fetch_add(1, Ordering::Relaxed);
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
            self.paired_calls.fetch_add(1, Ordering::Relaxed);
            *self.last_limit_type.lock().unwrap() = Some(request.limit_type.clone());
            *self.last_pubkey.lock().unwrap() = Some(request.pubkey.to_bytes());
            *self.last_fleet_ip.lock().unwrap() = Some(*request.fleet_ip);
            *self.last_window.lock().unwrap() = Some(request.window_secs());
            *self.last_tenant_limit.lock().unwrap() = Some(request.tenant_limit);
            *self.last_fleet_limit.lock().unwrap() = Some(request.fleet_limit);
            match self.paired_outcome {
                PairedStubOutcome::Allow => {
                    self.tenant_charged.fetch_add(1, Ordering::Relaxed);
                    self.fleet_charged.fetch_add(1, Ordering::Relaxed);
                    Ok(PairedAdmissionOutcome::Allowed {
                        tenant: RateLimitResult::allowed(
                            1,
                            request.tenant_limit,
                            request.window_secs(),
                        ),
                        fleet: RateLimitResult::allowed(
                            1,
                            request.fleet_limit,
                            request.window_secs(),
                        ),
                    })
                }
                PairedStubOutcome::DenyTenant => Ok(PairedAdmissionOutcome::TenantDenied(
                    RateLimitResult::denied(request.tenant_limit + 1, request.tenant_limit, 17),
                )),
                PairedStubOutcome::DenyFleet => Ok(PairedAdmissionOutcome::FleetDenied(
                    RateLimitResult::denied(request.fleet_limit + 1, request.fleet_limit, 23),
                )),
                PairedStubOutcome::Fail => Err(AuthError::Internal("redis unavailable".to_owned())),
            }
        }

        async fn check_hierarchical_admission(
            &self,
            request: HierarchicalAdmissionRequest<'_>,
        ) -> Result<HierarchicalAdmissionOutcome, AuthError> {
            self.hierarchical_calls.fetch_add(1, Ordering::Relaxed);
            *self.last_identity_pubkey.lock().unwrap() = Some(request.identity.to_bytes());
            *self.last_community_pubkey.lock().unwrap() = Some(request.community.to_bytes());
            *self.last_identity_limit.lock().unwrap() = Some(request.limits.identity);
            *self.last_limit_type.lock().unwrap() = Some(request.limit_type.clone());
            *self.last_pubkey.lock().unwrap() = Some(request.community.to_bytes());
            *self.last_fleet_ip.lock().unwrap() = Some(*request.fleet_ip);
            *self.last_window.lock().unwrap() = Some(request.window_secs());
            *self.last_tenant_limit.lock().unwrap() = Some(request.limits.community);
            *self.last_fleet_limit.lock().unwrap() = Some(request.limits.fleet);
            match self.hierarchical_outcome {
                HierarchicalStubOutcome::Allow => {
                    self.identity_charged.fetch_add(1, Ordering::Relaxed);
                    self.tenant_charged.fetch_add(1, Ordering::Relaxed);
                    self.fleet_charged.fetch_add(1, Ordering::Relaxed);
                    self.identity_created.fetch_add(1, Ordering::Relaxed);
                    Ok(HierarchicalAdmissionOutcome::Allowed {
                        identity: RateLimitResult::allowed(
                            1,
                            request.limits.identity,
                            request.window_secs(),
                        ),
                        community: RateLimitResult::allowed(
                            1,
                            request.limits.community,
                            request.window_secs(),
                        ),
                        fleet: RateLimitResult::allowed(
                            1,
                            request.limits.fleet,
                            request.window_secs(),
                        ),
                    })
                }
                HierarchicalStubOutcome::DenyIdentity => Ok(
                    HierarchicalAdmissionOutcome::IdentityDenied(RateLimitResult::denied(
                        request.limits.identity + 1,
                        request.limits.identity,
                        13,
                    )),
                ),
                HierarchicalStubOutcome::DenyCommunity => Ok(
                    HierarchicalAdmissionOutcome::CommunityDenied(RateLimitResult::denied(
                        request.limits.community + 1,
                        request.limits.community,
                        17,
                    )),
                ),
                HierarchicalStubOutcome::DenyFleet => {
                    Ok(HierarchicalAdmissionOutcome::FleetDenied(
                        RateLimitResult::denied(request.limits.fleet + 1, request.limits.fleet, 23),
                    ))
                }
                HierarchicalStubOutcome::Fail => {
                    Err(AuthError::Internal("redis unavailable".to_owned()))
                }
            }
        }

        async fn peek_hierarchical_identity_denial(
            &self,
            request: HierarchicalIdentityDenialPeekRequest<'_>,
        ) -> Result<HierarchicalIdentityDenialPeekOutcome, AuthError> {
            self.peek_calls.fetch_add(1, Ordering::Relaxed);
            *self.last_peek_identity.lock().unwrap() = Some(request.identity.to_bytes());
            *self.last_peek_limit_type.lock().unwrap() = Some(request.limit_type.clone());
            *self.last_peek_fleet_ip.lock().unwrap() = Some(*request.fleet_ip);
            *self.last_peek_identity_limit.lock().unwrap() = Some(request.identity_limit());
            match self.peek_outcome {
                IdentityPeekStubOutcome::Fail => {
                    Err(AuthError::Internal("redis unavailable".to_owned()))
                }
            }
        }
    }

    fn signer() -> PublicKey {
        Keys::generate().public_key()
    }

    #[test]
    fn keyed_attempt_keys_are_fixed_bounded_and_distinct_from_persist_and_client() {
        let ctx = tenant();
        let attacker = signer();
        let other = signer();
        let attempt_principal = keyed_http_attempt_admission_principal();
        let fresh_principal = keyed_http_fresh_admission_principal();
        let mut persist_principal_bytes = [0u8; 32];
        persist_principal_bytes[31] = 1;
        let persist_principal = PublicKey::from_byte_array(persist_principal_bytes);

        let attempt_tenant = buzz_auth::rate_limit::rate_limit_key(
            &ctx,
            &attempt_principal,
            &KEYED_HTTP_ATTEMPT_LIMIT_TYPE,
        );
        let fresh_tenant = buzz_auth::rate_limit::rate_limit_key(
            &ctx,
            &fresh_principal,
            &KEYED_HTTP_FRESH_LIMIT_TYPE,
        );
        let attacker_preauth =
            buzz_auth::rate_limit::rate_limit_key(&ctx, &attacker, &KEYED_HTTP_ATTEMPT_LIMIT_TYPE);
        let other_preauth =
            buzz_auth::rate_limit::rate_limit_key(&ctx, &other, &KEYED_HTTP_ATTEMPT_LIMIT_TYPE);
        let attacker_fresh =
            buzz_auth::rate_limit::rate_limit_key(&ctx, &attacker, &KEYED_HTTP_FRESH_LIMIT_TYPE);
        let persist_tenant = buzz_auth::rate_limit::rate_limit_key(
            &ctx,
            &persist_principal,
            &LimitType::IpConnections,
        );
        let attacker_api =
            buzz_auth::rate_limit::rate_limit_key(&ctx, &attacker, &LimitType::ApiCalls);
        let client_ip =
            buzz_auth::rate_limit::ip_rate_limit_key(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let persist_fleet =
            buzz_auth::rate_limit::ip_rate_limit_key(&IpAddr::V4(Ipv4Addr::BROADCAST));
        let ipv4_unspecified_fallback =
            buzz_auth::rate_limit::ip_rate_limit_key(&IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let attempt_fleet =
            buzz_auth::rate_limit::ip_rate_limit_key(&KEYED_HTTP_ATTEMPT_FLEET_SENTINEL);
        let fresh_fleet =
            buzz_auth::rate_limit::ip_rate_limit_key(&KEYED_HTTP_FRESH_FLEET_SENTINEL);

        assert!(attempt_tenant.ends_with(":katt"));
        assert!(fresh_tenant.ends_with(":kfsh"));
        assert!(attacker_preauth.ends_with(":katt"));
        assert!(attacker_preauth.contains(&attacker.to_hex()));
        assert!(persist_tenant.ends_with(":conn"));
        assert_ne!(attempt_tenant, persist_tenant);
        assert_ne!(attempt_tenant, fresh_tenant);
        assert_ne!(attempt_tenant, attacker_preauth);
        assert_ne!(attacker_preauth, other_preauth);
        assert_ne!(attempt_tenant, attacker_api);
        assert_ne!(attempt_tenant, attacker_fresh);
        assert_ne!(attacker_preauth, attacker_fresh);
        assert_ne!(attempt_fleet, persist_fleet);
        assert_ne!(attempt_fleet, fresh_fleet);
        assert_ne!(attempt_fleet, client_ip);
        assert_eq!(attempt_fleet, "buzz:ratelimit:ip::::conn");
        assert_eq!(fresh_fleet, "buzz:ratelimit:ip:ff02::1:conn");
        assert_eq!(ipv4_unspecified_fallback, "buzz:ratelimit:ip:0.0.0.0:conn");
        assert_ne!(attempt_fleet, ipv4_unspecified_fallback);
        assert_ne!(attempt_principal, persist_principal);
        assert_ne!(attempt_principal, fresh_principal);
        assert_ne!(attempt_principal, attacker);
        assert_ne!(fresh_principal, attacker);
        assert_eq!(KEYED_HTTP_ATTEMPT_LIMIT_TYPE, LimitType::KeyedHttpAttempts);
        assert_eq!(KEYED_HTTP_FRESH_LIMIT_TYPE, LimitType::KeyedHttpFresh);
        assert_ne!(KEYED_HTTP_ATTEMPT_LIMIT_TYPE, LimitType::ApiCalls);
        assert_ne!(KEYED_HTTP_ATTEMPT_LIMIT_TYPE, LimitType::IpConnections);
        assert_ne!(KEYED_HTTP_ATTEMPT_LIMIT_TYPE, LimitType::Messages);
        assert_ne!(KEYED_HTTP_FRESH_LIMIT_TYPE, KEYED_HTTP_ATTEMPT_LIMIT_TYPE);
    }

    #[test]
    fn attempt_identity_keys_are_the_authenticated_signer_on_the_attempt_lane() {
        let ctx = tenant();
        let mut unique_keys = std::collections::BTreeSet::new();
        for _ in 0..8 {
            let attacker = signer();
            let identity = buzz_auth::rate_limit::rate_limit_key(
                &ctx,
                &attacker,
                &KEYED_HTTP_ATTEMPT_LIMIT_TYPE,
            );
            assert!(identity.contains(&attacker.to_hex()));
            assert!(identity.ends_with(":katt"));
            assert!(unique_keys.insert(identity));
        }
        assert_eq!(
            unique_keys.len(),
            8,
            "distinct signers must use distinct identity keys"
        );
        unique_keys.insert(buzz_auth::rate_limit::rate_limit_key(
            &ctx,
            &keyed_http_attempt_admission_principal(),
            &KEYED_HTTP_ATTEMPT_LIMIT_TYPE,
        ));
        assert_eq!(unique_keys.len(), 9);
        assert_eq!(
            KEYED_HTTP_PREAUTH_IDENTITY_CARDINALITY_BOUND,
            KEYED_HTTP_ATTEMPT_COMMUNITY_PER_MIN
        );
        assert_eq!(
            KEYED_HTTP_FRESH_IDENTITY_CARDINALITY_BOUND,
            KEYED_HTTP_FRESH_COMMUNITY_PER_MIN
        );
        assert_eq!(KEYED_HTTP_PREAUTH_IDENTITY_CARDINALITY_BOUND, 1_200);
        assert_eq!(KEYED_HTTP_ATTEMPT_FLEET_PER_MIN, 2_400);
        assert_eq!(
            KEYED_HTTP_FAIR_SHARE_LIMIT.get(),
            KEYED_HTTP_FAIR_SHARE_PER_MIN
        );
    }

    #[tokio::test]
    async fn keyed_attempt_allow_charges_all_three_once() {
        let limiter = RecordingPairedLimiter::hierarchical(HierarchicalStubOutcome::Allow);
        let pubkey = signer();
        check_keyed_http_attempt_admission(&limiter, &tenant(), &pubkey)
            .await
            .expect("allowed attempt");
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.principal_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.paired_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 1);
        assert_eq!(limiter.identity_charged.load(Ordering::Relaxed), 1);
        assert_eq!(limiter.tenant_charged.load(Ordering::Relaxed), 1);
        assert_eq!(limiter.fleet_charged.load(Ordering::Relaxed), 1);
        assert_eq!(limiter.identity_created.load(Ordering::Relaxed), 1);
        assert_eq!(
            limiter.last_identity_pubkey.lock().unwrap().clone(),
            Some(pubkey.to_bytes())
        );
        assert_eq!(
            limiter.last_community_pubkey.lock().unwrap().clone(),
            Some(keyed_http_attempt_admission_principal().to_bytes())
        );
        assert_eq!(
            limiter.last_limit_type.lock().unwrap().clone(),
            Some(LimitType::KeyedHttpAttempts)
        );
        assert_eq!(
            *limiter.last_fleet_ip.lock().unwrap(),
            Some(KEYED_HTTP_ATTEMPT_FLEET_SENTINEL)
        );
        assert_eq!(
            *limiter.last_identity_limit.lock().unwrap(),
            Some(KEYED_HTTP_FAIR_SHARE_PER_MIN)
        );
        assert_eq!(
            *limiter.last_tenant_limit.lock().unwrap(),
            Some(KEYED_HTTP_ATTEMPT_COMMUNITY_PER_MIN)
        );
        assert_eq!(
            *limiter.last_fleet_limit.lock().unwrap(),
            Some(KEYED_HTTP_ATTEMPT_FLEET_PER_MIN)
        );
        assert_eq!(*limiter.last_window.lock().unwrap(), Some(60));
    }

    #[tokio::test]
    async fn keyed_attempt_identity_denial_charges_none_and_creates_no_key() {
        let limiter = RecordingPairedLimiter::hierarchical(HierarchicalStubOutcome::DenyIdentity);
        let result = check_keyed_http_attempt_admission(&limiter, &tenant(), &signer())
            .await
            .expect_err("attempt identity denial");
        assert_eq!(result, AdmissionError::Exceeded { reset_in_secs: 13 });
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 1);
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.paired_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.principal_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.identity_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.tenant_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.fleet_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.identity_created.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn keyed_attempt_community_denial_charges_none() {
        let limiter = RecordingPairedLimiter::hierarchical(HierarchicalStubOutcome::DenyCommunity);
        let result = check_keyed_http_attempt_admission(&limiter, &tenant(), &signer())
            .await
            .expect_err("attempt community denial");
        assert_eq!(result, AdmissionError::Exceeded { reset_in_secs: 17 });
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 1);
        assert_eq!(limiter.identity_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.tenant_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.fleet_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.identity_created.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn keyed_attempt_fleet_denial_charges_none() {
        let limiter = RecordingPairedLimiter::hierarchical(HierarchicalStubOutcome::DenyFleet);
        let result = check_keyed_http_attempt_admission(&limiter, &tenant(), &signer())
            .await
            .expect_err("attempt fleet denial");
        assert_eq!(result, AdmissionError::Exceeded { reset_in_secs: 23 });
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 1);
        assert_eq!(limiter.identity_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.tenant_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.fleet_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.identity_created.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn keyed_attempt_unavailable_fails_closed_without_charge() {
        let limiter = RecordingPairedLimiter::hierarchical(HierarchicalStubOutcome::Fail);
        let result = check_keyed_http_attempt_admission(&limiter, &tenant(), &signer())
            .await
            .expect_err("attempt failure");
        assert_eq!(result, AdmissionError::Unavailable);
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 1);
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.paired_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.principal_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.identity_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.tenant_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.fleet_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.identity_created.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn keyed_attempt_rotating_signers_are_bounded_by_community_and_fleet() {
        let limiter = RecordingPairedLimiter::hierarchical(HierarchicalStubOutcome::Allow);
        let tenant = tenant();
        const SIGNERS: usize = 32;
        for _ in 0..SIGNERS {
            let pubkey = signer();
            check_keyed_http_attempt_admission(&limiter, &tenant, &pubkey)
                .await
                .expect("rotating signer attempt");
        }
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), SIGNERS);
        assert_eq!(limiter.identity_charged.load(Ordering::Relaxed), SIGNERS);
        assert_eq!(limiter.tenant_charged.load(Ordering::Relaxed), SIGNERS);
        assert_eq!(limiter.fleet_charged.load(Ordering::Relaxed), SIGNERS);
        assert_eq!(limiter.identity_created.load(Ordering::Relaxed), SIGNERS);
        assert!(
            SIGNERS as u64 <= KEYED_HTTP_ATTEMPT_COMMUNITY_PER_MIN,
            "rotating signers remain bounded by community successes"
        );
        assert!(SIGNERS as u64 <= KEYED_HTTP_ATTEMPT_FLEET_PER_MIN);
        assert_eq!(
            limiter.last_limit_type.lock().unwrap().clone(),
            Some(LimitType::KeyedHttpAttempts)
        );
        assert_eq!(
            *limiter.last_fleet_ip.lock().unwrap(),
            Some(KEYED_HTTP_ATTEMPT_FLEET_SENTINEL)
        );
        assert_eq!(
            limiter.last_community_pubkey.lock().unwrap().clone(),
            Some(keyed_http_attempt_admission_principal().to_bytes())
        );
    }

    struct AmbiguousAttemptLimiter {
        calls: AtomicUsize,
        charge_on_loss: bool,
        identity_charged: AtomicUsize,
        tenant_charged: AtomicUsize,
        fleet_charged: AtomicUsize,
    }

    impl AmbiguousAttemptLimiter {
        fn lost_reply(charge_on_loss: bool) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                charge_on_loss,
                identity_charged: AtomicUsize::new(0),
                tenant_charged: AtomicUsize::new(0),
                fleet_charged: AtomicUsize::new(0),
            }
        }
    }

    impl RateLimiter for AmbiguousAttemptLimiter {
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

        async fn check_hierarchical_admission(
            &self,
            request: HierarchicalAdmissionRequest<'_>,
        ) -> Result<HierarchicalAdmissionOutcome, AuthError> {
            let prior = self.calls.fetch_add(1, Ordering::Relaxed);
            assert_eq!(prior, 0, "ambiguous attempt must not be blindly retried");
            if self.charge_on_loss {
                self.identity_charged.fetch_add(1, Ordering::Relaxed);
                self.tenant_charged.fetch_add(1, Ordering::Relaxed);
                self.fleet_charged.fetch_add(1, Ordering::Relaxed);
            }
            let _ = request;
            Err(AuthError::Internal(
                "hierarchical admission reply lost".to_owned(),
            ))
        }
    }

    #[tokio::test]
    async fn keyed_attempt_ambiguous_lost_reply_is_all_or_none_and_not_retried() {
        for charge in [true, false] {
            let limiter = AmbiguousAttemptLimiter::lost_reply(charge);
            let result = check_keyed_http_attempt_admission(&limiter, &tenant(), &signer())
                .await
                .expect_err("ambiguous attempt must fail closed");
            assert_eq!(result, AdmissionError::Unavailable);
            assert_eq!(limiter.calls.load(Ordering::Relaxed), 1);
            let identity = limiter.identity_charged.load(Ordering::Relaxed);
            let tenant_c = limiter.tenant_charged.load(Ordering::Relaxed);
            let fleet = limiter.fleet_charged.load(Ordering::Relaxed);
            assert_eq!(identity, tenant_c);
            assert_eq!(tenant_c, fleet);
            if charge {
                assert_eq!(identity, 1);
            } else {
                assert_eq!(identity, 0);
            }
        }
    }

    #[tokio::test]
    async fn keyed_fresh_allow_uses_signer_identity_and_distinct_shared_lane() {
        let limiter = RecordingPairedLimiter::hierarchical(HierarchicalStubOutcome::Allow);
        let pubkey = signer();
        check_keyed_http_fresh_admission(&limiter, &tenant(), &pubkey)
            .await
            .expect("allowed fresh");
        assert_eq!(limiter.principal_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.paired_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 1);
        assert_eq!(limiter.identity_charged.load(Ordering::Relaxed), 1);
        assert_eq!(limiter.tenant_charged.load(Ordering::Relaxed), 1);
        assert_eq!(limiter.fleet_charged.load(Ordering::Relaxed), 1);
        assert_eq!(
            limiter.last_identity_pubkey.lock().unwrap().clone(),
            Some(pubkey.to_bytes())
        );
        assert_eq!(
            *limiter.last_identity_limit.lock().unwrap(),
            Some(KEYED_HTTP_FAIR_SHARE_PER_MIN)
        );
        assert_eq!(
            limiter.last_limit_type.lock().unwrap().clone(),
            Some(LimitType::KeyedHttpFresh)
        );
        assert_eq!(
            limiter.last_community_pubkey.lock().unwrap().clone(),
            Some(keyed_http_fresh_admission_principal().to_bytes())
        );
        assert_eq!(
            *limiter.last_fleet_ip.lock().unwrap(),
            Some(KEYED_HTTP_FRESH_FLEET_SENTINEL)
        );
        assert_eq!(
            *limiter.last_tenant_limit.lock().unwrap(),
            Some(KEYED_HTTP_FRESH_COMMUNITY_PER_MIN)
        );
        assert_eq!(
            *limiter.last_fleet_limit.lock().unwrap(),
            Some(KEYED_HTTP_FRESH_FLEET_PER_MIN)
        );
    }

    #[tokio::test]
    async fn keyed_fresh_identity_denial_charges_no_legitimate_counter() {
        let limiter = RecordingPairedLimiter::hierarchical(HierarchicalStubOutcome::DenyIdentity);
        let result = check_keyed_http_fresh_admission(&limiter, &tenant(), &signer())
            .await
            .expect_err("fresh identity denial");
        assert_eq!(result, AdmissionError::Exceeded { reset_in_secs: 13 });
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 1);
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.identity_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.tenant_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.fleet_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.identity_created.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn keyed_fresh_community_denial_charges_neither_counter() {
        let limiter = RecordingPairedLimiter::new(PairedStubOutcome::DenyTenant);
        let result = check_keyed_http_fresh_admission(&limiter, &tenant(), &signer())
            .await
            .expect_err("fresh community denial");
        assert_eq!(result, AdmissionError::Exceeded { reset_in_secs: 17 });
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 1);
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.identity_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.tenant_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.fleet_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.identity_created.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn keyed_fresh_fleet_denial_charges_neither_counter() {
        let limiter = RecordingPairedLimiter::new(PairedStubOutcome::DenyFleet);
        let result = check_keyed_http_fresh_admission(&limiter, &tenant(), &signer())
            .await
            .expect_err("fresh fleet denial");
        assert_eq!(result, AdmissionError::Exceeded { reset_in_secs: 23 });
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 1);
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.identity_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.tenant_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.fleet_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.identity_created.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn keyed_fresh_unavailable_fails_closed_without_charge() {
        let limiter = RecordingPairedLimiter::new(PairedStubOutcome::Fail);
        let result = check_keyed_http_fresh_admission(&limiter, &tenant(), &signer())
            .await
            .expect_err("fresh redis failure");
        assert_eq!(result, AdmissionError::Unavailable);
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 1);
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.identity_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.tenant_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.fleet_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.identity_created.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn paired_admission_still_maps_tenant_denial_without_hierarchical_charge() {
        let limiter = RecordingPairedLimiter::new(PairedStubOutcome::DenyTenant);
        let outcome = limiter
            .check_paired_admission(PairedAdmissionRequest::new(
                &tenant(),
                &keyed_http_attempt_admission_principal(),
                KEYED_HTTP_ATTEMPT_LIMIT_TYPE,
                KEYED_HTTP_ATTEMPT_WINDOW,
                KEYED_HTTP_ATTEMPT_COMMUNITY_PER_MIN,
                &KEYED_HTTP_ATTEMPT_FLEET_SENTINEL,
                KEYED_HTTP_ATTEMPT_FLEET_PER_MIN,
            ))
            .await
            .expect("paired remains callable");
        assert!(
            matches!(
                outcome,
                PairedAdmissionOutcome::TenantDenied(ref result)
                    if !result.allowed && result.reset_in_secs == 17
            ),
            "got {outcome:?}"
        );
        assert_eq!(limiter.paired_calls.load(Ordering::Relaxed), 1);
        assert_eq!(limiter.hierarchical_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.peek_calls.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.tenant_charged.load(Ordering::Relaxed), 0);
        assert_eq!(limiter.fleet_charged.load(Ordering::Relaxed), 0);
    }

    struct TypedKeyedFailureLimiter {
        class: KeyedAdmissionErrorClass,
        message: &'static str,
        typed_hierarchical_calls: AtomicUsize,
        typed_peek_calls: AtomicUsize,
        untyped_hierarchical_calls: AtomicUsize,
        untyped_peek_calls: AtomicUsize,
    }

    impl TypedKeyedFailureLimiter {
        fn new(class: KeyedAdmissionErrorClass, message: &'static str) -> Self {
            Self {
                class,
                message,
                typed_hierarchical_calls: AtomicUsize::new(0),
                typed_peek_calls: AtomicUsize::new(0),
                untyped_hierarchical_calls: AtomicUsize::new(0),
                untyped_peek_calls: AtomicUsize::new(0),
            }
        }

        fn failure(&self) -> KeyedAdmissionFailure {
            KeyedAdmissionFailure::new(AuthError::Internal(self.message.to_owned()), self.class)
        }
    }

    impl RateLimiter for TypedKeyedFailureLimiter {
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
            self.untyped_hierarchical_calls
                .fetch_add(1, Ordering::Relaxed);
            Err(AuthError::Internal(
                "untyped path: Redis pool: connection timed out".to_owned(),
            ))
        }

        async fn peek_hierarchical_identity_denial(
            &self,
            _request: HierarchicalIdentityDenialPeekRequest<'_>,
        ) -> Result<HierarchicalIdentityDenialPeekOutcome, AuthError> {
            self.untyped_peek_calls.fetch_add(1, Ordering::Relaxed);
            Err(AuthError::Internal(
                "untyped path: Redis pool: connection timed out".to_owned(),
            ))
        }

        async fn check_hierarchical_admission_classified(
            &self,
            _request: HierarchicalAdmissionRequest<'_>,
        ) -> Result<HierarchicalAdmissionOutcome, KeyedAdmissionFailure> {
            self.typed_hierarchical_calls
                .fetch_add(1, Ordering::Relaxed);
            Err(self.failure())
        }

        async fn peek_hierarchical_identity_denial_classified(
            &self,
            _request: HierarchicalIdentityDenialPeekRequest<'_>,
        ) -> Result<HierarchicalIdentityDenialPeekOutcome, KeyedAdmissionFailure> {
            self.typed_peek_calls.fetch_add(1, Ordering::Relaxed);
            Err(self.failure())
        }
    }

    #[test]
    fn relay_keyed_class_label_is_stable_when_error_prose_is_reworded() {
        let classes = [
            KeyedAdmissionErrorClass::BackendTimeout,
            KeyedAdmissionErrorClass::CounterCorrupt,
            KeyedAdmissionErrorClass::BackendUnavailable,
            KeyedAdmissionErrorClass::Contract,
            KeyedAdmissionErrorClass::Unknown,
        ];
        let poisons = [
            "timeout",
            "timed-out",
            "timed out",
            "Redis pool: connection timed out",
            "Redis hierarchical admission script: timed-out",
            "Redis identity denial peek script: timed out",
            "paired admission counter is corrupt",
            "hierarchical admission counter is corrupt",
            "arbitrarily reworded internal failure",
        ];
        for class in classes {
            for message in poisons {
                let failure =
                    KeyedAdmissionFailure::new(AuthError::Internal((*message).to_owned()), class);
                assert_eq!(
                    keyed_error_class_label(&failure),
                    class.as_str(),
                    "typed class {} must not be overridden by {message:?}",
                    class.as_str()
                );
            }
        }
        let timeout_prose = KeyedAdmissionFailure::new(
            AuthError::Internal("Redis pool: connection timed out timed-out timeout".into()),
            KeyedAdmissionErrorClass::CounterCorrupt,
        );
        assert_eq!(keyed_error_class_label(&timeout_prose), "counter_corrupt");
        assert_ne!(keyed_error_class_label(&timeout_prose), "backend_timeout");
    }

    #[tokio::test]
    async fn keyed_fresh_and_attempt_use_supplied_typed_class_despite_reworded_prose() {
        let cases = [
            (KeyedAdmissionErrorClass::BackendTimeout, "backend_timeout"),
            (KeyedAdmissionErrorClass::CounterCorrupt, "counter_corrupt"),
            (
                KeyedAdmissionErrorClass::BackendUnavailable,
                "backend_unavailable",
            ),
            (KeyedAdmissionErrorClass::Contract, "contract"),
            (KeyedAdmissionErrorClass::Unknown, "unknown"),
        ];
        let poisons = [
            "timeout timed-out timed out Redis pool: connection timed out",
            "arbitrarily reworded producer text",
            "hierarchical admission counter is corrupt",
        ];
        for (class, label) in cases {
            for message in poisons {
                let limiter = TypedKeyedFailureLimiter::new(class, message);
                let fresh = check_keyed_http_fresh_admission(&limiter, &tenant(), &signer())
                    .await
                    .expect_err("fresh typed failure");
                assert_eq!(fresh, AdmissionError::Unavailable);
                assert_eq!(limiter.typed_hierarchical_calls.load(Ordering::Relaxed), 1);
                assert_eq!(
                    limiter.untyped_hierarchical_calls.load(Ordering::Relaxed),
                    0
                );
                assert_eq!(limiter.typed_peek_calls.load(Ordering::Relaxed), 0);
                assert_eq!(keyed_error_class_label(&limiter.failure()), label);
                if class != KeyedAdmissionErrorClass::BackendTimeout {
                    assert_ne!(
                        keyed_error_class_label(&limiter.failure()),
                        "backend_timeout"
                    );
                }

                let limiter = TypedKeyedFailureLimiter::new(class, message);
                let attempt = check_keyed_http_attempt_admission(&limiter, &tenant(), &signer())
                    .await
                    .expect_err("attempt typed failure");
                assert_eq!(attempt, AdmissionError::Unavailable);
                assert_eq!(limiter.typed_hierarchical_calls.load(Ordering::Relaxed), 1);
                assert_eq!(
                    limiter.untyped_hierarchical_calls.load(Ordering::Relaxed),
                    0
                );
                assert_eq!(limiter.typed_peek_calls.load(Ordering::Relaxed), 0);
                assert_eq!(keyed_error_class_label(&limiter.failure()), label);
                if class != KeyedAdmissionErrorClass::BackendTimeout {
                    assert_ne!(
                        keyed_error_class_label(&limiter.failure()),
                        "backend_timeout"
                    );
                }
            }
        }
    }
}
