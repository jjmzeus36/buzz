use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    /// Invalid argument or flag value — user error
    #[error("{0}")]
    Usage(String),

    /// Relay returned a non-2xx response
    #[error("relay error {status}: {body}")]
    Relay { status: u16, body: String },

    /// Keyed 503 whose valid positive Retry-After is a wait floor the
    /// operation cannot or will not consume with another internal attempt.
    /// This includes an over-bound delay and final-attempt exhaustion.
    /// Unqualified callers must not retry immediately; they MUST wait at
    /// least `retry_after_seconds`.
    #[error("relay error {status}: {body}")]
    RelayDeferred {
        status: u16,
        body: String,
        retry_after_seconds: u64,
    },

    /// Keyed 503 whose Retry-After is a valid wait floor that cannot be
    /// represented as a finite `u64` (all-digit delay above `u64`, or an
    /// unrepresentable HTTP-date conversion). Unqualified callers must not
    /// retry immediately. Public JSON must not invent a smaller finite wait.
    #[error("relay error {status}: {body}")]
    RelayRetryAfterOverflow { status: u16, body: String },

    /// Network-level failure (connect, timeout, DNS)
    #[error("network error: {}", fmt_reqwest_error(.0))]
    Network(#[from] reqwest::Error),

    /// Auth missing or rejected (401/403)
    #[error("auth error: {0}")]
    Auth(String),

    /// Nostr key error (NIP-98 signing in `buzz auth`)
    #[error("key error: {0}")]
    Key(String),

    /// Relay accepted the event but reported it as superseded by a newer
    /// head — used by `buzz mem` set/rm to surface NIP-33 LWW conflicts.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Requested resource was absent or tombstoned (e.g. `buzz mem get`
    /// for a slug with no head).
    #[error("{0}")]
    NotFound(String),

    /// A non-idempotent command's outcome is unknown: the request may have
    /// reached the relay, but the response was lost. Never auto-retried and
    /// never labeled retryable — the relay executes these commands before any
    /// dedup, so a blind re-run can duplicate the mutation.
    #[error("delivery unknown: {0}")]
    DeliveryUnknown(String),

    /// Public NIP-11 metadata exceeded the client's fixed read ceiling.
    ///
    /// Non-retryable. The message carries only the byte limit — never a
    /// relay status line or response body.
    #[error("public metadata exceeds {limit} bytes")]
    PublicMetadataTooLarge {
        /// Inclusive maximum the client will read, in bytes.
        limit: usize,
    },

    /// Keyed HTTP response body exceeded the client's fixed read ceiling.

    /// Non-retryable. The message carries only the byte limit — never a
    /// relay status line or response body.
    #[error("keyed response exceeds {limit} bytes")]
    KeyedResponseTooLarge {
        /// Inclusive maximum the client will read, in bytes.
        limit: usize,
    },

    /// Catch-all for unexpected failures
    #[error("{0}")]
    Other(String),
}

/// Walk the full `std::error::Error::source()` chain on a `reqwest::Error`
/// and render it as a colon-separated string, e.g.
/// `error sending request: dns error: failed to lookup address information: ...`
fn fmt_reqwest_error(e: &reqwest::Error) -> String {
    let mut msg = e.to_string();
    let mut source: &dyn std::error::Error = e;
    while let Some(cause) = source.source() {
        let cause_str = cause.to_string();
        if !msg.contains(&cause_str) {
            msg.push_str(": ");
            msg.push_str(&cause_str);
        }
        source = cause;
    }
    msg
}

/// Returns `true` when the error is transient and a retry may succeed.
///
/// Transport-level network errors (connect failure, timeout, mid-request,
/// mid-body transfer, or body decode failure) and relay overload responses
/// (429 / 502 / 503 / 504) are retryable.  `DeliveryUnknown` is never
/// retryable: the operation may already have executed.  Keyed 503 with an
/// unrepresentable Retry-After overflow is never retryable and never
/// advertises a finite wait.  All other errors indicate a permanent
/// failure: auth, bad input, builder errors, or logic errors.
pub fn is_retryable_error(e: &CliError) -> bool {
    match e {
        CliError::Network(ref net_err) => {
            net_err.is_connect()
                || net_err.is_timeout()
                || net_err.is_request()
                || net_err.is_body()
                || net_err.is_decode()
        }
        CliError::Relay { status, .. } => matches!(status, 429 | 502 | 503 | 504),
        CliError::RelayDeferred { .. } => false,
        CliError::RelayRetryAfterOverflow { .. } => false,
        CliError::DeliveryUnknown(_) => false,
        CliError::PublicMetadataTooLarge { .. } => false,
        CliError::KeyedResponseTooLarge { .. } => false,
        _ => false,
    }
}

/// Map CliError to process exit code.
/// 0=success (not an error), 1=user/not-found, 2=network/relay, 3=auth,
/// 4=other, 5=write conflict (NIP-33 dominated head).
pub fn exit_code(e: &CliError) -> i32 {
    match e {
        CliError::Usage(_) => 1,
        CliError::Relay { status, .. }
        | CliError::RelayDeferred { status, .. }
        | CliError::RelayRetryAfterOverflow { status, .. } => {
            if *status == 401 || *status == 403 {
                3
            } else {
                2
            }
        }
        CliError::Network(_) => 2,
        CliError::Auth(_) => 3,
        CliError::Key(_) => 3,
        CliError::Conflict(_) => 5,
        CliError::NotFound(_) => 1,
        CliError::DeliveryUnknown(_) => 2,
        CliError::PublicMetadataTooLarge { .. } => 2,
        CliError::KeyedResponseTooLarge { .. } => 2,
        CliError::Other(_) => 4,
    }
}

/// Serialize error to JSON and write to stderr.
/// Format: {"error": "<category>", "message": "<human-readable detail>", "retryable": <bool>}
pub fn print_error(e: &CliError) {
    eprintln!("{}", error_json(e));
}

/// JSON object written by [`print_error`].
pub fn error_json(e: &CliError) -> serde_json::Value {
    let category = match e {
        CliError::Usage(_) => "user_error",
        CliError::Relay { status, .. }
        | CliError::RelayDeferred { status, .. }
        | CliError::RelayRetryAfterOverflow { status, .. } => {
            if *status == 401 || *status == 403 {
                "auth_error"
            } else {
                "relay_error"
            }
        }
        CliError::Network(_) => "network_error",
        CliError::Auth(_) => "auth_error",
        CliError::Key(_) => "key_error",
        CliError::Conflict(_) => "conflict",
        CliError::NotFound(_) => "not_found",
        CliError::DeliveryUnknown(_) => "delivery_unknown",
        CliError::PublicMetadataTooLarge { .. } => "relay_error",
        CliError::KeyedResponseTooLarge { .. } => "relay_error",
        CliError::Other(_) => "error",
    };
    let mut obj = serde_json::json!({
        "error": category,
        "message": e.to_string(),
        "retryable": is_retryable_error(e),
    });
    if let CliError::RelayDeferred {
        retry_after_seconds,
        ..
    } = e
    {
        obj["retry_after_seconds"] = serde_json::json!(retry_after_seconds);
    }
    obj
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- is_retryable_error ----

    #[test]
    fn network_builder_errors_are_not_retryable() {
        // A bad URL produces a builder-level reqwest::Error (is_builder() == true).
        // Builder errors are not transport failures — not retryable.
        // Transport errors (is_connect/timeout/request) require live I/O to construct;
        // the predicate here mirrors with_retry's condition exactly.
        let e = reqwest::Client::new().get("not-a-url").build().unwrap_err();
        assert!(e.is_builder(), "expected a builder error from bad URL");
        assert!(!is_retryable_error(&CliError::Network(e)));
    }

    #[test]
    fn relay_429_502_503_504_are_retryable() {
        for status in [429u16, 502, 503, 504] {
            assert!(
                is_retryable_error(&CliError::Relay {
                    status,
                    body: String::new()
                }),
                "status {status} should be retryable"
            );
        }
    }

    #[test]
    fn relay_400_401_403_404_422_are_not_retryable() {
        for status in [400u16, 401, 403, 404, 422] {
            assert!(
                !is_retryable_error(&CliError::Relay {
                    status,
                    body: String::new()
                }),
                "status {status} should not be retryable"
            );
        }
    }

    #[test]
    fn other_errors_are_not_retryable() {
        assert!(!is_retryable_error(&CliError::Usage("bad flag".into())));
        assert!(!is_retryable_error(&CliError::Auth("missing key".into())));
        assert!(!is_retryable_error(&CliError::Key("bad key".into())));
        assert!(!is_retryable_error(&CliError::Conflict(
            "superseded".into()
        )));
        assert!(!is_retryable_error(&CliError::NotFound("gone".into())));
        assert!(!is_retryable_error(&CliError::Other("unexpected".into())));
        assert!(!is_retryable_error(&CliError::PublicMetadataTooLarge {
            limit: 65_536
        }));
        assert!(!is_retryable_error(&CliError::KeyedResponseTooLarge {
            limit: 65_536
        }));
        assert!(!is_retryable_error(&CliError::RelayDeferred {
            status: 503,
            body: "idempotency unavailable".into(),
            retry_after_seconds: 3_600,
        }));
        assert!(!is_retryable_error(&CliError::RelayRetryAfterOverflow {
            status: 503,
            body: "idempotency unavailable".into(),
        }));
        assert!(is_retryable_error(&CliError::Relay {
            status: 503,
            body: "idempotency unavailable".into(),
        }));
    }

    #[test]
    fn deferred_503_json_is_relay_error_with_wait_floor() {
        let err = CliError::RelayDeferred {
            status: 503,
            body: "idempotency unavailable".into(),
            retry_after_seconds: 3_600,
        };
        assert_eq!(exit_code(&err), 2);
        assert_eq!(err.to_string(), "relay error 503: idempotency unavailable");
        let v = error_json(&err);
        assert_eq!(v["error"].as_str(), Some("relay_error"));
        assert_eq!(
            v["message"].as_str(),
            Some("relay error 503: idempotency unavailable")
        );
        assert_eq!(v["retryable"].as_bool(), Some(false));
        assert_eq!(v["retry_after_seconds"].as_u64(), Some(3_600));
    }

    #[test]
    fn deferred_503_at_remaining_deadline_is_not_ambiguous() {
        let err = CliError::RelayDeferred {
            status: 503,
            body: "idempotency unavailable".into(),
            retry_after_seconds: 90,
        };
        assert!(!is_retryable_error(&err));
        assert!(!matches!(err, CliError::DeliveryUnknown(_)));
        assert!(!matches!(err, CliError::Other(_)));
        assert!(!matches!(err, CliError::Usage(_)));
        let v = error_json(&err);
        assert_eq!(v["retry_after_seconds"].as_u64(), Some(90));
        assert_eq!(v["retryable"].as_bool(), Some(false));
    }

    #[test]
    fn ordinary_503_json_stays_retryable_without_wait_field() {
        let err = CliError::Relay {
            status: 503,
            body: "idempotency unavailable".into(),
        };
        let v = error_json(&err);
        assert_eq!(v["error"].as_str(), Some("relay_error"));
        assert_eq!(v["retryable"].as_bool(), Some(true));
        assert!(v.get("retry_after_seconds").is_none());
    }

    #[test]
    fn overflow_503_json_is_relay_error_without_wait_field() {
        let err = CliError::RelayRetryAfterOverflow {
            status: 503,
            body: "idempotency unavailable".into(),
        };
        assert!(!is_retryable_error(&err));
        assert_eq!(exit_code(&err), 2);
        assert_eq!(err.to_string(), "relay error 503: idempotency unavailable");
        let v = error_json(&err);
        assert_eq!(v["error"].as_str(), Some("relay_error"));
        assert_eq!(
            v["message"].as_str(),
            Some("relay error 503: idempotency unavailable")
        );
        assert_eq!(v["retryable"].as_bool(), Some(false));
        assert!(
            v.get("retry_after_seconds").is_none(),
            "overflow must not invent a finite retry_after_seconds, got {v}"
        );
        assert!(!matches!(err, CliError::DeliveryUnknown(_)));
        assert!(!matches!(err, CliError::Relay { .. }));
        assert!(!matches!(err, CliError::RelayDeferred { .. }));
    }

    // ---- print_error "retryable" field ----

    #[test]
    fn json_error_includes_retryable_field_for_network() {
        // Builder errors (bad URL) are not transport-level — retryable: false.
        // This test verifies the JSON shape and that the field is present.
        let e = reqwest::Client::new().get("not-a-url").build().unwrap_err();
        let err = CliError::Network(e);
        let v = serde_json::json!({
            "error": "network_error",
            "message": err.to_string(),
            "retryable": is_retryable_error(&err),
        });
        assert_eq!(v["retryable"].as_bool(), Some(false));
        assert_eq!(v["error"].as_str(), Some("network_error"));
    }

    #[test]
    fn json_error_retryable_false_for_usage() {
        let err = CliError::Usage("bad flag".into());
        let v = serde_json::json!({
            "error": "user_error",
            "message": err.to_string(),
            "retryable": is_retryable_error(&err),
        });
        assert_eq!(v["retryable"].as_bool(), Some(false));
    }

    // ---- Display source-chain ----

    #[test]
    fn public_metadata_too_large_reports_only_the_limit() {
        let err = CliError::PublicMetadataTooLarge { limit: 65_536 };
        assert!(!is_retryable_error(&err));
        assert_eq!(exit_code(&err), 2);
        assert_eq!(err.to_string(), "public metadata exceeds 65536 bytes");
        let v = error_json(&err);
        assert_eq!(v["error"].as_str(), Some("relay_error"));
        assert_eq!(
            v["message"].as_str(),
            Some("public metadata exceeds 65536 bytes")
        );
        assert_eq!(v["retryable"].as_bool(), Some(false));
        assert!(v.get("retry_after_seconds").is_none());
        assert!(!err.to_string().contains("hostile"));
        assert!(!err.to_string().contains('{'));
    }

    #[test]
    fn keyed_response_too_large_reports_only_the_limit() {
        let err = CliError::KeyedResponseTooLarge { limit: 65_536 };
        assert!(!is_retryable_error(&err));
        assert_eq!(exit_code(&err), 2);
        assert_eq!(err.to_string(), "keyed response exceeds 65536 bytes");
        let debug = format!("{err:?}");
        let v = error_json(&err);
        assert_eq!(v["error"].as_str(), Some("relay_error"));
        assert_eq!(
            v["message"].as_str(),
            Some("keyed response exceeds 65536 bytes")
        );
        assert_eq!(v["retryable"].as_bool(), Some(false));
        assert!(v.get("retry_after_seconds").is_none());
        assert!(!err.to_string().contains("RELAY_BODY_SENTINEL"));
        assert!(!debug.contains("RELAY_BODY_SENTINEL"));
        assert!(!v.to_string().contains("RELAY_BODY_SENTINEL"));
        assert!(!err.to_string().contains('{'));
    }

    #[test]
    fn network_display_includes_detail_beyond_prefix() {
        let e = reqwest::Client::new().get("not-a-url").build().unwrap_err();
        let display = CliError::Network(e).to_string();
        assert!(
            display.starts_with("network error:"),
            "display should start with 'network error:': {display}"
        );
        assert!(
            display.len() > "network error: ".len(),
            "display should contain error detail: {display}"
        );
    }
}
