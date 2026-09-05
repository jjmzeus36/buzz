//! Database error types.

use thiserror::Error;

/// Errors produced by database operations.
#[derive(Debug, Error)]
pub enum DbError {
    /// A SQLx driver-level error.
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),

    /// A SQLx migration error.
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    /// Attempted to store an AUTH event (kind 22242), which is forbidden.
    #[error("AUTH events (kind 22242) must not be stored")]
    AuthEventRejected,

    /// Attempted to store an ephemeral event (kinds 20000–29999), which is forbidden.
    #[error("ephemeral events (kind {0}) must not be stored")]
    EphemeralEventRejected(u16),

    /// The requested channel does not exist.
    #[error("channel not found: {0}")]
    ChannelNotFound(uuid::Uuid),

    /// The requested member is not in the channel.
    #[error("member not found in channel {0}")]
    MemberNotFound(uuid::Uuid),

    /// A generic not-found error.
    #[error("not found: {0}")]
    NotFound(String),

    /// The caller lacks permission for the requested operation.
    #[error("access denied: {0}")]
    AccessDenied(String),

    /// JSON serialization or deserialization failed.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// A value in the database is malformed or unexpected.
    #[error("invalid data: {0}")]
    InvalidData(String),

    /// A serving write admitted before the lifecycle transition is still live.
    /// This is an ordinary retryable drain condition, not a safety violation.
    #[error(
        "community {community_id} still has {active_count} active serving write lease(s): {operations:?}"
    )]
    ServingWritesNotDrained {
        /// Community whose lifecycle transition must retry.
        community_id: uuid::Uuid,
        /// Number of currently unexpired serving-write leases.
        active_count: i64,
        /// Distinct operation categories holding those leases.
        operations: Vec<String>,
    },

    /// A deletion safety invariant is structurally violated and requires
    /// operator/code remediation rather than blind retry.
    #[error("deletion safety error: {0}")]
    DeletionSafety(String),

    /// A stored timestamp value could not be interpreted.
    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(i64),

    /// A roster mutation would remove the last effective relay Operator,
    /// leaving no one able to administer the deployment through the API.
    /// The transaction is rolled back and the caller must add a replacement
    /// Operator before demoting or deleting the current one.
    #[error("operation would remove the last relay operator")]
    LastOperator,
}

/// Convenience alias for `Result<T, DbError>`.
pub type Result<T> = std::result::Result<T, DbError>;

pub(crate) const IDEMPOTENCY_AUTHOR_MISMATCH: &str =
    "idempotency author does not match event pubkey";
pub(crate) const IDEMPOTENCY_UNSUPPORTED_KIND: &str =
    "idempotency is not supported for this event kind";
pub(crate) const IDEMPOTENCY_THREAD_METADATA_MISMATCH: &str =
    "idempotency thread metadata is not bound to the event";
pub(crate) const IDEMPOTENCY_TOO_MANY_MENTIONS: &str = "idempotency event exceeds the p-tag cap";
pub(crate) const IDEMPOTENCY_UNAVAILABLE: &str = "idempotency writer is busy";

impl DbError {
    pub(crate) fn idempotency_author_mismatch() -> Self {
        Self::InvalidData(IDEMPOTENCY_AUTHOR_MISMATCH.into())
    }

    pub(crate) fn idempotency_unsupported_kind() -> Self {
        Self::InvalidData(IDEMPOTENCY_UNSUPPORTED_KIND.into())
    }

    pub(crate) fn idempotency_thread_metadata_mismatch() -> Self {
        Self::InvalidData(IDEMPOTENCY_THREAD_METADATA_MISMATCH.into())
    }

    pub(crate) fn idempotency_too_many_mentions() -> Self {
        Self::InvalidData(IDEMPOTENCY_TOO_MANY_MENTIONS.into())
    }

    pub(crate) fn idempotency_unavailable() -> Self {
        Self::InvalidData(IDEMPOTENCY_UNAVAILABLE.into())
    }

    pub(crate) fn idempotency_canonicalize(
        error: buzz_core::idempotency::IdempotencyError,
    ) -> Self {
        Self::InvalidData(error.to_string())
    }

    /// True when a keyed writer timed out on a lock or statement slot.
    pub fn is_idempotency_unavailable(&self) -> bool {
        matches!(self, Self::InvalidData(message) if message == IDEMPOTENCY_UNAVAILABLE)
    }

    /// True when a keyed insert was attempted for an unsupported kind.
    pub fn is_idempotency_unsupported_kind(&self) -> bool {
        matches!(self, Self::InvalidData(message) if message == IDEMPOTENCY_UNSUPPORTED_KIND)
    }

    /// True when a keyed event exceeded the p-tag cap.
    pub fn is_idempotency_too_many_mentions(&self) -> bool {
        matches!(self, Self::InvalidData(message) if message == IDEMPOTENCY_TOO_MANY_MENTIONS)
    }
}

#[cfg(test)]
mod tests {
    use super::DbError;

    #[test]
    fn public_dberror_exhaustive_match_has_no_idempotency_variants() {
        fn classify(error: DbError) -> &'static str {
            match error {
                DbError::Sqlx(_) => "sqlx",
                DbError::Migrate(_) => "migrate",
                DbError::AuthEventRejected => "auth",
                DbError::EphemeralEventRejected(_) => "ephemeral",
                DbError::ChannelNotFound(_) => "channel",
                DbError::MemberNotFound(_) => "member",
                DbError::NotFound(_) => "not_found",
                DbError::AccessDenied(_) => "access",
                DbError::Serde(_) => "serde",
                DbError::InvalidData(_) => "invalid",
                DbError::ServingWritesNotDrained { .. } => "serving",
                DbError::DeletionSafety(_) => "deletion",
                DbError::InvalidTimestamp(_) => "timestamp",
                DbError::LastOperator => "last_operator",
            }
        }
        assert_eq!(classify(DbError::idempotency_unavailable()), "invalid");
        assert_eq!(classify(DbError::LastOperator), "last_operator");
    }
}
