//! Keyed kind:9 insert: reservation + event + thread + mentions, one writer tx.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use buzz_core::idempotency::{
    keyed_p_tag_count, supports_keyed_kind, PreparedKeyedIntent, KEYED_MAX_P_TAGS,
    RETENTION_SECONDS,
};
use buzz_core::{CommunityId, StoredEvent};
use buzz_datastore_tracing::datastore_span;
use chrono::{DateTime, Utc};
use nostr::Event;
use sqlx::{Postgres, Row};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, SemaphorePermit};
use uuid::Uuid;

use crate::event::{insert_event_with_thread_metadata_tx, ThreadMetadataParams};
use crate::insert_mentions_in_transaction;
use crate::{Db, DbError, Result};

/// Hard fail-fast cap on concurrent open keyed reservations. `try_acquire`
/// only — never a waiter queue. Capacity is acquired only for the
/// transactional reserve-or-classify path, never while Redis admission runs.
/// Global slots are tenant-fair: one community cannot occupy every permit.
pub const KEYED_RESERVATION_CAPACITY: usize = 8;

/// Per-community fail-fast cap. A tenant stalled on its deletion/advisory
/// lock can hold at most this many of [`KEYED_RESERVATION_CAPACITY`].
/// At least 2 so two same-tenant callers can enter the transactional
/// reserve-or-classify path together; at most half the global cap so one
/// tenant cannot monopolize the fleet.
pub const KEYED_RESERVATION_PER_TENANT_CAPACITY: usize = 4;

/// Fail-fast cap on concurrent post-COMMIT ownership-witness lookups.
/// Independent of reservation capacity so recovery cannot occupy writer slots.
pub const KEYED_COMMIT_RECOVERY_CAPACITY: usize = 8;

/// Bind a numeric timeout const to the exact `SET LOCAL` SQL production
/// executes. The seconds literal is the single source for both the `u64`
/// and the SQL body, so the two cannot drift.
macro_rules! keyed_local_timeout {
    ($(#[$attr:meta])* $secs_name:ident, $sql_name:ident, $setting:literal, $secs:literal) => {
        $(#[$attr])*
        pub const $secs_name: u64 = $secs;
        const $sql_name: &str = concat!("SET LOCAL ", $setting, " = '", stringify!($secs), "s'");
    };
}

keyed_local_timeout!(
    /// Seconds for `SET LOCAL lock_timeout` on a reserved writer transaction.
    /// Canonical numeric source for the production lock-timeout SQL.
    KEYED_RESERVATION_LOCK_TIMEOUT_SECS,
    KEYED_LOCK_TIMEOUT_SQL,
    "lock_timeout",
    5
);

keyed_local_timeout!(
    /// Seconds for `SET LOCAL idle_in_transaction_session_timeout` on a reserved
    /// writer transaction. PostgreSQL safety belt for an open reservation only;
    /// Redis admission runs before a transaction is acquired. Independent of the
    /// relay's caller-side admission budget, which must stay strictly shorter.
    KEYED_RESERVATION_IDLE_TIMEOUT_SECS,
    KEYED_IDLE_IN_TRANSACTION_SQL,
    "idle_in_transaction_session_timeout",
    10
);

keyed_local_timeout!(
    /// Seconds for `SET LOCAL statement_timeout` on a reserved writer
    /// transaction. Matches the relay persist budget; SQL statements stay
    /// bounded even if the caller future is not cancelled.
    KEYED_RESERVATION_STATEMENT_TIMEOUT_SECS,
    KEYED_STATEMENT_TIMEOUT_SQL,
    "statement_timeout",
    15
);

/// Seconds for the post-COMMIT primary-key ownership-witness lookup.
/// Independent of the reserved writer `statement_timeout` and of the
/// relay classify/begin persist budget: recovery opens a new transaction
/// after the writer tx is gone. Timeout fail-closes and is never success.
pub const KEYED_COMMIT_RECOVERY_LOOKUP_TIMEOUT_SECS: u64 = 15;

const _: () = {
    assert!(KEYED_RESERVATION_LOCK_TIMEOUT_SECS > 0);
    assert!(KEYED_RESERVATION_LOCK_TIMEOUT_SECS <= KEYED_RESERVATION_IDLE_TIMEOUT_SECS);
    assert!(KEYED_RESERVATION_IDLE_TIMEOUT_SECS <= KEYED_RESERVATION_STATEMENT_TIMEOUT_SECS);
    assert!(KEYED_COMMIT_RECOVERY_LOOKUP_TIMEOUT_SECS > 0);
    assert!(KEYED_RESERVATION_PER_TENANT_CAPACITY >= 2);
    assert!(KEYED_RESERVATION_PER_TENANT_CAPACITY * 2 <= KEYED_RESERVATION_CAPACITY);
    assert!(KEYED_COMMIT_RECOVERY_CAPACITY > 0);
    assert!(KEYED_RESERVATION_LOCK_TIMEOUT_SECS == 5);
    assert!(KEYED_RESERVATION_STATEMENT_TIMEOUT_SECS == 15);
    assert!(KEYED_RESERVATION_IDLE_TIMEOUT_SECS == 10);
};

/// DB-layer outcome of a keyed kind:9 insert. Only [`Self::Inserted`] and
/// [`Self::RecoveredFresh`] may dispatch.
#[derive(Debug)]
pub enum KeyedStreamInsert {
    /// New event row (and mentions if any) committed with the reservation.
    Inserted {
        /// Stored event returned by the event helper after a fresh insert.
        stored_event: Box<StoredEvent>,
    },
    /// This reservation's fresh insert, recovered after a lost COMMIT ack.
    ///
    /// The committed row matched tenant, author, key, intent hash, event id,
    /// and this reservation's durable ownership witness. Ingest must treat
    /// this as [`Self::Inserted`]: same dispatch, side effects, trace, metric,
    /// and accepted result.
    RecoveredFresh {
        /// Stored event produced by the persist that committed without an ack.
        stored_event: Box<StoredEvent>,
    },
    /// New key bound to an already-stored identical signed event.
    BoundExisting {
        /// Event id the new key now points at.
        event_id: [u8; 32],
    },
    /// Same key and same intent hash; original event id.
    Replay {
        /// Event id stored with the original reservation.
        original_event_id: [u8; 32],
    },
    /// Same key, different intent hash; no mutation.
    Conflict {
        /// Event id already bound to this key.
        existing_event_id: [u8; 32],
    },
}

impl KeyedStreamInsert {
    /// True only for a newly inserted event row, including lost-COMMIT
    /// recovery of this reservation's own ownership witness.
    pub fn should_dispatch(&self) -> bool {
        matches!(self, Self::Inserted { .. } | Self::RecoveredFresh { .. })
    }

    /// Stored event for the ingest success path.
    ///
    /// [`Self::Inserted`] and [`Self::RecoveredFresh`] share this so dispatch,
    /// side effects, trace, and the stored-event metric stay identical.
    /// Replay, BoundExisting, and Conflict remain non-dispatch outcomes.
    pub fn into_fresh_stored_event(self) -> std::result::Result<Box<StoredEvent>, Self> {
        match self {
            Self::Inserted { stored_event } | Self::RecoveredFresh { stored_event } => {
                Ok(stored_event)
            }
            other => Err(other),
        }
    }
}

/// Atomic reserve-or-classify outcome. Replay and conflict never persist a
/// reservation. [`Self::Reserved`] holds the open writer transaction until
/// [`KeyedReservation::complete`] or [`KeyedReservation::abort`].
///
/// The reserved transaction is pool-owned (SQLx 0.9 `'static`), not borrowed
/// from a local [`Db`].
pub enum KeyedReserveOutcome {
    /// This caller uniquely holds the uncommitted reservation.
    Reserved(Box<KeyedReservation>),
    /// Same key and same intent hash; original event id.
    Replay {
        /// Event id stored with the original reservation.
        original_event_id: [u8; 32],
    },
    /// Same key, different intent hash; no mutation.
    Conflict {
        /// Event id already bound to this key.
        existing_event_id: [u8; 32],
    },
}

/// Committed keyed-row classification from a read-only primary-key lookup.
///
/// Replay and conflict only. [`Db::classify_committed_keyed_stream`] returns
/// `None` on a miss, including an uncommitted first-insert race. This type
/// cannot hold a writer transaction.
#[derive(Debug)]
pub enum KeyedCommittedOutcome {
    /// Same key and same intent hash; original event id.
    Replay {
        /// Event id stored with the original reservation.
        original_event_id: [u8; 32],
    },
    /// Same key, different intent hash; no mutation.
    Conflict {
        /// Event id already bound to this key.
        existing_event_id: [u8; 32],
    },
}

/// Per-tenant registry value. `live_handles` is the linearizable checkout
/// count; it is not inferred from `Arc::strong_count`.
struct KeyedTenantReservationEntry {
    semaphore: Arc<Semaphore>,
    live_handles: usize,
}

/// Identity-carrying checkout of a per-tenant registry entry. Dropping
/// decrements `live_handles` under the registry mutex and reclaims the
/// entry only when the count is zero, `ptr_eq` still matches, and every
/// per-tenant permit is available.
struct KeyedTenantReservationHandle {
    community: Uuid,
    semaphore: Arc<Semaphore>,
}

impl Drop for KeyedTenantReservationHandle {
    fn drop(&mut self) {
        release_tenant_reservation_handle(self.community, &self.semaphore);
    }
}

/// Global plus per-tenant fail-fast reservation permits. Dropping releases
/// the owned tenant permit, then the global permit, then the registry
/// handle. Field takes in [`Drop`] keep that order independent of layout.
struct KeyedReservationPermits {
    tenant: Option<OwnedSemaphorePermit>,
    global: Option<SemaphorePermit<'static>>,
    handle: Option<KeyedTenantReservationHandle>,
}

impl Drop for KeyedReservationPermits {
    fn drop(&mut self) {
        drop(self.tenant.take());
        drop(self.global.take());
        drop(self.handle.take());
    }
}

/// Primary-key ownership-witness columns used after an ambiguous COMMIT.
struct KeyedOwnershipWitnessRow {
    intent_hash: Vec<u8>,
    event_id: Vec<u8>,
    reservation_witness: Vec<u8>,
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for KeyedOwnershipWitnessRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> sqlx::Result<Self> {
        Ok(Self {
            intent_hash: row.try_get("intent_hash")?,
            event_id: row.try_get("event_id")?,
            reservation_witness: row.try_get("reservation_witness")?,
        })
    }
}

/// Grouped inputs for the independently bounded lost-COMMIT-ack lookup.
struct LostCommitAckRecovery {
    community_id: CommunityId,
    author: [u8; 32],
    key: [u8; 32],
    intent_hash: [u8; 32],
    event_id: [u8; 32],
    witness: [u8; 32],
    persist_outcome: KeyedStreamInsert,
}

/// Uncommitted keyed reservation. Dropping without [`Self::complete`] rolls
/// the reservation back so it cannot be orphaned or treated as a replay, and
/// releases the pre-reservation capacity slots.
pub struct KeyedReservation {
    tx: Option<sqlx::Transaction<'static, Postgres>>,
    capacity: Option<KeyedReservationPermits>,
    pool: sqlx::PgPool,
    community_id: CommunityId,
    prepared: PreparedKeyedIntent,
    /// Unforgeable per-reservation ownership witness persisted with the key.
    witness: [u8; 32],
    channel_id: Option<Uuid>,
    #[cfg(test)]
    commit_ack_seam: CommitAckSeam,
    #[cfg(test)]
    recovery_witness_override: Option<[u8; 32]>,
}

/// Test-only commit acknowledgement seam. Production always performs a live
/// `COMMIT`. Tests use this to prove lost-ack recovery without holding the
/// failed transaction.
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
enum CommitAckSeam {
    Live,
    /// Commit for real, then report a synthetic lost acknowledgement.
    LostAck,
    /// Do not commit (drop/rollback), then report a commit error.
    FailWithoutCommit,
}

impl KeyedReservation {
    /// Roll back the uncommitted reservation and release capacity.
    pub async fn abort(mut self) -> Result<()> {
        let result = if let Some(tx) = self.tx.take() {
            tx.rollback().await.map_err(map_keyed_sqlx)
        } else {
            Ok(())
        };
        drop(self.capacity.take());
        result
    }

    /// Persist the reserved event and commit.
    ///
    /// A lost COMMIT acknowledgement discards the failed transaction, releases
    /// reservation capacity, and recovers as this request's fresh insert only
    /// when a bounded primary-key lookup matches tenant, author, key, intent
    /// hash, event id, and this reservation's durable ownership witness.
    /// Missing, different, or conflicting rows, lookup errors, and timeouts
    /// fail closed and are never fresh success.
    ///
    /// Persist statements are bounded by
    /// [`KEYED_RESERVATION_STATEMENT_TIMEOUT_SECS`] (per statement, including
    /// COMMIT). Recovery is a later phase bounded by
    /// [`KEYED_COMMIT_RECOVERY_LOOKUP_TIMEOUT_SECS`] and
    /// [`KEYED_COMMIT_RECOVERY_CAPACITY`]. Callers must not wrap this method
    /// in an external cancellation deadline: an ambiguous COMMIT always
    /// reaches the witness lookup before this future returns.
    ///
    /// `prepared` must be the same value used to reserve. Semantic intent is
    /// not hashed again; the event id binding is the signed Nostr id.
    pub async fn complete(
        mut self,
        prepared: &PreparedKeyedIntent,
        event: &Event,
        thread_meta: Option<ThreadMetadataParams<'_>>,
    ) -> Result<KeyedStreamInsert> {
        if let Err(error) =
            validate_prepared_before_db(prepared, event, self.channel_id, thread_meta.as_ref())
        {
            let _ = self.abort().await;
            return Err(error);
        }
        if !prepared_intent_eq(prepared, &self.prepared) {
            let _ = self.abort().await;
            return Err(DbError::idempotency_thread_metadata_mismatch());
        }
        let Some(mut tx) = self.tx.take() else {
            return Err(DbError::idempotency_unavailable());
        };
        match persist_reserved_event_in_tx(
            &mut tx,
            self.community_id,
            event,
            self.channel_id,
            thread_meta,
            *prepared.event_id(),
        )
        .await
        {
            Ok(outcome) => {
                let commit_error = match commit_reserved_tx(
                    tx,
                    #[cfg(test)]
                    self.commit_ack_seam,
                )
                .await
                {
                    Ok(()) => return Ok(outcome),
                    Err(error) => error,
                };
                drop(self.capacity.take());
                let recovery_witness = {
                    #[cfg(test)]
                    {
                        self.recovery_witness_override.unwrap_or(self.witness)
                    }
                    #[cfg(not(test))]
                    {
                        self.witness
                    }
                };
                match recover_lost_commit_ack(
                    &self.pool,
                    LostCommitAckRecovery {
                        community_id: self.community_id,
                        author: *self.prepared.author(),
                        key: *self.prepared.key(),
                        intent_hash: *self.prepared.intent_hash(),
                        event_id: *self.prepared.event_id(),
                        witness: recovery_witness,
                        persist_outcome: outcome,
                    },
                )
                .await
                {
                    Ok(Some(recovered)) => Ok(recovered),
                    Ok(None) => Err(map_keyed_sqlx(commit_error)),
                    Err(error) => Err(error),
                }
            }
            Err(error) => {
                let _ = tx.rollback().await;
                Err(error)
            }
        }
    }
}

#[cfg(test)]
impl KeyedReservation {
    fn with_lost_commit_ack(mut self) -> Self {
        self.commit_ack_seam = CommitAckSeam::LostAck;
        self
    }

    fn with_commit_failure_without_commit(mut self) -> Self {
        self.commit_ack_seam = CommitAckSeam::FailWithoutCommit;
        self
    }

    fn claiming_witness(mut self, witness: [u8; 32]) -> Self {
        self.recovery_witness_override = Some(witness);
        self
    }
}

/// One-transaction NIP-MI expired-key reap result, including an exact
/// remaining-expired probe for scheduler cursor reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventIdempotencyReapProgress {
    /// Rows deleted in this transaction.
    pub deleted: u64,
    /// Exclusive cursor naming the visited tenant.
    pub next_after: Option<Uuid>,
    /// True when this tick's wrap/scan has no further tenant to visit.
    pub exhausted: bool,
    /// Whether the scan wrapped from the high end back to the lowest id.
    pub wrapped: bool,
    /// Exact post-delete probe: this tenant still has expired rows.
    pub more_expired: bool,
}

/// Constant-time-ish 32-byte equality: XOR/OR over a fixed 32-iteration loop.
fn fixed_32_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= left[i] ^ right[i];
    }
    diff == 0
}

fn prepared_intent_eq(left: &PreparedKeyedIntent, right: &PreparedKeyedIntent) -> bool {
    fixed_32_eq(left.key(), right.key())
        && fixed_32_eq(left.intent_hash(), right.intent_hash())
        && fixed_32_eq(left.event_id(), right.event_id())
        && fixed_32_eq(left.author(), right.author())
}

fn validate_prepared_before_db(
    prepared: &PreparedKeyedIntent,
    event: &Event,
    channel_id: Option<Uuid>,
    thread_meta: Option<&ThreadMetadataParams<'_>>,
) -> Result<()> {
    if !prepared.binds_event(event) {
        return Err(DbError::idempotency_thread_metadata_mismatch());
    }
    validate_before_db(prepared.author(), event, channel_id, thread_meta)
}

fn event_created_at(event: &Event) -> Result<DateTime<Utc>> {
    let created_at_secs = event.created_at.as_secs() as i64;
    DateTime::from_timestamp(created_at_secs, 0).ok_or(DbError::InvalidTimestamp(created_at_secs))
}

fn copy_32(bytes: &[u8]) -> Result<[u8; 32]> {
    if bytes.len() != 32 {
        return Err(DbError::InvalidData(
            "event_idempotency_keys row was not 32-byte hash/id".into(),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Operator-safe busy class retained before the client-opaque mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KeyedSqlxBusy {
    class: &'static str,
    sqlstate: Option<&'static str>,
}

fn keyed_busy_sqlstate(code: Option<&str>) -> Option<KeyedSqlxBusy> {
    match code {
        Some("55P03") => Some(KeyedSqlxBusy {
            class: "lock_not_available",
            sqlstate: Some("55P03"),
        }),
        Some("57014") => Some(KeyedSqlxBusy {
            class: "statement_canceled",
            sqlstate: Some("57014"),
        }),
        Some("25P03") => Some(KeyedSqlxBusy {
            class: "idle_in_transaction_timeout",
            sqlstate: Some("25P03"),
        }),
        _ => None,
    }
}

fn keyed_sqlx_busy(error: &sqlx::Error) -> Option<KeyedSqlxBusy> {
    match error {
        sqlx::Error::PoolTimedOut => Some(KeyedSqlxBusy {
            class: "pool_timeout",
            sqlstate: None,
        }),
        sqlx::Error::Database(database) => keyed_busy_sqlstate(database.code().as_deref()),
        // Closed-connection Io/Protocol shapes are not uniquely an idle-in-
        // transaction timeout (server crash, network reset, pool teardown).
        // SQLSTATE 25P03 is the supported deterministic mapping.
        _ => None,
    }
}

fn map_keyed_sqlx(error: sqlx::Error) -> DbError {
    if let Some(busy) = keyed_sqlx_busy(&error) {
        tracing::warn!(
            class = busy.class,
            sqlstate = busy.sqlstate.unwrap_or(""),
            "keyed writer busy"
        );
        return DbError::idempotency_unavailable();
    }
    DbError::Sqlx(error)
}

/// 32-byte CSPRNG ownership witness unique to this reservation attempt.
fn new_reservation_witness() -> [u8; 32] {
    let mut witness = [0u8; 32];
    witness[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    witness[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    witness
}

#[cfg(test)]
fn lost_commit_ack_error() -> sqlx::Error {
    sqlx::Error::Io(std::io::Error::other("lost commit acknowledgement"))
}

async fn commit_reserved_tx(
    tx: sqlx::Transaction<'static, Postgres>,
    #[cfg(test)] seam: CommitAckSeam,
) -> std::result::Result<(), sqlx::Error> {
    #[cfg(test)]
    match seam {
        CommitAckSeam::Live => tx.commit().await,
        CommitAckSeam::LostAck => match tx.commit().await {
            Ok(()) => Err(lost_commit_ack_error()),
            Err(error) => Err(error),
        },
        CommitAckSeam::FailWithoutCommit => {
            drop(tx);
            Err(lost_commit_ack_error())
        }
    }
    #[cfg(not(test))]
    tx.commit().await
}

/// Bounded primary-key lookup after a COMMIT error. Recovers as this
/// reservation's persist outcome only when the committed row matches tenant,
/// author, key, intent hash, event id, and the exact ownership witness.
/// `Ok(None)` is not-ours (missing or mismatched). Lookup errors and
/// timeouts are `Err`.
async fn recover_lost_commit_ack(
    pool: &sqlx::PgPool,
    recovery: LostCommitAckRecovery,
) -> Result<Option<KeyedStreamInsert>> {
    let LostCommitAckRecovery {
        community_id,
        author,
        key,
        intent_hash,
        event_id,
        witness,
        persist_outcome,
    } = recovery;
    let _recovery_capacity = try_acquire_keyed_commit_recovery_capacity()?;
    let lookup = async {
        let mut tx = begin_attributed_keyed_transaction(
            pool,
            crate::observability::WriterOperation::EventWrite,
        )
        .await?;
        if let Err(error) = apply_keyed_reservation_timeouts(&mut tx).await {
            let _ = tx.rollback().await;
            return Err(error);
        }
        let existing = sqlx::query_as::<_, KeyedOwnershipWitnessRow>(
            r#"
            SELECT intent_hash, event_id, reservation_witness
              FROM event_idempotency_keys
             WHERE community_id = $1
               AND author_pubkey = $2
               AND idempotency_key = $3
            "#,
        )
        .bind(community_id.as_uuid())
        .bind(author.as_slice())
        .bind(key.as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_keyed_sqlx);
        let _ = tx.rollback().await;
        existing
    };

    let existing = match tokio::time::timeout(
        std::time::Duration::from_secs(KEYED_COMMIT_RECOVERY_LOOKUP_TIMEOUT_SECS),
        lookup,
    )
    .await
    {
        Ok(Ok(row)) => row,
        Ok(Err(error)) => return Err(error),
        Err(_elapsed) => return Err(DbError::idempotency_unavailable()),
    };

    let Some(existing) = existing else {
        return Ok(None);
    };
    let stored_hash = copy_32(&existing.intent_hash)?;
    let stored_event_id = copy_32(&existing.event_id)?;
    let stored_witness = copy_32(&existing.reservation_witness)?;
    if !(fixed_32_eq(&stored_hash, &intent_hash)
        && fixed_32_eq(&stored_event_id, &event_id)
        && fixed_32_eq(&stored_witness, &witness))
    {
        return Ok(None);
    }
    match persist_outcome {
        KeyedStreamInsert::Inserted { stored_event }
        | KeyedStreamInsert::RecoveredFresh { stored_event } => {
            Ok(Some(KeyedStreamInsert::RecoveredFresh { stored_event }))
        }
        KeyedStreamInsert::BoundExisting { event_id } => {
            Ok(Some(KeyedStreamInsert::BoundExisting { event_id }))
        }
        KeyedStreamInsert::Replay { .. } | KeyedStreamInsert::Conflict { .. } => {
            Err(DbError::idempotency_unavailable())
        }
    }
}

fn keyed_reservation_capacity() -> &'static Semaphore {
    static CAPACITY: OnceLock<Semaphore> = OnceLock::new();
    CAPACITY.get_or_init(|| Semaphore::new(KEYED_RESERVATION_CAPACITY))
}

fn keyed_commit_recovery_capacity() -> &'static Semaphore {
    static CAPACITY: OnceLock<Semaphore> = OnceLock::new();
    CAPACITY.get_or_init(|| Semaphore::new(KEYED_COMMIT_RECOVERY_CAPACITY))
}

fn keyed_tenant_reservation_semaphores(
) -> &'static Mutex<HashMap<Uuid, KeyedTenantReservationEntry>> {
    static TENANTS: OnceLock<Mutex<HashMap<Uuid, KeyedTenantReservationEntry>>> = OnceLock::new();
    TENANTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Create or get the live per-tenant entry, checked-increment its handle
/// count, and clone the semaphore into a checkout handle. The registry
/// mutex is released before any semaphore or global acquire. Overflow
/// fail-closes without inserting an empty entry. Mutex poison fail-closes.
fn checkout_tenant_reservation_handle(community: Uuid) -> Result<KeyedTenantReservationHandle> {
    let mut tenants = keyed_tenant_reservation_semaphores()
        .lock()
        .map_err(|_| DbError::idempotency_unavailable())?;
    match tenants.entry(community) {
        std::collections::hash_map::Entry::Occupied(mut occupied) => {
            let entry = occupied.get_mut();
            let Some(live_handles) = entry.live_handles.checked_add(1) else {
                return Err(DbError::idempotency_unavailable());
            };
            entry.live_handles = live_handles;
            Ok(KeyedTenantReservationHandle {
                community,
                semaphore: Arc::clone(&entry.semaphore),
            })
        }
        std::collections::hash_map::Entry::Vacant(vacant) => {
            let semaphore = Arc::new(Semaphore::new(KEYED_RESERVATION_PER_TENANT_CAPACITY));
            vacant.insert(KeyedTenantReservationEntry {
                semaphore: Arc::clone(&semaphore),
                live_handles: 1,
            });
            Ok(KeyedTenantReservationHandle {
                community,
                semaphore,
            })
        }
    }
}

/// Decrement the matching live identity. Remove only when the count reaches
/// zero, `ptr_eq` still identifies the mapped entry, and all per-tenant
/// permits are available. A zero count with outstanding permits is retained
/// (fail closed) so a replacement cannot split capacity. Skips on mutex
/// poison; acquire already fail-closes in that state.
fn release_tenant_reservation_handle(community: Uuid, expected: &Arc<Semaphore>) {
    let Ok(mut tenants) = keyed_tenant_reservation_semaphores().lock() else {
        return;
    };
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
    if expected.available_permits() < KEYED_RESERVATION_PER_TENANT_CAPACITY {
        return;
    }
    tenants.remove(&community);
}

/// Identity-checked idle remove without decrementing. Used by tests to prove
/// stale cleanup cannot evict a replacement. Same poison and retain rules as
/// handle drop.
#[cfg(test)]
fn maybe_reclaim_tenant_semaphore(community: Uuid, expected: &Arc<Semaphore>) {
    let Ok(mut tenants) = keyed_tenant_reservation_semaphores().lock() else {
        return;
    };
    let Some(entry) = tenants.get(&community) else {
        return;
    };
    if !Arc::ptr_eq(&entry.semaphore, expected) {
        return;
    }
    if entry.live_handles != 0 {
        return;
    }
    if expected.available_permits() < KEYED_RESERVATION_PER_TENANT_CAPACITY {
        return;
    }
    tenants.remove(&community);
}

fn try_acquire_keyed_reservation_capacity(community: Uuid) -> Result<KeyedReservationPermits> {
    let handle = checkout_tenant_reservation_handle(community)?;
    let tenant = match Arc::clone(&handle.semaphore).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return Err(DbError::idempotency_unavailable()),
    };
    match keyed_reservation_capacity().try_acquire() {
        Ok(global) => Ok(KeyedReservationPermits {
            tenant: Some(tenant),
            global: Some(global),
            handle: Some(handle),
        }),
        Err(_) => {
            drop(tenant);
            Err(DbError::idempotency_unavailable())
        }
    }
}

fn try_acquire_keyed_commit_recovery_capacity() -> Result<SemaphorePermit<'static>> {
    keyed_commit_recovery_capacity()
        .try_acquire()
        .map_err(|_| DbError::idempotency_unavailable())
}

#[cfg(test)]
fn keyed_reservation_available_permits() -> usize {
    keyed_reservation_capacity().available_permits()
}

#[cfg(test)]
fn keyed_commit_recovery_available_permits() -> usize {
    keyed_commit_recovery_capacity().available_permits()
}

#[cfg(test)]
fn keyed_tenant_reservation_registry_len() -> usize {
    keyed_tenant_reservation_semaphores()
        .lock()
        .map(|tenants| tenants.len())
        .expect("tenant reservation registry mutex")
}

#[cfg(test)]
fn keyed_tenant_reservation_registry_contains(community: Uuid) -> bool {
    keyed_tenant_reservation_semaphores()
        .lock()
        .map(|tenants| tenants.contains_key(&community))
        .expect("tenant reservation registry mutex")
}

#[cfg(test)]
fn keyed_tenant_reservation_semaphore_arc(community: Uuid) -> Option<Arc<Semaphore>> {
    keyed_tenant_reservation_semaphores()
        .lock()
        .ok()
        .and_then(|tenants| {
            tenants
                .get(&community)
                .map(|entry| Arc::clone(&entry.semaphore))
        })
}

#[cfg(test)]
fn keyed_tenant_reservation_live_handles(community: Uuid) -> Option<usize> {
    keyed_tenant_reservation_semaphores()
        .lock()
        .ok()
        .and_then(|tenants| tenants.get(&community).map(|entry| entry.live_handles))
}

#[cfg(test)]
fn keyed_direct_capacity_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(test)]
fn lock_direct_capacity_tests() -> std::sync::MutexGuard<'static, ()> {
    keyed_direct_capacity_test_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
impl KeyedReservationPermits {
    fn tenant_semaphore_identity(&self) -> &Arc<Semaphore> {
        &self
            .handle
            .as_ref()
            .expect("reservation permits retain their tenant handle")
            .semaphore
    }
}

/// Production timeout SQL executed by [`apply_keyed_reservation_timeouts`].
/// Each body is mechanically derived from the matching numeric constant.
fn keyed_reservation_timeout_sql() -> [&'static str; 3] {
    [
        KEYED_LOCK_TIMEOUT_SQL,
        KEYED_STATEMENT_TIMEOUT_SQL,
        KEYED_IDLE_IN_TRANSACTION_SQL,
    ]
}

async fn apply_keyed_reservation_timeouts(tx: &mut sqlx::Transaction<'_, Postgres>) -> Result<()> {
    for sql in keyed_reservation_timeout_sql() {
        sqlx::query(sql)
            .execute(&mut **tx)
            .await
            .map_err(map_keyed_sqlx)?;
    }
    Ok(())
}

async fn begin_attributed_keyed_transaction(
    pool: &sqlx::PgPool,
    operation: crate::observability::WriterOperation,
) -> Result<sqlx::Transaction<'static, Postgres>> {
    let connection = crate::observability::acquire_writer(pool, operation)
        .await
        .map_err(map_keyed_sqlx)?;
    sqlx::Transaction::begin(connection, None)
        .await
        .map_err(map_keyed_sqlx)
}

fn validate_before_db(
    author: &[u8; 32],
    event: &Event,
    channel_id: Option<Uuid>,
    thread_meta: Option<&ThreadMetadataParams<'_>>,
) -> Result<()> {
    if !fixed_32_eq(author, &event.pubkey.to_bytes()) {
        return Err(DbError::idempotency_author_mismatch());
    }
    if !supports_keyed_kind(u32::from(event.kind.as_u16())) {
        return Err(DbError::idempotency_unsupported_kind());
    }
    if keyed_p_tag_count(event) > KEYED_MAX_P_TAGS {
        return Err(DbError::idempotency_too_many_mentions());
    }
    if let Some(meta) = thread_meta {
        if meta.event_id != event.id.as_bytes().as_slice() {
            return Err(DbError::idempotency_thread_metadata_mismatch());
        }
        if meta.event_created_at != event_created_at(event)? {
            return Err(DbError::idempotency_thread_metadata_mismatch());
        }
        if Some(meta.channel_id) != channel_id {
            return Err(DbError::idempotency_thread_metadata_mismatch());
        }
    }
    Ok(())
}

/// Distinct-community skip-scan from the lowest id.
const REAP_NEXT_COMMUNITY_FIRST_SQL: &str = r#"
            SELECT community_id
              FROM event_idempotency_keys
             ORDER BY community_id
             LIMIT 1
            "#;

/// Distinct-community skip-scan after `$1`.
const REAP_NEXT_COMMUNITY_AFTER_SQL: &str = r#"
            SELECT community_id
              FROM event_idempotency_keys
             WHERE community_id > $1
             ORDER BY community_id
             LIMIT 1
            "#;

/// Max cold (no-expired-row) community probes inside one reaper transaction.
/// Each probe is a LIMIT-1 tenant-first index lookup. One tick can therefore
/// skip a thousand cold tenants and still reach a hot tenant.
const REAP_MAX_COLD_COMMUNITY_PROBES_PER_TX: u32 = 1024;

/// Tenant-equality expired-row probe. Inclusive community_id bounds keep the
/// tenant-first btree as a range path so the created-at-leading index cannot
/// win under cross-tenant created_at correlation. `$1` is community_id; `$2`
/// is retention seconds.
const REAP_HAS_EXPIRED_SQL: &str = r#"
            SELECT 1
              FROM event_idempotency_keys AS expired
             WHERE expired.community_id >= $1
               AND expired.community_id <= $1
               AND expired.created_at < clock_timestamp()
                   - make_interval(secs => $2)
             ORDER BY expired.community_id,
                      expired.created_at,
                      expired.author_pubkey,
                      expired.idempotency_key
             LIMIT 1
            "#;

/// Non-blocking shared deletion-lock probe. Uses the canonical
/// `community_deletion_lock_key` so it cannot drift from
/// `community_write_allowed`.
const REAP_TRY_SHARED_DELETION_LOCK_SQL: &str = r#"
            SELECT pg_try_advisory_xact_lock_shared(
                community_deletion_lock_key($1)
            )
            "#;

const REAP_COMMUNITY_WRITE_ALLOWED_SQL: &str = r#"
            SELECT community_write_allowed($1)
            "#;

/// Tenant-equality expired delete. `$1` community_id, `$2` retention seconds,
/// `$3` row limit.
const REAP_EXPIRED_EVENT_IDEMPOTENCY_KEYS_SQL: &str = r#"
            DELETE FROM event_idempotency_keys AS keys
             WHERE keys.ctid IN (
                SELECT doomed.ctid
                  FROM event_idempotency_keys AS doomed
                 WHERE doomed.community_id >= $1
                   AND doomed.community_id <= $1
                   AND doomed.created_at < clock_timestamp()
                       - make_interval(secs => $2)
                 ORDER BY doomed.community_id,
                          doomed.created_at,
                          doomed.author_pubkey,
                          doomed.idempotency_key
                 FOR UPDATE OF doomed SKIP LOCKED
                 LIMIT $3
             )
            "#;

/// Operator-global singleton exclusive scan bound. `FOR UPDATE` serializes
/// the one deployment cursor with the bounded delete in the same transaction.
const REAP_CURSOR_LOCK_SQL: &str = r#"
            SELECT after_community_id
              FROM event_idempotency_reaper_cursor
             WHERE id = 1
             FOR UPDATE
            "#;

const REAP_CURSOR_STORE_SQL: &str = r#"
            UPDATE event_idempotency_reaper_cursor
               SET after_community_id = $1
             WHERE id = 1
            "#;

async fn next_reap_community_id(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    after: Option<Uuid>,
) -> Result<Option<Uuid>> {
    let next = if let Some(after) = after {
        sqlx::query_scalar(REAP_NEXT_COMMUNITY_AFTER_SQL)
            .bind(after)
            .fetch_optional(&mut **tx)
            .await
    } else {
        sqlx::query_scalar(REAP_NEXT_COMMUNITY_FIRST_SQL)
            .fetch_optional(&mut **tx)
            .await
    };
    next.map_err(map_keyed_sqlx)
}

fn reap_progress(
    deleted: u64,
    next_after: Option<Uuid>,
    exhausted: bool,
    wrapped: bool,
    more_expired: bool,
) -> EventIdempotencyReapProgress {
    EventIdempotencyReapProgress {
        deleted,
        next_after,
        exhausted,
        wrapped,
        more_expired,
    }
}

fn reap_cursor_should_persist(more_expired: bool, deleted: u64, tick_complete: bool) -> bool {
    tick_complete || !(more_expired && deleted > 0)
}

fn committed_reaper_cursor(
    scan_after: Option<Uuid>,
    next_after: Option<Uuid>,
    more_expired: bool,
    deleted: u64,
    tick_complete: bool,
) -> Option<Uuid> {
    if reap_cursor_should_persist(more_expired, deleted, tick_complete) {
        next_after
    } else {
        scan_after
    }
}

async fn lock_reaper_cursor(tx: &mut sqlx::Transaction<'_, Postgres>) -> Result<Option<Uuid>> {
    sqlx::query_scalar(REAP_CURSOR_LOCK_SQL)
        .fetch_optional(&mut **tx)
        .await
        .map_err(map_keyed_sqlx)?
        .ok_or_else(|| {
            DbError::InvalidData(
                "event_idempotency_reaper_cursor singleton is missing; refuse reaper tick".into(),
            )
        })
}

async fn store_reaper_cursor(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    after: Option<Uuid>,
) -> Result<()> {
    let done = sqlx::query(REAP_CURSOR_STORE_SQL)
        .bind(after)
        .execute(&mut **tx)
        .await
        .map_err(map_keyed_sqlx)?;
    if done.rows_affected() != 1 {
        return Err(DbError::InvalidData(
            "event_idempotency_reaper_cursor singleton is missing; refuse reaper tick".into(),
        ));
    }
    Ok(())
}

async fn commit_reap_progress(
    mut tx: sqlx::Transaction<'_, Postgres>,
    cursor_endpoints: (Option<Uuid>, Option<Uuid>),
    deleted: u64,
    exhausted: bool,
    wrapped: bool,
    more_expired: bool,
    tick_budget_spent: bool,
) -> Result<EventIdempotencyReapProgress> {
    let (scan_after, next_after) = cursor_endpoints;
    let cursor = committed_reaper_cursor(
        scan_after,
        next_after,
        more_expired,
        deleted,
        exhausted || tick_budget_spent,
    );
    if let Err(error) = store_reaper_cursor(&mut tx, cursor).await {
        let _ = tx.rollback().await;
        return Err(error);
    }
    tx.commit().await.map_err(map_keyed_sqlx)?;
    Ok(reap_progress(
        deleted,
        next_after,
        exhausted,
        wrapped,
        more_expired,
    ))
}

impl Db {
    /// Canonicalize and hash keyed semantic intent exactly once.
    ///
    /// The keyed HTTP ingest path must call this once before pre-admission
    /// classification and reuse the returned value through authoritative
    /// begin and complete. This method calls [`PreparedKeyedIntent::prepare`]
    /// once.
    pub fn prepare_keyed_stream_intent(
        key: [u8; 32],
        event: &Event,
    ) -> Result<PreparedKeyedIntent> {
        PreparedKeyedIntent::prepare(key, event).map_err(DbError::idempotency_canonicalize)
    }

    /// Reserve a kind:9 idempotency key and persist the event in one writer tx.
    #[datastore_span(
        name = "insert_keyed_stream_event_with_thread_metadata",
        system = "postgresql"
    )]
    pub async fn insert_keyed_stream_event_with_thread_metadata(
        &self,
        community_id: CommunityId,
        author: [u8; 32],
        key: [u8; 32],
        event: &Event,
        channel_id: Option<Uuid>,
        thread_meta: Option<ThreadMetadataParams<'_>>,
    ) -> Result<KeyedStreamInsert> {
        if !fixed_32_eq(&author, &event.pubkey.to_bytes()) {
            return Err(DbError::idempotency_author_mismatch());
        }
        let prepared = Self::prepare_keyed_stream_intent(key, event)?;
        match self
            .begin_keyed_stream_reservation(
                community_id,
                &prepared,
                event,
                channel_id,
                thread_meta.as_ref(),
            )
            .await?
        {
            KeyedReserveOutcome::Replay { original_event_id } => {
                Ok(KeyedStreamInsert::Replay { original_event_id })
            }
            KeyedReserveOutcome::Conflict { existing_event_id } => {
                Ok(KeyedStreamInsert::Conflict { existing_event_id })
            }
            KeyedReserveOutcome::Reserved(reservation) => {
                reservation.complete(&prepared, event, thread_meta).await
            }
        }
    }

    /// Classify a committed keyed row from a read-only primary-key lookup.
    ///
    /// Replay and conflict do not take [`KEYED_RESERVATION_CAPACITY`] or a
    /// writer transaction. A miss, including an uncommitted first-insert
    /// race, returns `Ok(None)` so the caller can run Redis admission and
    /// then [`Self::begin_keyed_stream_reservation`], which remains
    /// authoritative. Returns [`KeyedCommittedOutcome`], never a reservation.
    pub async fn classify_committed_keyed_stream(
        &self,
        community_id: CommunityId,
        author: [u8; 32],
        key: [u8; 32],
        event: &Event,
        channel_id: Option<Uuid>,
        thread_meta: Option<&ThreadMetadataParams<'_>>,
    ) -> Result<Option<KeyedCommittedOutcome>> {
        validate_before_db(&author, event, channel_id, thread_meta)?;
        let prepared = Self::prepare_keyed_stream_intent(key, event)?;
        classify_committed_keyed_row(
            &self.pool,
            community_id,
            author,
            key,
            *prepared.intent_hash(),
        )
        .await
    }

    /// Classify a keyed stream before Redis admission.
    ///
    /// The existing [`Self::begin_keyed_stream_reservation`] committed lookup remains
    /// the no-capacity/no-writer fast path. A miss briefly uses that method's bounded
    /// reserve-or-classify transaction as a visibility fence against an already-open
    /// same-key reservation. A true miss is immediately rolled back before this method
    /// returns. Callers must not perform Redis admission until it returns.
    pub async fn classify_keyed_stream_before_admission(
        &self,
        community_id: CommunityId,
        prepared: &PreparedKeyedIntent,
        event: &Event,
        channel_id: Option<Uuid>,
        thread_meta: Option<&ThreadMetadataParams<'_>>,
    ) -> Result<Option<KeyedCommittedOutcome>> {
        match self
            .begin_keyed_stream_reservation(community_id, prepared, event, channel_id, thread_meta)
            .await?
        {
            KeyedReserveOutcome::Replay { original_event_id } => {
                Ok(Some(KeyedCommittedOutcome::Replay { original_event_id }))
            }
            KeyedReserveOutcome::Conflict { existing_event_id } => {
                Ok(Some(KeyedCommittedOutcome::Conflict { existing_event_id }))
            }
            KeyedReserveOutcome::Reserved(reservation) => {
                reservation.abort().await?;
                Ok(None)
            }
        }
    }

    /// Atomically reserve a key or classify replay/conflict without charging
    /// callers. Concurrent identical requests cannot both observe
    /// [`KeyedReserveOutcome::Reserved`]. Abort or drop rolls the reservation
    /// back so it is neither burned nor orphaned.
    ///
    /// A committed `(community_id, author_pubkey, idempotency_key)` hit
    /// classifies replay or conflict from a read-only primary-key lookup and
    /// does not take [`KEYED_RESERVATION_CAPACITY`] or a writer transaction.
    /// That lookup is an optimization: a miss, including an uncommitted
    /// first-insert race, falls through to the capacity-bounded
    /// transactional reserve-or-classify path, which remains authoritative.
    ///
    /// HTTP keyed ingest must classify committed rows and finish Redis
    /// admission before calling this method so neither a capacity permit nor
    /// a writer transaction is held during those awaits. This method still
    /// rechecks committed state before reserving.
    ///
    /// Capacity is acquired with `try_acquire` before the attributed EventWrite
    /// transaction so genuinely new work cannot open an unbounded number of
    /// transactions.
    /// The global cap is tenant-fair: one community can hold at most
    /// [`KEYED_RESERVATION_PER_TENANT_CAPACITY`] of
    /// [`KEYED_RESERVATION_CAPACITY`]. Replay and conflict on that path
    /// release those slots before returning.
    pub async fn begin_keyed_stream_reservation(
        &self,
        community_id: CommunityId,
        prepared: &PreparedKeyedIntent,
        event: &Event,
        channel_id: Option<Uuid>,
        thread_meta: Option<&ThreadMetadataParams<'_>>,
    ) -> Result<KeyedReserveOutcome> {
        validate_prepared_before_db(prepared, event, channel_id, thread_meta)?;
        let author = *prepared.author();
        let key = *prepared.key();
        let intent_hash = *prepared.intent_hash();
        let event_id = *prepared.event_id();

        if let Some(outcome) =
            classify_committed_keyed_row(&self.pool, community_id, author, key, intent_hash).await?
        {
            return Ok(match outcome {
                KeyedCommittedOutcome::Replay { original_event_id } => {
                    KeyedReserveOutcome::Replay { original_event_id }
                }
                KeyedCommittedOutcome::Conflict { existing_event_id } => {
                    KeyedReserveOutcome::Conflict { existing_event_id }
                }
            });
        }

        let capacity = try_acquire_keyed_reservation_capacity(*community_id.as_uuid())?;
        let mut tx: sqlx::Transaction<'static, Postgres> = match begin_attributed_keyed_transaction(
            &self.pool,
            crate::observability::WriterOperation::EventWrite,
        )
        .await
        {
            Ok(tx) => tx,
            Err(error) => {
                drop(capacity);
                return Err(error);
            }
        };
        if let Err(error) = apply_keyed_reservation_timeouts(&mut tx).await {
            let _ = tx.rollback().await;
            drop(capacity);
            return Err(error);
        }
        let witness = new_reservation_witness();
        match reserve_or_classify_in_tx(
            &mut tx,
            community_id,
            author,
            key,
            intent_hash,
            event_id,
            witness,
        )
        .await
        {
            Ok(KeyedClassify::Replay { original_event_id }) => {
                let rollback = tx.rollback().await;
                drop(capacity);
                rollback?;
                Ok(KeyedReserveOutcome::Replay { original_event_id })
            }
            Ok(KeyedClassify::Conflict { existing_event_id }) => {
                let rollback = tx.rollback().await;
                drop(capacity);
                rollback?;
                Ok(KeyedReserveOutcome::Conflict { existing_event_id })
            }
            Ok(KeyedClassify::Reserved) => {
                Ok(KeyedReserveOutcome::Reserved(Box::new(KeyedReservation {
                    tx: Some(tx),
                    capacity: Some(capacity),
                    pool: self.pool.clone(),
                    community_id,
                    prepared: *prepared,
                    witness,
                    channel_id,
                    #[cfg(test)]
                    commit_ack_seam: CommitAckSeam::Live,
                    #[cfg(test)]
                    recovery_witness_override: None,
                })))
            }
            Err(error) => {
                let _ = tx.rollback().await;
                drop(capacity);
                Err(error)
            }
        }
    }

    /// Delete expired reservations in one bounded batch. Leader-only.
    ///
    /// Starts from the committed operator-global cursor (`NULL` means the
    /// lowest community id). Cycle origin is the all-ones UUID so a committed
    /// maximum cursor can wrap onto a later-expired lower or equal tenant.
    /// Prefer [`Self::reap_expired_event_idempotency_keys_from`] when the
    /// caller tracks tick-local wrap state.
    pub async fn reap_expired_event_idempotency_keys(&self, batch_limit: i64) -> Result<u64> {
        Ok(self
            .reap_expired_event_idempotency_keys_from(
                batch_limit,
                false,
                Some(Uuid::from_u128(u128::MAX)),
            )
            .await?
            .0)
    }

    /// Delete expired reservations for at most one community in one
    /// transaction, resuming after the locked operator-global cursor
    /// (`community_id > after_community_id`, or the lowest id when that
    /// bound is `NULL`).
    ///
    /// The outer 300s tick may call this at most eight times, so a tick never
    /// opens more than eight cleanup transactions or deletes more than
    /// 8,000 rows (`batch_limit` 1,000). Cold tenants (visible keys, no
    /// expired rows) are skip-probed inside this transaction and do not each
    /// spend a tick slot. Wrap is a skip-scan in this transaction — no
    /// earlier-tenant deletion lock is retained while later tenant work runs.
    ///
    /// `wrapped` and `cycle_origin` are tick-local: the caller captures
    /// `cycle_origin` from the persistent cursor at tick start and threads
    /// `wrapped` across the eight calls. After wrap, a community strictly
    /// greater than `cycle_origin` ends the cycle. The equal start-bound
    /// tenant may be processed once. A tick that started at the lowest id
    /// (`cycle_origin` is `None`) is exhausted at the high end and does not
    /// wrap.
    ///
    /// A tenant whose exclusive deletion lock is held is skipped without
    /// waiting. `community_write_allowed` runs only after a successful shared
    /// try-lock, immediately before that tenant's bounded delete.
    ///
    /// Returns `(deleted, next exclusive cursor, exhausted, wrapped)`. The
    /// returned cursor names the visited tenant. Callers that need an exact
    /// post-delete remaining-expired probe, including whether this
    /// transaction made positive deletion progress, should use
    /// [`Self::reap_expired_event_idempotency_keys_progress`].
    pub async fn reap_expired_event_idempotency_keys_from(
        &self,
        batch_limit: i64,
        wrapped: bool,
        cycle_origin: Option<Uuid>,
    ) -> Result<(u64, Option<Uuid>, bool, bool)> {
        let progress = self
            .reap_expired_event_idempotency_keys_progress(batch_limit, wrapped, cycle_origin, false)
            .await?;
        Ok((
            progress.deleted,
            progress.next_after,
            progress.exhausted,
            progress.wrapped,
        ))
    }

    /// Same one-tenant bounded delete as
    /// [`Self::reap_expired_event_idempotency_keys_from`], plus an exact
    /// post-delete remaining-expired probe.
    ///
    /// `more_expired` is not inferred from `deleted == batch_limit`. Reuse
    /// the previous exclusive cursor only when `more_expired` is true **and**
    /// this transaction deleted at least one row, so `SKIP LOCKED` zero
    /// progress advances to another tenant. Stay on a hot tenant while it is
    /// deleting positive batches. Advance immediately when an exact-full
    /// delete exhausted expired work, even if fresh rows keep the tenant
    /// visible. Persist this cursor when the eight-transaction budget is
    /// spent so a >8,000-row tenant cannot starve the rest of the fleet.
    ///
    /// `tick_budget_spent` is true on the last allowed transaction of the
    /// outer 300s tick. The operator-global cursor is locked and written in
    /// this same transaction as the bounded delete so a crash cannot advance
    /// past work whose deletion rolled back. The locked row is the
    /// exclusive scan bound for this transaction: a stale independent
    /// `Db` or replacement process cannot overwrite or regress newer
    /// committed progress.
    pub async fn reap_expired_event_idempotency_keys_progress(
        &self,
        batch_limit: i64,
        mut wrapped: bool,
        cycle_origin: Option<Uuid>,
        tick_budget_spent: bool,
    ) -> Result<EventIdempotencyReapProgress> {
        if batch_limit < 1 {
            return Ok(EventIdempotencyReapProgress {
                deleted: 0,
                next_after: None,
                exhausted: true,
                wrapped,
                more_expired: false,
            });
        }
        let retention_secs = RETENTION_SECONDS as i64;
        let mut tx = begin_attributed_keyed_transaction(
            &self.pool,
            crate::observability::WriterOperation::Maintenance,
        )
        .await?;
        if let Err(error) = apply_keyed_reservation_timeouts(&mut tx).await {
            let _ = tx.rollback().await;
            return Err(error);
        }
        let scan_after = match lock_reaper_cursor(&mut tx).await {
            Ok(cursor) => cursor,
            Err(error) => {
                let _ = tx.rollback().await;
                return Err(error);
            }
        };
        let mut prev = scan_after;
        let mut cold_probes = 0u32;

        let community = loop {
            let next = match next_reap_community_id(&mut tx, prev).await {
                Ok(next) => next,
                Err(error) => {
                    let _ = tx.rollback().await;
                    return Err(error);
                }
            };
            let Some(community) = next else {
                if wrapped || cycle_origin.is_none() {
                    return commit_reap_progress(
                        tx,
                        (scan_after, prev),
                        0,
                        true,
                        wrapped,
                        false,
                        tick_budget_spent,
                    )
                    .await;
                }
                wrapped = true;
                prev = None;
                continue;
            };
            if wrapped && cycle_origin.is_some_and(|bound| community > bound) {
                return commit_reap_progress(
                    tx,
                    (scan_after, prev),
                    0,
                    true,
                    wrapped,
                    false,
                    tick_budget_spent,
                )
                .await;
            }
            let has_expired: Option<i32> = match sqlx::query_scalar(REAP_HAS_EXPIRED_SQL)
                .bind(community)
                .bind(retention_secs)
                .fetch_optional(&mut *tx)
                .await
                .map_err(map_keyed_sqlx)
            {
                Ok(hit) => hit,
                Err(error) => {
                    let _ = tx.rollback().await;
                    return Err(error);
                }
            };
            if has_expired.is_some() {
                break community;
            }
            prev = Some(community);
            cold_probes = cold_probes.saturating_add(1);
            if cold_probes >= REAP_MAX_COLD_COMMUNITY_PROBES_PER_TX {
                return commit_reap_progress(
                    tx,
                    (scan_after, Some(community)),
                    0,
                    false,
                    wrapped,
                    false,
                    tick_budget_spent,
                )
                .await;
            }
        };
        let locked: bool = match sqlx::query_scalar(REAP_TRY_SHARED_DELETION_LOCK_SQL)
            .bind(community)
            .fetch_one(&mut *tx)
            .await
            .map_err(map_keyed_sqlx)
        {
            Ok(locked) => locked,
            Err(error) => {
                let _ = tx.rollback().await;
                return Err(error);
            }
        };
        if !locked {
            return commit_reap_progress(
                tx,
                (scan_after, Some(community)),
                0,
                false,
                wrapped,
                false,
                tick_budget_spent,
            )
            .await;
        }
        let allowed: bool = match sqlx::query_scalar(REAP_COMMUNITY_WRITE_ALLOWED_SQL)
            .bind(community)
            .fetch_one(&mut *tx)
            .await
            .map_err(map_keyed_sqlx)
        {
            Ok(allowed) => allowed,
            Err(error) => {
                let _ = tx.rollback().await;
                return Err(error);
            }
        };
        if !allowed {
            return commit_reap_progress(
                tx,
                (scan_after, Some(community)),
                0,
                false,
                wrapped,
                false,
                tick_budget_spent,
            )
            .await;
        }
        let done = match sqlx::query(REAP_EXPIRED_EVENT_IDEMPOTENCY_KEYS_SQL)
            .bind(community)
            .bind(retention_secs)
            .bind(batch_limit)
            .execute(&mut *tx)
            .await
            .map_err(map_keyed_sqlx)
        {
            Ok(done) => done,
            Err(error) => {
                let _ = tx.rollback().await;
                return Err(error);
            }
        };
        let took = done.rows_affected();
        let more_expired: Option<i32> = match sqlx::query_scalar(REAP_HAS_EXPIRED_SQL)
            .bind(community)
            .bind(retention_secs)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_keyed_sqlx)
        {
            Ok(hit) => hit,
            Err(error) => {
                let _ = tx.rollback().await;
                return Err(error);
            }
        };
        commit_reap_progress(
            tx,
            (scan_after, Some(community)),
            took,
            false,
            wrapped,
            more_expired.is_some(),
            tick_budget_spent,
        )
        .await
    }

    /// Load the singleton operator-global exclusive reaper cursor.
    pub async fn event_idempotency_reaper_cursor(&self) -> Result<Option<Uuid>> {
        sqlx::query_scalar(
            "SELECT after_community_id FROM event_idempotency_reaper_cursor WHERE id = 1",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_keyed_sqlx)
    }

    /// Fail closed at process start unless canonical NIP-MI catalog objects exist.
    ///
    /// Required columns are checked by name, ordinal, and properties. Extra
    /// columns are tolerated only when a legacy INSERT can omit them.
    pub async fn require_event_idempotency_schema(&self) -> Result<()> {
        let columns_ok: bool = sqlx::query_scalar(
            r#"
            SELECT
                EXISTS (
                    SELECT 1
                      FROM pg_attribute AS att
                      JOIN pg_class AS tbl ON tbl.oid = att.attrelid
                      JOIN pg_namespace AS ns ON ns.oid = tbl.relnamespace
                     WHERE ns.nspname = current_schema()
                       AND tbl.relname = 'event_idempotency_keys'
                       AND att.attnum = 1 AND NOT att.attisdropped
                       AND att.attname = 'community_id'
                       AND att.attnotnull
                       AND format_type(att.atttypid, att.atttypmod) = 'uuid'
                       AND att.attidentity = ''
                       AND att.attgenerated = ''
                       AND NOT EXISTS (
                            SELECT 1 FROM pg_attrdef AS def
                             WHERE def.adrelid = att.attrelid AND def.adnum = att.attnum
                       )
                )
                AND EXISTS (
                    SELECT 1
                      FROM pg_attribute AS att
                      JOIN pg_class AS tbl ON tbl.oid = att.attrelid
                      JOIN pg_namespace AS ns ON ns.oid = tbl.relnamespace
                     WHERE ns.nspname = current_schema()
                       AND tbl.relname = 'event_idempotency_keys'
                       AND att.attnum = 2 AND NOT att.attisdropped
                       AND att.attname = 'author_pubkey'
                       AND att.attnotnull
                       AND format_type(att.atttypid, att.atttypmod) = 'bytea'
                       AND att.attidentity = ''
                       AND att.attgenerated = ''
                       AND NOT EXISTS (
                            SELECT 1 FROM pg_attrdef AS def
                             WHERE def.adrelid = att.attrelid AND def.adnum = att.attnum
                       )
                )
                AND EXISTS (
                    SELECT 1
                      FROM pg_attribute AS att
                      JOIN pg_class AS tbl ON tbl.oid = att.attrelid
                      JOIN pg_namespace AS ns ON ns.oid = tbl.relnamespace
                     WHERE ns.nspname = current_schema()
                       AND tbl.relname = 'event_idempotency_keys'
                       AND att.attnum = 3 AND NOT att.attisdropped
                       AND att.attname = 'idempotency_key'
                       AND att.attnotnull
                       AND format_type(att.atttypid, att.atttypmod) = 'bytea'
                       AND att.attidentity = ''
                       AND att.attgenerated = ''
                       AND NOT EXISTS (
                            SELECT 1 FROM pg_attrdef AS def
                             WHERE def.adrelid = att.attrelid AND def.adnum = att.attnum
                       )
                )
                AND EXISTS (
                    SELECT 1
                      FROM pg_attribute AS att
                      JOIN pg_class AS tbl ON tbl.oid = att.attrelid
                      JOIN pg_namespace AS ns ON ns.oid = tbl.relnamespace
                     WHERE ns.nspname = current_schema()
                       AND tbl.relname = 'event_idempotency_keys'
                       AND att.attnum = 4 AND NOT att.attisdropped
                       AND att.attname = 'intent_hash'
                       AND att.attnotnull
                       AND format_type(att.atttypid, att.atttypmod) = 'bytea'
                       AND att.attidentity = ''
                       AND att.attgenerated = ''
                       AND NOT EXISTS (
                            SELECT 1 FROM pg_attrdef AS def
                             WHERE def.adrelid = att.attrelid AND def.adnum = att.attnum
                       )
                )
                AND EXISTS (
                    SELECT 1
                      FROM pg_attribute AS att
                      JOIN pg_class AS tbl ON tbl.oid = att.attrelid
                      JOIN pg_namespace AS ns ON ns.oid = tbl.relnamespace
                     WHERE ns.nspname = current_schema()
                       AND tbl.relname = 'event_idempotency_keys'
                       AND att.attnum = 5 AND NOT att.attisdropped
                       AND att.attname = 'event_id'
                       AND att.attnotnull
                       AND format_type(att.atttypid, att.atttypmod) = 'bytea'
                       AND att.attidentity = ''
                       AND att.attgenerated = ''
                       AND NOT EXISTS (
                            SELECT 1 FROM pg_attrdef AS def
                             WHERE def.adrelid = att.attrelid AND def.adnum = att.attnum
                       )
                )
                AND EXISTS (
                    SELECT 1
                      FROM pg_attribute AS att
                      JOIN pg_class AS tbl ON tbl.oid = att.attrelid
                      JOIN pg_namespace AS ns ON ns.oid = tbl.relnamespace
                      JOIN pg_attrdef AS def
                        ON def.adrelid = att.attrelid AND def.adnum = att.attnum
                     WHERE ns.nspname = current_schema()
                       AND tbl.relname = 'event_idempotency_keys'
                       AND att.attnum = 6 AND NOT att.attisdropped
                       AND att.attname = 'created_at'
                       AND att.attnotnull
                       AND format_type(att.atttypid, att.atttypmod)
                           = 'timestamp with time zone'
                       AND att.attidentity = ''
                       AND att.attgenerated = ''
                       AND pg_get_expr(def.adbin, def.adrelid) = 'clock_timestamp()'
                )
                AND EXISTS (
                    SELECT 1
                      FROM pg_attribute AS att
                      JOIN pg_class AS tbl ON tbl.oid = att.attrelid
                      JOIN pg_namespace AS ns ON ns.oid = tbl.relnamespace
                     WHERE ns.nspname = current_schema()
                       AND tbl.relname = 'event_idempotency_keys'
                       AND att.attnum = 7 AND NOT att.attisdropped
                       AND att.attname = 'reservation_witness'
                       AND att.attnotnull
                       AND format_type(att.atttypid, att.atttypmod) = 'bytea'
                       AND att.attidentity = ''
                       AND att.attgenerated = ''
                       AND NOT EXISTS (
                            SELECT 1 FROM pg_attrdef AS def
                             WHERE def.adrelid = att.attrelid AND def.adnum = att.attnum
                       )
                )
                AND (
                    SELECT count(*)
                      FROM pg_attribute AS att
                      JOIN pg_class AS tbl ON tbl.oid = att.attrelid
                      JOIN pg_namespace AS ns ON ns.oid = tbl.relnamespace
                     WHERE ns.nspname = current_schema()
                       AND tbl.relname = 'event_idempotency_keys'
                       AND att.attnum > 0
                       AND NOT att.attisdropped
                       AND att.attname IN (
                            'community_id',
                            'author_pubkey',
                            'idempotency_key',
                            'intent_hash',
                            'event_id',
                            'created_at',
                            'reservation_witness'
                       )
                ) = 7
            "#,
        )
        .fetch_one(&self.pool)
        .await?;
        if !columns_ok {
            return Err(DbError::InvalidData(
                "event_idempotency_keys columns or created_at default are invalid; refuse to start"
                    .into(),
            ));
        }

        let keys_column_names_unique: bool = sqlx::query_scalar(
            r#"
            SELECT NOT EXISTS (
                SELECT 1
                  FROM pg_attribute AS att
                  JOIN pg_class AS tbl ON tbl.oid = att.attrelid
                  JOIN pg_namespace AS ns ON ns.oid = tbl.relnamespace
                 WHERE ns.nspname = current_schema()
                   AND tbl.relname = 'event_idempotency_keys'
                   AND att.attnum > 0
                   AND NOT att.attisdropped
                 GROUP BY att.attname
                HAVING count(*) > 1
            )
            "#,
        )
        .fetch_one(&self.pool)
        .await?;
        if !keys_column_names_unique {
            return Err(DbError::InvalidData(
                "event_idempotency_keys has duplicate columns; refuse to start".into(),
            ));
        }

        let keys_extras_ok: bool = sqlx::query_scalar(
            r#"
            SELECT NOT EXISTS (
                SELECT 1
                  FROM pg_attribute AS att
                  JOIN pg_class AS tbl ON tbl.oid = att.attrelid
                  JOIN pg_namespace AS ns ON ns.oid = tbl.relnamespace
                 WHERE ns.nspname = current_schema()
                   AND tbl.relname = 'event_idempotency_keys'
                   AND att.attnum > 0
                   AND NOT att.attisdropped
                   AND att.attname <> ALL (ARRAY[
                        'community_id',
                        'author_pubkey',
                        'idempotency_key',
                        'intent_hash',
                        'event_id',
                        'created_at',
                        'reservation_witness'
                   ]::text[])
                   AND att.attnotnull
                   AND att.attidentity = ''
                   AND att.attgenerated = ''
                   AND NOT EXISTS (
                        SELECT 1
                          FROM pg_attrdef AS def
                         WHERE def.adrelid = att.attrelid
                           AND def.adnum = att.attnum
                           AND pg_get_expr(def.adbin, def.adrelid) IS NOT NULL
                           AND btrim(pg_get_expr(def.adbin, def.adrelid))
                               !~* '^NULL(::.*)?$'
                   )
            )
            "#,
        )
        .fetch_one(&self.pool)
        .await?;
        if !keys_extras_ok {
            return Err(DbError::InvalidData(
                "event_idempotency_keys has an extra NOT NULL column with no default, identity, or generated supplier; refuse to start"
                    .into(),
            ));
        }

        let uniqueness_ok: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1
                  FROM pg_class AS idx
                  JOIN pg_namespace AS idx_ns ON idx_ns.oid = idx.relnamespace
                  JOIN pg_index AS i ON i.indexrelid = idx.oid
                  JOIN pg_class AS tbl ON tbl.oid = i.indrelid
                  JOIN pg_namespace AS tbl_ns ON tbl_ns.oid = tbl.relnamespace
                 WHERE idx_ns.nspname = current_schema()
                   AND idx.relname = 'event_idempotency_keys_pkey'
                   AND tbl_ns.nspname = current_schema()
                   AND tbl.relname = 'event_idempotency_keys'
                   AND i.indisunique
                   AND i.indisvalid
                   AND i.indisready
                   AND i.indisprimary
                   AND i.indimmediate
                   AND i.indpred IS NULL
                   AND i.indexprs IS NULL
                   AND i.indnkeyatts = 3
                   AND i.indnatts = 3
                   AND (
                        SELECT array_agg(att.attname::text ORDER BY k.ordinality)
                          FROM unnest(i.indkey) WITH ORDINALITY AS k(attnum, ordinality)
                          JOIN pg_attribute AS att
                            ON att.attrelid = tbl.oid AND att.attnum = k.attnum
                   ) = ARRAY['community_id','author_pubkey','idempotency_key']::text[]
            )
            "#,
        )
        .fetch_one(&self.pool)
        .await?;
        if !uniqueness_ok {
            return Err(DbError::InvalidData(
                "event_idempotency_keys_pkey is missing or invalid; refuse to start".into(),
            ));
        }

        let pk_ok: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1
                  FROM pg_constraint AS c
                  JOIN pg_class AS t ON t.oid = c.conrelid
                  JOIN pg_namespace AS n ON n.oid = t.relnamespace
                 WHERE n.nspname = current_schema()
                   AND t.relname = 'event_idempotency_keys'
                   AND c.conname = 'event_idempotency_keys_pkey'
                   AND c.contype = 'p'
                   AND c.convalidated
                   AND (
                        SELECT array_agg(att.attname::text ORDER BY k.ordinality)
                          FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum, ordinality)
                          JOIN pg_attribute AS att
                            ON att.attrelid = t.oid AND att.attnum = k.attnum
                   ) = ARRAY['community_id','author_pubkey','idempotency_key']::text[]
            )
            "#,
        )
        .fetch_one(&self.pool)
        .await?;
        if !pk_ok {
            return Err(DbError::InvalidData(
                "event_idempotency_keys_pkey constraint is missing or invalid; refuse to start"
                    .into(),
            ));
        }

        let covering_ok: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1
                  FROM pg_class AS idx
                  JOIN pg_namespace AS idx_ns ON idx_ns.oid = idx.relnamespace
                  JOIN pg_index AS i ON i.indexrelid = idx.oid
                  JOIN pg_class AS tbl ON tbl.oid = i.indrelid
                  JOIN pg_namespace AS tbl_ns ON tbl_ns.oid = tbl.relnamespace
                 WHERE idx_ns.nspname = current_schema()
                   AND idx.relname = 'idx_event_idempotency_keys_created_at'
                   AND tbl_ns.nspname = current_schema()
                   AND tbl.relname = 'event_idempotency_keys'
                   AND i.indisvalid
                   AND i.indisready
                   AND i.indpred IS NULL
                   AND i.indexprs IS NULL
                   AND i.indnkeyatts = 4
                   AND i.indnatts = 4
                   AND (
                        SELECT array_agg(att.attname::text ORDER BY k.ordinality)
                          FROM unnest(i.indkey) WITH ORDINALITY AS k(attnum, ordinality)
                          JOIN pg_attribute AS att
                            ON att.attrelid = tbl.oid AND att.attnum = k.attnum
                   ) = ARRAY['created_at','community_id','author_pubkey','idempotency_key']::text[]
            )
            "#,
        )
        .fetch_one(&self.pool)
        .await?;
        if !covering_ok {
            return Err(DbError::InvalidData(
                "idx_event_idempotency_keys_created_at is missing or invalid; refuse to start"
                    .into(),
            ));
        }

        let community_created_ok: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1
                  FROM pg_class AS idx
                  JOIN pg_namespace AS idx_ns ON idx_ns.oid = idx.relnamespace
                  JOIN pg_index AS i ON i.indexrelid = idx.oid
                  JOIN pg_class AS tbl ON tbl.oid = i.indrelid
                  JOIN pg_namespace AS tbl_ns ON tbl_ns.oid = tbl.relnamespace
                 WHERE idx_ns.nspname = current_schema()
                   AND idx.relname = 'idx_event_idempotency_keys_community_created_at'
                   AND tbl_ns.nspname = current_schema()
                   AND tbl.relname = 'event_idempotency_keys'
                   AND i.indisvalid
                   AND i.indisready
                   AND i.indpred IS NULL
                   AND i.indexprs IS NULL
                   AND i.indnkeyatts = 4
                   AND i.indnatts = 4
                   AND (
                        SELECT array_agg(att.attname::text ORDER BY k.ordinality)
                          FROM unnest(i.indkey) WITH ORDINALITY AS k(attnum, ordinality)
                          JOIN pg_attribute AS att
                            ON att.attrelid = tbl.oid AND att.attnum = k.attnum
                   ) = ARRAY['community_id','created_at','author_pubkey','idempotency_key']::text[]
            )
            "#,
        )
        .fetch_one(&self.pool)
        .await?;
        if !community_created_ok {
            return Err(DbError::InvalidData(
                "idx_event_idempotency_keys_community_created_at is missing or invalid; refuse to start"
                    .into(),
            ));
        }

        let checks_ok: bool = sqlx::query_scalar(
            r#"
            SELECT
                EXISTS (
                    SELECT 1 FROM pg_constraint AS c
                    JOIN pg_class AS t ON t.oid = c.conrelid
                    JOIN pg_namespace AS n ON n.oid = t.relnamespace
                    JOIN pg_attribute AS att
                      ON att.attrelid = t.oid AND att.attnum = c.conkey[1]
                    WHERE n.nspname = current_schema()
                      AND t.relname = 'event_idempotency_keys'
                      AND c.conname = 'event_idempotency_keys_author_pubkey_check'
                      AND c.contype = 'c' AND c.convalidated
                      AND cardinality(c.conkey) = 1 AND att.attname = 'author_pubkey'
                      AND pg_get_expr(c.conbin, c.conrelid)
                          = '(octet_length(author_pubkey) = 32)'
                )
                AND EXISTS (
                    SELECT 1 FROM pg_constraint AS c
                    JOIN pg_class AS t ON t.oid = c.conrelid
                    JOIN pg_namespace AS n ON n.oid = t.relnamespace
                    JOIN pg_attribute AS att
                      ON att.attrelid = t.oid AND att.attnum = c.conkey[1]
                    WHERE n.nspname = current_schema()
                      AND t.relname = 'event_idempotency_keys'
                      AND c.conname = 'event_idempotency_keys_idempotency_key_check'
                      AND c.contype = 'c' AND c.convalidated
                      AND cardinality(c.conkey) = 1 AND att.attname = 'idempotency_key'
                      AND pg_get_expr(c.conbin, c.conrelid)
                          = '(octet_length(idempotency_key) = 32)'
                )
                AND EXISTS (
                    SELECT 1 FROM pg_constraint AS c
                    JOIN pg_class AS t ON t.oid = c.conrelid
                    JOIN pg_namespace AS n ON n.oid = t.relnamespace
                    JOIN pg_attribute AS att
                      ON att.attrelid = t.oid AND att.attnum = c.conkey[1]
                    WHERE n.nspname = current_schema()
                      AND t.relname = 'event_idempotency_keys'
                      AND c.conname = 'event_idempotency_keys_intent_hash_check'
                      AND c.contype = 'c' AND c.convalidated
                      AND cardinality(c.conkey) = 1 AND att.attname = 'intent_hash'
                      AND pg_get_expr(c.conbin, c.conrelid)
                          = '(octet_length(intent_hash) = 32)'
                )
                AND EXISTS (
                    SELECT 1 FROM pg_constraint AS c
                    JOIN pg_class AS t ON t.oid = c.conrelid
                    JOIN pg_namespace AS n ON n.oid = t.relnamespace
                    JOIN pg_attribute AS att
                      ON att.attrelid = t.oid AND att.attnum = c.conkey[1]
                    WHERE n.nspname = current_schema()
                      AND t.relname = 'event_idempotency_keys'
                      AND c.conname = 'event_idempotency_keys_event_id_check'
                      AND c.contype = 'c' AND c.convalidated
                      AND cardinality(c.conkey) = 1 AND att.attname = 'event_id'
                      AND pg_get_expr(c.conbin, c.conrelid)
                          = '(octet_length(event_id) = 32)'
                )
                AND EXISTS (
                    SELECT 1 FROM pg_constraint AS c
                    JOIN pg_class AS t ON t.oid = c.conrelid
                    JOIN pg_namespace AS n ON n.oid = t.relnamespace
                    JOIN pg_attribute AS att
                      ON att.attrelid = t.oid AND att.attnum = c.conkey[1]
                    WHERE n.nspname = current_schema()
                      AND t.relname = 'event_idempotency_keys'
                      AND c.conname = 'event_idempotency_keys_reservation_witness_check'
                      AND c.contype = 'c' AND c.convalidated
                      AND cardinality(c.conkey) = 1 AND att.attname = 'reservation_witness'
                      AND pg_get_expr(c.conbin, c.conrelid)
                          = '(octet_length(reservation_witness) = 32)'
                )
            "#,
        )
        .fetch_one(&self.pool)
        .await?;
        if !checks_ok {
            return Err(DbError::InvalidData(
                "event_idempotency_keys octet_length CHECKs are missing or invalid; refuse to start"
                    .into(),
            ));
        }

        let fk_ok: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1
                  FROM pg_constraint AS c
                  JOIN pg_class AS src ON src.oid = c.conrelid
                  JOIN pg_namespace AS src_ns ON src_ns.oid = src.relnamespace
                  JOIN pg_class AS dst ON dst.oid = c.confrelid
                  JOIN pg_namespace AS dst_ns ON dst_ns.oid = dst.relnamespace
                 WHERE src_ns.nspname = current_schema()
                   AND src.relname = 'event_idempotency_keys'
                   AND c.conname = 'event_idempotency_keys_community_id_fkey'
                   AND dst_ns.nspname = current_schema()
                   AND dst.relname = 'communities'
                   AND c.contype = 'f'
                   AND c.convalidated
                   AND c.confupdtype = 'a'
                   AND c.confdeltype = 'a'
                   AND NOT c.condeferrable
                   AND (
                        SELECT array_agg(att.attname::text ORDER BY k.ordinality)
                          FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum, ordinality)
                          JOIN pg_attribute AS att
                            ON att.attrelid = src.oid AND att.attnum = k.attnum
                   ) = ARRAY['community_id']::text[]
                   AND (
                        SELECT array_agg(att.attname::text ORDER BY k.ordinality)
                          FROM unnest(c.confkey) WITH ORDINALITY AS k(attnum, ordinality)
                          JOIN pg_attribute AS att
                            ON att.attrelid = dst.oid AND att.attnum = k.attnum
                   ) = ARRAY['id']::text[]
            )
            "#,
        )
        .fetch_one(&self.pool)
        .await?;
        if !fk_ok {
            return Err(DbError::InvalidData(
                "event_idempotency_keys_community_id_fkey is missing or invalid; refuse to start"
                    .into(),
            ));
        }

        let trigger_ok: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1
                  FROM pg_trigger AS tg
                  JOIN pg_class AS tbl ON tbl.oid = tg.tgrelid
                  JOIN pg_namespace AS tbl_ns ON tbl_ns.oid = tbl.relnamespace
                  JOIN pg_proc AS fn ON fn.oid = tg.tgfoid
                  JOIN pg_namespace AS fn_ns ON fn_ns.oid = fn.pronamespace
                  JOIN pg_language AS lang ON lang.oid = fn.prolang
                 WHERE tbl_ns.nspname = current_schema()
                   AND tbl.relname = 'event_idempotency_keys'
                   AND tg.tgname = 'event_idempotency_keys_immutable'
                   AND NOT tg.tgisinternal
                   AND tg.tgenabled IN ('O', 'A')
                   AND tg.tgtype::integer = 19
                   AND cardinality(tg.tgattr) = 0
                   AND tg.tgnargs = 0
                   AND tg.tgqual IS NULL
                   AND fn_ns.nspname = current_schema()
                   AND fn.proname = 'prevent_event_idempotency_keys_update'
                   AND fn.prokind = 'f'
                   AND NOT fn.prosecdef
                   AND fn.pronargs = 0
                   AND pg_get_function_identity_arguments(fn.oid) = ''
                   AND fn.prorettype = 'trigger'::regtype
                   AND lang.lanname = 'plpgsql'
                   AND btrim(regexp_replace(fn.prosrc, E'\\s+', ' ', 'g'))
                       = 'BEGIN RAISE EXCEPTION ''event_idempotency_keys rows are immutable'' USING ERRCODE = ''integrity_constraint_violation''; END;'
            )
            "#,
        )
        .fetch_one(&self.pool)
        .await?;
        if !trigger_ok {
            return Err(DbError::InvalidData(
                "event_idempotency_keys_immutable is missing or invalid; refuse to start".into(),
            ));
        }

        let cursor_columns_ok: bool = sqlx::query_scalar(
            r#"
            SELECT
                EXISTS (
                    SELECT 1
                      FROM pg_attribute AS att
                      JOIN pg_class AS tbl ON tbl.oid = att.attrelid
                      JOIN pg_namespace AS ns ON ns.oid = tbl.relnamespace
                     WHERE ns.nspname = current_schema()
                       AND tbl.relname = 'event_idempotency_reaper_cursor'
                       AND att.attnum = 1 AND NOT att.attisdropped
                       AND att.attname = 'id'
                       AND att.attnotnull
                       AND format_type(att.atttypid, att.atttypmod) = 'smallint'
                       AND att.attidentity = ''
                       AND att.attgenerated = ''
                )
                AND EXISTS (
                    SELECT 1
                      FROM pg_attribute AS att
                      JOIN pg_class AS tbl ON tbl.oid = att.attrelid
                      JOIN pg_namespace AS ns ON ns.oid = tbl.relnamespace
                     WHERE ns.nspname = current_schema()
                       AND tbl.relname = 'event_idempotency_reaper_cursor'
                       AND att.attnum = 2 AND NOT att.attisdropped
                       AND att.attname = 'after_community_id'
                       AND NOT att.attnotnull
                       AND format_type(att.atttypid, att.atttypmod) = 'uuid'
                       AND att.attidentity = ''
                       AND att.attgenerated = ''
                )
                AND (
                    SELECT count(*)
                      FROM pg_attribute AS att
                      JOIN pg_class AS tbl ON tbl.oid = att.attrelid
                      JOIN pg_namespace AS ns ON ns.oid = tbl.relnamespace
                     WHERE ns.nspname = current_schema()
                       AND tbl.relname = 'event_idempotency_reaper_cursor'
                       AND att.attnum > 0
                       AND NOT att.attisdropped
                       AND att.attname IN ('id', 'after_community_id')
                ) = 2
            "#,
        )
        .fetch_one(&self.pool)
        .await?;
        if !cursor_columns_ok {
            return Err(DbError::InvalidData(
                "event_idempotency_reaper_cursor columns are missing or incompatible; refuse to start"
                    .into(),
            ));
        }

        let cursor_column_names_unique: bool = sqlx::query_scalar(
            r#"
            SELECT NOT EXISTS (
                SELECT 1
                  FROM pg_attribute AS att
                  JOIN pg_class AS tbl ON tbl.oid = att.attrelid
                  JOIN pg_namespace AS ns ON ns.oid = tbl.relnamespace
                 WHERE ns.nspname = current_schema()
                   AND tbl.relname = 'event_idempotency_reaper_cursor'
                   AND att.attnum > 0
                   AND NOT att.attisdropped
                 GROUP BY att.attname
                HAVING count(*) > 1
            )
            "#,
        )
        .fetch_one(&self.pool)
        .await?;
        if !cursor_column_names_unique {
            return Err(DbError::InvalidData(
                "event_idempotency_reaper_cursor has duplicate columns; refuse to start".into(),
            ));
        }

        let cursor_community_id_absent: bool = sqlx::query_scalar(
            r#"
            SELECT NOT EXISTS (
                SELECT 1
                  FROM pg_attribute AS att
                  JOIN pg_class AS tbl ON tbl.oid = att.attrelid
                  JOIN pg_namespace AS ns ON ns.oid = tbl.relnamespace
                 WHERE ns.nspname = current_schema()
                   AND tbl.relname = 'event_idempotency_reaper_cursor'
                   AND att.attnum > 0
                   AND NOT att.attisdropped
                   AND att.attname = 'community_id'
            )
            "#,
        )
        .fetch_one(&self.pool)
        .await?;
        if !cursor_community_id_absent {
            return Err(DbError::InvalidData(
                "event_idempotency_reaper_cursor must not carry community_id; refuse to start"
                    .into(),
            ));
        }

        let cursor_extras_ok: bool = sqlx::query_scalar(
            r#"
            SELECT NOT EXISTS (
                SELECT 1
                  FROM pg_attribute AS att
                  JOIN pg_class AS tbl ON tbl.oid = att.attrelid
                  JOIN pg_namespace AS ns ON ns.oid = tbl.relnamespace
                 WHERE ns.nspname = current_schema()
                   AND tbl.relname = 'event_idempotency_reaper_cursor'
                   AND att.attnum > 0
                   AND NOT att.attisdropped
                   AND att.attname <> ALL (ARRAY['id', 'after_community_id']::text[])
                   AND att.attnotnull
                   AND att.attidentity = ''
                   AND att.attgenerated = ''
                   AND NOT EXISTS (
                        SELECT 1
                          FROM pg_attrdef AS def
                         WHERE def.adrelid = att.attrelid
                           AND def.adnum = att.attnum
                           AND pg_get_expr(def.adbin, def.adrelid) IS NOT NULL
                           AND btrim(pg_get_expr(def.adbin, def.adrelid))
                               !~* '^NULL(::.*)?$'
                   )
            )
            "#,
        )
        .fetch_one(&self.pool)
        .await?;
        if !cursor_extras_ok {
            return Err(DbError::InvalidData(
                "event_idempotency_reaper_cursor has an extra NOT NULL column with no default, identity, or generated supplier; refuse to start"
                    .into(),
            ));
        }

        let cursor_ok: bool = sqlx::query_scalar(
            r#"
            SELECT
                EXISTS (
                    SELECT 1
                      FROM pg_constraint AS c
                      JOIN pg_class AS t ON t.oid = c.conrelid
                      JOIN pg_namespace AS n ON n.oid = t.relnamespace
                     WHERE n.nspname = current_schema()
                       AND t.relname = 'event_idempotency_reaper_cursor'
                       AND c.contype = 'p'
                       AND c.convalidated
                       AND (
                            SELECT array_agg(att.attname::text ORDER BY k.ordinality)
                              FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum, ordinality)
                              JOIN pg_attribute AS att
                                ON att.attrelid = t.oid AND att.attnum = k.attnum
                       ) = ARRAY['id']::text[]
                )
                AND EXISTS (
                    SELECT 1
                      FROM pg_constraint AS c
                      JOIN pg_class AS t ON t.oid = c.conrelid
                      JOIN pg_namespace AS n ON n.oid = t.relnamespace
                     WHERE n.nspname = current_schema()
                       AND t.relname = 'event_idempotency_reaper_cursor'
                       AND c.contype = 'c'
                       AND c.convalidated
                       AND pg_get_expr(c.conbin, c.conrelid) = '(id = 1)'
                )
                AND NOT EXISTS (
                    SELECT 1
                      FROM pg_trigger AS tg
                      JOIN pg_class AS tbl ON tbl.oid = tg.tgrelid
                      JOIN pg_namespace AS ns ON ns.oid = tbl.relnamespace
                     WHERE ns.nspname = current_schema()
                       AND tbl.relname = 'event_idempotency_reaper_cursor'
                       AND NOT tg.tgisinternal
                )
                AND (SELECT count(*) FROM event_idempotency_reaper_cursor WHERE id = 1) = 1
                AND has_table_privilege(
                    current_user,
                    'event_idempotency_reaper_cursor'::regclass,
                    'SELECT'
                )
                AND has_table_privilege(
                    current_user,
                    'event_idempotency_reaper_cursor'::regclass,
                    'UPDATE'
                )
                AND EXISTS (
                    SELECT 1
                      FROM _operator_global_tables
                     WHERE table_name = 'event_idempotency_reaper_cursor'
                )
            "#,
        )
        .fetch_one(&self.pool)
        .await?;
        if !cursor_ok {
            return Err(DbError::InvalidData(
                "event_idempotency_reaper_cursor singleton, privileges, or registry are invalid; refuse to start"
                    .into(),
            ));
        }
        Ok(())
    }
}

enum KeyedClassify {
    Reserved,
    Replay { original_event_id: [u8; 32] },
    Conflict { existing_event_id: [u8; 32] },
}

fn classify_stored_keyed_hashes(
    stored_hash: &[u8],
    stored_event_id: &[u8],
    intent_hash: &[u8; 32],
) -> Result<KeyedClassify> {
    let stored_hash_arr = copy_32(stored_hash)?;
    let stored_id_arr = copy_32(stored_event_id)?;
    if fixed_32_eq(&stored_hash_arr, intent_hash) {
        Ok(KeyedClassify::Replay {
            original_event_id: stored_id_arr,
        })
    } else {
        Ok(KeyedClassify::Conflict {
            existing_event_id: stored_id_arr,
        })
    }
}

fn keyed_classify_replay_or_conflict(classify: KeyedClassify) -> Result<KeyedCommittedOutcome> {
    match classify {
        KeyedClassify::Replay { original_event_id } => {
            Ok(KeyedCommittedOutcome::Replay { original_event_id })
        }
        KeyedClassify::Conflict { existing_event_id } => {
            Ok(KeyedCommittedOutcome::Conflict { existing_event_id })
        }
        KeyedClassify::Reserved => Err(DbError::idempotency_unavailable()),
    }
}

/// Read-only committed primary-key precheck. Uncommitted reservations are
/// invisible here and must fall through to [`reserve_or_classify_in_tx`].
async fn classify_committed_keyed_row(
    pool: &sqlx::PgPool,
    community_id: CommunityId,
    author: [u8; 32],
    key: [u8; 32],
    intent_hash: [u8; 32],
) -> Result<Option<KeyedCommittedOutcome>> {
    let mut connection = crate::observability::acquire_writer(
        pool,
        crate::observability::WriterOperation::EventWrite,
    )
    .await
    .map_err(map_keyed_sqlx)?;
    let existing: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
        r#"
            SELECT intent_hash, event_id
              FROM event_idempotency_keys
             WHERE community_id = $1
               AND author_pubkey = $2
               AND idempotency_key = $3
            "#,
    )
    .bind(community_id.as_uuid())
    .bind(author.as_slice())
    .bind(key.as_slice())
    .fetch_optional(&mut *connection)
    .await
    .map_err(map_keyed_sqlx)?;
    let Some((stored_hash, stored_event_id)) = existing else {
        return Ok(None);
    };
    keyed_classify_replay_or_conflict(classify_stored_keyed_hashes(
        &stored_hash,
        &stored_event_id,
        &intent_hash,
    )?)
    .map(Some)
}

async fn reserve_or_classify_in_tx(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    community_id: CommunityId,
    author: [u8; 32],
    key: [u8; 32],
    intent_hash: [u8; 32],
    event_id: [u8; 32],
    witness: [u8; 32],
) -> Result<KeyedClassify> {
    let mut reserved: Option<(Vec<u8>, Vec<u8>)> = None;
    for _ in 0..8 {
        reserved = sqlx::query_as(
            r#"
            INSERT INTO event_idempotency_keys (
                community_id, author_pubkey, idempotency_key, intent_hash, event_id, created_at,
                reservation_witness
            ) VALUES ($1, $2, $3, $4, $5, clock_timestamp(), $6)
            ON CONFLICT (community_id, author_pubkey, idempotency_key) DO NOTHING
            RETURNING intent_hash, event_id
            "#,
        )
        .bind(community_id.as_uuid())
        .bind(author.as_slice())
        .bind(key.as_slice())
        .bind(intent_hash.as_slice())
        .bind(event_id.as_slice())
        .bind(witness.as_slice())
        .fetch_optional(&mut **tx)
        .await
        .map_err(map_keyed_sqlx)?;
        if reserved.is_some() {
            break;
        }
        let existing: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            r#"
            SELECT intent_hash, event_id
              FROM event_idempotency_keys
             WHERE community_id = $1
               AND author_pubkey = $2
               AND idempotency_key = $3
             FOR UPDATE
            "#,
        )
        .bind(community_id.as_uuid())
        .bind(author.as_slice())
        .bind(key.as_slice())
        .fetch_optional(&mut **tx)
        .await
        .map_err(map_keyed_sqlx)?;
        if let Some((stored_hash, stored_event_id)) = existing {
            return classify_stored_keyed_hashes(&stored_hash, &stored_event_id, &intent_hash);
        }
    }
    if reserved.is_none() {
        return Err(DbError::idempotency_unavailable());
    }
    Ok(KeyedClassify::Reserved)
}

async fn persist_reserved_event_in_tx(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    community_id: CommunityId,
    event: &Event,
    channel_id: Option<Uuid>,
    thread_meta: Option<ThreadMetadataParams<'_>>,
    event_id: [u8; 32],
) -> Result<KeyedStreamInsert> {
    let (stored, was_inserted) =
        insert_event_with_thread_metadata_tx(tx, community_id, event, channel_id, thread_meta)
            .await
            .map_err(|error| match error {
                DbError::Sqlx(sqlx_error) => map_keyed_sqlx(sqlx_error),
                other => other,
            })?;
    if was_inserted {
        insert_mentions_in_transaction(tx, community_id, event, channel_id)
            .await
            .map_err(|error| match error {
                DbError::Sqlx(sqlx_error) => map_keyed_sqlx(sqlx_error),
                other => other,
            })?;
        Ok(KeyedStreamInsert::Inserted {
            stored_event: Box::new(stored),
        })
    } else {
        Ok(KeyedStreamInsert::BoundExisting { event_id })
    }
}

#[cfg(test)]
mod postgres_tests {
    use super::*;
    use crate::deletion::{EXPECTED_SCOPED_TABLES, PURGE_SCOPED_TABLES};
    use crate::event::{insert_event_with_thread_metadata, ThreadMetadataParams};
    use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp};
    use sqlx::postgres::PgPoolOptions;
    use sqlx::PgPool;

    impl Db {
        async fn begin_keyed_stream_reservation_for_event(
            &self,
            community_id: CommunityId,
            author: [u8; 32],
            key: [u8; 32],
            event: &Event,
            channel_id: Option<Uuid>,
            thread_meta: Option<&ThreadMetadataParams<'_>>,
        ) -> Result<KeyedReserveOutcome> {
            if !fixed_32_eq(&author, &event.pubkey.to_bytes()) {
                return Err(DbError::idempotency_author_mismatch());
            }
            let prepared = Self::prepare_keyed_stream_intent(key, event)?;
            Db::begin_keyed_stream_reservation(
                self,
                community_id,
                &prepared,
                event,
                channel_id,
                thread_meta,
            )
            .await
        }

        async fn classify_keyed_stream_before_admission_for_event(
            &self,
            community_id: CommunityId,
            author: [u8; 32],
            key: [u8; 32],
            event: &Event,
            channel_id: Option<Uuid>,
            thread_meta: Option<&ThreadMetadataParams<'_>>,
        ) -> Result<Option<KeyedCommittedOutcome>> {
            if !fixed_32_eq(&author, &event.pubkey.to_bytes()) {
                return Err(DbError::idempotency_author_mismatch());
            }
            let prepared = Self::prepare_keyed_stream_intent(key, event)?;
            Db::classify_keyed_stream_before_admission(
                self,
                community_id,
                &prepared,
                event,
                channel_id,
                thread_meta,
            )
            .await
        }
    }

    impl KeyedReservation {
        async fn complete_for_event(
            self,
            event: &Event,
            thread_meta: Option<ThreadMetadataParams<'_>>,
        ) -> Result<KeyedStreamInsert> {
            let prepared = self.prepared;
            KeyedReservation::complete(self, &prepared, event, thread_meta).await
        }
    }

    async fn setup_pool() -> PgPool {
        PgPool::connect(&crate::test_support::database_url())
            .await
            .expect("connect to test DB")
    }

    async fn make_test_community(pool: &PgPool) -> Uuid {
        let id = Uuid::new_v4();
        let host = format!("idempotency-test-{}.example", id.simple());
        sqlx::query("INSERT INTO communities (id, host) VALUES ($1, $2)")
            .bind(id)
            .bind(host)
            .execute(pool)
            .await
            .expect("insert test community");
        id
    }

    async fn make_test_channel(pool: &PgPool, community_id: Uuid) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO channels (id, community_id, name, created_by) VALUES ($1, $2, $3, $4)",
        )
        .bind(id)
        .bind(community_id)
        .bind(format!("idempotency-{}", id.simple()))
        .bind(vec![7_u8; 32])
        .execute(pool)
        .await
        .expect("insert test channel");
        id
    }

    fn stream_event(keys: &Keys, content: &str, created_at: u64, extra_tags: Vec<Tag>) -> Event {
        EventBuilder::new(Kind::Custom(9), content)
            .tags(extra_tags)
            .custom_created_at(Timestamp::from(created_at))
            .sign_with_keys(keys)
            .expect("sign")
    }

    fn bound_meta<'a>(event: &'a Event, channel_id: Uuid) -> ThreadMetadataParams<'a> {
        ThreadMetadataParams {
            event_id: event.id.as_bytes(),
            event_created_at: event_created_at(event).expect("chrono timestamp"),
            channel_id,
            parent_event_id: None,
            parent_event_created_at: None,
            root_event_id: None,
            root_event_created_at: None,
            depth: 0,
            broadcast: false,
        }
    }

    fn key_n(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn mention_hex(n: u16) -> String {
        format!("{n:064x}")
    }

    async fn key_count(pool: &PgPool, community: Uuid) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM event_idempotency_keys WHERE community_id = $1")
            .bind(community)
            .fetch_one(pool)
            .await
            .expect("count keys")
    }

    async fn event_count(pool: &PgPool, community: Uuid) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM events WHERE community_id = $1")
            .bind(community)
            .fetch_one(pool)
            .await
            .expect("count events")
    }

    async fn mention_pubkeys(pool: &PgPool, community: Uuid, event_id: &[u8]) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT pubkey_hex FROM event_mentions \
             WHERE community_id = $1 AND event_id = $2 \
             ORDER BY pubkey_hex",
        )
        .bind(community)
        .bind(event_id)
        .fetch_all(pool)
        .await
        .expect("list mentions")
    }

    async fn mention_count(pool: &PgPool, community: Uuid) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM event_mentions WHERE community_id = $1")
            .bind(community)
            .fetch_one(pool)
            .await
            .expect("count mentions")
    }

    async fn install_community_mention_insert_failure(
        pool: &PgPool,
        community: Uuid,
    ) -> (String, String) {
        let suffix = community.simple().to_string();
        let fn_name = format!("buzz_fail_mentions_{suffix}");
        let trig_name = format!("buzz_fail_mentions_{suffix}");
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE FUNCTION {fn_name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced mention insertion failure' USING ERRCODE = 'integrity_constraint_violation'; END; $$"
        )))
        .execute(pool)
        .await
        .expect("create mention-fail function");
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE TRIGGER {trig_name} BEFORE INSERT ON event_mentions FOR EACH ROW WHEN (NEW.community_id = '{community}') EXECUTE FUNCTION {fn_name}()"
        )))
        .execute(pool)
        .await
        .expect("create mention-fail trigger");
        (fn_name, trig_name)
    }

    async fn uninstall_community_mention_insert_failure(
        pool: &PgPool,
        trig_name: &str,
        fn_name: &str,
    ) {
        let _ = sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP TRIGGER IF EXISTS {trig_name} ON event_mentions"
        )))
        .execute(pool)
        .await;
        let _ = sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP FUNCTION IF EXISTS {fn_name}()"
        )))
        .execute(pool)
        .await;
    }

    #[test]
    fn fixed_32_eq_equal_first_byte_and_last_byte() {
        let base = [7u8; 32];
        assert!(fixed_32_eq(&base, &base));
        let mut first = base;
        first[0] ^= 1;
        assert!(!fixed_32_eq(&base, &first));
        let mut last = base;
        last[31] ^= 1;
        assert!(!fixed_32_eq(&base, &last));
    }

    #[test]
    fn keyed_busy_telemetry_distinguishes_classes_without_sql_text() {
        let pool = keyed_sqlx_busy(&sqlx::Error::PoolTimedOut).expect("pool timeout");
        assert_eq!(pool.class, "pool_timeout");
        assert_eq!(pool.sqlstate, None);
        let lock = keyed_busy_sqlstate(Some("55P03")).expect("lock");
        assert_eq!(lock.class, "lock_not_available");
        assert_eq!(lock.sqlstate, Some("55P03"));
        let canceled = keyed_busy_sqlstate(Some("57014")).expect("canceled");
        assert_eq!(canceled.class, "statement_canceled");
        assert_eq!(canceled.sqlstate, Some("57014"));
        let idle = keyed_busy_sqlstate(Some("25P03")).expect("idle in transaction");
        assert_eq!(idle.class, "idle_in_transaction_timeout");
        assert_eq!(idle.sqlstate, Some("25P03"));
        assert!(keyed_busy_sqlstate(Some("40P01")).is_none());
        assert!(keyed_busy_sqlstate(Some("57P01")).is_none());
        assert!(keyed_busy_sqlstate(None).is_none());
        assert!(
            keyed_sqlx_busy(&sqlx::Error::Io(std::io::Error::from(
                std::io::ErrorKind::ConnectionReset
            )))
            .is_none(),
            "closed-connection Io is not uniquely idle-timeout; SQLSTATE 25P03 is the mapping"
        );
        let mapped = map_keyed_sqlx(sqlx::Error::PoolTimedOut);
        assert!(mapped.is_idempotency_unavailable());
        let rendered = mapped.to_string();
        assert!(
            rendered.contains("idempotency writer is busy"),
            "busy mapping must keep the public InvalidData text, got {rendered}"
        );
        assert!(
            !rendered.contains("PoolTimedOut")
                && !rendered.contains("55P03")
                && !rendered.contains("25P03"),
            "client mapping must stay opaque, got {rendered}"
        );
    }

    #[test]
    fn idle_in_transaction_sqlstate_maps_to_keyed_busy() {
        let idle = keyed_busy_sqlstate(Some("25P03")).expect("25P03");
        assert_eq!(idle.sqlstate, Some("25P03"));
        assert_eq!(idle.class, "idle_in_transaction_timeout");
        assert!(
            keyed_busy_sqlstate(Some("25P02")).is_none(),
            "in_failed_sql_transaction is not an idle-timeout busy class"
        );
        // `sqlx::Error::Database` cannot be constructed without a live
        // `PgDatabaseError`. `keyed_sqlx_busy` routes Database codes through
        // `keyed_busy_sqlstate`, so 25P03 is the same busy class
        // `map_keyed_sqlx` already applies to PoolTimedOut / 55P03 / 57014.
        assert!(
            keyed_sqlx_busy(&sqlx::Error::Io(std::io::Error::from(
                std::io::ErrorKind::BrokenPipe
            )))
            .is_none(),
            "Io closed-connection is not mapped; SQLSTATE 25P03 is the supported form"
        );
    }

    #[test]
    fn commit_recovery_lookup_timeout_is_bounded_and_independent() {
        const {
            assert!(KEYED_COMMIT_RECOVERY_LOOKUP_TIMEOUT_SECS > 0);
            assert!(KEYED_RESERVATION_STATEMENT_TIMEOUT_SECS > 0);
            assert!(
                KEYED_RESERVATION_IDLE_TIMEOUT_SECS <= KEYED_RESERVATION_STATEMENT_TIMEOUT_SECS
            );
        }
        assert_eq!(KEYED_COMMIT_RECOVERY_LOOKUP_TIMEOUT_SECS, 15);
        assert_eq!(KEYED_RESERVATION_STATEMENT_TIMEOUT_SECS, 15);
        assert_ne!(
            KEYED_COMMIT_RECOVERY_LOOKUP_TIMEOUT_SECS, 0,
            "recovery lookup must stay bounded"
        );
        // Numeric equality with the writer statement timeout is allowed;
        // recovery is still a later, separately named phase so a caller
        // deadline of one statement bound cannot stand in for both.
        const {
            assert!(
                KEYED_RESERVATION_STATEMENT_TIMEOUT_SECS
                    + KEYED_COMMIT_RECOVERY_LOOKUP_TIMEOUT_SECS
                    > KEYED_RESERVATION_STATEMENT_TIMEOUT_SECS
            );
        }
    }

    #[test]
    fn keyed_reservation_timeout_sql_is_mechanically_canonical() {
        let sql = keyed_reservation_timeout_sql();
        assert_eq!(sql[0], KEYED_LOCK_TIMEOUT_SQL);
        assert_eq!(sql[1], KEYED_STATEMENT_TIMEOUT_SQL);
        assert_eq!(sql[2], KEYED_IDLE_IN_TRANSACTION_SQL);
        assert_eq!(
            sql[0],
            format!(
                "SET LOCAL lock_timeout = '{}s'",
                KEYED_RESERVATION_LOCK_TIMEOUT_SECS
            )
        );
        assert_eq!(
            sql[1],
            format!(
                "SET LOCAL statement_timeout = '{}s'",
                KEYED_RESERVATION_STATEMENT_TIMEOUT_SECS
            )
        );
        assert_eq!(
            sql[2],
            format!(
                "SET LOCAL idle_in_transaction_session_timeout = '{}s'",
                KEYED_RESERVATION_IDLE_TIMEOUT_SECS
            )
        );
        assert_eq!(KEYED_RESERVATION_LOCK_TIMEOUT_SECS, 5);
        assert_eq!(KEYED_RESERVATION_STATEMENT_TIMEOUT_SECS, 15);
        assert_eq!(KEYED_RESERVATION_IDLE_TIMEOUT_SECS, 10);
        assert_eq!(KEYED_COMMIT_RECOVERY_LOOKUP_TIMEOUT_SECS, 15);
        assert_ne!(
            KEYED_COMMIT_RECOVERY_LOOKUP_TIMEOUT_SECS, 0,
            "lost-ack recovery lookup stays an independent 15s budget"
        );
    }

    #[test]
    fn prepared_intent_rejects_event_mix_and_match() {
        let keys = Keys::generate();
        let first = stream_event(&keys, "prepare-bind-a", 1_700_000_001, vec![]);
        let second = stream_event(&keys, "prepare-bind-b", 1_700_000_002, vec![]);
        let prepared = PreparedKeyedIntent::prepare(key_n(1), &first).expect("prepare");
        assert!(prepared.binds_event(&first));
        assert!(!prepared.binds_event(&second));
        assert!(validate_prepared_before_db(&prepared, &first, None, None).is_ok());
        assert!(validate_prepared_before_db(&prepared, &second, None, None).is_err());
        let other_key = PreparedKeyedIntent::prepare(key_n(2), &first).expect("other key");
        assert!(!prepared_intent_eq(&prepared, &other_key));
        assert_eq!(prepared.event_id(), first.id.as_bytes());
        assert_eq!(prepared.author(), &first.pubkey.to_bytes());
    }

    #[test]
    fn reservation_capacity_is_fail_fast_and_does_not_grow_waiters() {
        let _capacity_tests = lock_direct_capacity_tests();
        assert_eq!(KEYED_RESERVATION_CAPACITY, 8);
        assert_eq!(KEYED_RESERVATION_PER_TENANT_CAPACITY, 4);
        assert_eq!(KEYED_COMMIT_RECOVERY_CAPACITY, 8);
        assert_eq!(KEYED_RESERVATION_LOCK_TIMEOUT_SECS, 5);
        assert_eq!(KEYED_RESERVATION_IDLE_TIMEOUT_SECS, 10);
        assert_eq!(KEYED_RESERVATION_STATEMENT_TIMEOUT_SECS, 15);
        assert_eq!(KEYED_COMMIT_RECOVERY_LOOKUP_TIMEOUT_SECS, 15);
        const {
            assert!(KEYED_COMMIT_RECOVERY_LOOKUP_TIMEOUT_SECS > 0);
        }
        const {
            assert!(KEYED_RESERVATION_PER_TENANT_CAPACITY >= 2);
            assert!(KEYED_RESERVATION_PER_TENANT_CAPACITY * 2 <= KEYED_RESERVATION_CAPACITY);
        }
        assert_eq!(REAP_MAX_COLD_COMMUNITY_PROBES_PER_TX, 1024);
        assert_eq!(
            keyed_reservation_timeout_sql(),
            [
                KEYED_LOCK_TIMEOUT_SQL,
                KEYED_STATEMENT_TIMEOUT_SQL,
                KEYED_IDLE_IN_TRANSACTION_SQL,
            ]
        );
        assert_eq!(KEYED_LOCK_TIMEOUT_SQL, "SET LOCAL lock_timeout = '5s'");
        assert_eq!(
            KEYED_STATEMENT_TIMEOUT_SQL,
            "SET LOCAL statement_timeout = '15s'"
        );
        assert_eq!(
            KEYED_IDLE_IN_TRANSACTION_SQL,
            "SET LOCAL idle_in_transaction_session_timeout = '10s'"
        );

        let mut held = Vec::new();
        for i in 0..KEYED_RESERVATION_CAPACITY {
            held.push(
                try_acquire_keyed_reservation_capacity(Uuid::from_u128((i as u128) + 1))
                    .expect("test must fill reservation cap"),
            );
        }
        assert_eq!(keyed_reservation_available_permits(), 0);
        let started = std::time::Instant::now();
        let ninth = try_acquire_keyed_reservation_capacity(Uuid::from_u128(9));
        assert!(
            started.elapsed() < std::time::Duration::from_millis(20),
            "a full reservation cap must fail closed immediately"
        );
        match ninth {
            Err(error) => assert!(
                error.is_idempotency_unavailable(),
                "ninth acquire must map to keyed busy, got {error}"
            ),
            Ok(_) => panic!("a full reservation cap must fail closed immediately"),
        }
        assert_eq!(
            keyed_reservation_available_permits(),
            0,
            "try_acquire must not enqueue waiters past {KEYED_RESERVATION_CAPACITY}"
        );
        drop(held);
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY
        );

        let tenant = Uuid::from_u128(100);
        let mut same_tenant = Vec::new();
        for _ in 0..KEYED_RESERVATION_PER_TENANT_CAPACITY {
            let permit = try_acquire_keyed_reservation_capacity(tenant)
                .expect("same-tenant reservation slot");
            same_tenant.push(permit);
        }
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY - KEYED_RESERVATION_PER_TENANT_CAPACITY
        );
        let started = std::time::Instant::now();
        let fifth_same_tenant = try_acquire_keyed_reservation_capacity(tenant);
        assert!(
            started.elapsed() < std::time::Duration::from_millis(20),
            "a full per-tenant reservation cap must fail closed immediately"
        );
        match fifth_same_tenant {
            Err(error) => assert!(error.is_idempotency_unavailable()),
            Ok(_) => panic!(
                "one tenant must not occupy more than {KEYED_RESERVATION_PER_TENANT_CAPACITY} reservation slots"
            ),
        }
        let other = try_acquire_keyed_reservation_capacity(Uuid::from_u128(101))
            .expect("a distinct tenant must still obtain a global slot");
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY - KEYED_RESERVATION_PER_TENANT_CAPACITY - 1
        );
        drop(same_tenant);
        drop(other);
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY
        );

        let mut recovery_held = Vec::new();
        for _ in 0..KEYED_COMMIT_RECOVERY_CAPACITY {
            recovery_held.push(
                try_acquire_keyed_commit_recovery_capacity().expect("test must fill recovery cap"),
            );
        }
        assert_eq!(keyed_commit_recovery_available_permits(), 0);
        let started = std::time::Instant::now();
        let extra_recovery = try_acquire_keyed_commit_recovery_capacity();
        assert!(started.elapsed() < std::time::Duration::from_millis(20));
        match extra_recovery {
            Err(error) => assert!(error.is_idempotency_unavailable()),
            Ok(_) => panic!("recovery cap must fail closed immediately"),
        }
        drop(recovery_held);
        assert_eq!(
            keyed_commit_recovery_available_permits(),
            KEYED_COMMIT_RECOVERY_CAPACITY
        );
    }

    #[test]
    fn tenant_reservation_registry_is_bounded_and_identity_safe() {
        let _capacity_tests = lock_direct_capacity_tests();
        let baseline = keyed_tenant_reservation_registry_len();

        let shared = Uuid::new_v4();
        let first = try_acquire_keyed_reservation_capacity(shared)
            .expect("first concurrent same-tenant guard");
        let second = try_acquire_keyed_reservation_capacity(shared)
            .expect("second concurrent same-tenant guard");
        assert!(
            keyed_tenant_reservation_registry_contains(shared),
            "concurrent guards must share a live registry entry"
        );
        assert_eq!(keyed_tenant_reservation_live_handles(shared), Some(2));
        assert!(Arc::ptr_eq(
            first.tenant_semaphore_identity(),
            second.tenant_semaphore_identity()
        ));
        drop(first);
        assert!(
            keyed_tenant_reservation_registry_contains(shared),
            "the live entry must remain until the final guard drops"
        );
        drop(second);
        assert!(
            !keyed_tenant_reservation_registry_contains(shared),
            "the final guard drop must reclaim the idle tenant entry"
        );

        let pair = Uuid::new_v4();
        let left = try_acquire_keyed_reservation_capacity(pair)
            .expect("left same-tenant guard for concurrent final drop");
        let right = try_acquire_keyed_reservation_capacity(pair)
            .expect("right same-tenant guard for concurrent final drop");
        let start = std::sync::Arc::new(std::sync::Barrier::new(2));
        let left_thread = {
            let start = std::sync::Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                drop(left);
            })
        };
        let right_thread = {
            let start = std::sync::Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                drop(right);
            })
        };
        left_thread.join().expect("left final drop");
        right_thread.join().expect("right final drop");
        assert!(
            !keyed_tenant_reservation_registry_contains(pair),
            "two concurrent final same-tenant releases must reclaim the entry"
        );

        let kept = Uuid::new_v4();
        let older = try_acquire_keyed_reservation_capacity(kept)
            .expect("older live identity before overlapping lookup");
        let older_sema = std::sync::Arc::clone(older.tenant_semaphore_identity());
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (drop_tx, drop_rx) = std::sync::mpsc::channel();
        let older_thread = std::thread::spawn(move || {
            ready_tx.send(()).expect("older dropper ready");
            drop_rx.recv().expect("drop after overlapping lookup");
            drop(older);
        });
        ready_rx.recv().expect("older dropper is parked");
        let overlapping = try_acquire_keyed_reservation_capacity(kept)
            .expect("lookup counted before the older final drop");
        assert!(
            std::sync::Arc::ptr_eq(overlapping.tenant_semaphore_identity(), &older_sema),
            "a lookup counted before an older final drop must keep the same live identity"
        );
        assert_eq!(keyed_tenant_reservation_live_handles(kept), Some(2));
        drop_tx.send(()).expect("release older drop");
        older_thread.join().expect("older drop");
        assert!(
            keyed_tenant_reservation_registry_contains(kept),
            "the overlapping lookup must keep the live identity after the older drop"
        );
        assert!(std::sync::Arc::ptr_eq(
            &keyed_tenant_reservation_semaphore_arc(kept)
                .expect("overlapping identity must remain mapped"),
            overlapping.tenant_semaphore_identity()
        ));
        drop(overlapping);
        assert!(!keyed_tenant_reservation_registry_contains(kept));

        let split = Uuid::new_v4();
        let split_start = std::sync::Arc::new(std::sync::Barrier::new(
            KEYED_RESERVATION_PER_TENANT_CAPACITY,
        ));
        let split_threads: Vec<_> = (0..KEYED_RESERVATION_PER_TENANT_CAPACITY)
            .map(|_| {
                let start = std::sync::Arc::clone(&split_start);
                std::thread::spawn(move || {
                    start.wait();
                    try_acquire_keyed_reservation_capacity(split)
                        .expect("same-tenant concurrent acquire")
                })
            })
            .collect();
        let split_held: Vec<_> = split_threads
            .into_iter()
            .map(|thread| thread.join().expect("same-tenant acquire thread"))
            .collect();
        let mapped = keyed_tenant_reservation_semaphore_arc(split)
            .expect("concurrent same-tenant acquires must map one entry");
        assert_eq!(
            keyed_tenant_reservation_live_handles(split),
            Some(KEYED_RESERVATION_PER_TENANT_CAPACITY)
        );
        for permit in &split_held {
            assert!(
                std::sync::Arc::ptr_eq(permit.tenant_semaphore_identity(), &mapped),
                "mutex/identity logic must not create split live semaphores"
            );
        }
        drop(split_held);
        assert!(!keyed_tenant_reservation_registry_contains(split));

        let capped = Uuid::new_v4();
        let mut same_tenant = Vec::new();
        for _ in 0..KEYED_RESERVATION_PER_TENANT_CAPACITY {
            let permit =
                try_acquire_keyed_reservation_capacity(capped).expect("per-tenant cap fill");
            same_tenant.push(permit);
        }
        assert!(keyed_tenant_reservation_registry_contains(capped));
        match try_acquire_keyed_reservation_capacity(capped) {
            Err(error) => assert!(error.is_idempotency_unavailable()),
            Ok(_) => panic!("per-tenant cap must fail closed"),
        }
        assert!(
            keyed_tenant_reservation_registry_contains(capped),
            "a failed extra same-tenant acquire must keep the live owners' entry"
        );
        assert_eq!(
            keyed_tenant_reservation_live_handles(capped),
            Some(KEYED_RESERVATION_PER_TENANT_CAPACITY)
        );
        drop(same_tenant);
        assert!(
            !keyed_tenant_reservation_registry_contains(capped),
            "dropping the live owners after a failed extra acquire must reclaim"
        );

        let mixed = Uuid::new_v4();
        let mut mixed_held = Vec::new();
        for _ in 0..(KEYED_RESERVATION_PER_TENANT_CAPACITY - 1) {
            mixed_held.push(
                try_acquire_keyed_reservation_capacity(mixed)
                    .expect("same-target holder before mixed full failures"),
            );
        }
        let mut other_held = Vec::new();
        let other_slots = KEYED_RESERVATION_CAPACITY - (KEYED_RESERVATION_PER_TENANT_CAPACITY - 1);
        for _ in 0..other_slots {
            other_held.push(
                try_acquire_keyed_reservation_capacity(Uuid::new_v4())
                    .expect("fill remaining global slots"),
            );
        }
        assert_eq!(keyed_reservation_available_permits(), 0);
        let mixed_start = std::sync::Arc::new(std::sync::Barrier::new(2));
        let mixed_threads: Vec<_> = (0..2)
            .map(|_| {
                let start = std::sync::Arc::clone(&mixed_start);
                std::thread::spawn(move || {
                    start.wait();
                    try_acquire_keyed_reservation_capacity(mixed)
                })
            })
            .collect();
        let mixed_results: Vec<_> = mixed_threads
            .into_iter()
            .map(|thread| thread.join().expect("mixed full-failure thread"))
            .collect();
        assert!(
            mixed_results.iter().all(|result| result
                .as_ref()
                .err()
                .is_some_and(|error| error.is_idempotency_unavailable())),
            "same-target tenant-full and global-full attempts must fail closed"
        );
        assert!(
            keyed_tenant_reservation_registry_contains(mixed),
            "mixed full failures must not strand or drop live owners"
        );
        assert_eq!(
            keyed_tenant_reservation_live_handles(mixed),
            Some(KEYED_RESERVATION_PER_TENANT_CAPACITY - 1)
        );
        drop(mixed_held);
        assert!(
            !keyed_tenant_reservation_registry_contains(mixed),
            "simultaneous same-target tenant-full and global-full failures must not strand the entry"
        );
        drop(other_held);
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY
        );

        let mut transients = Vec::with_capacity(64);
        for _ in 0..64 {
            let tenant = Uuid::new_v4();
            drop(
                try_acquire_keyed_reservation_capacity(tenant)
                    .expect("transient distinct-tenant reservation"),
            );
            transients.push(tenant);
        }
        for tenant in &transients {
            assert!(
                !keyed_tenant_reservation_registry_contains(*tenant),
                "transient tenant {tenant} must not remain in the registry"
            );
        }
        let after_transients = keyed_tenant_reservation_registry_len();
        assert!(
            after_transients <= baseline + KEYED_RESERVATION_CAPACITY,
            "transient tenants must not grow the registry without bound, \
             baseline={baseline} after={after_transients}"
        );
        assert_eq!(
            after_transients, baseline,
            "repeated transient tenant IDs must return registry size to baseline"
        );

        let replaced = Uuid::new_v4();
        let original = try_acquire_keyed_reservation_capacity(replaced)
            .expect("original tenant reservation before replacement");
        let old_sema = keyed_tenant_reservation_semaphore_arc(replaced)
            .expect("live semaphore for the original reservation");
        drop(original);
        maybe_reclaim_tenant_semaphore(replaced, &old_sema);
        assert!(
            !keyed_tenant_reservation_registry_contains(replaced),
            "cleanup of the idle original identity must reclaim the entry"
        );
        let replacement = try_acquire_keyed_reservation_capacity(replaced)
            .expect("replacement tenant reservation");
        let new_sema = keyed_tenant_reservation_semaphore_arc(replaced)
            .expect("live semaphore for the replacement reservation");
        assert!(
            !Arc::ptr_eq(&old_sema, &new_sema),
            "replacement must install a distinct semaphore"
        );
        maybe_reclaim_tenant_semaphore(replaced, &old_sema);
        assert!(
            keyed_tenant_reservation_registry_contains(replaced),
            "stale cleanup must not remove a replacement entry"
        );
        assert!(
            Arc::ptr_eq(
                &keyed_tenant_reservation_semaphore_arc(replaced)
                    .expect("replacement entry must still be present"),
                &new_sema
            ),
            "stale cleanup must leave the replacement semaphore in place"
        );
        drop(old_sema);
        drop(new_sema);
        drop(replacement);
        assert!(
            !keyed_tenant_reservation_registry_contains(replaced),
            "the replacement entry must reclaim after its guard drops"
        );

        let mut held = Vec::new();
        for i in 0..KEYED_RESERVATION_CAPACITY {
            held.push(
                try_acquire_keyed_reservation_capacity(Uuid::from_u128(50_000 + i as u128))
                    .expect("test must fill reservation cap"),
            );
        }
        let stranded = Uuid::new_v4();
        let started = std::time::Instant::now();
        let global_full = try_acquire_keyed_reservation_capacity(stranded);
        assert!(
            started.elapsed() < std::time::Duration::from_millis(20),
            "a full global reservation cap must fail closed immediately"
        );
        match global_full {
            Err(error) => assert!(error.is_idempotency_unavailable()),
            Ok(_) => panic!("a full global reservation cap must fail closed immediately"),
        }
        assert!(
            !keyed_tenant_reservation_registry_contains(stranded),
            "a global-full failure must not strand a tenant registry entry"
        );

        let concurrent_stranded = Uuid::new_v4();
        let global_start = std::sync::Arc::new(std::sync::Barrier::new(2));
        let global_threads: Vec<_> = (0..2)
            .map(|_| {
                let start = std::sync::Arc::clone(&global_start);
                std::thread::spawn(move || {
                    start.wait();
                    try_acquire_keyed_reservation_capacity(concurrent_stranded)
                })
            })
            .collect();
        let global_results: Vec<_> = global_threads
            .into_iter()
            .map(|thread| thread.join().expect("concurrent global-full thread"))
            .collect();
        assert!(global_results.iter().all(|result| result
            .as_ref()
            .err()
            .is_some_and(|error| error.is_idempotency_unavailable())));
        assert!(
            !keyed_tenant_reservation_registry_contains(concurrent_stranded),
            "simultaneous same-target global-full failures must not strand the entry"
        );
        drop(held);
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY
        );
        assert!(
            keyed_tenant_reservation_registry_len() <= baseline + KEYED_RESERVATION_CAPACITY,
            "registry must stay bounded after global-full failure reclaim"
        );
        assert_eq!(
            keyed_tenant_reservation_registry_len(),
            baseline,
            "direct capacity tests must restore the registry to baseline"
        );
    }

    #[test]
    fn reap_tick_reuses_cursor_only_after_positive_expired_progress() {
        assert!(!reap_tick_should_advance_cursor(true, 1, false));
        assert!(reap_tick_should_advance_cursor(true, 0, false));
        assert!(reap_tick_should_advance_cursor(true, 1, true));
        assert!(reap_tick_should_advance_cursor(false, 1, false));
        assert!(reap_tick_should_advance_cursor(false, 0, false));
        let stay = Uuid::from_u128(1);
        let visited = Uuid::from_u128(2);
        assert_eq!(
            committed_reaper_cursor(Some(stay), Some(visited), true, 1, false),
            Some(stay),
            "hot-tenant stay must keep the previous exclusive bound"
        );
        assert_eq!(
            committed_reaper_cursor(Some(stay), Some(visited), true, 1, true),
            Some(visited),
            "spent tick budget must persist the visited tenant"
        );
        assert_eq!(
            committed_reaper_cursor(None, Some(visited), false, 0, false),
            Some(visited)
        );
    }

    #[test]
    fn deletion_inventory_lists_event_idempotency_keys() {
        assert!(EXPECTED_SCOPED_TABLES.contains(&"event_idempotency_keys"));
        assert!(PURGE_SCOPED_TABLES.contains(&"event_idempotency_keys"));
        let mentions = PURGE_SCOPED_TABLES
            .iter()
            .position(|t| *t == "event_mentions")
            .expect("mentions");
        let keys = PURGE_SCOPED_TABLES
            .iter()
            .position(|t| *t == "event_idempotency_keys")
            .expect("keys");
        let events = PURGE_SCOPED_TABLES
            .iter()
            .position(|t| *t == "events")
            .expect("events");
        assert!(mentions < keys && keys < events);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn catalog_pk_checks_and_both_triggers() {
        let pool = setup_pool().await;
        let cols: Vec<(String, i32)> = sqlx::query_as(
            "SELECT a.attname, a.atttypmod FROM pg_attribute a \
             JOIN pg_class c ON c.oid = a.attrelid \
             WHERE c.relname = 'event_idempotency_keys' AND a.attnum > 0 AND NOT a.attisdropped \
             ORDER BY a.attnum",
        )
        .fetch_all(&pool)
        .await
        .expect("columns");
        let names: Vec<_> = cols.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "community_id",
                "author_pubkey",
                "idempotency_key",
                "intent_hash",
                "event_id",
                "created_at",
                "reservation_witness"
            ]
        );
        let pk: String = sqlx::query_scalar(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
             WHERE conrelid = 'event_idempotency_keys'::regclass AND contype = 'p'",
        )
        .fetch_one(&pool)
        .await
        .expect("pk");
        assert!(pk.contains("community_id"));
        assert!(pk.contains("author_pubkey"));
        assert!(pk.contains("idempotency_key"));
        let checks: Vec<String> = sqlx::query_scalar(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
             WHERE conrelid = 'event_idempotency_keys'::regclass AND contype = 'c' \
             ORDER BY conname",
        )
        .fetch_all(&pool)
        .await
        .expect("checks");
        assert_eq!(checks.len(), 5);
        assert!(checks
            .iter()
            .all(|c| c.contains("octet_length") && c.contains("32")));
        assert!(checks
            .iter()
            .any(|c| c.contains("reservation_witness") && c.contains("32")));
        let triggers: Vec<(String, i16)> = sqlx::query_as(
            "SELECT tgname, tgtype FROM pg_trigger \
             WHERE tgrelid = 'event_idempotency_keys'::regclass AND NOT tgisinternal \
             ORDER BY tgname",
        )
        .fetch_all(&pool)
        .await
        .expect("triggers");
        assert!(triggers
            .iter()
            .any(|(n, t)| n == "community_write_fence_event_idempotency_keys" && (t & 31) == 31));
        assert!(triggers
            .iter()
            .any(|(n, t)| n == "event_idempotency_keys_immutable" && (t & 31) == 19));

        let cursor_cols: Vec<String> = sqlx::query_scalar(
            "SELECT a.attname FROM pg_attribute a \
             JOIN pg_class c ON c.oid = a.attrelid \
             JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = current_schema() \
               AND c.relname = 'event_idempotency_reaper_cursor' \
               AND a.attnum > 0 AND NOT a.attisdropped \
             ORDER BY a.attnum",
        )
        .fetch_all(&pool)
        .await
        .expect("cursor columns");
        assert_eq!(
            cursor_cols,
            vec!["id".to_owned(), "after_community_id".to_owned()]
        );
        let cursor_rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM event_idempotency_reaper_cursor WHERE id = 1")
                .fetch_one(&pool)
                .await
                .expect("cursor singleton");
        assert_eq!(cursor_rows, 1);
        let registered: bool = sqlx::query_scalar(
            "SELECT EXISTS (\
                 SELECT 1 FROM _operator_global_tables \
                 WHERE table_name = 'event_idempotency_reaper_cursor'\
             )",
        )
        .fetch_one(&pool)
        .await
        .expect("cursor registry");
        assert!(registered);
        let can_update: bool = sqlx::query_scalar(
            "SELECT has_table_privilege(current_user, \
                'event_idempotency_reaper_cursor'::regclass, 'UPDATE')",
        )
        .fetch_one(&pool)
        .await
        .expect("cursor update privilege");
        assert!(can_update);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn first_insert_dispatches_and_same_key_replay_conflict_bind() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let channel = make_test_channel(&pool, community_uuid).await;
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let key = key_n(1);
        let event = stream_event(&keys, "hello", 1_700_000_001, vec![]);

        let first = db
            .insert_keyed_stream_event_with_thread_metadata(
                community,
                author,
                key,
                &event,
                Some(channel),
                None,
            )
            .await
            .expect("first insert");
        assert!(first.should_dispatch());
        match first {
            KeyedStreamInsert::Inserted { stored_event } => {
                assert_eq!(stored_event.event.id, event.id);
            }
            other => panic!("expected Inserted, got {other:?}"),
        }
        assert_eq!(key_count(&pool, community_uuid).await, 1);
        assert_eq!(event_count(&pool, community_uuid).await, 1);

        let resigned = stream_event(&keys, "hello", 1_700_000_002, vec![]);
        let replay = db
            .insert_keyed_stream_event_with_thread_metadata(
                community,
                author,
                key,
                &resigned,
                Some(channel),
                None,
            )
            .await
            .expect("replay");
        assert!(!replay.should_dispatch());
        match replay {
            KeyedStreamInsert::Replay { original_event_id } => {
                assert_eq!(&original_event_id, event.id.as_bytes());
            }
            other => panic!("expected Replay, got {other:?}"),
        }
        assert_eq!(event_count(&pool, community_uuid).await, 1);

        let conflict_event = stream_event(&keys, "other", 1_700_000_003, vec![]);
        let conflict = db
            .insert_keyed_stream_event_with_thread_metadata(
                community,
                author,
                key,
                &conflict_event,
                Some(channel),
                None,
            )
            .await
            .expect("conflict");
        assert!(!conflict.should_dispatch());
        assert!(matches!(conflict, KeyedStreamInsert::Conflict { .. }));
        assert_eq!(event_count(&pool, community_uuid).await, 1);
    }

    async fn reserved_for(
        db: &Db,
        community: CommunityId,
        author: [u8; 32],
        key: [u8; 32],
        event: &Event,
    ) -> KeyedReservation {
        match db
            .begin_keyed_stream_reservation_for_event(community, author, key, event, None, None)
            .await
            .expect("reserve")
        {
            KeyedReserveOutcome::Reserved(reservation) => *reservation,
            KeyedReserveOutcome::Replay { .. } | KeyedReserveOutcome::Conflict { .. } => {
                panic!("expected Reserved, got replay or conflict")
            }
        }
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn lost_commit_ack_recovers_matching_witness_as_fresh() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let key = key_n(80);
        let event = stream_event(&keys, "lost-ack-fresh", 1_700_000_300, vec![]);
        let before = keyed_reservation_available_permits();
        let recovered = reserved_for(&db, community, author, key, &event)
            .await
            .with_lost_commit_ack()
            .complete_for_event(&event, None)
            .await
            .expect("matching witness must recover as fresh");
        assert_eq!(keyed_reservation_available_permits(), before);
        assert!(recovered.should_dispatch());
        let stored = recovered
            .into_fresh_stored_event()
            .expect("RecoveredFresh must take the ingest fresh extractor");
        assert_eq!(stored.event.id, event.id);
        assert_eq!(key_count(&pool, community_uuid).await, 1);
        assert_eq!(event_count(&pool, community_uuid).await, 1);

        let replay = db
            .insert_keyed_stream_event_with_thread_metadata(
                community, author, key, &event, None, None,
            )
            .await
            .expect("replay after recovered-fresh");
        assert!(!replay.should_dispatch());
        assert!(matches!(
            replay,
            KeyedStreamInsert::Replay { original_event_id }
                if &original_event_id == event.id.as_bytes()
        ));
        assert!(replay.into_fresh_stored_event().is_err());
        assert_eq!(event_count(&pool, community_uuid).await, 1);
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn fail_without_commit_stays_failure_and_key_is_retryable() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let key = key_n(81);
        let event = stream_event(&keys, "no-commit", 1_700_000_301, vec![]);
        let before = keyed_reservation_available_permits();
        let err = reserved_for(&db, community, author, key, &event)
            .await
            .with_commit_failure_without_commit()
            .complete_for_event(&event, None)
            .await
            .expect_err("a true non-commit must not become fresh success");
        assert!(matches!(err, DbError::Sqlx(_)), "got {err}");
        assert_eq!(keyed_reservation_available_permits(), before);
        assert_eq!(key_count(&pool, community_uuid).await, 0);
        assert_eq!(event_count(&pool, community_uuid).await, 0);

        let retry = db
            .insert_keyed_stream_event_with_thread_metadata(
                community, author, key, &event, None, None,
            )
            .await
            .expect("rolled-back key must stay retryable");
        assert!(retry.should_dispatch());
        assert!(matches!(retry, KeyedStreamInsert::Inserted { .. }));
        assert_eq!(key_count(&pool, community_uuid).await, 1);
        assert_eq!(event_count(&pool, community_uuid).await, 1);
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn different_witness_cannot_claim_committed_row() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let key = key_n(82);
        let event = stream_event(&keys, "witness-claim", 1_700_000_302, vec![]);
        let err = reserved_for(&db, community, author, key, &event)
            .await
            .with_lost_commit_ack()
            .claiming_witness([0xff; 32])
            .complete_for_event(&event, None)
            .await
            .expect_err("a different witness must not recover the committed row");
        assert!(matches!(err, DbError::Sqlx(_)), "got {err}");
        assert_eq!(key_count(&pool, community_uuid).await, 1);
        assert_eq!(event_count(&pool, community_uuid).await, 1);

        let retry = db
            .insert_keyed_stream_event_with_thread_metadata(
                community, author, key, &event, None, None,
            )
            .await
            .expect("committed row remains bound");
        assert!(!retry.should_dispatch());
        assert!(matches!(retry, KeyedStreamInsert::Replay { .. }));
        assert_eq!(event_count(&pool, community_uuid).await, 1);
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn conflict_cannot_recover_as_fresh() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let key = key_n(83);
        let original = stream_event(&keys, "conflict-owner", 1_700_000_303, vec![]);
        let other = stream_event(&keys, "conflict-other", 1_700_000_304, vec![]);
        db.insert_keyed_stream_event_with_thread_metadata(
            community, author, key, &original, None, None,
        )
        .await
        .expect("owner insert");

        match db
            .begin_keyed_stream_reservation_for_event(community, author, key, &other, None, None)
            .await
            .expect("conflict classify")
        {
            KeyedReserveOutcome::Conflict { existing_event_id } => {
                assert_eq!(&existing_event_id, original.id.as_bytes());
            }
            KeyedReserveOutcome::Reserved(_) => {
                panic!("conflict must not open a reservation that could recover")
            }
            KeyedReserveOutcome::Replay { .. } => {
                panic!("different intent must classify conflict, not replay")
            }
        }

        let (stored_hash, stored_id, stored_witness): (Vec<u8>, Vec<u8>, Vec<u8>) = sqlx::query_as(
            r#"
            SELECT intent_hash, event_id, reservation_witness
              FROM event_idempotency_keys
             WHERE community_id = $1
               AND author_pubkey = $2
               AND idempotency_key = $3
            "#,
        )
        .bind(community_uuid)
        .bind(author.as_slice())
        .bind(key.as_slice())
        .fetch_one(&pool)
        .await
        .expect("load committed witness");
        let stored_hash = copy_32(&stored_hash).expect("intent hash");
        let stored_id = copy_32(&stored_id).expect("event id");
        let stored_witness = copy_32(&stored_witness).expect("witness");
        let recovered = recover_lost_commit_ack(
            &pool,
            LostCommitAckRecovery {
                community_id: community,
                author,
                key,
                intent_hash: stored_hash,
                event_id: stored_id,
                witness: stored_witness,
                persist_outcome: KeyedStreamInsert::Conflict {
                    existing_event_id: stored_id,
                },
            },
        )
        .await;
        assert!(
            recovered.is_err(),
            "conflict persist outcome must not recover as success"
        );

        let conflict = db
            .insert_keyed_stream_event_with_thread_metadata(
                community, author, key, &other, None, None,
            )
            .await
            .expect("conflict insert");
        assert!(!conflict.should_dispatch());
        assert!(matches!(conflict, KeyedStreamInsert::Conflict { .. }));
        assert!(conflict.into_fresh_stored_event().is_err());
        assert_eq!(event_count(&pool, community_uuid).await, 1);
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn recovery_lookup_miss_and_wrong_provenance_are_not_success() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let key = key_n(84);
        let event = stream_event(&keys, "lookup-miss", 1_700_000_305, vec![]);
        db.insert_keyed_stream_event_with_thread_metadata(
            community, author, key, &event, None, None,
        )
        .await
        .expect("owner insert");

        let miss = recover_lost_commit_ack(
            &pool,
            LostCommitAckRecovery {
                community_id: community,
                author,
                key: key_n(85),
                intent_hash: [1u8; 32],
                event_id: *event.id.as_bytes(),
                witness: [2u8; 32],
                persist_outcome: KeyedStreamInsert::BoundExisting {
                    event_id: *event.id.as_bytes(),
                },
            },
        )
        .await
        .expect("missing key lookup");
        assert!(
            miss.is_none(),
            "a missing row must not become fresh success"
        );

        let (stored_hash, stored_id, _stored_witness): (Vec<u8>, Vec<u8>, Vec<u8>) =
            sqlx::query_as(
                r#"
            SELECT intent_hash, event_id, reservation_witness
              FROM event_idempotency_keys
             WHERE community_id = $1
               AND author_pubkey = $2
               AND idempotency_key = $3
            "#,
            )
            .bind(community_uuid)
            .bind(author.as_slice())
            .bind(key.as_slice())
            .fetch_one(&pool)
            .await
            .expect("load committed hashes");
        let wrong_witness = recover_lost_commit_ack(
            &pool,
            LostCommitAckRecovery {
                community_id: community,
                author,
                key,
                intent_hash: copy_32(&stored_hash).expect("intent hash"),
                event_id: copy_32(&stored_id).expect("event id"),
                witness: [0xee; 32],
                persist_outcome: KeyedStreamInsert::BoundExisting {
                    event_id: copy_32(&stored_id).expect("event id"),
                },
            },
        )
        .await
        .expect("wrong witness lookup");
        assert!(
            wrong_witness.is_none(),
            "different provenance must not become success"
        );
        assert_eq!(event_count(&pool, community_uuid).await, 1);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn committed_replay_and_conflict_leave_reservation_capacity_available() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let key = key_n(65);
        let event = stream_event(&keys, "capacity-precheck", 1_700_000_200, vec![]);
        db.insert_keyed_stream_event_with_thread_metadata(
            community, author, key, &event, None, None,
        )
        .await
        .expect("first insert");
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY
        );

        let mut held = Vec::new();
        for i in 0..KEYED_RESERVATION_CAPACITY {
            held.push(
                try_acquire_keyed_reservation_capacity(Uuid::from_u128((i as u128) + 10_000))
                    .expect("test must exhaust reservation cap"),
            );
        }
        assert_eq!(keyed_reservation_available_permits(), 0);

        let resigned = stream_event(&keys, "capacity-precheck", 1_700_000_201, vec![]);
        let replay = db
            .begin_keyed_stream_reservation_for_event(community, author, key, &resigned, None, None)
            .await
            .expect("committed replay must not need a reservation slot");
        match replay {
            KeyedReserveOutcome::Replay { original_event_id } => {
                assert_eq!(&original_event_id, event.id.as_bytes());
            }
            _other => panic!("expected Replay without taking capacity"),
        }
        assert_eq!(
            keyed_reservation_available_permits(),
            0,
            "committed replay must leave reservation capacity untouched"
        );

        let conflict_event = stream_event(&keys, "capacity-conflict", 1_700_000_202, vec![]);
        let conflict = db
            .begin_keyed_stream_reservation_for_event(
                community,
                author,
                key,
                &conflict_event,
                None,
                None,
            )
            .await
            .expect("committed conflict must not need a reservation slot");
        match conflict {
            KeyedReserveOutcome::Conflict { existing_event_id } => {
                assert_eq!(&existing_event_id, event.id.as_bytes());
            }
            _other => panic!("expected Conflict without taking capacity"),
        }
        assert_eq!(
            keyed_reservation_available_permits(),
            0,
            "committed conflict must leave reservation capacity untouched"
        );
        drop(held);
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY
        );
        assert_eq!(key_count(&pool, community_uuid).await, 1);
        assert_eq!(event_count(&pool, community_uuid).await, 1);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn classify_committed_replay_and_conflict_are_read_only_with_capacity_held() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let key = key_n(68);
        let event = stream_event(&keys, "classify-precheck", 1_700_000_220, vec![]);
        db.insert_keyed_stream_event_with_thread_metadata(
            community, author, key, &event, None, None,
        )
        .await
        .expect("first insert");

        let mut held = Vec::new();
        for i in 0..KEYED_RESERVATION_CAPACITY {
            held.push(
                try_acquire_keyed_reservation_capacity(Uuid::from_u128((i as u128) + 20_000))
                    .expect("test must exhaust reservation cap"),
            );
        }
        assert_eq!(keyed_reservation_available_permits(), 0);

        let resigned = stream_event(&keys, "classify-precheck", 1_700_000_221, vec![]);
        let replay = db
            .classify_committed_keyed_stream(community, author, key, &resigned, None, None)
            .await
            .expect("committed replay classify")
            .expect("committed replay must be Some");
        match replay {
            KeyedCommittedOutcome::Replay { original_event_id } => {
                assert_eq!(&original_event_id, event.id.as_bytes());
            }
            _other => panic!("expected Replay from read-only classify"),
        }

        let conflict_event = stream_event(&keys, "classify-conflict", 1_700_000_222, vec![]);
        let conflict = db
            .classify_committed_keyed_stream(community, author, key, &conflict_event, None, None)
            .await
            .expect("committed conflict classify")
            .expect("committed conflict must be Some");
        match conflict {
            KeyedCommittedOutcome::Conflict { existing_event_id } => {
                assert_eq!(&existing_event_id, event.id.as_bytes());
            }
            _other => panic!("expected Conflict from read-only classify"),
        }
        assert_eq!(
            keyed_reservation_available_permits(),
            0,
            "read-only classify must not take reservation capacity"
        );
        drop(held);
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY
        );
        assert_eq!(key_count(&pool, community_uuid).await, 1);
        assert_eq!(event_count(&pool, community_uuid).await, 1);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn classify_committed_miss_does_not_take_capacity_or_a_writer_transaction() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let missing_key = key_n(69);
        let missing_event = stream_event(&keys, "classify-miss", 1_700_000_230, vec![]);

        let mut held = Vec::new();
        for i in 0..KEYED_RESERVATION_CAPACITY {
            held.push(
                try_acquire_keyed_reservation_capacity(Uuid::from_u128((i as u128) + 30_000))
                    .expect("test must exhaust reservation cap"),
            );
        }
        let classified = db
            .classify_committed_keyed_stream(
                community,
                author,
                missing_key,
                &missing_event,
                None,
                None,
            )
            .await
            .expect("committed miss classify");
        assert!(
            classified.is_none(),
            "an initial miss must not reserve before admission"
        );
        assert_eq!(
            keyed_reservation_available_permits(),
            0,
            "a committed miss must not take reservation capacity"
        );
        assert_eq!(key_count(&pool, community_uuid).await, 0);
        assert_eq!(event_count(&pool, community_uuid).await, 0);
        let err = match db
            .begin_keyed_stream_reservation_for_event(
                community,
                author,
                missing_key,
                &missing_event,
                None,
                None,
            )
            .await
        {
            Err(error) => error,
            Ok(_) => panic!("begin must still fail closed when reservation cap is exhausted"),
        };
        assert!(err.is_idempotency_unavailable());
        drop(held);
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY
        );

        let held_key = key_n(70);
        let held_event = stream_event(&keys, "uncommitted-invisible", 1_700_000_231, vec![]);
        let reservation = match db
            .begin_keyed_stream_reservation_for_event(
                community,
                author,
                held_key,
                &held_event,
                None,
                None,
            )
            .await
            .expect("reserve")
        {
            KeyedReserveOutcome::Reserved(reservation) => *reservation,
            _other => panic!("expected an open reservation"),
        };
        let started = std::time::Instant::now();
        let uncommitted = db
            .classify_committed_keyed_stream(community, author, held_key, &held_event, None, None)
            .await
            .expect("classify while a writer transaction is open");
        assert!(
            started.elapsed() < std::time::Duration::from_millis(200),
            "read-only classify must not wait on an uncommitted reservation transaction"
        );
        assert!(
            uncommitted.is_none(),
            "an uncommitted reservation must stay invisible to the committed classifier"
        );
        reservation.abort().await.expect("abort held reservation");
        assert_eq!(key_count(&pool, community_uuid).await, 0);
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn authoritative_reserve_after_committed_miss_is_one_winner() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let replay_key = key_n(71);
        let first = stream_event(&keys, "post-admit-race", 1_700_000_240, vec![]);
        let second = stream_event(&keys, "post-admit-race", 1_700_000_241, vec![]);

        let classified = db
            .classify_committed_keyed_stream(community, author, replay_key, &first, None, None)
            .await
            .expect("initial miss");
        assert!(classified.is_none());
        db.insert_keyed_stream_event_with_thread_metadata(
            community, author, replay_key, &first, None, None,
        )
        .await
        .expect("winner insert");
        let raced = db
            .begin_keyed_stream_reservation_for_event(
                community, author, replay_key, &second, None, None,
            )
            .await
            .expect("authoritative recheck");
        match raced {
            KeyedReserveOutcome::Replay { original_event_id } => {
                assert_eq!(&original_event_id, first.id.as_bytes());
            }
            _other => panic!("post-admission race must classify replay, not insert again"),
        }
        assert_eq!(key_count(&pool, community_uuid).await, 1);
        assert_eq!(event_count(&pool, community_uuid).await, 1);

        let conflict_key = key_n(72);
        let original = stream_event(&keys, "post-admit-one", 1_700_000_242, vec![]);
        let other = stream_event(&keys, "post-admit-two", 1_700_000_243, vec![]);
        assert!(db
            .classify_committed_keyed_stream(community, author, conflict_key, &original, None, None)
            .await
            .expect("conflict miss")
            .is_none());
        db.insert_keyed_stream_event_with_thread_metadata(
            community,
            author,
            conflict_key,
            &original,
            None,
            None,
        )
        .await
        .expect("conflict winner");
        let conflict = db
            .begin_keyed_stream_reservation_for_event(
                community,
                author,
                conflict_key,
                &other,
                None,
                None,
            )
            .await
            .expect("authoritative conflict recheck");
        match conflict {
            KeyedReserveOutcome::Conflict { existing_event_id } => {
                assert_eq!(&existing_event_id, original.id.as_bytes());
            }
            _other => panic!("post-admission different-intent race must classify conflict"),
        }
        assert_eq!(key_count(&pool, community_uuid).await, 2);
        assert_eq!(event_count(&pool, community_uuid).await, 2);
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY
        );
    }

    async fn one_connection_probe_pool(application_name: String) -> PgPool {
        let database_url = crate::test_support::database_url();
        PgPoolOptions::new()
            .max_connections(1)
            .after_connect(move |conn, _meta| {
                let application_name = application_name.clone();
                Box::pin(async move {
                    sqlx::query("SELECT set_config('application_name', $1, false)")
                        .bind(application_name)
                        .execute(&mut *conn)
                        .await?;
                    Ok(())
                })
            })
            .connect(&database_url)
            .await
            .expect("connect one-connection probe pool")
    }

    /// Catalog observation is the blocked-probe proof; this loop does not sleep.
    async fn wait_until_application_lock_wait(observer: &PgPool, application_name: &str) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            let waiting: bool = sqlx::query_scalar(
                r#"
                SELECT EXISTS (
                    SELECT 1
                      FROM pg_stat_activity
                     WHERE application_name = $1
                       AND wait_event_type = 'Lock'
                )
                "#,
            )
            .bind(application_name)
            .fetch_one(observer)
            .await
            .expect("observe probe lock wait");
            if waiting {
                return;
            }
            if std::time::Instant::now() >= deadline {
                panic!(
                    "pg_stat_activity never reported application_name={application_name} \
                     with wait_event_type=Lock"
                );
            }
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn classify_keyed_stream_before_admission_same_intent_observes_lock_then_replays() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let key = key_n(90);
        let holder_event = stream_event(&keys, "before-admit-same", 1_700_000_400, vec![]);
        let probe_event = stream_event(&keys, "before-admit-same", 1_700_000_401, vec![]);
        let application_name = format!("keyed-before-admit-replay-{}", Uuid::new_v4().simple());
        let probe_pool = one_connection_probe_pool(application_name.clone()).await;
        let probe_db = Db::from_pool(probe_pool.clone());

        let holder = match db
            .begin_keyed_stream_reservation_for_event(
                community,
                author,
                key,
                &holder_event,
                None,
                None,
            )
            .await
            .expect("holder reserve")
        {
            KeyedReserveOutcome::Reserved(reservation) => *reservation,
            KeyedReserveOutcome::Replay { .. } => {
                panic!("holder must reserve a new key, got replay")
            }
            KeyedReserveOutcome::Conflict { .. } => {
                panic!("holder must reserve a new key, got conflict")
            }
        };
        let probe = tokio::spawn({
            let probe_event = probe_event.clone();
            async move {
                probe_db
                    .classify_keyed_stream_before_admission_for_event(
                        community,
                        author,
                        key,
                        &probe_event,
                        None,
                        None,
                    )
                    .await
            }
        });
        wait_until_application_lock_wait(&pool, &application_name).await;
        holder
            .complete_for_event(&holder_event, None)
            .await
            .expect("commit holder");
        let classified = probe.await.expect("probe join").expect("probe classify");
        match classified {
            Some(KeyedCommittedOutcome::Replay { original_event_id }) => {
                assert_eq!(&original_event_id, holder_event.id.as_bytes());
            }
            Some(KeyedCommittedOutcome::Conflict { .. }) => {
                panic!("same intent must classify replay, got conflict")
            }
            None => panic!("same intent after holder commit must not miss"),
        }
        assert_eq!(key_count(&pool, community_uuid).await, 1);
        assert_eq!(event_count(&pool, community_uuid).await, 1);
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY
        );
        probe_pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn classify_keyed_stream_before_admission_different_intent_observes_lock_then_conflicts()
    {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let key = key_n(91);
        let holder_event = stream_event(&keys, "before-admit-one", 1_700_000_410, vec![]);
        let probe_event = stream_event(&keys, "before-admit-two", 1_700_000_411, vec![]);
        let application_name = format!("keyed-before-admit-conflict-{}", Uuid::new_v4().simple());
        let probe_pool = one_connection_probe_pool(application_name.clone()).await;
        let probe_db = Db::from_pool(probe_pool.clone());

        let holder = match db
            .begin_keyed_stream_reservation_for_event(
                community,
                author,
                key,
                &holder_event,
                None,
                None,
            )
            .await
            .expect("holder reserve")
        {
            KeyedReserveOutcome::Reserved(reservation) => *reservation,
            KeyedReserveOutcome::Replay { .. } => {
                panic!("holder must reserve a new key, got replay")
            }
            KeyedReserveOutcome::Conflict { .. } => {
                panic!("holder must reserve a new key, got conflict")
            }
        };
        let probe = tokio::spawn({
            let probe_event = probe_event.clone();
            async move {
                probe_db
                    .classify_keyed_stream_before_admission_for_event(
                        community,
                        author,
                        key,
                        &probe_event,
                        None,
                        None,
                    )
                    .await
            }
        });
        wait_until_application_lock_wait(&pool, &application_name).await;
        holder
            .complete_for_event(&holder_event, None)
            .await
            .expect("commit holder");
        let classified = probe.await.expect("probe join").expect("probe classify");
        match classified {
            Some(KeyedCommittedOutcome::Conflict { existing_event_id }) => {
                assert_eq!(&existing_event_id, holder_event.id.as_bytes());
            }
            Some(KeyedCommittedOutcome::Replay { .. }) => {
                panic!("different intent must classify conflict, got replay")
            }
            None => panic!("different intent after holder commit must not miss"),
        }
        assert_eq!(key_count(&pool, community_uuid).await, 1);
        assert_eq!(event_count(&pool, community_uuid).await, 1);
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY
        );
        probe_pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn classify_keyed_stream_before_admission_holder_rollback_returns_none() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let key = key_n(92);
        let holder_event = stream_event(&keys, "before-admit-abort", 1_700_000_420, vec![]);
        let probe_event = stream_event(&keys, "before-admit-abort", 1_700_000_421, vec![]);
        let application_name = format!("keyed-before-admit-abort-{}", Uuid::new_v4().simple());
        let probe_pool = one_connection_probe_pool(application_name.clone()).await;
        let probe_db = Db::from_pool(probe_pool.clone());

        let holder = match db
            .begin_keyed_stream_reservation_for_event(
                community,
                author,
                key,
                &holder_event,
                None,
                None,
            )
            .await
            .expect("holder reserve")
        {
            KeyedReserveOutcome::Reserved(reservation) => *reservation,
            KeyedReserveOutcome::Replay { .. } => {
                panic!("holder must reserve a new key, got replay")
            }
            KeyedReserveOutcome::Conflict { .. } => {
                panic!("holder must reserve a new key, got conflict")
            }
        };
        let probe = tokio::spawn({
            let probe_event = probe_event.clone();
            async move {
                probe_db
                    .classify_keyed_stream_before_admission_for_event(
                        community,
                        author,
                        key,
                        &probe_event,
                        None,
                        None,
                    )
                    .await
            }
        });
        wait_until_application_lock_wait(&pool, &application_name).await;
        holder.abort().await.expect("abort holder");
        let classified = probe.await.expect("probe join").expect("probe classify");
        match classified {
            None => {}
            Some(KeyedCommittedOutcome::Replay { .. }) => {
                panic!("holder rollback must not classify replay")
            }
            Some(KeyedCommittedOutcome::Conflict { .. }) => {
                panic!("holder rollback must not classify conflict")
            }
        }
        assert_eq!(key_count(&pool, community_uuid).await, 0);
        assert_eq!(event_count(&pool, community_uuid).await, 0);
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY
        );

        let retry = match db
            .begin_keyed_stream_reservation_for_event(
                community,
                author,
                key,
                &holder_event,
                None,
                None,
            )
            .await
            .expect("authoritative begin after rollback")
        {
            KeyedReserveOutcome::Reserved(reservation) => *reservation,
            KeyedReserveOutcome::Replay { .. } => {
                panic!("rolled-back key must reserve again, got replay")
            }
            KeyedReserveOutcome::Conflict { .. } => {
                panic!("rolled-back key must reserve again, got conflict")
            }
        };
        retry.abort().await.expect("abort retry reservation");
        assert_eq!(key_count(&pool, community_uuid).await, 0);
        assert_eq!(event_count(&pool, community_uuid).await, 0);
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY
        );
        probe_pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn classify_keyed_stream_before_admission_lock_timeout_fail_closes() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let key = key_n(93);
        let holder_event = stream_event(&keys, "before-admit-timeout", 1_700_000_430, vec![]);
        let probe_event = stream_event(&keys, "before-admit-timeout", 1_700_000_431, vec![]);
        let application_name = format!("keyed-before-admit-timeout-{}", Uuid::new_v4().simple());
        let probe_pool = one_connection_probe_pool(application_name.clone()).await;
        let probe_db = Db::from_pool(probe_pool.clone());

        let holder = match db
            .begin_keyed_stream_reservation_for_event(
                community,
                author,
                key,
                &holder_event,
                None,
                None,
            )
            .await
            .expect("holder reserve")
        {
            KeyedReserveOutcome::Reserved(reservation) => *reservation,
            KeyedReserveOutcome::Replay { .. } => {
                panic!("holder must reserve a new key, got replay")
            }
            KeyedReserveOutcome::Conflict { .. } => {
                panic!("holder must reserve a new key, got conflict")
            }
        };
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY - 1
        );
        let probe = tokio::spawn({
            let probe_event = probe_event.clone();
            async move {
                probe_db
                    .classify_keyed_stream_before_admission_for_event(
                        community,
                        author,
                        key,
                        &probe_event,
                        None,
                        None,
                    )
                    .await
            }
        });
        wait_until_application_lock_wait(&pool, &application_name).await;
        let timed = tokio::time::timeout(std::time::Duration::from_millis(5_500), probe).await;
        let joined = match timed {
            Ok(joined) => joined,
            Err(_elapsed) => panic!("hang guard: probe did not fail closed after lock timeout"),
        };
        let err = match joined.expect("probe join") {
            Ok(outcome) => panic!("lock timeout must fail closed, got {outcome:?}"),
            Err(error) => error,
        };
        assert!(
            err.is_idempotency_unavailable(),
            "lock timeout must map to idempotency unavailable, got {err}"
        );
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY - 1,
            "probe must not retain capacity beyond the open holder permit"
        );
        holder.abort().await.expect("abort holder");
        assert_eq!(key_count(&pool, community_uuid).await, 0);
        assert_eq!(event_count(&pool, community_uuid).await, 0);
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY
        );
        probe_pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn absent_key_uses_transactional_path_and_cannot_double_reserve() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let missing_key = key_n(66);
        let missing_event = stream_event(&keys, "missing-cap", 1_700_000_210, vec![]);

        let mut held = Vec::new();
        for i in 0..KEYED_RESERVATION_CAPACITY {
            held.push(
                try_acquire_keyed_reservation_capacity(Uuid::from_u128((i as u128) + 40_000))
                    .expect("test must exhaust reservation cap"),
            );
        }
        let err = match db
            .begin_keyed_stream_reservation_for_event(
                community,
                author,
                missing_key,
                &missing_event,
                None,
                None,
            )
            .await
        {
            Err(error) => error,
            Ok(_) => panic!("a missing key must still take the transactional capacity path"),
        };
        assert!(
            err.is_idempotency_unavailable(),
            "absent/new work must fail closed when reservation cap is exhausted, got {err}"
        );
        assert_eq!(key_count(&pool, community_uuid).await, 0);
        assert_eq!(event_count(&pool, community_uuid).await, 0);
        drop(held);
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY
        );

        let race_key = key_n(67);
        let left_event = stream_event(&keys, "race-new", 1_700_000_211, vec![]);
        let right_event = stream_event(&keys, "race-new", 1_700_000_212, vec![]);
        let (left, right) = tokio::join!(
            db.insert_keyed_stream_event_with_thread_metadata(
                community,
                author,
                race_key,
                &left_event,
                None,
                None,
            ),
            db.insert_keyed_stream_event_with_thread_metadata(
                community,
                author,
                race_key,
                &right_event,
                None,
                None,
            ),
        );
        let left = left.expect("left race");
        let right = right.expect("right race");
        let inserted = matches!(left, KeyedStreamInsert::Inserted { .. }) as u8
            + matches!(right, KeyedStreamInsert::Inserted { .. }) as u8;
        let replayed = matches!(left, KeyedStreamInsert::Replay { .. }) as u8
            + matches!(right, KeyedStreamInsert::Replay { .. }) as u8;
        assert_eq!(inserted, 1, "absent/new work must not double-reserve");
        assert_eq!(
            replayed, 1,
            "the losing first-insert race must classify replay"
        );
        assert_eq!(key_count(&pool, community_uuid).await, 1);
        assert_eq!(event_count(&pool, community_uuid).await, 1);
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn replay_returns_before_invalid_timestamp() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let key = key_n(2);
        let first = stream_event(&keys, "hello", 1_700_000_010, vec![]);
        db.insert_keyed_stream_event_with_thread_metadata(
            community, author, key, &first, None, None,
        )
        .await
        .expect("first");

        let far = stream_event(&keys, "hello", i64::MAX as u64, vec![]);
        let replay = db
            .insert_keyed_stream_event_with_thread_metadata(
                community, author, key, &far, None, None,
            )
            .await
            .expect("replay before chrono");
        assert!(matches!(
            replay,
            KeyedStreamInsert::Replay { original_event_id }
                if &original_event_id == first.id.as_bytes()
        ));
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn invalid_timestamp_on_first_insert_rolls_back_reservation() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let key = key_n(3);
        let far = stream_event(&keys, "hello", i64::MAX as u64, vec![]);
        let err = db
            .insert_keyed_stream_event_with_thread_metadata(
                community, author, key, &far, None, None,
            )
            .await
            .expect_err("chrono overflow after reserve");
        assert!(matches!(err, DbError::InvalidTimestamp(_)));
        assert_eq!(key_count(&pool, community_uuid).await, 0);
        assert_eq!(event_count(&pool, community_uuid).await, 0);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn nonexistent_channel_fk_rolls_back_reservation_event_thread_mentions_push() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let key = key_n(4);
        let mention = keys.public_key().to_hex();
        let event = stream_event(
            &keys,
            "hello",
            1_700_000_020,
            vec![Tag::parse(["p", &mention]).expect("p")],
        );
        let missing = Uuid::new_v4();
        let meta = bound_meta(&event, missing);
        let err = db
            .insert_keyed_stream_event_with_thread_metadata(
                community,
                author,
                key,
                &event,
                Some(missing),
                Some(meta),
            )
            .await
            .expect_err("thread_metadata fk");
        assert!(matches!(err, DbError::Sqlx(_)));
        assert_eq!(key_count(&pool, community_uuid).await, 0);
        assert_eq!(event_count(&pool, community_uuid).await, 0);
        let mentions: i64 =
            sqlx::query_scalar("SELECT count(*) FROM event_mentions WHERE community_id = $1")
                .bind(community_uuid)
                .fetch_one(&pool)
                .await
                .expect("mentions");
        assert_eq!(mentions, 0);
        let threads: i64 =
            sqlx::query_scalar("SELECT count(*) FROM thread_metadata WHERE community_id = $1")
                .bind(community_uuid)
                .fetch_one(&pool)
                .await
                .expect("threads");
        assert_eq!(threads, 0);
        let push: i64 =
            sqlx::query_scalar("SELECT count(*) FROM push_match_queue WHERE community_id = $1")
                .bind(community_uuid)
                .fetch_one(&pool)
                .await
                .expect("push");
        assert_eq!(push, 0);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn after_fk_rollback_same_key_can_insert() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let channel = make_test_channel(&pool, community_uuid).await;
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let key = key_n(5);
        let failing = stream_event(&keys, "hello", 1_700_000_030, vec![]);
        let missing = Uuid::new_v4();
        let meta = bound_meta(&failing, missing);
        db.insert_keyed_stream_event_with_thread_metadata(
            community,
            author,
            key,
            &failing,
            Some(missing),
            Some(meta),
        )
        .await
        .expect_err("fk fail");

        let ok = stream_event(&keys, "hello", 1_700_000_031, vec![]);
        let inserted = db
            .insert_keyed_stream_event_with_thread_metadata(
                community,
                author,
                key,
                &ok,
                Some(channel),
                None,
            )
            .await
            .expect("reserve after rollback");
        assert!(inserted.should_dispatch());
        assert_eq!(key_count(&pool, community_uuid).await, 1);
        assert_eq!(event_count(&pool, community_uuid).await, 1);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn concurrent_same_key_same_intent_and_different_intent() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let same_key = key_n(6);
        let a = stream_event(&keys, "same", 1_700_000_040, vec![]);
        let b = stream_event(&keys, "same", 1_700_000_041, vec![]);
        let (left, right) = tokio::join!(
            db.insert_keyed_stream_event_with_thread_metadata(
                community, author, same_key, &a, None, None
            ),
            db.insert_keyed_stream_event_with_thread_metadata(
                community, author, same_key, &b, None, None
            ),
        );
        let left = left.expect("left");
        let right = right.expect("right");
        let inserted = matches!(left, KeyedStreamInsert::Inserted { .. }) as u8
            + matches!(right, KeyedStreamInsert::Inserted { .. }) as u8;
        let replayed = matches!(left, KeyedStreamInsert::Replay { .. }) as u8
            + matches!(right, KeyedStreamInsert::Replay { .. }) as u8;
        assert_eq!(inserted, 1);
        assert_eq!(replayed, 1);
        assert_eq!(event_count(&pool, community_uuid).await, 1);

        let other_key = key_n(7);
        let c = stream_event(&keys, "one", 1_700_000_042, vec![]);
        let d = stream_event(&keys, "two", 1_700_000_043, vec![]);
        let (left, right) = tokio::join!(
            db.insert_keyed_stream_event_with_thread_metadata(
                community, author, other_key, &c, None, None
            ),
            db.insert_keyed_stream_event_with_thread_metadata(
                community, author, other_key, &d, None, None
            ),
        );
        let left = left.expect("left2");
        let right = right.expect("right2");
        let outcomes = [left, right];
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| matches!(o, KeyedStreamInsert::Inserted { .. }))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| matches!(o, KeyedStreamInsert::Conflict { .. }))
                .count(),
            1
        );
        assert_eq!(event_count(&pool, community_uuid).await, 2);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn reserve_abort_does_not_orphan_so_retry_is_new_work() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let key = key_n(61);
        let event = stream_event(&keys, "abort", 1_700_000_044, vec![]);
        match db
            .begin_keyed_stream_reservation_for_event(community, author, key, &event, None, None)
            .await
            .expect("reserve")
        {
            KeyedReserveOutcome::Reserved(reservation) => {
                reservation.abort().await.expect("abort");
            }
            _other => panic!("expected a new reservation, got replay/conflict"),
        }
        assert_eq!(key_count(&pool, community_uuid).await, 0);
        assert_eq!(event_count(&pool, community_uuid).await, 0);
        let inserted = db
            .insert_keyed_stream_event_with_thread_metadata(
                community, author, key, &event, None, None,
            )
            .await
            .expect("retry after abort");
        assert!(inserted.should_dispatch());
        assert_eq!(key_count(&pool, community_uuid).await, 1);
        assert_eq!(event_count(&pool, community_uuid).await, 1);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn pool_owned_reservation_survives_local_db_drop() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let key = key_n(63);
        let event = stream_event(&keys, "lifetime", 1_700_000_048, vec![]);
        let waiter = tokio::spawn({
            let event = event.clone();
            let pool = pool.clone();
            async move {
                let db2 = Db::from_pool(pool);
                db2.begin_keyed_stream_reservation_for_event(
                    community, author, key, &event, None, None,
                )
                .await
            }
        });
        let outcome = waiter.await.expect("join").expect("reserve after db drop");
        match outcome {
            KeyedReserveOutcome::Reserved(reservation) => {
                assert_eq!(
                    keyed_reservation_available_permits(),
                    KEYED_RESERVATION_CAPACITY - 1
                );
                reservation.abort().await.expect("abort");
            }
            _ => panic!("expected a new reservation after local Db drop, got replay/conflict"),
        }
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY
        );
        assert_eq!(key_count(&pool, community_uuid).await, 0);
        assert_eq!(event_count(&pool, community_uuid).await, 0);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn timeout_abort_releases_capacity_and_retry_is_new_not_replay() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let key = key_n(64);
        let event = stream_event(&keys, "timeout", 1_700_000_049, vec![]);
        let reservation = match db
            .begin_keyed_stream_reservation_for_event(community, author, key, &event, None, None)
            .await
            .expect("reserve")
        {
            KeyedReserveOutcome::Reserved(reservation) => reservation,
            _ => panic!("expected a new reservation, got replay/conflict"),
        };
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY - 1
        );
        let pending = std::future::pending::<()>();
        let timed_out = tokio::time::timeout(std::time::Duration::from_millis(20), pending).await;
        assert!(timed_out.is_err(), "admission future must not resolve");
        reservation.abort().await.expect("timeout cleanup abort");
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY
        );
        assert_eq!(key_count(&pool, community_uuid).await, 0);
        assert_eq!(event_count(&pool, community_uuid).await, 0);
        let retry = db
            .insert_keyed_stream_event_with_thread_metadata(
                community, author, key, &event, None, None,
            )
            .await
            .expect("retry after timeout abort");
        assert!(
            retry.should_dispatch(),
            "retry after timeout must be new work, not replay"
        );
        assert_eq!(key_count(&pool, community_uuid).await, 1);
        assert_eq!(event_count(&pool, community_uuid).await, 1);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn concurrent_begin_cannot_both_treat_the_same_key_as_new() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let same_key = key_n(62);
        let first_event = stream_event(&keys, "same", 1_700_000_045, vec![]);
        let second_event = stream_event(&keys, "same", 1_700_000_046, vec![]);
        let reserved = match db
            .begin_keyed_stream_reservation_for_event(
                community,
                author,
                same_key,
                &first_event,
                None,
                None,
            )
            .await
            .expect("first begin")
        {
            KeyedReserveOutcome::Reserved(reservation) => reservation,
            _other => panic!("first caller must reserve, got replay/conflict"),
        };
        let db2 = Db::from_pool(pool.clone());
        let waiter = tokio::spawn({
            let second_event = second_event.clone();
            async move {
                db2.begin_keyed_stream_reservation_for_event(
                    community,
                    author,
                    same_key,
                    &second_event,
                    None,
                    None,
                )
                .await
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        reserved
            .complete_for_event(&first_event, None)
            .await
            .expect("complete first");
        let second = waiter.await.expect("join").expect("second begin");
        assert!(
            matches!(second, KeyedReserveOutcome::Replay { .. }),
            "second identical intent must classify as replay, not a second reservation"
        );
        assert_eq!(event_count(&pool, community_uuid).await, 1);
        assert_eq!(key_count(&pool, community_uuid).await, 1);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn two_keys_same_event_one_fresh_row() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let event = stream_event(&keys, "shared", 1_700_000_050, vec![]);
        let first = db
            .insert_keyed_stream_event_with_thread_metadata(
                community,
                author,
                key_n(8),
                &event,
                None,
                None,
            )
            .await
            .expect("first key");
        assert!(first.should_dispatch());
        let second = db
            .insert_keyed_stream_event_with_thread_metadata(
                community,
                author,
                key_n(9),
                &event,
                None,
                None,
            )
            .await
            .expect("second key");
        assert!(!second.should_dispatch());
        assert!(matches!(
            second,
            KeyedStreamInsert::BoundExisting { event_id }
                if &event_id == event.id.as_bytes()
        ));
        assert_eq!(key_count(&pool, community_uuid).await, 2);
        assert_eq!(event_count(&pool, community_uuid).await, 1);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn preexisting_event_binds_without_derived_mutation() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let channel = make_test_channel(&pool, community_uuid).await;
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let mention = keys.public_key().to_hex();
        let event = stream_event(
            &keys,
            "preexisting",
            1_700_000_060,
            vec![Tag::parse(["p", &mention]).expect("p")],
        );
        insert_event_with_thread_metadata(&pool, community, &event, Some(channel), None)
            .await
            .expect("unkeyed insert");
        let mentions_before: i64 =
            sqlx::query_scalar("SELECT count(*) FROM event_mentions WHERE community_id = $1")
                .bind(community_uuid)
                .fetch_one(&pool)
                .await
                .expect("mentions");
        let bound = db
            .insert_keyed_stream_event_with_thread_metadata(
                community,
                author,
                key_n(10),
                &event,
                Some(channel),
                None,
            )
            .await
            .expect("bind existing");
        assert!(!bound.should_dispatch());
        assert!(matches!(bound, KeyedStreamInsert::BoundExisting { .. }));
        let mentions_after: i64 =
            sqlx::query_scalar("SELECT count(*) FROM event_mentions WHERE community_id = $1")
                .bind(community_uuid)
                .fetch_one(&pool)
                .await
                .expect("mentions after");
        assert_eq!(mentions_before, mentions_after);
        assert_eq!(event_count(&pool, community_uuid).await, 1);
        assert_eq!(key_count(&pool, community_uuid).await, 1);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn author_kind_meta_mismatch_zero_rows_and_isolation() {
        let pool = setup_pool().await;
        let community_a = make_test_community(&pool).await;
        let community_b = make_test_community(&pool).await;
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let other = Keys::generate();
        let author = keys.public_key().to_bytes();
        let event = stream_event(&keys, "iso", 1_700_000_070, vec![]);
        let note = EventBuilder::new(Kind::TextNote, "iso")
            .custom_created_at(Timestamp::from(1_700_000_070))
            .sign_with_keys(&keys)
            .expect("note");

        assert!(matches!(
            db.insert_keyed_stream_event_with_thread_metadata(
                CommunityId::from_uuid(community_a),
                other.public_key().to_bytes(),
                key_n(11),
                &event,
                None,
                None,
            )
            .await,
            Err(error) if error.to_string().contains("idempotency author")
        ));
        assert!(matches!(
            db.insert_keyed_stream_event_with_thread_metadata(
                CommunityId::from_uuid(community_a),
                author,
                key_n(11),
                &note,
                None,
                None,
            )
            .await,
            Err(error) if error.to_string().contains("not supported for this event kind")
        ));
        let channel = make_test_channel(&pool, community_a).await;
        let zeros = [0u8; 32];
        let mut meta = bound_meta(&event, channel);
        meta.event_id = &zeros;
        assert!(matches!(
            db.insert_keyed_stream_event_with_thread_metadata(
                CommunityId::from_uuid(community_a),
                author,
                key_n(11),
                &event,
                Some(channel),
                Some(meta),
            )
            .await,
            Err(error) if error.to_string().contains("thread metadata")
        ));
        assert_eq!(key_count(&pool, community_a).await, 0);
        assert_eq!(event_count(&pool, community_a).await, 0);

        db.insert_keyed_stream_event_with_thread_metadata(
            CommunityId::from_uuid(community_a),
            author,
            key_n(12),
            &event,
            None,
            None,
        )
        .await
        .expect("community a");
        db.insert_keyed_stream_event_with_thread_metadata(
            CommunityId::from_uuid(community_b),
            author,
            key_n(12),
            &event,
            None,
            None,
        )
        .await
        .expect("community b");
        let other_event = stream_event(&other, "iso", 1_700_000_070, vec![]);
        db.insert_keyed_stream_event_with_thread_metadata(
            CommunityId::from_uuid(community_a),
            other.public_key().to_bytes(),
            key_n(12),
            &other_event,
            None,
            None,
        )
        .await
        .expect("other author");
        assert_eq!(key_count(&pool, community_a).await, 2);
        assert_eq!(key_count(&pool, community_b).await, 1);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn new_pool_replay_event_delete_keeps_key_purge_and_update_rejected() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let key = key_n(13);
        let event = stream_event(&keys, "persist", 1_700_000_080, vec![]);
        db.insert_keyed_stream_event_with_thread_metadata(
            community, author, key, &event, None, None,
        )
        .await
        .expect("insert");

        let db2 = Db::from_pool(pool.clone());
        let replay = db2
            .insert_keyed_stream_event_with_thread_metadata(
                community, author, key, &event, None, None,
            )
            .await
            .expect("new pool replay");
        assert!(matches!(replay, KeyedStreamInsert::Replay { .. }));

        crate::event::soft_delete_event(&pool, community, event.id.as_bytes())
            .await
            .expect("soft delete");
        assert_eq!(key_count(&pool, community_uuid).await, 1);

        let updated = sqlx::query(
            "UPDATE event_idempotency_keys SET created_at = now() WHERE community_id = $1",
        )
        .bind(community_uuid)
        .execute(&pool)
        .await;
        assert!(updated.is_err(), "UPDATE must be rejected");

        sqlx::query("DELETE FROM event_idempotency_keys WHERE community_id = $1")
            .bind(community_uuid)
            .execute(&pool)
            .await
            .expect("community purge delete");
        assert_eq!(key_count(&pool, community_uuid).await, 0);
    }

    async fn isolated_schema_pool() -> (String, PgPool, PgPool) {
        let admin = setup_pool().await;
        let schema = format!("mi_{}", Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await
            .expect("create isolated schema");
        let database_url = crate::test_support::database_url();
        let search_path = format!("{schema}, public");
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .after_connect(move |conn, _meta| {
                let search_path = search_path.clone();
                Box::pin(async move {
                    sqlx::query("SELECT set_config('search_path', $1, false)")
                        .bind(search_path)
                        .execute(&mut *conn)
                        .await?;
                    Ok(())
                })
            })
            .connect(&database_url)
            .await
            .expect("isolated pool");
        for stmt in [
            r#"CREATE TABLE communities (
                id UUID PRIMARY KEY,
                deletion_state TEXT NOT NULL DEFAULT 'active'
                    CHECK (deletion_state IN ('active', 'quiescing', 'fenced', 'tombstone'))
            )"#,
            r#"CREATE TABLE event_idempotency_keys (
                community_id UUID NOT NULL,
                author_pubkey BYTEA NOT NULL,
                idempotency_key BYTEA NOT NULL,
                intent_hash BYTEA NOT NULL,
                event_id BYTEA NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
                reservation_witness BYTEA NOT NULL,
                CONSTRAINT event_idempotency_keys_pkey
                    PRIMARY KEY (community_id, author_pubkey, idempotency_key),
                CONSTRAINT event_idempotency_keys_author_pubkey_check
                    CHECK (octet_length(author_pubkey) = 32),
                CONSTRAINT event_idempotency_keys_idempotency_key_check
                    CHECK (octet_length(idempotency_key) = 32),
                CONSTRAINT event_idempotency_keys_intent_hash_check
                    CHECK (octet_length(intent_hash) = 32),
                CONSTRAINT event_idempotency_keys_event_id_check
                    CHECK (octet_length(event_id) = 32),
                CONSTRAINT event_idempotency_keys_reservation_witness_check
                    CHECK (octet_length(reservation_witness) = 32),
                CONSTRAINT event_idempotency_keys_community_id_fkey
                    FOREIGN KEY (community_id) REFERENCES communities(id)
            )"#,
            r#"CREATE INDEX idx_event_idempotency_keys_created_at
                ON event_idempotency_keys
                (created_at, community_id, author_pubkey, idempotency_key)"#,
            r#"CREATE INDEX idx_event_idempotency_keys_community_created_at
                ON event_idempotency_keys
                (community_id, created_at, author_pubkey, idempotency_key)"#,
            r#"CREATE FUNCTION prevent_event_idempotency_keys_update()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $$
                BEGIN
                    RAISE EXCEPTION 'event_idempotency_keys rows are immutable'
                        USING ERRCODE = 'integrity_constraint_violation';
                END;
                $$"#,
            r#"CREATE TRIGGER event_idempotency_keys_immutable
                BEFORE UPDATE ON event_idempotency_keys
                FOR EACH ROW
                EXECUTE FUNCTION prevent_event_idempotency_keys_update()"#,
            r#"CREATE FUNCTION community_deletion_lock_key(p_community_id uuid)
                RETURNS bigint
                LANGUAGE sql
                IMMUTABLE
                PARALLEL SAFE
                AS $$
                    SELECT hashtextextended(
                        'buzz-community-deletion:' || p_community_id::text,
                        0
                    )
                $$"#,
            r#"CREATE TABLE event_idempotency_reaper_cursor (
                id SMALLINT PRIMARY KEY CHECK (id = 1),
                after_community_id UUID
            )"#,
            r#"INSERT INTO event_idempotency_reaper_cursor (id, after_community_id)
                VALUES (1, NULL)"#,
            r#"CREATE TABLE _operator_global_tables (
                table_name TEXT PRIMARY KEY,
                reason TEXT NOT NULL
            )"#,
            r#"INSERT INTO _operator_global_tables (table_name, reason) VALUES
                ('event_idempotency_reaper_cursor',
                 'singleton operator-global NIP-MI expired-key reaper cursor; never tenant-scoped')"#,
        ] {
            sqlx::query(stmt)
                .execute(&pool)
                .await
                .unwrap_or_else(|e| panic!("install canonical object: {e}"));
        }
        (schema, admin, pool)
    }

    async fn drop_isolated_schema(admin: &PgPool, schema: &str) {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA IF EXISTS {schema} CASCADE"
        )))
        .execute(admin)
        .await
        .expect("drop isolated schema");
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn require_schema_passes_and_rejects_clock_and_noop_function_drifts() {
        let (schema, admin, pool) = isolated_schema_pool().await;
        let db = Db::from_pool(pool.clone());

        async fn drop_r5b_probes(pool: &PgPool) -> std::result::Result<(), sqlx::Error> {
            sqlx::query(
                "ALTER TABLE event_idempotency_keys \
                 DROP COLUMN IF EXISTS r5b_probe_nullable, \
                 DROP COLUMN IF EXISTS r5b_probe_defaulted, \
                 DROP COLUMN IF EXISTS r5b_probe_identity, \
                 DROP COLUMN IF EXISTS r5b_probe_generated, \
                 DROP COLUMN IF EXISTS r5b_probe_unsafe",
            )
            .execute(pool)
            .await?;
            sqlx::query(
                "ALTER TABLE event_idempotency_reaper_cursor \
                 DROP COLUMN IF EXISTS r5b_probe_nullable, \
                 DROP COLUMN IF EXISTS r5b_probe_defaulted, \
                 DROP COLUMN IF EXISTS r5b_probe_identity, \
                 DROP COLUMN IF EXISTS r5b_probe_generated, \
                 DROP COLUMN IF EXISTS r5b_probe_unsafe, \
                 DROP COLUMN IF EXISTS community_id",
            )
            .execute(pool)
            .await?;
            Ok(())
        }

        async fn probe_shape(
            pool: &PgPool,
            table: &str,
            column: &str,
        ) -> std::result::Result<(bool, bool, bool, Option<String>), sqlx::Error> {
            sqlx::query_as(
                r#"
                SELECT att.attnotnull,
                       (att.attidentity = 'a'),
                       (att.attgenerated = 's'),
                       pg_get_expr(def.adbin, def.adrelid)
                  FROM pg_attribute AS att
                  JOIN pg_class AS tbl ON tbl.oid = att.attrelid
                  JOIN pg_namespace AS ns ON ns.oid = tbl.relnamespace
                  LEFT JOIN pg_attrdef AS def
                    ON def.adrelid = att.attrelid AND def.adnum = att.attnum
                 WHERE ns.nspname = current_schema()
                   AND tbl.relname = $1
                   AND att.attname = $2
                   AND att.attnum > 0
                   AND NOT att.attisdropped
                "#,
            )
            .bind(table)
            .bind(column)
            .fetch_one(pool)
            .await
        }

        let outcome = async {
            db.require_event_idempotency_schema()
                .await
                .map_err(|error| format!("canonical isolated schema must pass: {error}"))?;

            sqlx::query(
                "ALTER TABLE event_idempotency_keys \
                 ADD COLUMN r5b_probe_nullable TEXT, \
                 ADD COLUMN r5b_probe_defaulted TEXT NOT NULL DEFAULT 'r5b-keys-default', \
                 ADD COLUMN r5b_probe_identity BIGINT GENERATED ALWAYS AS IDENTITY, \
                 ADD COLUMN r5b_probe_generated BYTEA GENERATED ALWAYS AS (event_id) STORED",
            )
            .execute(&pool)
            .await
            .map_err(|error| format!("add keys omission-safe extras: {error}"))?;
            sqlx::query(
                "ALTER TABLE event_idempotency_reaper_cursor \
                 ADD COLUMN r5b_probe_nullable TEXT, \
                 ADD COLUMN r5b_probe_defaulted TEXT NOT NULL DEFAULT 'r5b-cursor-default', \
                 ADD COLUMN r5b_probe_identity BIGINT GENERATED ALWAYS AS IDENTITY, \
                 ADD COLUMN r5b_probe_generated SMALLINT GENERATED ALWAYS AS (id) STORED",
            )
            .execute(&pool)
            .await
            .map_err(|error| format!("add cursor omission-safe extras: {error}"))?;

            let community = Uuid::new_v4();
            sqlx::query("INSERT INTO communities (id) VALUES ($1)")
                .bind(community)
                .execute(&pool)
                .await
                .map_err(|error| format!("insert probe community: {error}"))?;
            let author = [0xC3_u8; 32];
            let key = [0xD4_u8; 32];
            let intent = [0xE5_u8; 32];
            let event_id = [0xA1_u8; 32];
            let witness = [0xB2_u8; 32];
            sqlx::query(
                r#"
                INSERT INTO event_idempotency_keys (
                    community_id, author_pubkey, idempotency_key, intent_hash, event_id,
                    created_at, reservation_witness, r5b_probe_nullable
                ) VALUES ($1, $2, $3, $4, $5, clock_timestamp(), $6, 'r5b-keys-nullable')
                "#,
            )
            .bind(community)
            .bind(author.as_slice())
            .bind(key.as_slice())
            .bind(intent.as_slice())
            .bind(event_id.as_slice())
            .bind(witness.as_slice())
            .execute(&pool)
            .await
            .map_err(|error| format!("insert keys sentinel: {error}"))?;
            sqlx::query(
                "UPDATE event_idempotency_reaper_cursor \
                    SET r5b_probe_nullable = 'r5b-cursor-nullable' \
                  WHERE id = 1",
            )
            .execute(&pool)
            .await
            .map_err(|error| format!("update cursor nullable sentinel: {error}"))?;

            let keys_before: (Option<String>, String, i64, Vec<u8>) = sqlx::query_as(
                "SELECT r5b_probe_nullable, r5b_probe_defaulted, r5b_probe_identity, \
                        r5b_probe_generated \
                   FROM event_idempotency_keys WHERE community_id = $1",
            )
            .bind(community)
            .fetch_one(&pool)
            .await
            .map_err(|error| format!("read keys probe sentinels: {error}"))?;
            let cursor_before: (Option<String>, String, i64, i16) = sqlx::query_as(
                "SELECT r5b_probe_nullable, r5b_probe_defaulted, r5b_probe_identity, \
                        r5b_probe_generated \
                   FROM event_idempotency_reaper_cursor WHERE id = 1",
            )
            .fetch_one(&pool)
            .await
            .map_err(|error| format!("read cursor probe sentinels: {error}"))?;
            if keys_before.0.as_deref() != Some("r5b-keys-nullable")
                || keys_before.1 != "r5b-keys-default"
                || keys_before.3.as_slice() != event_id.as_slice()
            {
                return Err(format!(
                    "keys probe sentinels were not stored: {keys_before:?}"
                ));
            }
            if cursor_before.0.as_deref() != Some("r5b-cursor-nullable")
                || cursor_before.1 != "r5b-cursor-default"
                || cursor_before.3 != 1
            {
                return Err(format!(
                    "cursor probe sentinels were not stored: {cursor_before:?}"
                ));
            }

            let keys_shapes_before = (
                probe_shape(&pool, "event_idempotency_keys", "r5b_probe_nullable").await,
                probe_shape(&pool, "event_idempotency_keys", "r5b_probe_defaulted").await,
                probe_shape(&pool, "event_idempotency_keys", "r5b_probe_identity").await,
                probe_shape(&pool, "event_idempotency_keys", "r5b_probe_generated").await,
            );
            let cursor_shapes_before = (
                probe_shape(
                    &pool,
                    "event_idempotency_reaper_cursor",
                    "r5b_probe_nullable",
                )
                .await,
                probe_shape(
                    &pool,
                    "event_idempotency_reaper_cursor",
                    "r5b_probe_defaulted",
                )
                .await,
                probe_shape(
                    &pool,
                    "event_idempotency_reaper_cursor",
                    "r5b_probe_identity",
                )
                .await,
                probe_shape(
                    &pool,
                    "event_idempotency_reaper_cursor",
                    "r5b_probe_generated",
                )
                .await,
            );
            let keys_shapes_before = (
                keys_shapes_before
                    .0
                    .map_err(|error| format!("keys nullable shape: {error}"))?,
                keys_shapes_before
                    .1
                    .map_err(|error| format!("keys defaulted shape: {error}"))?,
                keys_shapes_before
                    .2
                    .map_err(|error| format!("keys identity shape: {error}"))?,
                keys_shapes_before
                    .3
                    .map_err(|error| format!("keys generated shape: {error}"))?,
            );
            let cursor_shapes_before = (
                cursor_shapes_before
                    .0
                    .map_err(|error| format!("cursor nullable shape: {error}"))?,
                cursor_shapes_before
                    .1
                    .map_err(|error| format!("cursor defaulted shape: {error}"))?,
                cursor_shapes_before
                    .2
                    .map_err(|error| format!("cursor identity shape: {error}"))?,
                cursor_shapes_before
                    .3
                    .map_err(|error| format!("cursor generated shape: {error}"))?,
            );
            if keys_shapes_before.0 != (false, false, false, None)
                || !keys_shapes_before.1 .0
                || keys_shapes_before.1 .1
                || keys_shapes_before.1 .2
                || keys_shapes_before.1 .3.is_none()
                || !keys_shapes_before.2 .1
                || !keys_shapes_before.3 .2
                || cursor_shapes_before.0 != (false, false, false, None)
                || !cursor_shapes_before.1 .0
                || cursor_shapes_before.1 .1
                || cursor_shapes_before.1 .2
                || cursor_shapes_before.1 .3.is_none()
                || !cursor_shapes_before.2 .1
                || !cursor_shapes_before.3 .2
            {
                return Err(format!(
                    "omission-safe probe catalog shapes are wrong: keys={keys_shapes_before:?} \
                     cursor={cursor_shapes_before:?}"
                ));
            }

            db.require_event_idempotency_schema()
                .await
                .map_err(|error| {
                    format!("startup gate must accept omission-safe extras: {error}")
                })?;

            let keys_after: (Option<String>, String, i64, Vec<u8>) = sqlx::query_as(
                "SELECT r5b_probe_nullable, r5b_probe_defaulted, r5b_probe_identity, \
                        r5b_probe_generated \
                   FROM event_idempotency_keys WHERE community_id = $1",
            )
            .bind(community)
            .fetch_one(&pool)
            .await
            .map_err(|error| format!("reread keys probe sentinels: {error}"))?;
            let cursor_after: (Option<String>, String, i64, i16) = sqlx::query_as(
                "SELECT r5b_probe_nullable, r5b_probe_defaulted, r5b_probe_identity, \
                        r5b_probe_generated \
                   FROM event_idempotency_reaper_cursor WHERE id = 1",
            )
            .fetch_one(&pool)
            .await
            .map_err(|error| format!("reread cursor probe sentinels: {error}"))?;
            if keys_after != keys_before || cursor_after != cursor_before {
                return Err(format!(
                    "startup gate mutated probe data: keys {keys_before:?}->{keys_after:?}, \
                     cursor {cursor_before:?}->{cursor_after:?}"
                ));
            }

            sqlx::query("ALTER TABLE event_idempotency_reaper_cursor ADD COLUMN community_id UUID")
                .execute(&pool)
                .await
                .map_err(|error| format!("add forbidden cursor community_id: {error}"))?;
            let forbidden = db.require_event_idempotency_schema().await;
            sqlx::query("ALTER TABLE event_idempotency_reaper_cursor DROP COLUMN community_id")
                .execute(&pool)
                .await
                .map_err(|error| format!("drop forbidden cursor community_id: {error}"))?;
            match forbidden {
                Ok(()) => {
                    return Err("forbidden cursor community_id must fail closed".to_owned());
                }
                Err(error) => {
                    let text = error.to_string();
                    if !text.contains("community_id") {
                        return Err(format!(
                            "forbidden cursor community_id error must identify the column: {text}"
                        ));
                    }
                }
            }
            db.require_event_idempotency_schema()
                .await
                .map_err(|error| {
                    format!("gate must pass after dropping forbidden community_id: {error}")
                })?;

            sqlx::query(
                "ALTER TABLE event_idempotency_keys \
                 ADD COLUMN r5b_probe_unsafe TEXT NOT NULL DEFAULT 'unsafe'",
            )
            .execute(&pool)
            .await
            .map_err(|error| format!("add unsafe extra with default: {error}"))?;
            sqlx::query(
                "ALTER TABLE event_idempotency_keys ALTER COLUMN r5b_probe_unsafe DROP DEFAULT",
            )
            .execute(&pool)
            .await
            .map_err(|error| format!("drop unsafe extra default: {error}"))?;
            let unsafe_err = db.require_event_idempotency_schema().await;
            let unsafe_still_present: bool = sqlx::query_scalar(
                "SELECT EXISTS ( \
                     SELECT 1 FROM pg_attribute AS att \
                     JOIN pg_class AS tbl ON tbl.oid = att.attrelid \
                     JOIN pg_namespace AS ns ON ns.oid = tbl.relnamespace \
                    WHERE ns.nspname = current_schema() \
                      AND tbl.relname = 'event_idempotency_keys' \
                      AND att.attname = 'r5b_probe_unsafe' \
                      AND att.attnum > 0 AND NOT att.attisdropped \
                 )",
            )
            .fetch_one(&pool)
            .await
            .map_err(|error| format!("check unsafe extra survived: {error}"))?;
            sqlx::query("ALTER TABLE event_idempotency_keys DROP COLUMN r5b_probe_unsafe")
                .execute(&pool)
                .await
                .map_err(|error| format!("drop unsafe extra: {error}"))?;
            if !unsafe_still_present {
                return Err("unsafe extra must fail closed without being dropped".to_owned());
            }
            match unsafe_err {
                Ok(()) => {
                    return Err(
                        "extra NOT NULL column with no supplier must fail closed".to_owned()
                    );
                }
                Err(error) => {
                    let text = error.to_string();
                    if !text.contains("extra NOT NULL") {
                        return Err(format!(
                            "unsafe extra error must identify the omission-safety failure: {text}"
                        ));
                    }
                }
            }
            db.require_event_idempotency_schema()
                .await
                .map_err(|error| format!("gate must pass after dropping unsafe extra: {error}"))?;

            sqlx::query(
                "ALTER TABLE event_idempotency_keys ALTER COLUMN created_at SET DEFAULT now()",
            )
            .execute(&pool)
            .await
            .map_err(|error| format!("tamper created_at default: {error}"))?;
            let default_err = db.require_event_idempotency_schema().await;
            sqlx::query(
                "ALTER TABLE event_idempotency_keys \
                 ALTER COLUMN created_at SET DEFAULT clock_timestamp()",
            )
            .execute(&pool)
            .await
            .map_err(|error| format!("restore created_at default: {error}"))?;
            if default_err.is_ok() {
                return Err("DEFAULT now() must fail closed".to_owned());
            }
            db.require_event_idempotency_schema()
                .await
                .map_err(|error| format!("restored clock_timestamp default must pass: {error}"))?;

            sqlx::query(
                r#"
                CREATE OR REPLACE FUNCTION prevent_event_idempotency_keys_update()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $$
                BEGIN
                    RETURN NEW;
                END;
                $$
                "#,
            )
            .execute(&pool)
            .await
            .map_err(|error| format!("tamper function body: {error}"))?;
            let fn_err = db.require_event_idempotency_schema().await;
            sqlx::query(
                r#"
                CREATE OR REPLACE FUNCTION prevent_event_idempotency_keys_update()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $$
                BEGIN
                    RAISE EXCEPTION 'event_idempotency_keys rows are immutable'
                        USING ERRCODE = 'integrity_constraint_violation';
                END;
                $$
                "#,
            )
            .execute(&pool)
            .await
            .map_err(|error| format!("restore function body: {error}"))?;
            if fn_err.is_ok() {
                return Err("RETURN NEW replacement must fail closed".to_owned());
            }

            sqlx::query("ALTER TABLE event_idempotency_keys DROP COLUMN reservation_witness")
                .execute(&pool)
                .await
                .map_err(|error| format!("drop required reservation_witness: {error}"))?;
            let missing = db.require_event_idempotency_schema().await;
            if missing.is_ok() {
                return Err("missing required column must fail closed".to_owned());
            }
            Ok(())
        }
        .await;

        let cleanup = drop_r5b_probes(&pool).await;
        drop_isolated_schema(&admin, &schema).await;
        if let Err(error) = cleanup {
            panic!("probe columns must drop with scoped ALTER TABLE: {error}");
        }
        outcome.expect("schema gate assertions");
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn reap_expired_keys_keeps_unexpired_and_honors_batch_limit() {
        let (schema, admin, pool) = isolated_schema_pool().await;
        let install = sqlx::query(
            r#"
            CREATE FUNCTION community_write_allowed(p_community_id uuid)
            RETURNS boolean
            LANGUAGE sql
            STABLE
            AS $$ SELECT TRUE $$
            "#,
        )
        .execute(&pool)
        .await;
        if let Err(error) = install {
            drop_isolated_schema(&admin, &schema).await;
            panic!("install community_write_allowed stub: {error}");
        }

        let community = Uuid::new_v4();
        if let Err(error) = sqlx::query("INSERT INTO communities (id) VALUES ($1)")
            .bind(community)
            .execute(&pool)
            .await
        {
            drop_isolated_schema(&admin, &schema).await;
            panic!("insert isolated community: {error}");
        }

        let author = [7u8; 32];
        let intent = [8u8; 32];
        let insert_key = |key: [u8; 32], event_id: [u8; 32], age_secs: Option<i64>| {
            let pool = pool.clone();
            async move {
                match age_secs {
                    Some(secs) => sqlx::query(
                        r#"
                        INSERT INTO event_idempotency_keys (
                            community_id, author_pubkey, idempotency_key,
                            intent_hash, event_id, created_at, reservation_witness
                        ) VALUES (
                            $1, $2, $3, $4, $5,
                            clock_timestamp() - make_interval(secs => $6),
                            $7
                        )
                        "#,
                    )
                    .bind(community)
                    .bind(author.as_slice())
                    .bind(key.as_slice())
                    .bind(intent.as_slice())
                    .bind(event_id.as_slice())
                    .bind(secs)
                    .bind(key.as_slice())
                    .execute(&pool)
                    .await
                    .map(|_| ()),
                    None => sqlx::query(
                        r#"
                        INSERT INTO event_idempotency_keys (
                            community_id, author_pubkey, idempotency_key,
                            intent_hash, event_id, created_at, reservation_witness
                        ) VALUES ($1, $2, $3, $4, $5, clock_timestamp(), $6)
                        "#,
                    )
                    .bind(community)
                    .bind(author.as_slice())
                    .bind(key.as_slice())
                    .bind(intent.as_slice())
                    .bind(event_id.as_slice())
                    .bind(key.as_slice())
                    .execute(&pool)
                    .await
                    .map(|_| ()),
                }
            }
        };

        let expired_age = RETENTION_SECONDS as i64 + 60;
        let setup = async {
            insert_key(key_n(1), key_n(21), Some(expired_age)).await?;
            insert_key(key_n(2), key_n(22), Some(expired_age)).await?;
            insert_key(key_n(3), key_n(23), Some(expired_age)).await?;
            insert_key(key_n(10), key_n(30), None).await?;
            insert_key(key_n(11), key_n(31), None).await?;
            Ok::<_, sqlx::Error>(())
        }
        .await;
        if let Err(error) = setup {
            drop_isolated_schema(&admin, &schema).await;
            panic!("insert reap fixtures: {error}");
        }

        let db = Db::from_pool(pool.clone());
        let first = db.reap_expired_event_idempotency_keys(2).await;
        let first = match first {
            Ok(deleted) => deleted,
            Err(error) => {
                drop_isolated_schema(&admin, &schema).await;
                panic!("first bounded reap: {error}");
            }
        };
        if first != 2 {
            drop_isolated_schema(&admin, &schema).await;
            panic!("first reap must delete exactly the batch limit, got {first}");
        }

        let remaining = key_count(&pool, community).await;
        if remaining != 3 {
            drop_isolated_schema(&admin, &schema).await;
            panic!("after batch=2, 1 expired + 2 unexpired must remain, got {remaining}");
        }

        let expired_left: std::result::Result<i64, sqlx::Error> = sqlx::query_scalar(
            r#"
            SELECT count(*)
              FROM event_idempotency_keys
             WHERE community_id = $1
               AND created_at < clock_timestamp()
                   - make_interval(secs => $2)
            "#,
        )
        .bind(community)
        .bind(RETENTION_SECONDS as i64)
        .fetch_one(&pool)
        .await;
        let expired_left = match expired_left {
            Ok(count) => count,
            Err(error) => {
                drop_isolated_schema(&admin, &schema).await;
                panic!("count leftover expired: {error}");
            }
        };
        if expired_left != 1 {
            drop_isolated_schema(&admin, &schema).await;
            panic!("exactly one expired row must survive the first batch, got {expired_left}");
        }

        let second = db.reap_expired_event_idempotency_keys(1000).await;
        let second = match second {
            Ok(deleted) => deleted,
            Err(error) => {
                drop_isolated_schema(&admin, &schema).await;
                panic!("second reap: {error}");
            }
        };
        if second != 1 {
            drop_isolated_schema(&admin, &schema).await;
            panic!("second reap must delete the leftover expired row, got {second}");
        }

        let leftover_keys: std::result::Result<Vec<Vec<u8>>, sqlx::Error> = sqlx::query_scalar(
            r#"
            SELECT idempotency_key
              FROM event_idempotency_keys
             WHERE community_id = $1
             ORDER BY idempotency_key
            "#,
        )
        .bind(community)
        .fetch_all(&pool)
        .await;
        drop_isolated_schema(&admin, &schema).await;
        let leftover_keys = leftover_keys.expect("list surviving keys");
        assert_eq!(
            leftover_keys,
            vec![key_n(10).to_vec(), key_n(11).to_vec()],
            "just-accepted unexpired rows must survive reaping"
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn reap_skips_older_fenced_backlog_and_reaps_active() {
        let (schema, admin, pool) = isolated_schema_pool().await;
        let install_calls = sqlx::query(
            r#"
            CREATE TABLE reap_fence_calls (
                community_id uuid PRIMARY KEY,
                calls integer NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await;
        if let Err(error) = install_calls {
            drop_isolated_schema(&admin, &schema).await;
            panic!("install fence call counter: {error}");
        }
        let install = sqlx::query(
            r#"
            CREATE FUNCTION community_write_allowed(p_community_id uuid)
            RETURNS boolean
            LANGUAGE plpgsql
            VOLATILE
            AS $$
            DECLARE
                lifecycle TEXT;
            BEGIN
                IF current_setting('transaction_isolation') <> 'read committed' THEN
                    RAISE EXCEPTION 'community writes require READ COMMITTED isolation'
                        USING ERRCODE = 'invalid_transaction_state';
                END IF;
                INSERT INTO reap_fence_calls (community_id, calls)
                VALUES (p_community_id, 1)
                ON CONFLICT (community_id) DO UPDATE
                SET calls = reap_fence_calls.calls + 1;
                PERFORM pg_advisory_xact_lock_shared(
                    community_deletion_lock_key(p_community_id)
                );
                SELECT deletion_state
                  INTO lifecycle
                  FROM communities
                 WHERE id = p_community_id;
                RETURN FOUND AND lifecycle = 'active';
            END
            $$
            "#,
        )
        .execute(&pool)
        .await;
        if let Err(error) = install {
            drop_isolated_schema(&admin, &schema).await;
            panic!("install community_write_allowed fence stub: {error}");
        }

        let fenced = Uuid::new_v4();
        let active = Uuid::new_v4();
        let fresh = Uuid::new_v4();
        let setup_communities = async {
            sqlx::query("INSERT INTO communities (id, deletion_state) VALUES ($1, 'fenced')")
                .bind(fenced)
                .execute(&pool)
                .await?;
            sqlx::query("INSERT INTO communities (id, deletion_state) VALUES ($1, 'active')")
                .bind(active)
                .execute(&pool)
                .await?;
            sqlx::query("INSERT INTO communities (id, deletion_state) VALUES ($1, 'active')")
                .bind(fresh)
                .execute(&pool)
                .await?;
            Ok::<_, sqlx::Error>(())
        }
        .await;
        if let Err(error) = setup_communities {
            drop_isolated_schema(&admin, &schema).await;
            panic!("insert fenced and active communities: {error}");
        }

        let author = [7u8; 32];
        let intent = [8u8; 32];
        let expired_age_fenced = RETENTION_SECONDS as i64 + 120;
        let expired_age_active = RETENTION_SECONDS as i64 + 60;
        const FENCED_BACKLOG: i32 = 2_000;
        const ACTIVE_EXPIRED: i32 = 50;
        const FRESH_UNEXPIRED: i32 = 10;
        let seed = sqlx::query(
            r#"
            INSERT INTO event_idempotency_keys (
                community_id, author_pubkey, idempotency_key,
                intent_hash, event_id, created_at, reservation_witness
            )
            SELECT $1,
                   $4,
                   decode(lpad(to_hex(g), 64, '0'), 'hex'),
                   $5,
                   decode(lpad(to_hex(g + 100000), 64, '0'), 'hex'),
                   clock_timestamp() - make_interval(secs => $6),
                   decode(lpad(to_hex(g + 600000), 64, '0'), 'hex')
              FROM generate_series(1, $7) AS g
            UNION ALL
            SELECT $2,
                   $4,
                   decode(lpad(to_hex(g + 200000), 64, '0'), 'hex'),
                   $5,
                   decode(lpad(to_hex(g + 300000), 64, '0'), 'hex'),
                   clock_timestamp() - make_interval(secs => $8),
                   decode(lpad(to_hex(g + 700000), 64, '0'), 'hex')
              FROM generate_series(1, $9) AS g
            UNION ALL
            SELECT $3,
                   $4,
                   decode(lpad(to_hex(g + 400000), 64, '0'), 'hex'),
                   $5,
                   decode(lpad(to_hex(g + 500000), 64, '0'), 'hex'),
                   clock_timestamp(),
                   decode(lpad(to_hex(g + 800000), 64, '0'), 'hex')
              FROM generate_series(1, $10) AS g
            "#,
        )
        .bind(fenced)
        .bind(active)
        .bind(fresh)
        .bind(author.as_slice())
        .bind(intent.as_slice())
        .bind(expired_age_fenced)
        .bind(FENCED_BACKLOG)
        .bind(expired_age_active)
        .bind(ACTIVE_EXPIRED)
        .bind(FRESH_UNEXPIRED)
        .execute(&pool)
        .await;
        if let Err(error) = seed {
            drop_isolated_schema(&admin, &schema).await;
            panic!("insert fenced backlog ahead of active expired rows: {error}");
        }
        if let Err(error) = sqlx::query("ANALYZE event_idempotency_keys")
            .execute(&pool)
            .await
        {
            drop_isolated_schema(&admin, &schema).await;
            panic!("analyze event_idempotency_keys: {error}");
        }

        let index_cols: std::result::Result<Option<Vec<String>>, sqlx::Error> = sqlx::query_scalar(
            r#"
            SELECT (
                SELECT array_agg(att.attname::text ORDER BY k.ordinality)
                  FROM unnest(i.indkey) WITH ORDINALITY AS k(attnum, ordinality)
                  JOIN pg_attribute AS att
                    ON att.attrelid = tbl.oid AND att.attnum = k.attnum
            )
              FROM pg_class AS idx
              JOIN pg_namespace AS idx_ns ON idx_ns.oid = idx.relnamespace
              JOIN pg_index AS i ON i.indexrelid = idx.oid
              JOIN pg_class AS tbl ON tbl.oid = i.indrelid
              JOIN pg_namespace AS tbl_ns ON tbl_ns.oid = tbl.relnamespace
             WHERE idx_ns.nspname = current_schema()
               AND idx.relname = 'idx_event_idempotency_keys_community_created_at'
               AND tbl_ns.nspname = current_schema()
               AND tbl.relname = 'event_idempotency_keys'
               AND i.indisvalid
               AND i.indisready
               AND i.indpred IS NULL
               AND i.indexprs IS NULL
               AND i.indnkeyatts = 4
               AND i.indnatts = 4
            "#,
        )
        .fetch_optional(&pool)
        .await;
        let index_cols = match index_cols {
            Ok(cols) => cols,
            Err(error) => {
                drop_isolated_schema(&admin, &schema).await;
                panic!("read community created_at index catalog: {error}");
            }
        };
        if index_cols.as_deref()
            != Some(
                [
                    "community_id".to_owned(),
                    "created_at".to_owned(),
                    "author_pubkey".to_owned(),
                    "idempotency_key".to_owned(),
                ]
                .as_slice(),
            )
        {
            drop_isolated_schema(&admin, &schema).await;
            panic!(
                "idx_event_idempotency_keys_community_created_at must be \
                 (community_id, created_at, author_pubkey, idempotency_key), got {index_cols:?}"
            );
        }

        let mut explain_tx = match pool.begin().await {
            Ok(tx) => tx,
            Err(error) => {
                drop_isolated_schema(&admin, &schema).await;
                panic!("begin production-plan transaction: {error}");
            }
        };
        let explain_sql =
            format!("EXPLAIN (ANALYZE, FORMAT TEXT){REAP_EXPIRED_EVENT_IDEMPOTENCY_KEYS_SQL}");
        // Static EXPLAIN prefix plus private production SQL only; no request input.
        let plan_lines: std::result::Result<Vec<String>, sqlx::Error> =
            sqlx::query_scalar(sqlx::AssertSqlSafe(explain_sql))
                .bind(active)
                .bind(RETENTION_SECONDS as i64)
                .bind(1000_i64)
                .fetch_all(&mut *explain_tx)
                .await;
        let _ = explain_tx.rollback().await;
        let plan = match plan_lines {
            Ok(lines) => lines.join("\n"),
            Err(error) => {
                drop_isolated_schema(&admin, &schema).await;
                panic!("explain production reaper statement: {error}");
            }
        };
        if !plan.contains("idx_event_idempotency_keys_community_created_at") {
            drop_isolated_schema(&admin, &schema).await;
            panic!(
                "production reaper must use \
                 idx_event_idempotency_keys_community_created_at; plan was:\n{plan}"
            );
        }
        if plan.contains("using idx_event_idempotency_keys_created_at") {
            drop_isolated_schema(&admin, &schema).await;
            panic!(
                "production reaper must not use the created_at-leading index; plan was:\n{plan}"
            );
        }
        let probe_sql = format!("EXPLAIN (ANALYZE, FORMAT TEXT){REAP_HAS_EXPIRED_SQL}");
        let probe_lines: std::result::Result<Vec<String>, sqlx::Error> =
            sqlx::query_scalar(sqlx::AssertSqlSafe(probe_sql))
                .bind(active)
                .bind(RETENTION_SECONDS as i64)
                .fetch_all(&pool)
                .await;
        let probe_plan = match probe_lines {
            Ok(lines) => lines.join("\n"),
            Err(error) => {
                drop_isolated_schema(&admin, &schema).await;
                panic!("explain expired-row probe: {error}");
            }
        };
        if !probe_plan.contains("idx_event_idempotency_keys_community_created_at") {
            drop_isolated_schema(&admin, &schema).await;
            panic!("expired-row probe must use the tenant-first index; plan was:\n{probe_plan}");
        }
        if probe_plan.contains("using idx_event_idempotency_keys_created_at") {
            drop_isolated_schema(&admin, &schema).await;
            panic!(
                "expired-row probe must not use the created_at-leading index; plan was:\n{probe_plan}"
            );
        }
        let walk_sql = format!("EXPLAIN (FORMAT TEXT){REAP_NEXT_COMMUNITY_FIRST_SQL}");
        let walk_lines: std::result::Result<Vec<String>, sqlx::Error> =
            sqlx::query_scalar(sqlx::AssertSqlSafe(walk_sql))
                .fetch_all(&pool)
                .await;
        let walk_plan = match walk_lines {
            Ok(lines) => lines.join("\n"),
            Err(error) => {
                drop_isolated_schema(&admin, &schema).await;
                panic!("explain community skip-scan: {error}");
            }
        };
        if walk_plan.contains("using idx_event_idempotency_keys_created_at") {
            drop_isolated_schema(&admin, &schema).await;
            panic!(
                "community skip-scan must not use the created_at-leading index; plan was:\n{walk_plan}"
            );
        }
        let fenced_filter = format!("Rows Removed by Filter: {FENCED_BACKLOG}");
        if plan.contains(&fenced_filter) {
            drop_isolated_schema(&admin, &schema).await;
            panic!("production reaper must not filter the fenced backlog; plan was:\n{plan}");
        }

        let db = Db::from_pool(pool.clone());
        let (deleted, _, _, txs) = reap_eight_tx_tick(&db, &pool, None, 1000).await;
        if txs > 8 {
            drop_isolated_schema(&admin, &schema).await;
            panic!("tick opened {txs} transactions");
        }
        if deleted != ACTIVE_EXPIRED as u64 {
            drop_isolated_schema(&admin, &schema).await;
            panic!("reaper must delete the {ACTIVE_EXPIRED} active expired rows, got {deleted}");
        }

        let fence_calls: std::result::Result<Vec<(Uuid, i32)>, sqlx::Error> = sqlx::query_as(
            "SELECT community_id, calls FROM reap_fence_calls ORDER BY community_id",
        )
        .fetch_all(&pool)
        .await;
        let fence_calls = match fence_calls {
            Ok(rows) => rows,
            Err(error) => {
                drop_isolated_schema(&admin, &schema).await;
                panic!("read fence call counts: {error}");
            }
        };
        let fenced_left = key_count(&pool, fenced).await;
        let active_left = key_count(&pool, active).await;
        let fresh_left = key_count(&pool, fresh).await;
        drop_isolated_schema(&admin, &schema).await;
        assert_eq!(
            fence_calls.len(),
            2,
            "fence must run once per expired-row community, not per row: {fence_calls:?}"
        );
        let fenced_calls = fence_calls
            .iter()
            .find(|(id, _)| *id == fenced)
            .map(|(_, n)| *n);
        let active_calls = fence_calls
            .iter()
            .find(|(id, _)| *id == active)
            .map(|(_, n)| *n);
        assert_eq!(fenced_calls, Some(1), "fenced community fenced once");
        assert_eq!(active_calls, Some(1), "active community fenced once");
        assert!(
            fence_calls.iter().all(|(id, _)| *id != fresh),
            "unexpired community must not reach the fence check"
        );
        assert_eq!(
            fenced_left, FENCED_BACKLOG as i64,
            "fenced expired backlog must remain untouched"
        );
        assert_eq!(
            active_left, 0,
            "active expired rows must be reaped while the fenced backlog remains"
        );
        assert_eq!(
            fresh_left, FRESH_UNEXPIRED as i64,
            "unexpired rows must survive reaping"
        );
    }

    async fn install_write_allowed_fence_stub(pool: &PgPool) -> sqlx::Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS reap_fence_calls (
                community_id uuid PRIMARY KEY,
                calls integer NOT NULL
            )
            "#,
        )
        .execute(pool)
        .await?;
        sqlx::query(
            r#"
            CREATE OR REPLACE FUNCTION community_write_allowed(p_community_id uuid)
            RETURNS boolean
            LANGUAGE plpgsql
            VOLATILE
            AS $$
            DECLARE
                lifecycle TEXT;
            BEGIN
                IF current_setting('transaction_isolation') <> 'read committed' THEN
                    RAISE EXCEPTION 'community writes require READ COMMITTED isolation'
                        USING ERRCODE = 'invalid_transaction_state';
                END IF;
                INSERT INTO reap_fence_calls (community_id, calls)
                VALUES (p_community_id, 1)
                ON CONFLICT (community_id) DO UPDATE
                SET calls = reap_fence_calls.calls + 1;
                PERFORM pg_advisory_xact_lock_shared(
                    community_deletion_lock_key(p_community_id)
                );
                SELECT deletion_state
                  INTO lifecycle
                  FROM communities
                 WHERE id = p_community_id;
                RETURN FOUND AND lifecycle = 'active';
            END
            $$
            "#,
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    async fn insert_aged_key(
        pool: &PgPool,
        community: Uuid,
        key: [u8; 32],
        age_secs: i64,
    ) -> sqlx::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO event_idempotency_keys (
                community_id, author_pubkey, idempotency_key,
                intent_hash, event_id, created_at, reservation_witness
            ) VALUES (
                $1, $2, $3, $4, $5,
                clock_timestamp() - make_interval(secs => $6),
                $3
            )
            "#,
        )
        .bind(community)
        .bind([7u8; 32].as_slice())
        .bind(key.as_slice())
        .bind([8u8; 32].as_slice())
        .bind(key.as_slice())
        .bind(age_secs)
        .execute(pool)
        .await
        .map(|_| ())
    }

    fn tenant_key(community: Uuid, n: u8) -> [u8; 32] {
        let mut key = [n; 32];
        key[..16].copy_from_slice(community.as_bytes());
        key
    }

    fn reap_tick_should_advance_cursor(
        more_expired: bool,
        deleted: u64,
        tick_complete: bool,
    ) -> bool {
        reap_cursor_should_persist(more_expired, deleted, tick_complete)
    }

    async fn insert_aged_keys(
        pool: &PgPool,
        community: Uuid,
        count: i32,
        age_secs: i64,
        series_offset: i32,
    ) -> sqlx::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO event_idempotency_keys (
                community_id, author_pubkey, idempotency_key,
                intent_hash, event_id, created_at, reservation_witness
            )
            SELECT $1,
                   $2,
                   decode(lpad(to_hex(g + $6), 64, '0'), 'hex'),
                   $3,
                   decode(lpad(to_hex(g + $6 + 100000), 64, '0'), 'hex'),
                   clock_timestamp() - make_interval(secs => $4),
                   decode(lpad(to_hex(g + $6 + 200000), 64, '0'), 'hex')
              FROM generate_series(1, $5) AS g
            "#,
        )
        .bind(community)
        .bind([7u8; 32].as_slice())
        .bind([8u8; 32].as_slice())
        .bind(age_secs)
        .bind(count)
        .bind(series_offset)
        .execute(pool)
        .await
        .map(|_| ())
    }

    async fn seed_reaper_cursor(pool: &PgPool, after: Option<Uuid>) {
        sqlx::query(
            "UPDATE event_idempotency_reaper_cursor SET after_community_id = $1 WHERE id = 1",
        )
        .bind(after)
        .execute(pool)
        .await
        .expect("seed reaper cursor");
    }

    async fn reap_eight_tx_tick(
        db: &Db,
        pool: &PgPool,
        mut after: Option<Uuid>,
        batch_limit: i64,
    ) -> (u64, Option<Uuid>, bool, u64) {
        seed_reaper_cursor(pool, after).await;
        let cycle_origin = after;
        let mut wrapped = false;
        let mut deleted = 0u64;
        let mut exhausted = false;
        let mut txs = 0u64;
        for batch in 1..=8u32 {
            txs += 1;
            let progress = db
                .reap_expired_event_idempotency_keys_progress(
                    batch_limit,
                    wrapped,
                    cycle_origin,
                    batch == 8,
                )
                .await
                .expect("reap transaction");
            deleted += progress.deleted;
            exhausted = progress.exhausted;
            let done = progress.exhausted || batch == 8;
            if reap_tick_should_advance_cursor(progress.more_expired, progress.deleted, done) {
                after = progress.next_after;
                wrapped = progress.wrapped;
            }
            if done {
                break;
            }
        }
        (deleted, after, exhausted, txs)
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn reap_processes_multiple_sparse_tenants_in_one_batch() {
        let (schema, admin, pool) = isolated_schema_pool().await;
        if let Err(error) = install_write_allowed_fence_stub(&pool).await {
            drop_isolated_schema(&admin, &schema).await;
            panic!("install fence stub: {error}");
        }
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        let c = Uuid::from_u128(3);
        let setup = async {
            for id in [a, b, c] {
                sqlx::query("INSERT INTO communities (id) VALUES ($1)")
                    .bind(id)
                    .execute(&pool)
                    .await?;
                insert_aged_key(&pool, id, tenant_key(id, 1), RETENTION_SECONDS as i64 + 60)
                    .await?;
            }
            Ok::<_, sqlx::Error>(())
        }
        .await;
        if let Err(error) = setup {
            drop_isolated_schema(&admin, &schema).await;
            panic!("insert sparse tenants: {error}");
        }
        let db = Db::from_pool(pool.clone());
        let (deleted, _, exhausted, txs) = reap_eight_tx_tick(&db, &pool, None, 1000).await;
        let leftover = [
            key_count(&pool, a).await,
            key_count(&pool, b).await,
            key_count(&pool, c).await,
        ];
        let fence_calls: std::result::Result<i64, sqlx::Error> =
            sqlx::query_scalar("SELECT coalesce(sum(calls), 0) FROM reap_fence_calls")
                .fetch_one(&pool)
                .await;
        drop_isolated_schema(&admin, &schema).await;
        assert!(txs <= 8, "tick opened {txs} transactions");
        assert_eq!(
            deleted, 3,
            "sparse tenants must be cleaned within the eight-transaction tick"
        );
        assert_eq!(leftover, [0, 0, 0]);
        assert_eq!(fence_calls.expect("fence calls"), 3);
        assert!(exhausted);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn reap_public_wrapper_wraps_from_high_cursor_to_later_expired_low_without_rescan() {
        let (schema, admin, pool) = isolated_schema_pool().await;
        if let Err(error) = install_write_allowed_fence_stub(&pool).await {
            drop_isolated_schema(&admin, &schema).await;
            panic!("install fence stub: {error}");
        }
        let low = Uuid::from_u128(1);
        let high = Uuid::from_u128(u128::MAX);
        assert!(low < high, "L < H split");
        let expired_age = RETENTION_SECONDS as i64 + 60;
        let setup = async {
            for id in [low, high] {
                sqlx::query("INSERT INTO communities (id) VALUES ($1)")
                    .bind(id)
                    .execute(&pool)
                    .await?;
            }
            insert_aged_key(&pool, low, tenant_key(low, 1), 0).await?;
            insert_aged_key(&pool, high, tenant_key(high, 1), expired_age).await?;
            Ok::<_, sqlx::Error>(())
        }
        .await;
        if let Err(error) = setup {
            drop_isolated_schema(&admin, &schema).await;
            panic!("insert L < H tenants: {error}");
        }
        let db = Db::from_pool(pool.clone());
        let first = db.reap_expired_event_idempotency_keys(1000).await;
        let first = match first {
            Ok(deleted) => deleted,
            Err(error) => {
                drop_isolated_schema(&admin, &schema).await;
                panic!("first public reap: {error}");
            }
        };
        let low_after_first = key_count(&pool, low).await;
        let high_after_first = key_count(&pool, high).await;
        let cursor_after_first = persisted_reaper_cursor(&pool).await;
        let fence_after_first: std::result::Result<Vec<(Uuid, i32)>, sqlx::Error> = sqlx::query_as(
            "SELECT community_id, calls FROM reap_fence_calls ORDER BY community_id",
        )
        .fetch_all(&pool)
        .await;
        if let Err(error) = insert_aged_key(&pool, low, tenant_key(low, 2), expired_age).await {
            drop_isolated_schema(&admin, &schema).await;
            panic!("insert later-expired low row: {error}");
        }
        let second = db.reap_expired_event_idempotency_keys(1000).await;
        let second = match second {
            Ok(deleted) => deleted,
            Err(error) => {
                drop_isolated_schema(&admin, &schema).await;
                panic!("second public reap: {error}");
            }
        };
        let leftover = [key_count(&pool, low).await, key_count(&pool, high).await];
        let cursor_after_second = persisted_reaper_cursor(&pool).await;
        let fence_after_second: std::result::Result<Vec<(Uuid, i32)>, sqlx::Error> =
            sqlx::query_as(
                "SELECT community_id, calls FROM reap_fence_calls ORDER BY community_id",
            )
            .fetch_all(&pool)
            .await;
        drop_isolated_schema(&admin, &schema).await;
        assert_eq!(
            first, 1,
            "first public call must delete the expired high tenant"
        );
        assert_eq!(
            cursor_after_first,
            Some(high),
            "first call must persist the exclusive cursor at H"
        );
        assert_eq!(
            low_after_first, 1,
            "fresh low row must survive the first call"
        );
        assert_eq!(
            high_after_first, 0,
            "expired high row must be gone after the first call"
        );
        let fence_after_first = fence_after_first.expect("fence after first");
        assert_eq!(
            fence_after_first,
            vec![(high, 1)],
            "first call must skip-probe L and fence only H"
        );
        assert_eq!(
            second, 1,
            "second public call must wrap and delete the later-expired low row"
        );
        assert_eq!(
            cursor_after_second,
            Some(low),
            "wrap must persist the exclusive cursor at L"
        );
        assert_eq!(leftover, [1, 0], "fresh low row remains; high stays empty");
        let fence_after_second = fence_after_second.expect("fence after second");
        assert_eq!(
            fence_after_second,
            vec![(low, 1), (high, 1)],
            "wrap must fence L once and must not rescan H"
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn reap_bounds_fence_work_independent_of_tenant_cardinality() {
        let (schema, admin, pool) = isolated_schema_pool().await;
        if let Err(error) = install_write_allowed_fence_stub(&pool).await {
            drop_isolated_schema(&admin, &schema).await;
            panic!("install fence stub: {error}");
        }
        const TENANTS: u128 = 12;
        const PROBE_BOUND: i64 = 3;
        let setup = async {
            for n in 1..=TENANTS {
                let id = Uuid::from_u128(n);
                sqlx::query("INSERT INTO communities (id) VALUES ($1)")
                    .bind(id)
                    .execute(&pool)
                    .await?;
                insert_aged_key(&pool, id, tenant_key(id, 1), RETENTION_SECONDS as i64 + 60)
                    .await?;
            }
            Ok::<_, sqlx::Error>(())
        }
        .await;
        if let Err(error) = setup {
            drop_isolated_schema(&admin, &schema).await;
            panic!("insert cardinality tenants: {error}");
        }
        let db = Db::from_pool(pool.clone());
        let (deleted, _, exhausted, txs) = reap_eight_tx_tick(&db, &pool, None, PROBE_BOUND).await;
        let fence_n: std::result::Result<i64, sqlx::Error> =
            sqlx::query_scalar("SELECT count(*) FROM reap_fence_calls")
                .fetch_one(&pool)
                .await;
        let remaining: std::result::Result<i64, sqlx::Error> =
            sqlx::query_scalar("SELECT count(*) FROM event_idempotency_keys")
                .fetch_one(&pool)
                .await;
        drop_isolated_schema(&admin, &schema).await;
        let fence_n = fence_n.expect("fence cardinality");
        let remaining = remaining.expect("remaining keys");
        assert!(txs <= 8, "tick opened {txs} transactions");
        assert!(
            fence_n <= 8,
            "fence/lock probes must be <= eight transactions, got {fence_n} with {TENANTS} tenants"
        );
        assert!(deleted <= 8_000);
        assert_eq!(remaining, TENANTS as i64 - deleted as i64);
        assert!(!exhausted);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn reap_skips_exclusive_deletion_lock_and_cleans_other_tenants() {
        let (schema, admin, pool) = isolated_schema_pool().await;
        if let Err(error) = install_write_allowed_fence_stub(&pool).await {
            drop_isolated_schema(&admin, &schema).await;
            panic!("install fence stub: {error}");
        }
        let busy = Uuid::from_u128(10);
        let free = Uuid::from_u128(20);
        let setup = async {
            for id in [busy, free] {
                sqlx::query("INSERT INTO communities (id) VALUES ($1)")
                    .bind(id)
                    .execute(&pool)
                    .await?;
                insert_aged_key(&pool, id, tenant_key(id, 1), RETENTION_SECONDS as i64 + 60)
                    .await?;
            }
            Ok::<_, sqlx::Error>(())
        }
        .await;
        if let Err(error) = setup {
            drop_isolated_schema(&admin, &schema).await;
            panic!("insert lock tenants: {error}");
        }
        let database_url = crate::test_support::database_url();
        let locker_path = format!("{schema}, public");
        let locker = match PgPoolOptions::new()
            .max_connections(1)
            .after_connect(move |conn, _meta| {
                let search_path = locker_path.clone();
                Box::pin(async move {
                    sqlx::query("SELECT set_config('search_path', $1, false)")
                        .bind(search_path)
                        .execute(&mut *conn)
                        .await?;
                    Ok(())
                })
            })
            .connect(&database_url)
            .await
        {
            Ok(pool) => pool,
            Err(error) => {
                drop_isolated_schema(&admin, &schema).await;
                panic!("locker pool: {error}");
            }
        };
        let mut hold = match locker.begin().await {
            Ok(tx) => tx,
            Err(error) => {
                drop_isolated_schema(&admin, &schema).await;
                panic!("begin exclusive lock tx: {error}");
            }
        };
        if let Err(error) = sqlx::query(
            r#"
            SELECT pg_advisory_xact_lock(community_deletion_lock_key($1))
            "#,
        )
        .bind(busy)
        .execute(&mut *hold)
        .await
        {
            let _ = hold.rollback().await;
            drop_isolated_schema(&admin, &schema).await;
            panic!("take exclusive deletion lock: {error}");
        }

        let db = Db::from_pool(pool.clone());
        let (deleted, _, _, txs) = reap_eight_tx_tick(&db, &pool, None, 1000).await;
        let busy_left = key_count(&pool, busy).await;
        let free_left = key_count(&pool, free).await;
        let _ = hold.rollback().await;
        drop_isolated_schema(&admin, &schema).await;
        assert!(txs <= 8, "tick opened {txs} transactions");
        assert_eq!(busy_left, 1, "locked tenant must be skipped, not deleted");
        assert_eq!(free_left, 0, "unlocked tenant must still be reaped");
        assert_eq!(deleted, 1);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn reap_skip_locked_zero_progress_does_not_starve_sparse_tenant() {
        let (schema, admin, pool) = isolated_schema_pool().await;
        if let Err(error) = install_write_allowed_fence_stub(&pool).await {
            drop_isolated_schema(&admin, &schema).await;
            panic!("install fence stub: {error}");
        }
        let hot = Uuid::from_u128(1);
        let sparse = Uuid::from_u128(2);
        let expired_age = RETENTION_SECONDS as i64 + 60;
        let hot_key = tenant_key(hot, 1);
        let setup = async {
            for id in [hot, sparse] {
                sqlx::query("INSERT INTO communities (id) VALUES ($1)")
                    .bind(id)
                    .execute(&pool)
                    .await?;
            }
            insert_aged_key(&pool, hot, hot_key, expired_age).await?;
            insert_aged_key(&pool, sparse, tenant_key(sparse, 1), expired_age).await?;
            Ok::<_, sqlx::Error>(())
        }
        .await;
        if let Err(error) = setup {
            drop_isolated_schema(&admin, &schema).await;
            panic!("insert skip-locked tenants: {error}");
        }
        let database_url = crate::test_support::database_url();
        let locker_path = format!("{schema}, public");
        let locker = match PgPoolOptions::new()
            .max_connections(1)
            .after_connect(move |conn, _meta| {
                let search_path = locker_path.clone();
                Box::pin(async move {
                    sqlx::query("SELECT set_config('search_path', $1, false)")
                        .bind(search_path)
                        .execute(&mut *conn)
                        .await?;
                    Ok(())
                })
            })
            .connect(&database_url)
            .await
        {
            Ok(pool) => pool,
            Err(error) => {
                drop_isolated_schema(&admin, &schema).await;
                panic!("row-lock pool: {error}");
            }
        };
        let mut hold = match locker.begin().await {
            Ok(tx) => tx,
            Err(error) => {
                drop_isolated_schema(&admin, &schema).await;
                panic!("begin row-lock tx: {error}");
            }
        };
        if let Err(error) = sqlx::query(
            r#"
            SELECT 1
              FROM event_idempotency_keys
             WHERE community_id = $1
               AND author_pubkey = $2
               AND idempotency_key = $3
             FOR UPDATE
            "#,
        )
        .bind(hot)
        .bind([7u8; 32].as_slice())
        .bind(hot_key.as_slice())
        .execute(&mut *hold)
        .await
        {
            let _ = hold.rollback().await;
            drop_isolated_schema(&admin, &schema).await;
            panic!("take expired row lock: {error}");
        }

        let db = Db::from_pool(pool.clone());
        let (deleted, _, _, txs) = reap_eight_tx_tick(&db, &pool, None, 1000).await;
        let hot_left = key_count(&pool, hot).await;
        let sparse_left = key_count(&pool, sparse).await;
        let _ = hold.rollback().await;
        drop_isolated_schema(&admin, &schema).await;
        assert!(txs <= 8, "tick opened {txs} transactions");
        assert_eq!(hot_left, 1, "row-locked expired reservation must remain");
        assert_eq!(sparse_left, 0, "sparse tenant must still be reaped");
        assert_eq!(deleted, 1);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn reap_hot_tenant_3000_and_sparse_progress_in_one_tick() {
        let (schema, admin, pool) = isolated_schema_pool().await;
        if let Err(error) = install_write_allowed_fence_stub(&pool).await {
            drop_isolated_schema(&admin, &schema).await;
            panic!("install fence stub: {error}");
        }
        let hot = Uuid::from_u128(1);
        let sparse = Uuid::from_u128(2);
        let expired_age = RETENTION_SECONDS as i64 + 60;
        const HOT_EXPIRED: i32 = 3_000;
        let setup = async {
            for id in [hot, sparse] {
                sqlx::query("INSERT INTO communities (id) VALUES ($1)")
                    .bind(id)
                    .execute(&pool)
                    .await?;
            }
            insert_aged_keys(&pool, hot, HOT_EXPIRED, expired_age, 0).await?;
            insert_aged_key(&pool, sparse, tenant_key(sparse, 1), expired_age).await?;
            Ok::<_, sqlx::Error>(())
        }
        .await;
        if let Err(error) = setup {
            drop_isolated_schema(&admin, &schema).await;
            panic!("insert hot and sparse tenants: {error}");
        }
        let db = Db::from_pool(pool.clone());
        let (deleted, _, _, txs) = reap_eight_tx_tick(&db, &pool, None, 1000).await;
        let hot_left = key_count(&pool, hot).await;
        let sparse_left = key_count(&pool, sparse).await;
        let fence_calls: std::result::Result<Vec<(Uuid, i32)>, sqlx::Error> = sqlx::query_as(
            "SELECT community_id, calls FROM reap_fence_calls ORDER BY community_id",
        )
        .fetch_all(&pool)
        .await;
        drop_isolated_schema(&admin, &schema).await;
        let fence_calls = fence_calls.expect("fence calls");
        assert!(txs <= 8, "tick opened {txs} transactions");
        assert!(deleted <= 8_000);
        assert_eq!(
            deleted, 3_001,
            "hot tenant 3,000 plus sparse 1 must drain in one tick, got {deleted}"
        );
        assert_eq!(hot_left, 0, "hot tenant must not grow a leftover backlog");
        assert_eq!(sparse_left, 0, "sparse tenant must still make progress");
        let hot_fences = fence_calls
            .iter()
            .find(|(id, _)| *id == hot)
            .map(|(_, n)| *n)
            .unwrap_or(0);
        assert!(
            (3..=8).contains(&hot_fences),
            "hot tenant needs multiple bounded batches, fences={hot_fences}"
        );
        assert!(
            fence_calls.iter().any(|(id, n)| *id == sparse && *n == 1),
            "sparse tenant must be fenced once: {fence_calls:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn reap_six_exact_full_tenants_with_fresh_rows_in_one_tick() {
        let (schema, admin, pool) = isolated_schema_pool().await;
        if let Err(error) = install_write_allowed_fence_stub(&pool).await {
            drop_isolated_schema(&admin, &schema).await;
            panic!("install fence stub: {error}");
        }
        const TENANTS: u128 = 6;
        const EXPIRED_EACH: i32 = 1_000;
        let expired_age = RETENTION_SECONDS as i64 + 60;
        let ids: Vec<Uuid> = (1..=TENANTS).map(Uuid::from_u128).collect();
        let setup = async {
            for (i, id) in ids.iter().enumerate() {
                sqlx::query("INSERT INTO communities (id) VALUES ($1)")
                    .bind(id)
                    .execute(&pool)
                    .await?;
                let offset = (i as i32 + 1) * 10_000;
                insert_aged_keys(&pool, *id, EXPIRED_EACH, expired_age, offset).await?;
                insert_aged_keys(&pool, *id, 1, 0, offset + EXPIRED_EACH).await?;
            }
            Ok::<_, sqlx::Error>(())
        }
        .await;
        if let Err(error) = setup {
            drop_isolated_schema(&admin, &schema).await;
            panic!("insert exact-full tenants with fresh rows: {error}");
        }
        let db = Db::from_pool(pool.clone());
        let (deleted, _, _, txs) = reap_eight_tx_tick(&db, &pool, None, 1000).await;
        let leftovers: Vec<i64> = {
            let mut left = Vec::new();
            for id in &ids {
                left.push(key_count(&pool, *id).await);
            }
            left
        };
        drop_isolated_schema(&admin, &schema).await;
        assert!(txs <= 8, "tick opened {txs} transactions");
        assert_eq!(
            deleted, 6_000,
            "six exact-full tenants must drain in one tick; a full-batch stay heuristic deletes ~4,000, got {deleted} in {txs} txs"
        );
        assert!(
            leftovers.iter().all(|n| *n == 1),
            "each tenant must keep its fresh row, leftovers={leftovers:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn reap_full_tick_budget_then_sparse_progress_next_tick() {
        let (schema, admin, pool) = isolated_schema_pool().await;
        if let Err(error) = install_write_allowed_fence_stub(&pool).await {
            drop_isolated_schema(&admin, &schema).await;
            panic!("install fence stub: {error}");
        }
        let hot = Uuid::from_u128(1);
        let sparse = Uuid::from_u128(2);
        let expired_age = RETENTION_SECONDS as i64 + 60;
        const HOT_EXPIRED: i32 = 9_000;
        let setup = async {
            for id in [hot, sparse] {
                sqlx::query("INSERT INTO communities (id) VALUES ($1)")
                    .bind(id)
                    .execute(&pool)
                    .await?;
            }
            insert_aged_keys(&pool, hot, HOT_EXPIRED, expired_age, 0).await?;
            insert_aged_key(&pool, sparse, tenant_key(sparse, 1), expired_age).await?;
            Ok::<_, sqlx::Error>(())
        }
        .await;
        if let Err(error) = setup {
            drop_isolated_schema(&admin, &schema).await;
            panic!("insert oversized hot tenant: {error}");
        }
        let db = Db::from_pool(pool.clone());
        let (deleted_first, after_first, _, txs_first) =
            reap_eight_tx_tick(&db, &pool, None, 1000).await;
        let hot_after_first = key_count(&pool, hot).await;
        let sparse_after_first = key_count(&pool, sparse).await;
        if txs_first != 8 || deleted_first != 8_000 {
            drop_isolated_schema(&admin, &schema).await;
            panic!(
                "first tick must spend exactly 8 × 1,000, got txs={txs_first} deleted={deleted_first}"
            );
        }
        if hot_after_first != 1_000 || sparse_after_first != 1 {
            drop_isolated_schema(&admin, &schema).await;
            panic!(
                "first tick must cap the hot tenant at 8,000 and leave sparse, \
                 got hot={hot_after_first} sparse={sparse_after_first}"
            );
        }
        let (deleted_second, _, _, txs_second) =
            reap_eight_tx_tick(&db, &pool, after_first, 1000).await;
        let hot_left = key_count(&pool, hot).await;
        let sparse_left = key_count(&pool, sparse).await;
        drop_isolated_schema(&admin, &schema).await;
        assert!(
            txs_second <= 8,
            "second tick opened {txs_second} transactions"
        );
        assert!(deleted_second <= 8_000);
        assert_eq!(sparse_left, 0, "next tick must serve the sparse tenant");
        assert_eq!(hot_left, 0, "remaining hot rows must drain after yielding");
        assert_eq!(deleted_second, 1_001);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn reap_tick_exact_eight_by_thousand_ceilings() {
        let (schema, admin, pool) = isolated_schema_pool().await;
        if let Err(error) = install_write_allowed_fence_stub(&pool).await {
            drop_isolated_schema(&admin, &schema).await;
            panic!("install fence stub: {error}");
        }
        let hot = Uuid::from_u128(1);
        let expired_age = RETENTION_SECONDS as i64 + 60;
        let setup = async {
            sqlx::query("INSERT INTO communities (id) VALUES ($1)")
                .bind(hot)
                .execute(&pool)
                .await?;
            insert_aged_keys(&pool, hot, 8_000, expired_age, 0).await?;
            Ok::<_, sqlx::Error>(())
        }
        .await;
        if let Err(error) = setup {
            drop_isolated_schema(&admin, &schema).await;
            panic!("insert 8,000-row tenant: {error}");
        }
        let db = Db::from_pool(pool.clone());
        let (deleted, _, _, txs) = reap_eight_tx_tick(&db, &pool, None, 1000).await;
        let leftover = key_count(&pool, hot).await;
        drop_isolated_schema(&admin, &schema).await;
        assert_eq!(txs, 8, "exactly eight transactions, got {txs}");
        assert_eq!(deleted, 8_000, "exactly 8,000 rows, got {deleted}");
        assert_eq!(leftover, 0);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn reap_releases_earlier_tenant_lock_before_pausing_later_tenant() {
        let (schema, admin, pool) = isolated_schema_pool().await;
        if let Err(error) = install_write_allowed_fence_stub(&pool).await {
            drop_isolated_schema(&admin, &schema).await;
            panic!("install fence stub: {error}");
        }
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        let expired_age = RETENTION_SECONDS as i64 + 60;
        let setup = async {
            for id in [a, b] {
                sqlx::query("INSERT INTO communities (id) VALUES ($1)")
                    .bind(id)
                    .execute(&pool)
                    .await?;
                insert_aged_key(&pool, id, tenant_key(id, 1), expired_age).await?;
            }
            sqlx::query(
                r#"
                CREATE OR REPLACE FUNCTION community_write_allowed(p_community_id uuid)
                RETURNS boolean
                LANGUAGE plpgsql
                VOLATILE
                AS $$
                DECLARE
                    lifecycle TEXT;
                BEGIN
                    IF current_setting('transaction_isolation') <> 'read committed' THEN
                        RAISE EXCEPTION 'community writes require READ COMMITTED isolation'
                            USING ERRCODE = 'invalid_transaction_state';
                    END IF;
                    INSERT INTO reap_fence_calls (community_id, calls)
                    VALUES (p_community_id, 1)
                    ON CONFLICT (community_id) DO UPDATE
                    SET calls = reap_fence_calls.calls + 1;
                    PERFORM pg_advisory_xact_lock_shared(
                        community_deletion_lock_key(p_community_id)
                    );
                    IF p_community_id = '00000000-0000-0000-0000-000000000002'::uuid THEN
                        PERFORM pg_sleep(30);
                    END IF;
                    SELECT deletion_state
                      INTO lifecycle
                      FROM communities
                     WHERE id = p_community_id;
                    RETURN FOUND AND lifecycle = 'active';
                END
                $$
                "#,
            )
            .execute(&pool)
            .await?;
            Ok::<_, sqlx::Error>(())
        }
        .await;
        if let Err(error) = setup {
            drop_isolated_schema(&admin, &schema).await;
            panic!("insert pause tenants: {error}");
        }
        let database_url = crate::test_support::database_url();
        let locker_path = format!("{schema}, public");
        let locker = match PgPoolOptions::new()
            .max_connections(1)
            .after_connect(move |conn, _meta| {
                let search_path = locker_path.clone();
                Box::pin(async move {
                    sqlx::query("SELECT set_config('search_path', $1, false)")
                        .bind(search_path)
                        .execute(&mut *conn)
                        .await?;
                    Ok(())
                })
            })
            .connect(&database_url)
            .await
        {
            Ok(pool) => pool,
            Err(error) => {
                drop_isolated_schema(&admin, &schema).await;
                panic!("quiesce pool: {error}");
            }
        };
        let db = Db::from_pool(pool.clone());
        let reap = tokio::spawn(async move {
            let mut after = None;
            let cycle_origin = after;
            let mut wrapped = false;
            let mut deleted = 0u64;
            for _ in 1..=8u32 {
                let progress = db
                    .reap_expired_event_idempotency_keys_progress(
                        1000,
                        wrapped,
                        cycle_origin,
                        false,
                    )
                    .await?;
                deleted += progress.deleted;
                after = progress.next_after;
                wrapped = progress.wrapped;
                if progress.exhausted {
                    break;
                }
            }
            Ok::<_, crate::DbError>((deleted, after))
        });
        let mut waited = 0u32;
        loop {
            let a_left = key_count(&locker, a).await;
            if a_left == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            waited += 1;
            if waited > 500 {
                reap.abort();
                drop_isolated_schema(&admin, &schema).await;
                panic!("reaper never finished community A before pausing B");
            }
        }
        let mut hold = match locker.begin().await {
            Ok(tx) => tx,
            Err(error) => {
                reap.abort();
                drop_isolated_schema(&admin, &schema).await;
                panic!("begin quiesce A: {error}");
            }
        };
        if let Err(error) = sqlx::query("SET LOCAL lock_timeout = '1s'")
            .execute(&mut *hold)
            .await
        {
            let _ = hold.rollback().await;
            reap.abort();
            drop_isolated_schema(&admin, &schema).await;
            panic!("set lock_timeout for quiesce A: {error}");
        }
        let quiesce = sqlx::query(
            r#"
            SELECT pg_advisory_xact_lock(community_deletion_lock_key($1))
            "#,
        )
        .bind(a)
        .execute(&mut *hold)
        .await;
        let _ = hold.rollback().await;
        reap.abort();
        drop_isolated_schema(&admin, &schema).await;
        quiesce.expect("begin_quiescing(A) must not wait while the reaper is paused on B");
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn reap_tick_never_exceeds_eight_transactions_or_eight_thousand_rows_including_wrap() {
        let (schema, admin, pool) = isolated_schema_pool().await;
        if let Err(error) = install_write_allowed_fence_stub(&pool).await {
            drop_isolated_schema(&admin, &schema).await;
            panic!("install fence stub: {error}");
        }
        const TENANTS: u128 = 24;
        let setup = async {
            for n in 1..=TENANTS {
                let id = Uuid::from_u128(n);
                sqlx::query("INSERT INTO communities (id) VALUES ($1)")
                    .bind(id)
                    .execute(&pool)
                    .await?;
                insert_aged_key(&pool, id, tenant_key(id, 1), RETENTION_SECONDS as i64 + 60)
                    .await?;
            }
            Ok::<_, sqlx::Error>(())
        }
        .await;
        if let Err(error) = setup {
            drop_isolated_schema(&admin, &schema).await;
            panic!("insert wrap tenants: {error}");
        }
        let db = Db::from_pool(pool.clone());
        let start_after = Uuid::from_u128(20);
        let (deleted, _, exhausted, txs) =
            reap_eight_tx_tick(&db, &pool, Some(start_after), 1000).await;
        let remaining: std::result::Result<i64, sqlx::Error> =
            sqlx::query_scalar("SELECT count(*) FROM event_idempotency_keys")
                .fetch_one(&pool)
                .await;
        let fence_calls: std::result::Result<Vec<(Uuid, i32)>, sqlx::Error> = sqlx::query_as(
            "SELECT community_id, calls FROM reap_fence_calls ORDER BY community_id",
        )
        .fetch_all(&pool)
        .await;
        let low_left = key_count(&pool, Uuid::from_u128(1)).await;
        drop_isolated_schema(&admin, &schema).await;
        let remaining = remaining.expect("remaining keys");
        let fence_calls = fence_calls.expect("fence calls");
        assert!(
            txs <= 8,
            "including wrap, a tick must open at most eight transactions, got {txs}"
        );
        assert!(
            deleted <= 8_000,
            "a tick must delete at most 8,000 rows, got {deleted}"
        );
        assert_eq!(
            remaining,
            TENANTS as i64 - deleted as i64,
            "deleted+remaining must cover the sparse fleet"
        );
        assert!(
            deleted >= 8,
            "wrap must still make sparse progress, got {deleted}"
        );
        assert!(
            !exhausted,
            "24 tenants starting after 20 cannot finish a full cycle in eight calls"
        );
        assert_eq!(low_left, 0, "wrap must progress into lower unseen tenants");
        assert!(
            fence_calls.iter().all(|(_, n)| *n == 1),
            "a tick must not refence a tenant: {fence_calls:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn reap_tick_wrap_completes_without_repeating_a_tenant() {
        let (schema, admin, pool) = isolated_schema_pool().await;
        if let Err(error) = install_write_allowed_fence_stub(&pool).await {
            drop_isolated_schema(&admin, &schema).await;
            panic!("install fence stub: {error}");
        }
        let tenants = [
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            Uuid::from_u128(3),
            Uuid::from_u128(4),
            Uuid::from_u128(5),
        ];
        let setup = async {
            for id in tenants {
                sqlx::query("INSERT INTO communities (id) VALUES ($1)")
                    .bind(id)
                    .execute(&pool)
                    .await?;
                insert_aged_key(&pool, id, tenant_key(id, 1), RETENTION_SECONDS as i64 + 60)
                    .await?;
            }
            Ok::<_, sqlx::Error>(())
        }
        .await;
        if let Err(error) = setup {
            drop_isolated_schema(&admin, &schema).await;
            panic!("insert cycle tenants: {error}");
        }
        let db = Db::from_pool(pool.clone());
        let (deleted, _, exhausted, txs) =
            reap_eight_tx_tick(&db, &pool, Some(Uuid::from_u128(3)), 1000).await;
        let leftover: std::result::Result<i64, sqlx::Error> =
            sqlx::query_scalar("SELECT count(*) FROM event_idempotency_keys")
                .fetch_one(&pool)
                .await;
        let fence_calls: std::result::Result<Vec<(Uuid, i32)>, sqlx::Error> = sqlx::query_as(
            "SELECT community_id, calls FROM reap_fence_calls ORDER BY community_id",
        )
        .fetch_all(&pool)
        .await;
        drop_isolated_schema(&admin, &schema).await;
        let leftover = leftover.expect("leftover");
        let fence_calls = fence_calls.expect("fence calls");
        assert!(txs <= 8, "tick opened {txs} transactions");
        assert!(deleted <= 8_000);
        assert_eq!(deleted, 5, "full cycle must clean every sparse tenant");
        assert_eq!(leftover, 0);
        assert!(exhausted, "five tenants must exhaust within eight calls");
        assert_eq!(fence_calls.len(), 5);
        assert!(
            fence_calls.iter().all(|(_, n)| *n == 1),
            "cycle must terminate without a repeated tenant: {fence_calls:?}"
        );
    }

    async fn persisted_reaper_cursor(pool: &PgPool) -> Option<Uuid> {
        sqlx::query_scalar(
            "SELECT after_community_id FROM event_idempotency_reaper_cursor WHERE id = 1",
        )
        .fetch_one(pool)
        .await
        .expect("load persisted reaper cursor")
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn reap_cursor_survives_independent_store_handoff() {
        let (schema, admin, pool) = isolated_schema_pool().await;
        if let Err(error) = install_write_allowed_fence_stub(&pool).await {
            drop_isolated_schema(&admin, &schema).await;
            panic!("install fence stub: {error}");
        }
        let expired_age = RETENTION_SECONDS as i64 + 60;
        let setup = async {
            for n in 1..=3u128 {
                let id = Uuid::from_u128(n);
                sqlx::query("INSERT INTO communities (id) VALUES ($1)")
                    .bind(id)
                    .execute(&pool)
                    .await?;
                insert_aged_key(&pool, id, tenant_key(id, 1), expired_age).await?;
            }
            Ok::<_, sqlx::Error>(())
        }
        .await;
        if let Err(error) = setup {
            drop_isolated_schema(&admin, &schema).await;
            panic!("insert handoff tenants: {error}");
        }
        let db1 = Db::from_pool(pool.clone());
        let first = db1
            .reap_expired_event_idempotency_keys_progress(1000, false, None, false)
            .await;
        let first = match first {
            Ok(progress) => progress,
            Err(error) => {
                drop_isolated_schema(&admin, &schema).await;
                panic!("first store reap: {error}");
            }
        };
        let persisted = match db1.event_idempotency_reaper_cursor().await {
            Ok(cursor) => cursor,
            Err(error) => {
                drop_isolated_schema(&admin, &schema).await;
                panic!("load cursor from first store: {error}");
            }
        };
        if persisted != first.next_after {
            drop_isolated_schema(&admin, &schema).await;
            panic!(
                "committed cursor must match visited tenant, persisted={persisted:?} next={:?}",
                first.next_after
            );
        }
        let db2 = Db::from_pool(pool.clone());
        let loaded = match db2.event_idempotency_reaper_cursor().await {
            Ok(cursor) => cursor,
            Err(error) => {
                drop_isolated_schema(&admin, &schema).await;
                panic!("independent store must load the committed cursor: {error}");
            }
        };
        if loaded != persisted {
            drop_isolated_schema(&admin, &schema).await;
            panic!("independent store loaded {loaded:?}, expected {persisted:?}");
        }
        let second = db2
            .reap_expired_event_idempotency_keys_progress(1000, false, loaded, false)
            .await;
        let leftover = [
            key_count(&pool, Uuid::from_u128(1)).await,
            key_count(&pool, Uuid::from_u128(2)).await,
            key_count(&pool, Uuid::from_u128(3)).await,
        ];
        drop_isolated_schema(&admin, &schema).await;
        let second = second.expect("second store continues from committed cursor");
        assert_eq!(first.deleted, 1);
        assert_eq!(second.deleted, 1);
        assert_eq!(leftover[0], 0, "first tenant reaped by the first store");
        assert_eq!(leftover[1], 0, "second store must continue, not restart");
        assert_eq!(leftover[2], 1, "later tenants wait behind the cursor");
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn reap_cursor_does_not_advance_when_delete_rolls_back() {
        let (schema, admin, pool) = isolated_schema_pool().await;
        if let Err(error) = install_write_allowed_fence_stub(&pool).await {
            drop_isolated_schema(&admin, &schema).await;
            panic!("install fence stub: {error}");
        }
        let community = Uuid::from_u128(1);
        let setup = async {
            sqlx::query("INSERT INTO communities (id) VALUES ($1)")
                .bind(community)
                .execute(&pool)
                .await?;
            insert_aged_key(
                &pool,
                community,
                tenant_key(community, 1),
                RETENTION_SECONDS as i64 + 60,
            )
            .await?;
            sqlx::query(
                r#"
                CREATE FUNCTION fail_reap_delete() RETURNS trigger
                LANGUAGE plpgsql
                AS $$
                BEGIN
                    RAISE EXCEPTION 'reap delete rolled back'
                        USING ERRCODE = 'raise_exception';
                END;
                $$
                "#,
            )
            .execute(&pool)
            .await?;
            sqlx::query(
                r#"
                CREATE TRIGGER fail_reap_delete
                AFTER DELETE ON event_idempotency_keys
                FOR EACH STATEMENT
                EXECUTE FUNCTION fail_reap_delete()
                "#,
            )
            .execute(&pool)
            .await?;
            Ok::<_, sqlx::Error>(())
        }
        .await;
        if let Err(error) = setup {
            drop_isolated_schema(&admin, &schema).await;
            panic!("install rollback fixtures: {error}");
        }
        let db = Db::from_pool(pool.clone());
        let before = persisted_reaper_cursor(&pool).await;
        let failed = db
            .reap_expired_event_idempotency_keys_progress(1000, false, None, false)
            .await;
        let after = persisted_reaper_cursor(&pool).await;
        let leftover = key_count(&pool, community).await;
        drop_isolated_schema(&admin, &schema).await;
        assert!(failed.is_err(), "forced delete failure must surface");
        assert_eq!(before, None);
        assert_eq!(
            after, None,
            "rolled-back delete must not persist the cursor"
        );
        assert_eq!(leftover, 1, "rolled-back delete must keep expired rows");
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn reap_nine_tenants_repeated_leader_reaches_ninth() {
        let (schema, admin, pool) = isolated_schema_pool().await;
        if let Err(error) = install_write_allowed_fence_stub(&pool).await {
            drop_isolated_schema(&admin, &schema).await;
            panic!("install fence stub: {error}");
        }
        let expired_age = RETENTION_SECONDS as i64 + 60;
        let setup = async {
            for n in 1..=9u128 {
                let id = Uuid::from_u128(n);
                sqlx::query("INSERT INTO communities (id) VALUES ($1)")
                    .bind(id)
                    .execute(&pool)
                    .await?;
                insert_aged_key(&pool, id, tenant_key(id, 1), expired_age).await?;
                if n <= 8 {
                    insert_aged_key(&pool, id, tenant_key(id, 2), 0).await?;
                }
            }
            Ok::<_, sqlx::Error>(())
        }
        .await;
        if let Err(error) = setup {
            drop_isolated_schema(&admin, &schema).await;
            panic!("insert nine-tenant fixtures: {error}");
        }
        let leader1 = Db::from_pool(pool.clone());
        let (deleted1, after1, _, txs1) = reap_eight_tx_tick(&leader1, &pool, None, 1000).await;
        let ninth = Uuid::from_u128(9);
        let ninth_after_first = key_count(&pool, ninth).await;
        let persisted = match leader1.event_idempotency_reaper_cursor().await {
            Ok(cursor) => cursor,
            Err(error) => {
                drop_isolated_schema(&admin, &schema).await;
                panic!("first leader cursor: {error}");
            }
        };
        if txs1 != 8 || deleted1 != 8 || ninth_after_first != 1 || persisted != after1 {
            drop_isolated_schema(&admin, &schema).await;
            panic!(
                "first replacement tick must spend eight tenants and persist, \
                 txs={txs1} deleted={deleted1} ninth={ninth_after_first} cursor={persisted:?}"
            );
        }
        let leader2 = Db::from_pool(pool.clone());
        let loaded = match leader2.event_idempotency_reaper_cursor().await {
            Ok(cursor) => cursor,
            Err(error) => {
                drop_isolated_schema(&admin, &schema).await;
                panic!("replacement leader load: {error}");
            }
        };
        let (deleted2, _, _, txs2) = reap_eight_tx_tick(&leader2, &pool, loaded, 1000).await;
        let ninth_left = key_count(&pool, ninth).await;
        drop_isolated_schema(&admin, &schema).await;
        assert_eq!(loaded, Some(Uuid::from_u128(8)));
        assert!(txs2 <= 8);
        assert_eq!(deleted2, 1, "replacement leader must reap the ninth tenant");
        assert_eq!(ninth_left, 0);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn reap_persisted_cursor_wraps_without_repeating_start_bound() {
        let (schema, admin, pool) = isolated_schema_pool().await;
        if let Err(error) = install_write_allowed_fence_stub(&pool).await {
            drop_isolated_schema(&admin, &schema).await;
            panic!("install fence stub: {error}");
        }
        let expired_age = RETENTION_SECONDS as i64 + 60;
        let setup = async {
            for n in 1..=5u128 {
                let id = Uuid::from_u128(n);
                sqlx::query("INSERT INTO communities (id) VALUES ($1)")
                    .bind(id)
                    .execute(&pool)
                    .await?;
                insert_aged_key(&pool, id, tenant_key(id, 1), expired_age).await?;
            }
            Ok::<_, sqlx::Error>(())
        }
        .await;
        if let Err(error) = setup {
            drop_isolated_schema(&admin, &schema).await;
            panic!("insert wrap cursor tenants: {error}");
        }
        let db = Db::from_pool(pool.clone());
        let start = Some(Uuid::from_u128(3));
        let (deleted, after, exhausted, txs) = reap_eight_tx_tick(&db, &pool, start, 1000).await;
        let persisted = persisted_reaper_cursor(&pool).await;
        let leftover: std::result::Result<i64, sqlx::Error> =
            sqlx::query_scalar("SELECT count(*) FROM event_idempotency_keys")
                .fetch_one(&pool)
                .await;
        drop_isolated_schema(&admin, &schema).await;
        assert!(txs <= 8);
        assert_eq!(deleted, 5);
        assert!(exhausted);
        assert_eq!(after, start);
        assert_eq!(persisted, start);
        assert_eq!(leftover.expect("leftover"), 0);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn keyed_insert_persists_valid_mentions_and_skips_malformed_p_tags() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let valid: Vec<String> = (1u16..=63).map(mention_hex).collect();
        let raw = "not-a-hex-pubkey-value";
        let mut mixed_tags: Vec<Tag> = valid
            .iter()
            .map(|hex| Tag::parse(["p", hex]).expect("valid p"))
            .collect();
        mixed_tags.push(Tag::parse(["p", raw]).expect("malformed p"));
        let event = stream_event(&keys, "mentions", 1_700_000_200, mixed_tags);
        let inserted = db
            .insert_keyed_stream_event_with_thread_metadata(
                community,
                author,
                key_n(40),
                &event,
                None,
                None,
            )
            .await
            .expect("keyed insert with mixed p-tags");
        assert!(inserted.should_dispatch());
        let mentions: Vec<String> = sqlx::query_scalar(
            "SELECT pubkey_hex FROM event_mentions WHERE community_id = $1 ORDER BY pubkey_hex",
        )
        .bind(community_uuid)
        .fetch_all(&pool)
        .await
        .expect("list mentions");
        let mut expected = valid.clone();
        expected.sort();
        assert_eq!(mentions.len(), 63);
        assert_eq!(mentions, expected);
        assert!(!mentions.iter().any(|value| value == raw));

        let control_community_uuid = make_test_community(&pool).await;
        let control_community = CommunityId::from_uuid(control_community_uuid);
        let control_valid: Vec<String> = (100u16..=162).map(mention_hex).collect();
        let control_tags: Vec<Tag> = control_valid
            .iter()
            .map(|hex| Tag::parse(["p", hex]).expect("valid p"))
            .collect();
        let control_event = stream_event(&keys, "all-valid", 1_700_000_201, control_tags);
        let control_inserted = db
            .insert_keyed_stream_event_with_thread_metadata(
                control_community,
                author,
                key_n(41),
                &control_event,
                None,
                None,
            )
            .await
            .expect("keyed insert with all-valid p-tags");
        assert!(control_inserted.should_dispatch());
        let control_mentions: Vec<String> = sqlx::query_scalar(
            "SELECT pubkey_hex FROM event_mentions WHERE community_id = $1 AND event_id = $2 ORDER BY pubkey_hex",
        )
        .bind(control_community_uuid)
        .bind(control_event.id.as_bytes().as_slice())
        .fetch_all(&pool)
        .await
        .expect("list all-valid mentions");
        let mut control_expected = control_valid;
        control_expected.sort();
        assert_eq!(control_mentions.len(), 63);
        assert_eq!(control_mentions, control_expected);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn keyed_duplicate_mixed_case_p_tags_do_not_fail_completion() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let hex = "ab".repeat(32);
        let upper = hex.to_ascii_uppercase();
        let mixed: String = hex
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect();
        let event = stream_event(
            &keys,
            "dup-ptags",
            1_700_000_211,
            vec![
                Tag::parse(["p", &upper]).expect("upper p"),
                Tag::parse(["p", &hex]).expect("lower p"),
                Tag::parse(["p", &mixed]).expect("mixed p"),
            ],
        );
        let inserted = db
            .insert_keyed_stream_event_with_thread_metadata(
                community,
                author,
                key_n(42),
                &event,
                None,
                None,
            )
            .await
            .expect("duplicate mixed-case p-tags must not fail completion");
        assert!(inserted.should_dispatch());
        assert_eq!(
            mention_pubkeys(&pool, community_uuid, event.id.as_bytes().as_slice()).await,
            vec![hex]
        );
        assert_eq!(event_count(&pool, community_uuid).await, 1);
        assert_eq!(key_count(&pool, community_uuid).await, 1);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn keyed_mention_insert_failure_rolls_back_event_mentions_and_key() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let hex = mention_hex(7);
        let event = stream_event(
            &keys,
            "mention-fail",
            1_700_000_212,
            vec![Tag::parse(["p", &hex]).expect("p")],
        );
        let (fn_name, trig_name) =
            install_community_mention_insert_failure(&pool, community_uuid).await;
        let err = db
            .insert_keyed_stream_event_with_thread_metadata(
                community,
                author,
                key_n(43),
                &event,
                None,
                None,
            )
            .await
            .expect_err("mention failure must fail keyed completion");
        assert!(matches!(err, DbError::Sqlx(_)), "got {err:?}");
        assert_eq!(event_count(&pool, community_uuid).await, 0);
        assert_eq!(mention_count(&pool, community_uuid).await, 0);
        assert_eq!(key_count(&pool, community_uuid).await, 0);

        uninstall_community_mention_insert_failure(&pool, &trig_name, &fn_name).await;
        let retried = db
            .insert_keyed_stream_event_with_thread_metadata(
                community,
                author,
                key_n(43),
                &event,
                None,
                None,
            )
            .await
            .expect("same key must remain reservable after mention rollback");
        assert!(retried.should_dispatch());
        assert_eq!(event_count(&pool, community_uuid).await, 1);
        assert_eq!(key_count(&pool, community_uuid).await, 1);
        assert_eq!(
            mention_pubkeys(&pool, community_uuid, event.id.as_bytes().as_slice()).await,
            vec![hex]
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn ordinary_and_keyed_mention_rows_match_for_the_same_tags() {
        let pool = setup_pool().await;
        let ordinary_community_uuid = make_test_community(&pool).await;
        let keyed_community_uuid = make_test_community(&pool).await;
        let ordinary_community = CommunityId::from_uuid(ordinary_community_uuid);
        let keyed_community = CommunityId::from_uuid(keyed_community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let hex = "cd".repeat(32);
        let upper = hex.to_ascii_uppercase();
        let trailing = mention_hex(9);
        let tags = vec![
            Tag::parse(["p", &upper]).expect("upper p"),
            Tag::parse(["p", &hex]).expect("lower p"),
            Tag::parse(["p", &trailing, "wss://relay.example"]).expect("trailing p"),
            Tag::parse(["P", &mention_hex(11)]).expect("uppercase kind"),
            Tag::parse(["e", &"11".repeat(32)]).expect("e tag"),
            Tag::parse(["p", "not-a-hex-pubkey-value"]).expect("malformed p"),
        ];
        let ordinary_event = stream_event(&keys, "ordinary-path", 1_700_000_213, tags.clone());
        let keyed_event = stream_event(&keys, "keyed-path", 1_700_000_214, tags);
        insert_event_with_thread_metadata(&pool, ordinary_community, &ordinary_event, None, None)
            .await
            .expect("ordinary event");
        crate::insert_mentions(&pool, ordinary_community, &ordinary_event, None)
            .await
            .expect("ordinary mentions");
        let keyed_inserted = db
            .insert_keyed_stream_event_with_thread_metadata(
                keyed_community,
                author,
                key_n(44),
                &keyed_event,
                None,
                None,
            )
            .await
            .expect("keyed insert");
        assert!(keyed_inserted.should_dispatch());
        let ordinary_mentions = mention_pubkeys(
            &pool,
            ordinary_community_uuid,
            ordinary_event.id.as_bytes().as_slice(),
        )
        .await;
        let keyed_mentions = mention_pubkeys(
            &pool,
            keyed_community_uuid,
            keyed_event.id.as_bytes().as_slice(),
        )
        .await;
        assert_eq!(ordinary_mentions, keyed_mentions);
        let mut expected = vec![hex, trailing];
        expected.sort();
        assert_eq!(ordinary_mentions, expected);
    }

    #[test]
    fn old_outer_complete_deadline_cannot_cover_phased_persist_and_recovery() {
        const OLD_GUESSED_OUTER_SECS: u64 = 31;
        const MIN_PERSIST_STATEMENTS: u64 = 2;
        const {
            assert!(
                MIN_PERSIST_STATEMENTS * KEYED_RESERVATION_STATEMENT_TIMEOUT_SECS
                    + KEYED_COMMIT_RECOVERY_LOOKUP_TIMEOUT_SECS
                    > OLD_GUESSED_OUTER_SECS,
                "an external 31s complete deadline can cancel witness recovery after COMMIT"
            );
        }
        assert_eq!(REAP_MAX_COLD_COMMUNITY_PROBES_PER_TX, 1024);
        assert!(
            std::mem::size_of::<KeyedReservation>() > 128,
            "Reserved must stay boxed so large_enum_variant stays clean"
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn lost_commit_ack_is_one_accepted_dispatch_then_exactly_once_replay() {
        let pool = setup_pool().await;
        let community_uuid = make_test_community(&pool).await;
        let community = CommunityId::from_uuid(community_uuid);
        let db = Db::from_pool(pool.clone());
        let keys = Keys::generate();
        let author = keys.public_key().to_bytes();
        let key = key_n(90);
        let event = stream_event(&keys, "old-boundary-lost-ack", 1_700_000_400, vec![]);
        let recovered = reserved_for(&db, community, author, key, &event)
            .await
            .with_lost_commit_ack()
            .complete_for_event(&event, None)
            .await
            .expect("ambiguous COMMIT must reach witness recovery");
        assert!(
            recovered.should_dispatch(),
            "lost-ack recovery of this witness is the one accepted dispatch"
        );
        let stored = recovered
            .into_fresh_stored_event()
            .expect("RecoveredFresh uses the ingest fresh branch");
        assert_eq!(stored.event.id, event.id);
        assert_eq!(event_count(&pool, community_uuid).await, 1);

        let retry = db
            .insert_keyed_stream_event_with_thread_metadata(
                community, author, key, &event, None, None,
            )
            .await
            .expect("retry after recovered-fresh");
        assert!(
            !retry.should_dispatch(),
            "retry after durable commit must not dispatch again"
        );
        assert!(matches!(
            retry,
            KeyedStreamInsert::Replay { original_event_id }
                if &original_event_id == event.id.as_bytes()
        ));
        assert_eq!(event_count(&pool, community_uuid).await, 1);
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY
        );
        assert_eq!(
            keyed_commit_recovery_available_permits(),
            KEYED_COMMIT_RECOVERY_CAPACITY
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn reap_many_cold_tenants_do_not_delay_one_hot_tenant() {
        let (schema, admin, pool) = isolated_schema_pool().await;
        if let Err(error) = install_write_allowed_fence_stub(&pool).await {
            drop_isolated_schema(&admin, &schema).await;
            panic!("install fence stub: {error}");
        }
        const COLD: i32 = 1000;
        assert!(REAP_MAX_COLD_COMMUNITY_PROBES_PER_TX as i32 >= COLD);
        let hot = Uuid::from_u128(1001);
        let expired_age = RETENTION_SECONDS as i64 + 60;
        let setup = async {
            sqlx::query(
                r#"
                INSERT INTO communities (id)
                SELECT ('00000000-0000-0000-0000-0000' || lpad(to_hex(g), 8, '0'))::uuid
                  FROM generate_series(1, $1) AS g
                "#,
            )
            .bind(COLD)
            .execute(&pool)
            .await?;
            sqlx::query("INSERT INTO communities (id) VALUES ($1)")
                .bind(hot)
                .execute(&pool)
                .await?;
            sqlx::query(
                r#"
                INSERT INTO event_idempotency_keys (
                    community_id, author_pubkey, idempotency_key,
                    intent_hash, event_id, created_at, reservation_witness
                )
                SELECT ('00000000-0000-0000-0000-0000' || lpad(to_hex(g), 8, '0'))::uuid,
                       $2,
                       decode(lpad(to_hex(g), 64, '0'), 'hex'),
                       $3,
                       decode(lpad(to_hex(g + 100000), 64, '0'), 'hex'),
                       clock_timestamp(),
                       decode(lpad(to_hex(g + 200000), 64, '0'), 'hex')
                  FROM generate_series(1, $1) AS g
                "#,
            )
            .bind(COLD)
            .bind([7u8; 32].as_slice())
            .bind([8u8; 32].as_slice())
            .execute(&pool)
            .await?;
            insert_aged_keys(&pool, hot, 3, expired_age, 50_000).await?;
            Ok::<_, sqlx::Error>(())
        }
        .await;
        if let Err(error) = setup {
            drop_isolated_schema(&admin, &schema).await;
            panic!("insert many-cold/one-hot fixtures: {error}");
        }
        let db = Db::from_pool(pool.clone());
        let (deleted, _, exhausted, txs) = reap_eight_tx_tick(&db, &pool, None, 1000).await;
        let hot_left = key_count(&pool, hot).await;
        let cold_left: std::result::Result<i64, sqlx::Error> = sqlx::query_scalar(
            r#"
            SELECT count(*)
              FROM event_idempotency_keys
             WHERE community_id <> $1
            "#,
        )
        .bind(hot)
        .fetch_one(&pool)
        .await;
        let fence_calls: std::result::Result<Vec<(Uuid, i32)>, sqlx::Error> = sqlx::query_as(
            "SELECT community_id, calls FROM reap_fence_calls ORDER BY community_id",
        )
        .fetch_all(&pool)
        .await;
        drop_isolated_schema(&admin, &schema).await;
        let cold_left = cold_left.expect("cold leftover");
        let fence_calls = fence_calls.expect("fence calls");
        assert!(
            txs <= 8,
            "a thousand cold tenants must not spend the eight-transaction tick, got {txs}"
        );
        assert_eq!(
            deleted, 3,
            "the hot tenant's expired rows must be reaped in the same tick, got {deleted}"
        );
        assert_eq!(hot_left, 0, "hot tenant must make progress this tick");
        assert_eq!(
            cold_left, COLD as i64,
            "cold unexpired rows must survive the skip-ahead"
        );
        assert_eq!(
            fence_calls.len(),
            1,
            "only the hot tenant must reach the deletion fence: {fence_calls:?}"
        );
        assert_eq!(fence_calls[0].0, hot);
        assert!(
            exhausted,
            "skipping 1,000 cold tenants then deleting the final/highest hot tenant \
             reaches end of scan on the next transaction; exhausted must be true"
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn stalled_tenant_cannot_consume_every_reservation_slot() {
        let pool = setup_pool().await;
        let stalled_uuid = make_test_community(&pool).await;
        let other_uuid = make_test_community(&pool).await;
        let stalled_community = CommunityId::from_uuid(stalled_uuid);
        let other_community = CommunityId::from_uuid(other_uuid);
        let db = Db::from_pool(pool.clone());
        let stalled_keys = Keys::generate();
        let other_keys = Keys::generate();
        let stalled_author = stalled_keys.public_key().to_bytes();
        let other_author = other_keys.public_key().to_bytes();

        let mut hold = pool.begin().await.expect("begin exclusive deletion lock");
        sqlx::query("SELECT pg_advisory_xact_lock(community_deletion_lock_key($1))")
            .bind(stalled_uuid)
            .execute(&mut *hold)
            .await
            .expect("take exclusive deletion lock");

        let mut waiters = Vec::new();
        for i in 0..KEYED_RESERVATION_PER_TENANT_CAPACITY {
            let db = Db::from_pool(pool.clone());
            let event = stream_event(
                &stalled_keys,
                &format!("stalled-{i}"),
                1_700_000_500 + i as u64,
                vec![],
            );
            let key = key_n(100 + i as u8);
            waiters.push(tokio::spawn(async move {
                db.begin_keyed_stream_reservation_for_event(
                    stalled_community,
                    stalled_author,
                    key,
                    &event,
                    None,
                    None,
                )
                .await
            }));
        }

        let expected_available = KEYED_RESERVATION_CAPACITY - KEYED_RESERVATION_PER_TENANT_CAPACITY;
        let started = std::time::Instant::now();
        loop {
            if keyed_reservation_available_permits() == expected_available {
                break;
            }
            if started.elapsed() > std::time::Duration::from_secs(1) {
                for waiter in &waiters {
                    waiter.abort();
                }
                for waiter in waiters {
                    let _ = waiter.await;
                }
                let _ = hold.rollback().await;
                panic!("stalled tenant never filled its per-tenant reservation cap");
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            keyed_reservation_available_permits(),
            expected_available,
            "one stalled tenant must occupy exactly {KEYED_RESERVATION_PER_TENANT_CAPACITY} of {KEYED_RESERVATION_CAPACITY} global slots"
        );

        let other_event = stream_event(&other_keys, "other-tenant", 1_700_000_520, vec![]);
        let other_started = std::time::Instant::now();
        let other = db
            .begin_keyed_stream_reservation_for_event(
                other_community,
                other_author,
                key_n(200),
                &other_event,
                None,
                None,
            )
            .await;
        assert!(
            other_started.elapsed() < std::time::Duration::from_millis(500),
            "unrelated tenant must not wait on the stalled tenant's deletion lock"
        );
        let other = other.expect("unrelated tenant reservation");
        match other {
            KeyedReserveOutcome::Reserved(reservation) => {
                reservation.abort().await.expect("abort other tenant");
            }
            KeyedReserveOutcome::Replay { .. } | KeyedReserveOutcome::Conflict { .. } => {
                panic!("unrelated tenant must reserve successfully")
            }
        }
        assert_eq!(
            keyed_reservation_available_permits(),
            expected_available,
            "aborting the unrelated tenant must restore the stalled-tenant ceiling"
        );

        for waiter in &waiters {
            waiter.abort();
        }
        for waiter in waiters {
            let _ = waiter.await;
        }
        let _ = hold.rollback().await;
        assert_eq!(
            keyed_reservation_available_permits(),
            KEYED_RESERVATION_CAPACITY
        );
        assert_eq!(
            keyed_commit_recovery_available_permits(),
            KEYED_COMMIT_RECOVERY_CAPACITY
        );
    }
}
