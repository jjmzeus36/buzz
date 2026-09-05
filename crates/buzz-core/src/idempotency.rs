//! Canonical event idempotency keys and semantic-intent hashing (NIP-MI).
//!
//! Durable keyed `POST /events` acceptance is a Postgres unique reservation.
//! Redis/WebSocket delivery stays the relay's existing best-effort path.

#[cfg(feature = "test-utils")]
use std::collections::HashMap;
#[cfg(feature = "test-utils")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "test-utils")]
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};

use nostr::Event;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::kind::KIND_STREAM_MESSAGE;

/// NIP-11 `supported_extensions` token advertised by a keyed relay.
pub const EXTENSION_ID: &str = "buzz-idempotency";

/// HTTP header carrying the caller-chosen key.
pub const HEADER_NAME: &str = "Idempotency-Key";

/// First element of the canonical intent array. Changing this is a new hash.
pub const CANONICAL_VERSION: &str = "buzz-idempotency-v1";

/// Required hex character count for an idempotency key.
pub const KEY_HEX_LEN: usize = 64;

/// SHA-256 digest size stored with each reservation.
pub const HASH_LEN: usize = 32;

/// Compact JSON pattern advertised in NIP-11 `idempotency.key_pattern`.
pub const KEY_PATTERN: &str = "^[0-9a-f]{64}$";

/// HTTP status for same-key different-intent collision.
pub const CONFLICT_STATUS: u64 = 409;

/// Guaranteed Replay/Conflict horizon in seconds (seven days).
pub const RETENTION_SECONDS: u64 = 604_800;

/// Maximum raw `p` tags allowed on a keyed event before reservation.
pub const KEYED_MAX_P_TAGS: usize = 64;

/// Exact NIP-11 `idempotency.scope` (order is part of the contract).
pub const SCOPE: [&str; 2] = ["community", "author"];

/// Exact NIP-11 `idempotency.intent` (order is part of the contract).
pub const INTENT: [&str; 4] = ["pubkey", "kind", "tags", "content"];

/// Errors produced while parsing a key or hashing semantic intent.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IdempotencyError {
    /// Key is not exactly 64 lowercase hexadecimal characters.
    #[error("idempotency key must be exactly 64 lowercase hexadecimal characters")]
    InvalidKey,
    /// Canonical intent JSON could not be encoded.
    #[error("idempotency intent could not be canonicalized")]
    Canonicalize,
}

/// Parsed 32-byte key plus the semantic-intent hash for one signed event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventIdempotencyClaim {
    /// Caller-chosen key (decoded 32 bytes).
    pub key: [u8; HASH_LEN],
    /// SHA-256 of the canonical semantic-intent array.
    pub intent_hash: [u8; HASH_LEN],
}

impl EventIdempotencyClaim {
    /// Parse `key_hex` and bind it to `event`'s canonical semantic intent.
    pub fn from_key_and_event(key_hex: &str, event: &Event) -> Result<Self, IdempotencyError> {
        Ok(EventIdempotencyClaim::from(
            &PreparedKeyedIntent::from_key_hex_and_event(key_hex, event)?,
        ))
    }
}

/// Immutable keyed intent: canonical semantic hash computed exactly once.
///
/// Fields are private so a later phase cannot pair one event's hash with
/// another event, key, or author. Binding uses the already-validated
/// Nostr event id (SHA-256 of the signed canonical serialization) rather
/// than cloning the tag matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreparedKeyedIntent {
    key: [u8; HASH_LEN],
    intent_hash: [u8; HASH_LEN],
    event_id: [u8; HASH_LEN],
    author: [u8; HASH_LEN],
}

impl PreparedKeyedIntent {
    /// Canonicalize, serialize, and SHA-256-hash semantic intent exactly once.
    pub fn prepare(key: [u8; HASH_LEN], event: &Event) -> Result<Self, IdempotencyError> {
        Ok(Self {
            key,
            intent_hash: semantic_intent_hash(event)?,
            event_id: *event.id.as_bytes(),
            author: event.pubkey.to_bytes(),
        })
    }

    /// Parse `key_hex` and prepare semantic intent for `event` in one pass.
    pub fn from_key_hex_and_event(key_hex: &str, event: &Event) -> Result<Self, IdempotencyError> {
        Self::prepare(parse_idempotency_key(key_hex)?, event)
    }

    /// Caller-chosen key bound to this preparation.
    pub fn key(&self) -> &[u8; HASH_LEN] {
        &self.key
    }

    /// SHA-256 of the canonical semantic-intent array, computed at prepare.
    pub fn intent_hash(&self) -> &[u8; HASH_LEN] {
        &self.intent_hash
    }

    /// Signed event id this preparation is bound to.
    pub fn event_id(&self) -> &[u8; HASH_LEN] {
        &self.event_id
    }

    /// Author pubkey taken from the prepared event.
    pub fn author(&self) -> &[u8; HASH_LEN] {
        &self.author
    }

    /// True when `event` is the exact signed event this preparation bound.
    pub fn binds_event(&self, event: &Event) -> bool {
        self.event_id == *event.id.as_bytes() && self.author == event.pubkey.to_bytes()
    }
}

impl From<&PreparedKeyedIntent> for EventIdempotencyClaim {
    fn from(prepared: &PreparedKeyedIntent) -> Self {
        Self {
            key: prepared.key,
            intent_hash: prepared.intent_hash,
        }
    }
}

/// Parse a 64-character lowercase hex idempotency key into 32 bytes.
pub fn parse_idempotency_key(key_hex: &str) -> Result<[u8; HASH_LEN], IdempotencyError> {
    if !is_lowercase_hex_key(key_hex) {
        return Err(IdempotencyError::InvalidKey);
    }
    let mut key = [0u8; HASH_LEN];
    hex::decode_to_slice(key_hex.as_bytes(), &mut key).map_err(|_| IdempotencyError::InvalidKey)?;
    Ok(key)
}

/// Return true when `key_hex` is exactly 64 lowercase hexadecimal characters.
pub fn is_lowercase_hex_key(key_hex: &str) -> bool {
    key_hex.len() == KEY_HEX_LEN
        && key_hex
            .as_bytes()
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// v1 keyed `POST /events` allowlist: kind 9 (`KIND_STREAM_MESSAGE`) only.
pub const fn supports_keyed_kind(kind: u32) -> bool {
    kind == KIND_STREAM_MESSAGE
}

/// Count tags whose first element is exactly the literal `"p"`.
pub fn keyed_p_tag_count(event: &Event) -> usize {
    event
        .tags
        .iter()
        .filter(|tag| tag.as_slice().first().map(String::as_str) == Some("p"))
        .count()
}

/// Canonical six-field NIP-11 `idempotency` object.
pub fn canonical_nip11_descriptor() -> Value {
    serde_json::json!({
        "header": HEADER_NAME,
        "key_pattern": KEY_PATTERN,
        "scope": SCOPE,
        "intent": INTENT,
        "conflict_status": CONFLICT_STATUS,
        "retention_seconds": RETENTION_SECONDS,
    })
}

/// Keyed-client fail-closed gate: exact extension token and closed descriptor.
///
/// True only when `supported_extensions` contains the exact `buzz-idempotency`
/// token and `idempotency` is an object of exactly six keys with the v1 values
/// and array order. Token-only, descriptor-only, extra fields, reordering, and
/// type/value mismatches are rejected.
pub fn nip11_keyed_client_accepts(doc: &Value) -> bool {
    let Some(root) = doc.as_object() else {
        return false;
    };
    let token_ok = root
        .get("supported_extensions")
        .and_then(Value::as_array)
        .is_some_and(|extensions| {
            extensions
                .iter()
                .any(|value| value.as_str() == Some(EXTENSION_ID))
        });
    if !token_ok {
        return false;
    }
    let Some(descriptor) = root.get("idempotency") else {
        return false;
    };
    descriptor_matches_canonical(descriptor)
}

fn descriptor_matches_canonical(value: &Value) -> bool {
    let Some(obj) = value.as_object() else {
        return false;
    };
    if obj.len() != 6 {
        return false;
    }
    if !obj.contains_key("header")
        || !obj.contains_key("key_pattern")
        || !obj.contains_key("scope")
        || !obj.contains_key("intent")
        || !obj.contains_key("conflict_status")
        || !obj.contains_key("retention_seconds")
    {
        return false;
    }
    if obj.get("header").and_then(Value::as_str) != Some(HEADER_NAME) {
        return false;
    }
    if obj.get("key_pattern").and_then(Value::as_str) != Some(KEY_PATTERN) {
        return false;
    }
    if !string_array_eq(obj.get("scope"), &SCOPE) {
        return false;
    }
    if !string_array_eq(obj.get("intent"), &INTENT) {
        return false;
    }
    if obj.get("conflict_status").and_then(Value::as_u64) != Some(CONFLICT_STATUS) {
        return false;
    }
    obj.get("retention_seconds").and_then(Value::as_u64) == Some(RETENTION_SECONDS)
}

fn string_array_eq(value: Option<&Value>, expected: &[&str]) -> bool {
    let Some(items) = value.and_then(Value::as_array) else {
        return false;
    };
    if items.len() != expected.len() {
        return false;
    }
    items
        .iter()
        .zip(expected.iter())
        .all(|(item, want)| item.as_str() == Some(*want))
}

#[cfg(feature = "test-utils")]
struct SemanticIntentHashWatchRegistry {
    next_id: u64,
    by_event: HashMap<[u8; HASH_LEN], HashMap<u64, Weak<AtomicU64>>>,
}

#[cfg(feature = "test-utils")]
fn semantic_intent_hash_watchers() -> &'static Mutex<SemanticIntentHashWatchRegistry> {
    static WATCHERS: OnceLock<Mutex<SemanticIntentHashWatchRegistry>> = OnceLock::new();
    WATCHERS.get_or_init(|| {
        Mutex::new(SemanticIntentHashWatchRegistry {
            next_id: 0,
            by_event: HashMap::new(),
        })
    })
}

#[cfg(feature = "test-utils")]
fn lock_semantic_intent_hash_watchers() -> MutexGuard<'static, SemanticIntentHashWatchRegistry> {
    semantic_intent_hash_watchers()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(feature = "test-utils")]
fn record_semantic_intent_hash(event_id: [u8; HASH_LEN]) {
    let mut registry = lock_semantic_intent_hash_watchers();
    let empty = match registry.by_event.get_mut(&event_id) {
        Some(bucket) => {
            bucket.retain(|_, weak| {
                if let Some(counter) = weak.upgrade() {
                    counter.fetch_add(1, Ordering::Relaxed);
                    true
                } else {
                    false
                }
            });
            bucket.is_empty()
        }
        None => false,
    };
    if empty {
        registry.by_event.remove(&event_id);
    }
}

/// Test-only RAII watch of actual [`semantic_intent_hash`] executions for one event id.
///
/// Regression instrumentation, not a production API. Each install owns an
/// independent counter. One hash execution increments every live watcher
/// registered for that exact event id. [`Self::count`] reads only this
/// watcher. Drop deregisters only this watcher and removes the event-id
/// bucket when it is empty. Unrelated event ids do not share this count.
/// Poisoned locks recover without panicking.
#[cfg(feature = "test-utils")]
pub struct SemanticIntentHashWatch {
    event_id: [u8; HASH_LEN],
    watcher_id: u64,
    counter: Arc<AtomicU64>,
}

#[cfg(feature = "test-utils")]
impl SemanticIntentHashWatch {
    /// Install a watch for `event_id` with this watcher's count at zero.
    pub fn install(event_id: [u8; HASH_LEN]) -> Self {
        let counter = Arc::new(AtomicU64::new(0));
        let mut registry = lock_semantic_intent_hash_watchers();
        let watcher_id = registry.next_id;
        registry.next_id = registry.next_id.wrapping_add(1);
        registry
            .by_event
            .entry(event_id)
            .or_default()
            .insert(watcher_id, Arc::downgrade(&counter));
        Self {
            event_id,
            watcher_id,
            counter,
        }
    }

    /// Observed [`semantic_intent_hash`] executions for this watcher.
    pub fn count(&self) -> u64 {
        self.counter.load(Ordering::Relaxed)
    }
}

#[cfg(feature = "test-utils")]
impl Drop for SemanticIntentHashWatch {
    fn drop(&mut self) {
        let mut registry = lock_semantic_intent_hash_watchers();
        let empty = match registry.by_event.get_mut(&self.event_id) {
            Some(bucket) => {
                bucket.remove(&self.watcher_id);
                bucket.is_empty()
            }
            None => false,
        };
        if empty {
            registry.by_event.remove(&self.event_id);
        }
    }
}

/// SHA-256 of the canonical semantic-intent array for `event`.
///
/// The array is `["buzz-idempotency-v1", pubkey, kind, tags, content]` encoded
/// as compact UTF-8 JSON. `id`, `created_at`, and `sig` are excluded.
pub fn semantic_intent_hash(event: &Event) -> Result<[u8; HASH_LEN], IdempotencyError> {
    let bytes = canonical_intent_bytes(event)?;
    #[cfg(feature = "test-utils")]
    record_semantic_intent_hash(*event.id.as_bytes());
    Ok(Sha256::digest(&bytes).into())
}

/// Compact JSON bytes hashed by [`semantic_intent_hash`].
pub fn canonical_intent_bytes(event: &Event) -> Result<Vec<u8>, IdempotencyError> {
    serde_json::to_vec(&canonical_intent_value(event)).map_err(|_| IdempotencyError::Canonicalize)
}

/// JSON array form of the canonical semantic intent.
pub fn canonical_intent_value(event: &Event) -> Value {
    let tags: Vec<Vec<String>> = event
        .tags
        .iter()
        .map(|tag| tag.as_slice().to_vec())
        .collect();
    serde_json::json!([
        CANONICAL_VERSION,
        event.pubkey.to_hex(),
        event.kind.as_u16(),
        tags,
        event.content.as_str(),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp};
    use serde_json::json;

    const GOLDEN_SECRET_HEX: &str =
        "0000000000000000000000000000000000000000000000000000000000000001";
    const GOLDEN_PUBKEY_HEX: &str =
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    /// Independently specified compact UTF-8 (161 bytes). Not produced by hashing
    /// the live `Event` in this test.
    const GOLDEN_CANONICAL_UTF8: &[u8] =
        br#"["buzz-idempotency-v1","79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",9,[["h","00000000-0000-0000-0000-000000000001"],["t","alpha"]],"hello"]"#;
    /// Independently computed SHA-256 of `GOLDEN_CANONICAL_UTF8`.
    const GOLDEN_INTENT_SHA256_HEX: &str =
        "6a9586ea5ba8311721ca16b67864b1b47b47fb87e938649c19b30a6ebb1f586d";

    fn signed_event(keys: &Keys, content: &str, created_at: u64, extra_tags: Vec<Tag>) -> Event {
        EventBuilder::new(Kind::TextNote, content)
            .tags(extra_tags)
            .custom_created_at(Timestamp::from(created_at))
            .sign_with_keys(keys)
            .expect("sign")
    }

    fn golden_event(created_at: u64) -> Event {
        let keys = Keys::parse(GOLDEN_SECRET_HEX).expect("golden secret");
        EventBuilder::new(Kind::Custom(9), "hello")
            .tags([
                Tag::parse(["h", "00000000-0000-0000-0000-000000000001"]).expect("h tag"),
                Tag::parse(["t", "alpha"]).expect("t tag"),
            ])
            .custom_created_at(Timestamp::from(created_at))
            .sign_with_keys(&keys)
            .expect("sign")
    }

    fn exact_descriptor() -> Value {
        canonical_nip11_descriptor()
    }

    fn exact_nip11() -> Value {
        json!({
            "supported_extensions": ["nip-er", EXTENSION_ID],
            "idempotency": exact_descriptor(),
        })
    }

    fn nip11_with_descriptor(descriptor: Value) -> Value {
        json!({
            "supported_extensions": [EXTENSION_ID],
            "idempotency": descriptor,
        })
    }

    #[test]
    fn parse_rejects_empty_uppercase_short_long_and_non_hex() {
        assert_eq!(parse_idempotency_key(""), Err(IdempotencyError::InvalidKey));
        assert_eq!(
            parse_idempotency_key(&"A".repeat(64)),
            Err(IdempotencyError::InvalidKey)
        );
        assert_eq!(
            parse_idempotency_key(&"ab".repeat(31)),
            Err(IdempotencyError::InvalidKey)
        );
        assert_eq!(
            parse_idempotency_key(&format!("{}a", "ab".repeat(32))),
            Err(IdempotencyError::InvalidKey)
        );
        assert_eq!(
            parse_idempotency_key(&format!("{}g", "a".repeat(63))),
            Err(IdempotencyError::InvalidKey)
        );
        assert_eq!(
            parse_idempotency_key(&format!("{}A", "a".repeat(63))),
            Err(IdempotencyError::InvalidKey)
        );
    }

    #[test]
    fn parse_accepts_lowercase_hex_and_round_trips() {
        let hex = "0123456789abcdef".repeat(4);
        let key = parse_idempotency_key(&hex).expect("valid key");
        assert_eq!(hex::encode(key), hex);
    }

    #[test]
    fn hash_excludes_id_created_at_and_sig() {
        let keys = Keys::generate();
        let first = signed_event(&keys, "hello", 1_700_000_000, vec![]);
        let second = signed_event(&keys, "hello", 1_700_000_001, vec![]);
        assert_ne!(first.id, second.id);
        assert_ne!(first.created_at, second.created_at);
        assert_ne!(first.sig, second.sig);
        assert_eq!(
            semantic_intent_hash(&first).expect("hash"),
            semantic_intent_hash(&second).expect("hash")
        );
    }

    #[test]
    fn hash_includes_pubkey_kind_tags_and_content() {
        let keys = Keys::generate();
        let other = Keys::generate();
        let base = signed_event(&keys, "hello", 1_700_000_000, vec![]);
        let different_content = signed_event(&keys, "hello!", 1_700_000_000, vec![]);
        let different_author = signed_event(&other, "hello", 1_700_000_000, vec![]);
        let with_tag = signed_event(
            &keys,
            "hello",
            1_700_000_000,
            vec![Tag::parse(["t", "x"]).expect("tag")],
        );
        let different_kind = EventBuilder::new(Kind::Custom(9), "hello")
            .custom_created_at(Timestamp::from(1_700_000_000))
            .sign_with_keys(&keys)
            .expect("sign");
        let base_hash = semantic_intent_hash(&base).expect("hash");
        assert_ne!(
            base_hash,
            semantic_intent_hash(&different_content).expect("hash")
        );
        assert_ne!(
            base_hash,
            semantic_intent_hash(&different_author).expect("hash")
        );
        assert_ne!(base_hash, semantic_intent_hash(&with_tag).expect("hash"));
        assert_ne!(
            base_hash,
            semantic_intent_hash(&different_kind).expect("hash")
        );
    }

    #[test]
    fn tag_order_is_semantic() {
        let keys = Keys::generate();
        let first = signed_event(
            &keys,
            "hello",
            1,
            vec![
                Tag::parse(["t", "a"]).expect("tag"),
                Tag::parse(["t", "b"]).expect("tag"),
            ],
        );
        let second = signed_event(
            &keys,
            "hello",
            1,
            vec![
                Tag::parse(["t", "b"]).expect("tag"),
                Tag::parse(["t", "a"]).expect("tag"),
            ],
        );
        assert_ne!(
            semantic_intent_hash(&first).expect("hash"),
            semantic_intent_hash(&second).expect("hash")
        );
    }

    #[test]
    fn golden_canonical_utf8_and_sha256() {
        assert_eq!(GOLDEN_CANONICAL_UTF8.len(), 161);
        let event_a = golden_event(1);
        let event_b = golden_event(99);
        assert_eq!(event_a.pubkey.to_hex(), GOLDEN_PUBKEY_HEX);
        let bytes_a = canonical_intent_bytes(&event_a).expect("bytes");
        let bytes_b = canonical_intent_bytes(&event_b).expect("bytes");
        assert_eq!(bytes_a.as_slice(), GOLDEN_CANONICAL_UTF8);
        assert_eq!(bytes_b.as_slice(), GOLDEN_CANONICAL_UTF8);
        assert_eq!(
            hex::encode(semantic_intent_hash(&event_a).expect("hash")),
            GOLDEN_INTENT_SHA256_HEX
        );
    }

    #[test]
    fn supports_keyed_kind_is_stream_message_only() {
        assert!(supports_keyed_kind(KIND_STREAM_MESSAGE));
        assert!(supports_keyed_kind(9));
        assert!(!supports_keyed_kind(1));
        assert!(!supports_keyed_kind(5));
        assert!(!supports_keyed_kind(7));
        assert!(!supports_keyed_kind(0));
        assert!(!supports_keyed_kind(3));
        assert!(!supports_keyed_kind(45001));
        assert!(!supports_keyed_kind(45003));
        assert!(!supports_keyed_kind(40002));
        assert!(!supports_keyed_kind(40008));
        assert!(!supports_keyed_kind(30000));
        assert!(!supports_keyed_kind(9007));
    }

    #[test]
    fn nip11_keyed_client_accepts_exact_token_and_descriptor() {
        assert!(nip11_keyed_client_accepts(&exact_nip11()));
    }

    #[test]
    fn nip11_keyed_client_rejects_token_only() {
        assert!(!nip11_keyed_client_accepts(&json!({
            "supported_extensions": [EXTENSION_ID]
        })));
    }

    #[test]
    fn nip11_keyed_client_rejects_case_variant_extension_token() {
        assert!(!nip11_keyed_client_accepts(&json!({
            "supported_extensions": ["Buzz-idempotency"],
            "idempotency": exact_descriptor(),
        })));
    }

    #[test]
    fn nip11_keyed_client_rejects_descriptor_only() {
        assert!(!nip11_keyed_client_accepts(&json!({
            "idempotency": exact_descriptor()
        })));
    }

    #[test]
    fn nip11_keyed_client_rejects_missing_descriptor_fields() {
        assert!(!nip11_keyed_client_accepts(&nip11_with_descriptor(json!({
            "key_pattern": KEY_PATTERN,
            "scope": SCOPE,
            "intent": INTENT,
            "conflict_status": 409
        }))));
        assert!(!nip11_keyed_client_accepts(&nip11_with_descriptor(json!({
            "header": HEADER_NAME,
            "scope": SCOPE,
            "intent": INTENT,
            "conflict_status": 409
        }))));
        assert!(!nip11_keyed_client_accepts(&nip11_with_descriptor(json!({
            "header": HEADER_NAME,
            "key_pattern": KEY_PATTERN,
            "intent": INTENT,
            "conflict_status": 409
        }))));
        assert!(!nip11_keyed_client_accepts(&nip11_with_descriptor(json!({
            "header": HEADER_NAME,
            "key_pattern": KEY_PATTERN,
            "scope": SCOPE,
            "conflict_status": 409
        }))));
        assert!(!nip11_keyed_client_accepts(&nip11_with_descriptor(json!({
            "header": HEADER_NAME,
            "key_pattern": KEY_PATTERN,
            "scope": SCOPE,
            "intent": INTENT
        }))));
        assert!(!nip11_keyed_client_accepts(&nip11_with_descriptor(json!({
            "header": HEADER_NAME,
            "key_pattern": KEY_PATTERN,
            "scope": SCOPE,
            "intent": INTENT,
            "conflict_status": 409
        }))));
    }

    #[test]
    fn nip11_keyed_client_rejects_wrong_values_types_and_order() {
        assert!(!nip11_keyed_client_accepts(&nip11_with_descriptor(json!({
            "header": "X-Idempotency-Key",
            "key_pattern": KEY_PATTERN,
            "scope": SCOPE,
            "intent": INTENT,
            "conflict_status": 409,
            "retention_seconds": RETENTION_SECONDS
        }))));
        assert!(!nip11_keyed_client_accepts(&nip11_with_descriptor(json!({
            "header": HEADER_NAME,
            "key_pattern": "^[0-9a-f]{32}$",
            "scope": SCOPE,
            "intent": INTENT,
            "conflict_status": 409,
            "retention_seconds": RETENTION_SECONDS
        }))));
        assert!(!nip11_keyed_client_accepts(&nip11_with_descriptor(json!({
            "header": HEADER_NAME,
            "key_pattern": KEY_PATTERN,
            "scope": ["author", "community"],
            "intent": INTENT,
            "conflict_status": 409,
            "retention_seconds": RETENTION_SECONDS
        }))));
        assert!(!nip11_keyed_client_accepts(&nip11_with_descriptor(json!({
            "header": HEADER_NAME,
            "key_pattern": KEY_PATTERN,
            "scope": SCOPE,
            "intent": ["kind", "pubkey", "tags", "content"],
            "conflict_status": 409,
            "retention_seconds": RETENTION_SECONDS
        }))));
        assert!(!nip11_keyed_client_accepts(&nip11_with_descriptor(json!({
            "header": HEADER_NAME,
            "key_pattern": KEY_PATTERN,
            "scope": SCOPE,
            "intent": INTENT,
            "conflict_status": 400,
            "retention_seconds": RETENTION_SECONDS
        }))));
        assert!(!nip11_keyed_client_accepts(&nip11_with_descriptor(json!({
            "header": HEADER_NAME,
            "key_pattern": KEY_PATTERN,
            "scope": SCOPE,
            "intent": INTENT,
            "conflict_status": "409",
            "retention_seconds": RETENTION_SECONDS
        }))));
        assert!(!nip11_keyed_client_accepts(&nip11_with_descriptor(json!({
            "header": HEADER_NAME,
            "key_pattern": KEY_PATTERN,
            "scope": SCOPE,
            "intent": INTENT,
            "conflict_status": 409.0,
            "retention_seconds": RETENTION_SECONDS
        }))));
        assert!(!nip11_keyed_client_accepts(&nip11_with_descriptor(json!({
            "header": HEADER_NAME,
            "key_pattern": KEY_PATTERN,
            "scope": SCOPE,
            "intent": INTENT,
            "conflict_status": 409,
            "retention_seconds": 0
        }))));
    }

    #[test]
    fn nip11_keyed_client_rejects_extra_descriptor_field() {
        assert!(!nip11_keyed_client_accepts(&nip11_with_descriptor(json!({
            "header": HEADER_NAME,
            "key_pattern": KEY_PATTERN,
            "scope": SCOPE,
            "intent": INTENT,
            "conflict_status": 409,
            "retention_seconds": RETENTION_SECONDS,
            "version": 1
        }))));
    }

    #[test]
    fn keyed_p_tag_count_is_literal_p_only() {
        let keys = Keys::generate();
        let none = signed_event(&keys, "hello", 1, vec![]);
        assert_eq!(keyed_p_tag_count(&none), 0);
        let mixed = signed_event(
            &keys,
            "hello",
            1,
            vec![
                Tag::parse(["p", "aa"]).expect("p"),
                Tag::parse(["t", "p"]).expect("t"),
                Tag::parse(["preimage", "x"]).expect("preimage"),
                Tag::parse(["p", "bb", "relay"]).expect("p2"),
            ],
        );
        assert_eq!(keyed_p_tag_count(&mixed), 2);
        assert!(keyed_p_tag_count(&mixed) <= KEYED_MAX_P_TAGS);
    }

    #[test]
    fn claim_binds_parsed_key_to_intent() {
        let keys = Keys::generate();
        let event = signed_event(&keys, "hello", 1, vec![]);
        let hex = "fd".repeat(32);
        let claim = EventIdempotencyClaim::from_key_and_event(&hex, &event).expect("claim");
        assert_eq!(hex::encode(claim.key), hex);
        assert_eq!(
            claim.intent_hash,
            semantic_intent_hash(&event).expect("hash")
        );
    }

    #[test]
    fn prepare_matches_golden_hash_and_binds_signed_event_id() {
        let event_a = golden_event(1);
        let event_b = golden_event(99);
        let key = parse_idempotency_key(&"ab".repeat(32)).expect("key");
        let prepared = PreparedKeyedIntent::prepare(key, &event_a).expect("prepare");
        assert_eq!(
            hex::encode(prepared.intent_hash()),
            GOLDEN_INTENT_SHA256_HEX
        );
        assert_eq!(prepared.key(), &key);
        assert_eq!(prepared.event_id(), event_a.id.as_bytes());
        assert_eq!(prepared.author(), &event_a.pubkey.to_bytes());
        assert!(prepared.binds_event(&event_a));
        assert!(!prepared.binds_event(&event_b));
        let claim = EventIdempotencyClaim::from(&prepared);
        assert_eq!(claim.key, key);
        assert_eq!(claim.intent_hash, *prepared.intent_hash());
    }

    #[cfg(feature = "test-utils")]
    #[test]
    fn overlapping_semantic_intent_hash_watchers_count_independently() {
        let keys = Keys::generate();
        let event_a = signed_event(&keys, "watch-a", 1, vec![]);
        let event_b = signed_event(&keys, "watch-b", 2, vec![]);
        let id_a = *event_a.id.as_bytes();
        let id_b = *event_b.id.as_bytes();
        assert_ne!(id_a, id_b);

        let first = SemanticIntentHashWatch::install(id_a);
        semantic_intent_hash(&event_a).expect("hash a");
        assert_eq!(first.count(), 1);

        let second = SemanticIntentHashWatch::install(id_a);
        let other = SemanticIntentHashWatch::install(id_b);
        assert_eq!(
            first.count(),
            1,
            "installing another watcher must not reset a live one"
        );
        assert_eq!(second.count(), 0);
        assert_eq!(other.count(), 0);

        semantic_intent_hash(&event_a).expect("hash a again");
        semantic_intent_hash(&event_b).expect("hash b");
        assert_eq!(first.count(), 2);
        assert_eq!(second.count(), 1);
        assert_eq!(other.count(), 1);

        drop(first);
        assert_eq!(
            second.count(),
            1,
            "dropping one watcher must not reset another"
        );
        assert_eq!(other.count(), 1);

        semantic_intent_hash(&event_a).expect("hash a after drop");
        assert_eq!(second.count(), 2);
        assert_eq!(other.count(), 1);
    }
}
