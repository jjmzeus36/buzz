NIP-MI
======

Event Idempotency
-----------------

`draft` `optional` `relay`

Keyed HTTP `POST /events` binds a caller-chosen key to one durable accepted
event in `(community, author)` scope. This NIP does not change NIP-01 identity
(`id`, `created_at`, `sig`). It does not add an outbox or retry worker.

Redis and WebSocket delivery stay the relay's existing best-effort, lossy,
replayable wakeups. No end-to-end physical exactly-once delivery is claimed.
WebSocket `EVENT` does not accept `Idempotency-Key`.

## v1 kind allowlist

v1 accepts a keyed request only for kind `9` (`KIND_STREAM_MESSAGE`). Other
kinds on a keyed `POST /events` MUST fail HTTP 400 without reservation.

## Generic external `p` cap

Every externally accepted event — keyed HTTP, unkeyed HTTP, and WebSocket —
MUST reject more than 64 raw `p` tags (tag whose first element is the
literal lowercase character `"p"`) with HTTP 400 / the existing invalid
ingest contract, before reservation. Malformed and duplicate lowercase `p`
tags count toward the cap. Uppercase `"P"` and non-`p` tags do not.
Trusted direct-DB writers that are not kind `9` remain uncapped.

## Keyed HTTP admission order

Keyed `POST /events` MUST follow this order. This is a protocol contract,
not a release, deployment, or Stage 1 completion claim.

1. Idempotency-Key header parse and host→community binding.
2. Cryptographic NIP-98 authentication and authenticated-signer derivation
   only. Invalid header, unmapped host, failed authentication, and unkeyed
   requests never enter this lane.
3. Start one absolute five-second early deadline immediately after
   authentication. It is never reset per await. Obtain a fail-fast local
   pre-attempt permit: process-global 32 and authenticated-community 16,
   without a waiter queue. Local resource exhaustion MUST return HTTP 503
   with `Retry-After` before upstream attempt charging or replay-marker I/O.
   Such rejected requests consume no attempt, fresh, or persist quota. Keep
   the permit until early ingress is acquired or this request exits.
4. For a request admitted by that local bound, perform atomic authenticated
   attempt identity+community+fleet admission exactly once
   (`KeyedHttpAttempts`, 60s window, 300 / 1,200 / 2,400). Allowed
   increments all three once. Explicit identity/community/fleet denial and
   known pre-mutation failure increment none and stop. An ambiguous
   transport timeout or lost reply fails closed and may leave all three
   changed or all three unchanged, never a subset, and MUST NOT be blindly
   retried.
5. Fail-fast RAII ingress: process-global 32 and authenticated-community
   16. No waiter queue. Acquire ingress before releasing the pre-attempt
   permit. The remaining early deadline covers attempt admission and every
   cancellation-safe fallible early I/O await through replay, validation,
   committed classification, fresh admission, and atomic persist admission.
   Blocking signature verification is joined before those permits can release.
6. NIP-98 replay-marker check/write.
7. Parse, event signature, membership, verified-owner metadata,
   supported-kind, body, and the generic external `p` cap.
8. Semantic intent preparation exactly once and committed DB classification
   (Replay, Conflict, or miss — no Pending variant).
9. Fresh identity+community+fleet admission only for a committed miss
   (`KeyedHttpFresh`). Replay, Conflict, and open-reservation
   replay/conflict/timeout consume no fresh or persist admission.
   Rollback-to-miss may proceed to fresh. A classify-miss that later
   races to replay at authoritative reserve may honestly have consumed
   fresh and persist.
10. Atomic persist identity+community+fleet admission (authenticated HTTP
    principal, tenant-prefixed community key, unreachable persist fleet
    sentinel, `ApiCalls`, 60s, configured-principal / 600 / 1,200).
11. Release early ingress permits.
12. Authoritative reservation, persist/commit, abort/replay/conflict
    handling. Do not hold a DB transaction or reservation across Redis
    awaits. Do not time out a durable DB commit after it has begun.
    Verified-owner materialization waits until after an accepted terminal
    result and after early permits are released.

## Capability

When NIP-MI advertisement is enabled, NIP-11 MUST include
`supported_extensions` token `buzz-idempotency` and an `idempotency` object
with exactly six fields:

```json
{
  "header": "Idempotency-Key",
  "key_pattern": "^[0-9a-f]{64}$",
  "scope": ["community", "author"],
  "intent": ["pubkey", "kind", "tags", "content"],
  "conflict_status": 409,
  "retention_seconds": 604800
}
```

When advertisement is off, NIP-11 MUST omit both the token and the top-level
descriptor. Token-only and descriptor-only advertisements are incompatible.

`retention_seconds` is 604800 (seven days): the guaranteed Replay/Conflict
horizon while the reservation row exists. It is not lifetime retention.
A leader-only sweeper deletes expired rows in bounded batches (up to eight
transactions of 1000 rows per 300s tick, `FOR UPDATE SKIP LOCKED`,
`community_write_allowed`). Cleanup may lag only within that backlog; it
MUST NOT be advertised as forever.

Keyed clients MUST fail closed unless the token is present and the descriptor
matches that object exactly (types and values). Extra or missing descriptor
fields, or reordered scope or intent array elements, are incompatible.

The relay MUST refuse to start if `event_idempotency_keys` and its covering
index `(created_at, community_id, author_pubkey, idempotency_key)` are missing.
NIP-11 MUST NOT advertise this capability before that schema prerequisite
holds and every serving replica enforces keyed `POST /events`.

Advertisement is gated by `BUZZ_IDEMPOTENCY_ADVERTISE` (default off). Only
the clear affirmatives `true` and `1` enable it. Baseline pods silently
ignore `Idempotency-Key`, so a mixed-version `RollingUpdate` (`maxSurge: 1`,
`maxUnavailable: 0`) MUST NOT advertise while an old binary can still
receive traffic. Use existing chart `relay.extraEnv` in two phases:

1. Roll the new enforcing binary with the gate absent or false. Old and new
   pods advertise nothing. After this rollout, every serving replica enforces
   keyed semantics.
2. Set `BUZZ_IDEMPOTENCY_ADVERTISE=true` and roll configuration. During this
   second rollout every replica already enforces, even if only some advertise.

## Header

`POST /events` MAY include one `Idempotency-Key` of exactly 64 lowercase hex
characters. Duplicate physical headers, comma-folded values, non-UTF8, and
any other shape MUST be rejected with HTTP 400 before database reservation.
Authentication and all semantic validation MUST precede reservation.

## Canonical intent

SHA-256 of compact UTF-8 JSON:

`["buzz-idempotency-v1", <pubkey-hex>, <kind>, <tags>, <content>]`

Excluded: `id`, `created_at`, `sig`. Included: every user-semantic field
(`pubkey`, `kind`, `tags` in event order with every element, `content`).


The v1 canonical bytes MUST use the following encoding. These rules pin the
existing Buzz encoding; they do not change the meaning of retained v1 hashes.

- Encode the array as UTF-8 without a BOM, trailing newline, or whitespace
  outside strings. Use the field order shown above. Encode `pubkey-hex` as
  64 lowercase hex characters and `kind` as an unsigned base-10 integer with
  no leading zeros (except `0`), exponent, or decimal point.
- Preserve tag order, every tag element, and the exact Unicode scalar sequence
  of every string. Do not sort, deduplicate, trim, or normalize Unicode.
- In strings, encode double quote as `\"` and backslash as `\\`. Encode U+0008,
  U+0009, U+000A, U+000C, and U+000D as `\b`, `\t`, `\n`, `\f`, and `\r` respectively.
  Encode every other U+0000–U+001F scalar as `\u00xx`, using lowercase hex.
- Emit every other scalar directly in UTF-8. In particular, `/`, non-ASCII
  text, U+007F, U+2028, and U+2029 MUST NOT be escaped. Alternative JSON
  spellings that decode to the same string are not alternative canonical bytes.

The core `canonical_intent_matches_escaping_and_unicode_golden_vector` fixture
pins an interoperability vector containing all U+0000–U+001F controls, quote,
backslash, slash, composed and decomposed accented text, CJK, an astral scalar,
U+2028, U+2029, and U+007F in content, plus escapable and Unicode tag data.
Its canonical UTF-8 SHA-256 is `9013b8c4e31c852a35a9479f8bb46f54c696b866a7095053914ae965b7dac761`.

## Reservation

In the same Postgres transaction, INSERT the unique key
`(community_id, author_pubkey, idempotency_key)` first, bound to
`intent_hash` and `event_id`. The atomic unit is the reservation, the event
row, thread metadata and counters, the mention index, and any DB-triggered
`push_match_queue` rows. Any failure or commit error rolls all of those back.

UPDATE of a key row is rejected. DELETE remains so community purge and the
seven-day sweeper can remove rows. There is no foreign key to partitioned
`events`. `event_id` is a BYTEA copy of the signed id.

A new key bound to an already-stored identical signed event (`BoundExisting`)
MUST persist that alias until expiry so a later same-key different body is
HTTP 409, not a new write.

## First insert, replay, conflict, preexisting

Same key, same intent: return the original event id, no dispatch.

Same key, different intent: rollback, HTTP 409 (body MUST NOT expose the
existing event id). CLI exit 5.

Keyed writer busy (admission stripe/global timeout, fleet aggregate, or SQL
`55P03`/`57014`): HTTP 503 with `Retry-After`. Clients MUST wait at least that
hint and MAY add bounded jitter. Malformed or missing hints use client jitter
only.

New key, new event: post-commit dispatch once. Replay and BoundExisting do
not dispatch.

## CLI

`buzz messages send --idempotency-key <64 lowercase hex>` validates key and
kind 9 locally before any upload or relay side effect, fail-closes on NIP-11,
reuses the same signed event and header on 503/network retries with fresh
NIP-98, waits at least the server `Retry-After` hint and may add jitter, and
maps 409 to exit 5.
