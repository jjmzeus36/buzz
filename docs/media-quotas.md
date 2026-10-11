# Media quotas

Media quotas are disabled by default. Leave both `BUZZ_MEDIA_QUOTA_BYTES` and
`BUZZ_MEDIA_QUOTA_BASELINE_ID` absent until the operator has approved a limit
and verified complete historical ownership. Supplying only one, an empty
value, a nonpositive or overflowing limit, or a nil/invalid UUID fails startup.

The policy counts logical original bytes once per `(community, uploader,
SHA-256)`. A second owner or community claiming shared bytes receives its own
charge, even when the object already exists. Empty originals cost zero bytes.
Thumbnails, upload records, orphan derivatives, and historical S3 versions are
outside this logical quota; it is not a physical bucket-size cap. There is no
automatic refund or per-user blob deletion. Whole-community deletion purges
that community's ledger and preserves other communities' claims.

## Admission and failures

Images and files are validated and hashed before admission. Video is spooled
to a bounded temporary file, hashed, and structurally validated first. The
ledger uses actual original bytes, independent of `Content-Length`. A short
PostgreSQL transaction locks the owner account and reserves capacity before
any object-store request; it does not hold a connection during S3 I/O.

Both `pending` and `charged` rows consume capacity. Completion marks the exact
operation UUID charged only after the original, derivatives, optional upload
record, and sidecar publication succeed. The upload's existing durable serving
lease authorizes these ledger writes during deletion quiescing; stale or
cross-community leases cannot finish them.

Capacity exhaustion returns HTTP 413. Missing historical verification,
inconsistent epoch/limit, a pending same-hash operation, or unavailable
accounting returns HTTP 503. Accounting failures never fall back to allowing
an upload. A failed/canceled upload or a lost acknowledgement may have written
objects: its reservation does not expire or refund. Retrying a pending hash
requires operator reconciliation. An already charged same-size hash adds no
new liability; its normal storage retry can repair a missing object.

## Verify and enroll history

Migration 0047 creates an empty ledger. An absent account means **unknown**,
not zero. Blob metadata has no uploader and upload-event records were optional;
neither bucket listing, absent records, nor an empty ledger proves complete
owner history. Establish ownership and original sizes independently. If that
cannot be done, leave the rollout disabled for a deployment whose required
owners must continue uploading.

1. Pause upload ingress and stop/drain **every** writer, including older or
   quota-disabled replicas and in-flight storage tasks. Keep the pause through
   inventory, enrollment, readback, and activation. The tool does not stop or
   detect writers.
2. Choose a fresh, non-nil rollout UUID, record it externally, and never reuse
   it after an accounting gap. Use one approved positive BIGINT byte limit and
   this epoch across the deployment. The ledger binds each enrolled account to
   both values; a replica with a mismatched limit or epoch is refused.
3. For each owner, construct a complete manifest. On renewal, export the
   account and every ledger object, including pending liabilities whose blobs
   are missing. Include every prior hash at exactly its prior size, plus all
   independently verified claims accumulated outside enforcement. Enrollment
   atomically rejects omitted or altered liabilities and preserves pending
   states and operation tokens. Imports may exceed the future limit.
4. Record inventory sources, completeness/ownership evidence, collection time,
   writer pause, release SHA, operator identity, and manifest digest. An empty
   manifest is valid only with positive evidence of complete empty history.

The example consumes one owner manifest, at most 8 MiB. Hashes must be unique,
lowercase SHA-256; sizes are integers from zero through `9223372036854775807`.
The key decodes to exactly 32 bytes and `evidence` is nonblank, at most 4096
UTF-8 bytes. The following values are synthetic, not recommended limits:

```json
{
  "community_id": "11111111-1111-4111-8111-111111111111",
  "pubkey": "0101010101010101010101010101010101010101010101010101010101010101",
  "evidence": "complete-owner-inventory-id; writers stopped and drained",
  "complete_history_verified": true,
  "upload_writers_stopped": true,
  "baseline_id": "22222222-2222-4222-8222-222222222222",
  "limit_bytes": 10,
  "objects": [
    {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "size_bytes": 7}
  ]
}
```

Build the reviewed example with `cargo build --release -p buzz-db --example
media-quota`. Dry run is the default:

```bash
./target/release/examples/media-quota enroll owner-manifest.json
```

Dry run validates manifest shape and attestations only. It does not connect to
the database, compare old liabilities, verify ownership, or verify writer
stoppage. Compare a read-only ledger export before applying:

```sql
SELECT baseline_id, limit_bytes, evidence, enrolled_at
FROM media_quota_accounts
WHERE community_id = :'community_id'::uuid
  AND pubkey = decode(:'pubkey_hex', 'hex');

SELECT sha256, size_bytes, state, operation_id, recovery_evidence
FROM media_quota_objects
WHERE community_id = :'community_id'::uuid
  AND pubkey = decode(:'pubkey_hex', 'hex') ORDER BY sha256;
```

For apply, explicitly set `BUZZ_QUOTA_DATABASE_URL` to the approved database;
the example loads no `.env`, runs no migrations, and has no default URL:

```bash
./target/release/examples/media-quota enroll owner-manifest.json --apply
```

Require exit zero and read back the exact epoch/limit, hash/size set, retained
tokens/states, evidence, and `SUM(size_bytes)`. The printed APPLY summary
precedes the DB transaction and alone is not proof of success. Enrollment is
atomic per owner, not across the rollout. Keep writers paused if any import or
readback fails. Configure every replica with the enrolled limit and epoch,
remove older/disabled writers from service, and only then reopen ingress.

## Reconciliation and policy changes

For an uncertain pending operation, inspect the exact owner/hash/token and
external writes. The conservative recovery tool marks it charged, records
evidence, and retains its full original-byte liability. It does not delete or
refund bytes, and it does not prove an old writer has stopped. Stop/drain that
writer before allowing same-hash retry. Recovery manifest:

```json
{
  "community_id": "11111111-1111-4111-8111-111111111111",
  "pubkey": "0101010101010101010101010101010101010101010101010101010101010101",
  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "operation_id": "33333333-3333-4333-8333-333333333333",
  "evidence": "reconciliation-id; old writer stopped; retain full charge"
}
```

Run `media-quota recover recovery.json` for dry run and add `--apply` to write.
An exact repeat with the same token and recovery evidence is idempotent, so a
lost acknowledgement can be checked and retried. Different tokens/evidence or
owner tuples cannot overwrite an already recovered operation.

After any enforcement gap, repeat the stopped-writer inventory with a fresh
epoch before reenabling. This includes rollback to an old binary or operation
with both settings absent. Rotate the epoch for policy changes too. Old
reservations retain their tokens and liabilities across renewal; an old exact
completion can safely mark them charged, so renewal is not a storage fence.
The database stores the current epoch, not an enforcement-gap detector or
UUID-reuse history. Freshness, historical completeness, and writer stoppage
are explicit operator obligations.
