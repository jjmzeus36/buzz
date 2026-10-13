# Durable channel metadata recovery

Channel metadata changes record a refresh intent in the same PostgreSQL
transaction as the channel or participant update. One row per channel coalesces
successive changes. This includes updates made by an older relay during a rolling
upgrade, because database triggers record the intent.

The normal publication path still emits relay-signed kind 39000 immediately.
Its transaction records completion only after the signed metadata replacement
has been stored. It captures the requested generation before reading source
state, so a concurrent update remains pending. A failed insert or completion
update rolls the replacement back and leaves the intent available for recovery.

Each relay checks the pending queue every five seconds. It claims at most eight
active-community channels per tick, with a two-minute lease and a ten-second
publication timeout per channel. A failed attempt retains its lease as retry
backoff. A crashed worker's claim expires. Successful workers release only their
own claim token. Shutdown cancels and joins this worker; any unfinished intent
remains durable.

Recovery signs the latest canonical channel snapshot. It does not replay the
historical topic or membership command, restart a failed workflow, or recreate
its system notice. Metadata publication is not user activity and does not extend
an ephemeral channel's expiration. Archived channel metadata can be recovered;
archived or deleting communities are excluded and existing write fences apply.
The queue is included in the community deletion manifest and cascades when its
channel is physically removed.

Apply additive migration 0048 before starting this relay version. The migration
queues existing active-community channels to repair previously missed metadata.
Desired-schema installs and the post-pgschema reconciliation preserve the same
table, triggers, write fence and initial queue. Migration 0047 belongs to the
separate media-quota change; this migration does not depend on it.

This change covers durable kind 39000 projection. Live Redis/WebSocket fanout
retains its existing behavior; clients can retrieve the stored metadata after a
missed live update. Other NIP-29 command/source transactions, group admin/member
projections, membership notices, and external effects need their own atomic or
durable recovery boundaries. They are not made replay-safe by this queue.
