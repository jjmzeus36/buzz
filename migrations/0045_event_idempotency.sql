-- Keyed POST /events reservation (NIP-MI). Unique per (community, author, key).
-- No FK to partitioned events. UPDATE is rejected; DELETE remains for community purge.

CREATE TABLE event_idempotency_keys (
    community_id     UUID NOT NULL REFERENCES communities(id),
    author_pubkey    BYTEA NOT NULL CHECK (octet_length(author_pubkey) = 32),
    idempotency_key  BYTEA NOT NULL CHECK (octet_length(idempotency_key) = 32),
    intent_hash      BYTEA NOT NULL CHECK (octet_length(intent_hash) = 32),
    event_id         BYTEA NOT NULL CHECK (octet_length(event_id) = 32),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    -- Per-reservation unforgeable ownership witness. Bound in the same
    -- transaction as the key and event so a lost COMMIT acknowledgement can
    -- recover as this request's fresh insert only when the committed row
    -- matches this exact witness.
    reservation_witness BYTEA NOT NULL CHECK (octet_length(reservation_witness) = 32),
    PRIMARY KEY (community_id, author_pubkey, idempotency_key)
);

CREATE INDEX idx_event_idempotency_keys_created_at
    ON event_idempotency_keys (created_at, community_id, author_pubkey, idempotency_key);

CREATE INDEX idx_event_idempotency_keys_community_created_at
    ON event_idempotency_keys (community_id, created_at, author_pubkey, idempotency_key);

CREATE FUNCTION prevent_event_idempotency_keys_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'event_idempotency_keys rows are immutable'
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$;

CREATE TRIGGER event_idempotency_keys_immutable
BEFORE UPDATE ON event_idempotency_keys
FOR EACH ROW
EXECUTE FUNCTION prevent_event_idempotency_keys_update();

SELECT attach_community_write_fence('event_idempotency_keys');

-- Singleton operator-global reaper cursor. One row for the deployment; a new
-- leader loads the committed exclusive bound and continues the skip-scan.
-- NULL after_community_id means "start at the lowest community_id".
-- No community_id column, no write-fence, no immutability trigger: this row
-- must UPDATE in the same transaction as bounded expired-key deletes.
CREATE TABLE event_idempotency_reaper_cursor (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    after_community_id UUID
);

INSERT INTO event_idempotency_reaper_cursor (id, after_community_id) VALUES (1, NULL);

INSERT INTO _operator_global_tables (table_name, reason) VALUES
    ('event_idempotency_reaper_cursor', 'singleton operator-global NIP-MI expired-key reaper cursor; never tenant-scoped');
