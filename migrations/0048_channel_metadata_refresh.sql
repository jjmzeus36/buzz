-- Canonical metadata publication is derived work, never a replay of the
-- membership/topic command that changed its source. Keep one bounded row per
-- channel and advance its generation in the same transaction as that source.
CREATE TABLE channel_metadata_refresh (
    community_id UUID NOT NULL,
    channel_id UUID NOT NULL,
    requested_version BIGINT NOT NULL DEFAULT 1 CHECK (requested_version > 0),
    completed_version BIGINT NOT NULL DEFAULT 0 CHECK (completed_version >= 0 AND completed_version <= requested_version),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    lease_token UUID,
    lease_until TIMESTAMPTZ,
    PRIMARY KEY (community_id, channel_id),
    FOREIGN KEY (community_id, channel_id) REFERENCES channels(community_id, id) ON DELETE CASCADE
);
CREATE INDEX idx_channel_metadata_refresh_pending ON channel_metadata_refresh (requested_at)
    WHERE completed_version < requested_version;
SELECT attach_community_write_fence('channel_metadata_refresh');

CREATE FUNCTION request_channel_metadata_refresh() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE
    target_community UUID;
    target_channel UUID;
BEGIN
    IF TG_TABLE_NAME = 'channels' THEN
        target_community := NEW.community_id;
        target_channel := NEW.id;
    ELSE
        target_community := CASE WHEN TG_OP = 'DELETE' THEN OLD.community_id ELSE NEW.community_id END;
        target_channel := CASE WHEN TG_OP = 'DELETE' THEN OLD.channel_id ELSE NEW.channel_id END;
    END IF;
    -- A cascading purge must not recreate a child of a deleted channel.
    INSERT INTO channel_metadata_refresh (community_id, channel_id)
    SELECT community_id, id FROM channels
    WHERE community_id = target_community AND id = target_channel AND deleted_at IS NULL
    ON CONFLICT (community_id, channel_id) DO UPDATE
    SET requested_version = channel_metadata_refresh.requested_version + 1,
        requested_at = CASE
            WHEN channel_metadata_refresh.completed_version = channel_metadata_refresh.requested_version THEN NOW()
            ELSE channel_metadata_refresh.requested_at
        END;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END
$$;
CREATE TRIGGER channels_request_metadata_refresh
AFTER INSERT OR UPDATE OF name, description, visibility, channel_type, topic, purpose, archived_at, ttl_seconds, ttl_deadline ON channels
FOR EACH ROW EXECUTE FUNCTION request_channel_metadata_refresh();
-- DM participant tags in kind:39000 are also canonical metadata.
CREATE TRIGGER channel_members_request_metadata_refresh
AFTER INSERT OR UPDATE OR DELETE ON channel_members
FOR EACH ROW EXECUTE FUNCTION request_channel_metadata_refresh();

-- Recover pre-upgrade stale projections without replaying their source actions.
INSERT INTO channel_metadata_refresh (community_id, channel_id)
SELECT c.community_id, c.id FROM channels c JOIN communities t ON t.id = c.community_id
WHERE c.deleted_at IS NULL AND t.archived_at IS NULL AND t.deletion_state = 'active';

-- Recovery must not keep ephemeral channels alive by publishing metadata.
CREATE OR REPLACE FUNCTION refresh_channel_ttl_after_event_insert() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    channel_ttl INTEGER;
BEGIN
    -- Channel creation initializes its deadline; derived metadata is not activity.
    IF NEW.channel_id IS NOT NULL AND NEW.kind <> 9007 AND NEW.kind <> 39000 THEN
        BEGIN
            PERFORM pg_advisory_xact_lock_shared(hashtextextended(
                'buzz_channel_ttl:' || NEW.community_id::text || ':' || NEW.channel_id::text, 0));

            SELECT ttl_seconds INTO channel_ttl
            FROM channels
            WHERE community_id = NEW.community_id AND id = NEW.channel_id;

            IF channel_ttl IS NOT NULL THEN
                UPDATE channels
                SET ttl_deadline = clock_timestamp() + make_interval(secs => ttl_seconds)
                WHERE community_id = NEW.community_id
                  AND id = NEW.channel_id
                  AND ttl_seconds IS NOT NULL
                  AND archived_at IS NULL
                  AND deleted_at IS NULL;
            END IF;
        EXCEPTION WHEN OTHERS THEN
            -- Preserve the existing best-effort contract: a TTL refresh failure
            -- must not reject an otherwise valid durable event.
            RAISE WARNING 'channel TTL refresh failed for community %, channel %: %',
                NEW.community_id, NEW.channel_id, SQLERRM;
        END;
    END IF;
    RETURN NULL;
END
$$;
