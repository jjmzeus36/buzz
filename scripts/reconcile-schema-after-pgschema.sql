-- Reconcile schema details that pgschema does not preserve.
--
-- pgschema reconciles DDL, but it does not execute seed DML, preserve every
-- table storage parameter from schema/schema.sql, or run side-effecting helper
-- calls such as SELECT attach_community_write_fence(...). It also currently
-- emits partition children as standalone CREATE TABLE statements. Every
-- pgschema apply caller must run this idempotent script so fresh bootstraps
-- converge on the same live database contract as migration-managed databases.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'events'::regclass
          AND inhrelid = 'events_p_past'::regclass
    ) THEN
        -- pgschema may copy parent triggers onto standalone children. Drop
        -- those copies before ATTACH; PostgreSQL recreates inherited parent
        -- triggers while attaching and rejects same-named child triggers.
        DROP TRIGGER IF EXISTS events_enqueue_push_match ON events_p_past;
        DROP TRIGGER IF EXISTS events_refresh_channel_ttl ON events_p_past;
        DROP TRIGGER IF EXISTS events_created_at_floor ON events_p_past;
        DROP TRIGGER IF EXISTS community_write_fence_events ON events_p_past;
        DROP TRIGGER IF EXISTS trg_events_guard_channel_roster_snapshot ON events_p_past;
        DROP TRIGGER IF EXISTS trg_events_nip_rs_watermark ON events_p_past;
        DROP TRIGGER IF EXISTS trg_events_purge_soft_deleted_nip_rs ON events_p_past;
        DROP TRIGGER IF EXISTS trg_events_purge_soft_deleted_buzz_mesh_status ON events_p_past;
        DROP TRIGGER IF EXISTS trg_events_guard_nip_rs_hard_delete ON events_p_past;
        ALTER TABLE events ATTACH PARTITION events_p_past
            FOR VALUES FROM (MINVALUE) TO ('2026-01-01');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'events'::regclass
          AND inhrelid = 'events_p2026_01'::regclass
    ) THEN
        DROP TRIGGER IF EXISTS events_enqueue_push_match ON events_p2026_01;
        DROP TRIGGER IF EXISTS events_refresh_channel_ttl ON events_p2026_01;
        DROP TRIGGER IF EXISTS events_created_at_floor ON events_p2026_01;
        DROP TRIGGER IF EXISTS community_write_fence_events ON events_p2026_01;
        DROP TRIGGER IF EXISTS trg_events_guard_channel_roster_snapshot ON events_p2026_01;
        DROP TRIGGER IF EXISTS trg_events_nip_rs_watermark ON events_p2026_01;
        DROP TRIGGER IF EXISTS trg_events_purge_soft_deleted_nip_rs ON events_p2026_01;
        DROP TRIGGER IF EXISTS trg_events_purge_soft_deleted_buzz_mesh_status ON events_p2026_01;
        DROP TRIGGER IF EXISTS trg_events_guard_nip_rs_hard_delete ON events_p2026_01;
        ALTER TABLE events ATTACH PARTITION events_p2026_01
            FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'events'::regclass
          AND inhrelid = 'events_p2026_02'::regclass
    ) THEN
        DROP TRIGGER IF EXISTS events_enqueue_push_match ON events_p2026_02;
        DROP TRIGGER IF EXISTS events_refresh_channel_ttl ON events_p2026_02;
        DROP TRIGGER IF EXISTS events_created_at_floor ON events_p2026_02;
        DROP TRIGGER IF EXISTS community_write_fence_events ON events_p2026_02;
        DROP TRIGGER IF EXISTS trg_events_guard_channel_roster_snapshot ON events_p2026_02;
        DROP TRIGGER IF EXISTS trg_events_nip_rs_watermark ON events_p2026_02;
        DROP TRIGGER IF EXISTS trg_events_purge_soft_deleted_nip_rs ON events_p2026_02;
        DROP TRIGGER IF EXISTS trg_events_purge_soft_deleted_buzz_mesh_status ON events_p2026_02;
        DROP TRIGGER IF EXISTS trg_events_guard_nip_rs_hard_delete ON events_p2026_02;
        ALTER TABLE events ATTACH PARTITION events_p2026_02
            FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'events'::regclass
          AND inhrelid = 'events_p2026_03'::regclass
    ) THEN
        DROP TRIGGER IF EXISTS events_enqueue_push_match ON events_p2026_03;
        DROP TRIGGER IF EXISTS events_refresh_channel_ttl ON events_p2026_03;
        DROP TRIGGER IF EXISTS events_created_at_floor ON events_p2026_03;
        DROP TRIGGER IF EXISTS community_write_fence_events ON events_p2026_03;
        DROP TRIGGER IF EXISTS trg_events_guard_channel_roster_snapshot ON events_p2026_03;
        DROP TRIGGER IF EXISTS trg_events_nip_rs_watermark ON events_p2026_03;
        DROP TRIGGER IF EXISTS trg_events_purge_soft_deleted_nip_rs ON events_p2026_03;
        DROP TRIGGER IF EXISTS trg_events_purge_soft_deleted_buzz_mesh_status ON events_p2026_03;
        DROP TRIGGER IF EXISTS trg_events_guard_nip_rs_hard_delete ON events_p2026_03;
        ALTER TABLE events ATTACH PARTITION events_p2026_03
            FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'events'::regclass
          AND inhrelid = 'events_p2026_04'::regclass
    ) THEN
        DROP TRIGGER IF EXISTS events_enqueue_push_match ON events_p2026_04;
        DROP TRIGGER IF EXISTS events_refresh_channel_ttl ON events_p2026_04;
        DROP TRIGGER IF EXISTS events_created_at_floor ON events_p2026_04;
        DROP TRIGGER IF EXISTS community_write_fence_events ON events_p2026_04;
        DROP TRIGGER IF EXISTS trg_events_guard_channel_roster_snapshot ON events_p2026_04;
        DROP TRIGGER IF EXISTS trg_events_nip_rs_watermark ON events_p2026_04;
        DROP TRIGGER IF EXISTS trg_events_purge_soft_deleted_nip_rs ON events_p2026_04;
        DROP TRIGGER IF EXISTS trg_events_purge_soft_deleted_buzz_mesh_status ON events_p2026_04;
        DROP TRIGGER IF EXISTS trg_events_guard_nip_rs_hard_delete ON events_p2026_04;
        ALTER TABLE events ATTACH PARTITION events_p2026_04
            FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'events'::regclass
          AND inhrelid = 'events_p2026_05'::regclass
    ) THEN
        DROP TRIGGER IF EXISTS events_enqueue_push_match ON events_p2026_05;
        DROP TRIGGER IF EXISTS events_refresh_channel_ttl ON events_p2026_05;
        DROP TRIGGER IF EXISTS events_created_at_floor ON events_p2026_05;
        DROP TRIGGER IF EXISTS community_write_fence_events ON events_p2026_05;
        DROP TRIGGER IF EXISTS trg_events_guard_channel_roster_snapshot ON events_p2026_05;
        DROP TRIGGER IF EXISTS trg_events_nip_rs_watermark ON events_p2026_05;
        DROP TRIGGER IF EXISTS trg_events_purge_soft_deleted_nip_rs ON events_p2026_05;
        DROP TRIGGER IF EXISTS trg_events_purge_soft_deleted_buzz_mesh_status ON events_p2026_05;
        DROP TRIGGER IF EXISTS trg_events_guard_nip_rs_hard_delete ON events_p2026_05;
        ALTER TABLE events ATTACH PARTITION events_p2026_05
            FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'events'::regclass
          AND inhrelid = 'events_p2026_06'::regclass
    ) THEN
        DROP TRIGGER IF EXISTS events_enqueue_push_match ON events_p2026_06;
        DROP TRIGGER IF EXISTS events_refresh_channel_ttl ON events_p2026_06;
        DROP TRIGGER IF EXISTS events_created_at_floor ON events_p2026_06;
        DROP TRIGGER IF EXISTS community_write_fence_events ON events_p2026_06;
        DROP TRIGGER IF EXISTS trg_events_guard_channel_roster_snapshot ON events_p2026_06;
        DROP TRIGGER IF EXISTS trg_events_nip_rs_watermark ON events_p2026_06;
        DROP TRIGGER IF EXISTS trg_events_purge_soft_deleted_nip_rs ON events_p2026_06;
        DROP TRIGGER IF EXISTS trg_events_purge_soft_deleted_buzz_mesh_status ON events_p2026_06;
        DROP TRIGGER IF EXISTS trg_events_guard_nip_rs_hard_delete ON events_p2026_06;
        ALTER TABLE events ATTACH PARTITION events_p2026_06
            FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'events'::regclass
          AND inhrelid = 'events_p_future'::regclass
    ) THEN
        DROP TRIGGER IF EXISTS events_enqueue_push_match ON events_p_future;
        DROP TRIGGER IF EXISTS events_refresh_channel_ttl ON events_p_future;
        DROP TRIGGER IF EXISTS events_created_at_floor ON events_p_future;
        DROP TRIGGER IF EXISTS community_write_fence_events ON events_p_future;
        DROP TRIGGER IF EXISTS trg_events_guard_channel_roster_snapshot ON events_p_future;
        DROP TRIGGER IF EXISTS trg_events_nip_rs_watermark ON events_p_future;
        DROP TRIGGER IF EXISTS trg_events_purge_soft_deleted_nip_rs ON events_p_future;
        DROP TRIGGER IF EXISTS trg_events_purge_soft_deleted_buzz_mesh_status ON events_p_future;
        DROP TRIGGER IF EXISTS trg_events_guard_nip_rs_hard_delete ON events_p_future;
        ALTER TABLE events ATTACH PARTITION events_p_future
            FOR VALUES FROM ('2026-07-01') TO (MAXVALUE);
    END IF;

    -- When pgschema creates partition children as standalone tables, it also
    -- preserves the parent's identity column on delivery_log children. PostgreSQL
    -- rejects attaching a child table that has its own identity column, so each
    -- delivery_log attach path drops that standalone identity first. Raw
    -- schema-created partitions are already attached, so these branches do not
    -- run against inherited partition columns.

    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'delivery_log'::regclass
          AND inhrelid = 'delivery_log_p_past'::regclass
    ) THEN
        ALTER TABLE delivery_log_p_past ALTER COLUMN id DROP IDENTITY IF EXISTS;
        DROP TRIGGER IF EXISTS community_write_fence_delivery_log ON delivery_log_p_past;
        ALTER TABLE delivery_log ATTACH PARTITION delivery_log_p_past
            FOR VALUES FROM (MINVALUE) TO ('2026-03-01');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'delivery_log'::regclass
          AND inhrelid = 'delivery_log_p2026_03'::regclass
    ) THEN
        ALTER TABLE delivery_log_p2026_03 ALTER COLUMN id DROP IDENTITY IF EXISTS;
        DROP TRIGGER IF EXISTS community_write_fence_delivery_log ON delivery_log_p2026_03;
        ALTER TABLE delivery_log ATTACH PARTITION delivery_log_p2026_03
            FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'delivery_log'::regclass
          AND inhrelid = 'delivery_log_p2026_04'::regclass
    ) THEN
        ALTER TABLE delivery_log_p2026_04 ALTER COLUMN id DROP IDENTITY IF EXISTS;
        DROP TRIGGER IF EXISTS community_write_fence_delivery_log ON delivery_log_p2026_04;
        ALTER TABLE delivery_log ATTACH PARTITION delivery_log_p2026_04
            FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'delivery_log'::regclass
          AND inhrelid = 'delivery_log_p2026_05'::regclass
    ) THEN
        ALTER TABLE delivery_log_p2026_05 ALTER COLUMN id DROP IDENTITY IF EXISTS;
        DROP TRIGGER IF EXISTS community_write_fence_delivery_log ON delivery_log_p2026_05;
        ALTER TABLE delivery_log ATTACH PARTITION delivery_log_p2026_05
            FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'delivery_log'::regclass
          AND inhrelid = 'delivery_log_p2026_06'::regclass
    ) THEN
        ALTER TABLE delivery_log_p2026_06 ALTER COLUMN id DROP IDENTITY IF EXISTS;
        DROP TRIGGER IF EXISTS community_write_fence_delivery_log ON delivery_log_p2026_06;
        ALTER TABLE delivery_log ATTACH PARTITION delivery_log_p2026_06
            FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'delivery_log'::regclass
          AND inhrelid = 'delivery_log_p_future'::regclass
    ) THEN
        ALTER TABLE delivery_log_p_future ALTER COLUMN id DROP IDENTITY IF EXISTS;
        DROP TRIGGER IF EXISTS community_write_fence_delivery_log ON delivery_log_p_future;
        ALTER TABLE delivery_log ATTACH PARTITION delivery_log_p_future
            FOR VALUES FROM ('2026-07-01') TO (MAXVALUE);
    END IF;
END $$;

-- pgschema reconciles DDL but does not apply seed DML or table storage
-- parameters from schema/schema.sql. Restore those parts of the desired-state
-- contract explicitly and fail the bootstrap if the live catalog disagrees.
ALTER TABLE replica_heartbeat SET (vacuum_truncate = false);

INSERT INTO replica_heartbeat (id) VALUES (1)
ON CONFLICT (id) DO NOTHING;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_class AS relation
        JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = current_schema()
          AND relation.relname = 'replica_heartbeat'
          AND COALESCE(
              relation.reloptions @> ARRAY['vacuum_truncate=false']::text[],
              false
          )
    ) THEN
        RAISE EXCEPTION 'replica_heartbeat must disable vacuum truncation after pgschema apply';
    END IF;

    IF (SELECT count(*) FROM replica_heartbeat WHERE id = 1) <> 1 THEN
        RAISE EXCEPTION 'replica_heartbeat must contain its singleton row after pgschema apply';
    END IF;
END $$;

SELECT attach_community_write_fence('event_idempotency_keys'::regclass);

INSERT INTO event_idempotency_reaper_cursor (id, after_community_id)
VALUES (1, NULL)
ON CONFLICT (id) DO NOTHING;

INSERT INTO _operator_global_tables (table_name, reason) VALUES
    ('event_idempotency_reaper_cursor', 'singleton operator-global NIP-MI expired-key reaper cursor; never tenant-scoped')
ON CONFLICT (table_name) DO NOTHING;

DO $$
DECLARE
    cursor_bad_col TEXT;
BEGIN
    IF (SELECT count(*) FROM event_idempotency_reaper_cursor WHERE id = 1) <> 1 THEN
        RAISE EXCEPTION
            'event_idempotency_reaper_cursor must contain its singleton row after pgschema apply';
    END IF;

    IF NOT (
        has_table_privilege(current_user, 'event_idempotency_reaper_cursor'::regclass, 'SELECT')
        AND has_table_privilege(current_user, 'event_idempotency_reaper_cursor'::regclass, 'UPDATE')
    ) THEN
        RAISE EXCEPTION
            'event_idempotency_reaper_cursor must be selectable and updatable after pgschema apply';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM _operator_global_tables
         WHERE table_name = 'event_idempotency_reaper_cursor'
    ) THEN
        RAISE EXCEPTION
            'event_idempotency_reaper_cursor must be registered operator-global after pgschema apply';
    END IF;

    SELECT required.attname
      INTO cursor_bad_col
      FROM (VALUES
            (1, 'id', 'smallint', true),
            (2, 'after_community_id', 'uuid', false)
           ) AS required(attnum, attname, fmt, is_not_null)
     WHERE NOT EXISTS (
            SELECT 1
              FROM pg_attribute AS att
              JOIN pg_class AS tbl ON tbl.oid = att.attrelid
              JOIN pg_namespace AS namespace ON namespace.oid = tbl.relnamespace
             WHERE namespace.nspname = current_schema()
               AND tbl.relname = 'event_idempotency_reaper_cursor'
               AND att.attnum = required.attnum
               AND NOT att.attisdropped
               AND att.attname = required.attname
               AND att.attnotnull = required.is_not_null
               AND format_type(att.atttypid, att.atttypmod) = required.fmt
               AND att.attidentity = ''
               AND att.attgenerated = ''
         )
     LIMIT 1;
    IF cursor_bad_col IS NOT NULL THEN
        RAISE EXCEPTION
            'event_idempotency_reaper_cursor.% is missing or incompatible after pgschema apply',
            cursor_bad_col;
    END IF;

    IF EXISTS (
        SELECT 1
          FROM pg_attribute AS att
          JOIN pg_class AS tbl ON tbl.oid = att.attrelid
          JOIN pg_namespace AS namespace ON namespace.oid = tbl.relnamespace
         WHERE namespace.nspname = current_schema()
           AND tbl.relname = 'event_idempotency_reaper_cursor'
           AND att.attnum > 0
           AND NOT att.attisdropped
         GROUP BY att.attname
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION
            'event_idempotency_reaper_cursor has duplicate columns after pgschema apply';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM pg_attribute AS att
          JOIN pg_class AS tbl ON tbl.oid = att.attrelid
          JOIN pg_namespace AS namespace ON namespace.oid = tbl.relnamespace
         WHERE namespace.nspname = current_schema()
           AND tbl.relname = 'event_idempotency_reaper_cursor'
           AND att.attnum > 0
           AND NOT att.attisdropped
           AND att.attname = 'community_id'
    ) THEN
        RAISE EXCEPTION
            'event_idempotency_reaper_cursor must not carry community_id after pgschema apply';
    END IF;

    -- Unknown extras are preserved when a legacy writer can omit them.
    -- Unsafe NOT NULL extras fail closed and are not dropped.
    IF EXISTS (
        SELECT 1
          FROM pg_attribute AS att
          JOIN pg_class AS tbl ON tbl.oid = att.attrelid
          JOIN pg_namespace AS namespace ON namespace.oid = tbl.relnamespace
         WHERE namespace.nspname = current_schema()
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
    ) THEN
        RAISE EXCEPTION
            'event_idempotency_reaper_cursor has an extra NOT NULL column with no default, identity, or generated supplier after pgschema apply';
    END IF;
END $$;

DO $$
DECLARE
    fence_tg pg_trigger%ROWTYPE;
    imm_tg pg_trigger%ROWTYPE;
    fence_fn NAME;
    fence_fn_schema NAME;
    imm_fn NAME;
    imm_fn_schema NAME;
    imm_body TEXT;
    imm_lang NAME;
    imm_nargs INTEGER;
    imm_secdef BOOLEAN;
    imm_kind "char";
    imm_rettype REGTYPE;
    keys_bad_col TEXT;
BEGIN
    SELECT t.*
      INTO fence_tg
      FROM pg_trigger AS t
      JOIN pg_class AS relation ON relation.oid = t.tgrelid
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = current_schema()
       AND relation.relname = 'event_idempotency_keys'
       AND t.tgname = 'community_write_fence_event_idempotency_keys'
       AND NOT t.tgisinternal;
    IF NOT FOUND THEN
        RAISE EXCEPTION
            'event_idempotency_keys community write fence trigger is missing after pgschema apply';
    END IF;
    IF fence_tg.tgenabled NOT IN ('O', 'A') THEN
        RAISE EXCEPTION
            'event_idempotency_keys community write fence trigger is not enabled';
    END IF;
    IF (fence_tg.tgtype::integer & 31) <> 31 THEN
        RAISE EXCEPTION
            'event_idempotency_keys community write fence trigger tgtype&31=% expected 31',
            fence_tg.tgtype;
    END IF;
    SELECT p.proname, n.nspname
      INTO fence_fn, fence_fn_schema
      FROM pg_proc AS p
      JOIN pg_namespace AS n ON n.oid = p.pronamespace
     WHERE p.oid = fence_tg.tgfoid;
    IF fence_fn IS DISTINCT FROM 'enforce_community_write_fence'
       OR fence_fn_schema IS DISTINCT FROM current_schema() THEN
        RAISE EXCEPTION
            'event_idempotency_keys fence trigger calls %.% expected %.enforce_community_write_fence',
            fence_fn_schema, fence_fn, current_schema();
    END IF;

    SELECT t.*
      INTO imm_tg
      FROM pg_trigger AS t
      JOIN pg_class AS relation ON relation.oid = t.tgrelid
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = current_schema()
       AND relation.relname = 'event_idempotency_keys'
       AND t.tgname = 'event_idempotency_keys_immutable'
       AND NOT t.tgisinternal;
    IF NOT FOUND THEN
        RAISE EXCEPTION
            'event_idempotency_keys immutable trigger is missing after pgschema apply';
    END IF;
    IF imm_tg.tgenabled NOT IN ('O', 'A') THEN
        RAISE EXCEPTION 'event_idempotency_keys immutable trigger is not enabled';
    END IF;
    IF imm_tg.tgtype::integer <> 19 THEN
        RAISE EXCEPTION
            'event_idempotency_keys immutable trigger tgtype=% expected 19',
            imm_tg.tgtype;
    END IF;
    IF cardinality(imm_tg.tgattr) <> 0 THEN
        RAISE EXCEPTION 'event_idempotency_keys immutable trigger must not list columns';
    END IF;
    IF imm_tg.tgnargs <> 0 THEN
        RAISE EXCEPTION 'event_idempotency_keys immutable trigger must have zero args';
    END IF;
    IF imm_tg.tgqual IS NOT NULL THEN
        RAISE EXCEPTION 'event_idempotency_keys immutable trigger must not have WHEN';
    END IF;
    SELECT p.proname, n.nspname, p.prosrc, l.lanname, p.pronargs, p.prosecdef, p.prokind,
           p.prorettype::regtype
      INTO imm_fn, imm_fn_schema, imm_body, imm_lang, imm_nargs, imm_secdef, imm_kind, imm_rettype
      FROM pg_proc AS p
      JOIN pg_namespace AS n ON n.oid = p.pronamespace
      JOIN pg_language AS l ON l.oid = p.prolang
     WHERE p.oid = imm_tg.tgfoid;
    IF imm_fn IS DISTINCT FROM 'prevent_event_idempotency_keys_update'
       OR imm_fn_schema IS DISTINCT FROM current_schema()
       OR imm_lang IS DISTINCT FROM 'plpgsql'
       OR imm_kind IS DISTINCT FROM 'f'
       OR imm_secdef
       OR imm_nargs <> 0
       OR imm_rettype IS DISTINCT FROM 'trigger'::regtype
       OR btrim(regexp_replace(imm_body, E'\\s+', ' ', 'g'))
          IS DISTINCT FROM
          'BEGIN RAISE EXCEPTION ''event_idempotency_keys rows are immutable'' USING ERRCODE = ''integrity_constraint_violation''; END;'
    THEN
        RAISE EXCEPTION
            'prevent_event_idempotency_keys_update is missing or not the canonical immutability function';
    END IF;

    IF (
        SELECT pg_get_expr(ad.adbin, ad.adrelid)
          FROM pg_attrdef AS ad
          JOIN pg_attribute AS att
            ON att.attrelid = ad.adrelid AND att.attnum = ad.adnum
          JOIN pg_class AS tbl ON tbl.oid = ad.adrelid
          JOIN pg_namespace AS namespace ON namespace.oid = tbl.relnamespace
         WHERE namespace.nspname = current_schema()
           AND tbl.relname = 'event_idempotency_keys'
           AND att.attname = 'created_at'
    ) IS DISTINCT FROM 'clock_timestamp()' THEN
        RAISE EXCEPTION
            'event_idempotency_keys.created_at must DEFAULT clock_timestamp() after pgschema apply';
    END IF;

    -- Required columns are a compatible subset. Unknown extras are kept when
    -- legacy writers can omit them; unsafe NOT NULL extras fail closed.
    SELECT required.attname
      INTO keys_bad_col
      FROM (VALUES
            (1, 'community_id', 'uuid', true, false, NULL::text),
            (2, 'author_pubkey', 'bytea', true, false, NULL::text),
            (3, 'idempotency_key', 'bytea', true, false, NULL::text),
            (4, 'intent_hash', 'bytea', true, false, NULL::text),
            (5, 'event_id', 'bytea', true, false, NULL::text),
            (6, 'created_at', 'timestamp with time zone', true, true, 'clock_timestamp()'),
            (7, 'reservation_witness', 'bytea', true, false, NULL::text)
           ) AS required(attnum, attname, fmt, is_not_null, has_default, def_expr)
     WHERE NOT EXISTS (
            SELECT 1
              FROM pg_attribute AS att
              JOIN pg_class AS tbl ON tbl.oid = att.attrelid
              JOIN pg_namespace AS namespace ON namespace.oid = tbl.relnamespace
              LEFT JOIN pg_attrdef AS def
                ON def.adrelid = att.attrelid AND def.adnum = att.attnum
             WHERE namespace.nspname = current_schema()
               AND tbl.relname = 'event_idempotency_keys'
               AND att.attnum = required.attnum
               AND NOT att.attisdropped
               AND att.attname = required.attname
               AND att.attnotnull = required.is_not_null
               AND format_type(att.atttypid, att.atttypmod) = required.fmt
               AND att.attidentity = ''
               AND att.attgenerated = ''
               AND (def.adrelid IS NOT NULL) = required.has_default
               AND (
                    required.def_expr IS NULL
                    OR pg_get_expr(def.adbin, def.adrelid) = required.def_expr
               )
         )
     LIMIT 1;
    IF keys_bad_col IS NOT NULL THEN
        RAISE EXCEPTION
            'event_idempotency_keys.% is missing or incompatible after pgschema apply',
            keys_bad_col;
    END IF;

    IF EXISTS (
        SELECT 1
          FROM pg_attribute AS att
          JOIN pg_class AS tbl ON tbl.oid = att.attrelid
          JOIN pg_namespace AS namespace ON namespace.oid = tbl.relnamespace
         WHERE namespace.nspname = current_schema()
           AND tbl.relname = 'event_idempotency_keys'
           AND att.attnum > 0
           AND NOT att.attisdropped
         GROUP BY att.attname
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION
            'event_idempotency_keys has duplicate columns after pgschema apply';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM pg_attribute AS att
          JOIN pg_class AS tbl ON tbl.oid = att.attrelid
          JOIN pg_namespace AS namespace ON namespace.oid = tbl.relnamespace
         WHERE namespace.nspname = current_schema()
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
    ) THEN
        RAISE EXCEPTION
            'event_idempotency_keys has an extra NOT NULL column with no default, identity, or generated supplier after pgschema apply';
    END IF;

    IF NOT EXISTS (
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
    ) THEN
        RAISE EXCEPTION
            'event_idempotency_keys.reservation_witness CHECK is missing after pgschema apply';
    END IF;

    IF NOT EXISTS (
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
    ) THEN
        RAISE EXCEPTION
            'event_idempotency_keys covering created_at index is missing after pgschema apply';
    END IF;

    IF NOT EXISTS (
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
    ) THEN
        RAISE EXCEPTION
            'event_idempotency_keys community created_at index is missing after pgschema apply';
    END IF;
END $$;

-- pgschema places the partition key first in the generated events PK, even
-- though schema.sql and migrations lead with the tenant. After attaching all
-- partitions, restore the declared order atomically. This is a no-op for an
-- already-converged database; the known reordered shape has identical logical
-- uniqueness, so rebuilding it cannot admit duplicate events.
DO $$
DECLARE
    actual_columns text[];
BEGIN
    SELECT array_agg(a.attname::text ORDER BY k.ordinality)
      INTO actual_columns
      FROM pg_constraint c
      CROSS JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, ordinality)
      JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
     WHERE c.conrelid = 'events'::regclass AND c.contype = 'p';
    IF actual_columns = ARRAY['created_at', 'community_id', 'id']::text[] THEN
        ALTER TABLE events DROP CONSTRAINT events_pkey,
            ADD CONSTRAINT events_pkey PRIMARY KEY (community_id, created_at, id);
    ELSIF actual_columns IS DISTINCT FROM ARRAY['community_id', 'created_at', 'id']::text[] THEN
        RAISE EXCEPTION 'events primary key has an unexpected shape after pgschema apply: %', actual_columns;
    END IF;
END $$;

-- Metadata refresh intents are source-transaction state, including fresh desired schemas.
SELECT attach_community_write_fence('channel_metadata_refresh'::regclass);
INSERT INTO channel_metadata_refresh (community_id, channel_id)
SELECT c.community_id, c.id FROM channels c JOIN communities t ON t.id = c.community_id
WHERE c.deleted_at IS NULL AND t.archived_at IS NULL AND t.deletion_state = 'active'
ON CONFLICT (community_id, channel_id) DO NOTHING;
