-- Logical original bytes, not a physical S3/version/derivative cap.
-- No accounts are enrolled automatically: absence means unknown history.
CREATE TABLE media_quota_accounts (
    community_id UUID NOT NULL REFERENCES communities(id),
    pubkey BYTEA NOT NULL CHECK (octet_length(pubkey) = 32),
    baseline_id UUID NOT NULL,
    limit_bytes BIGINT NOT NULL CHECK (limit_bytes > 0),
    evidence TEXT NOT NULL CHECK (length(evidence) BETWEEN 1 AND 4096),
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (community_id, pubkey)
);
CREATE TABLE media_quota_objects (
    community_id UUID NOT NULL,
    pubkey BYTEA NOT NULL,
    sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    operation_id UUID NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'charged')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    recovery_evidence TEXT CHECK (length(recovery_evidence) BETWEEN 1 AND 4096),
    PRIMARY KEY (community_id, pubkey, sha256),
    FOREIGN KEY (community_id, pubkey) REFERENCES media_quota_accounts(community_id, pubkey)
);
SELECT attach_community_write_fence('media_quota_accounts');
SELECT attach_community_write_fence('media_quota_objects');
