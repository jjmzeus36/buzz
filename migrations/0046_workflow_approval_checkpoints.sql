-- Durable approval checkpoints are private executor state, separate from the public trace.
ALTER TABLE workflow_approvals ADD COLUMN checkpoint JSONB;
CREATE INDEX idx_workflow_approvals_recovery ON workflow_approvals (created_at)
    WHERE status IN ('pending', 'granted');
