//! Atomic approval suspension, decision, and bounded recovery.

use super::*;

/// Private executor checkpoint for a claimed approval resume.
pub struct ApprovalResume {
    /// Run and trace read while holding the claim lock.
    pub run: WorkflowRunRecord,
    /// Approval record whose decision unlocked this run.
    pub approval: ApprovalRecord,
    /// Immutable executor input captured at the gate.
    pub checkpoint: serde_json::Value,
}

impl Db {
    /// Commit an approval and the waiting run together. A failed insert rolls
    /// back the status/trace update, so an unreachable waiting run cannot appear.
    pub async fn suspend_workflow_for_approval(
        &self,
        params: CreateApprovalParams<'_>,
        trace: &serde_json::Value,
        checkpoint: &serde_json::Value,
    ) -> Result<()> {
        let mut tx = self.begin_event_write_transaction().await?;
        let changed = sqlx::query(
            "UPDATE workflow_runs SET status = 'waiting_approval', current_step = $3, execution_trace = $4 \
             WHERE community_id = $1 AND id = $2 AND workflow_id = $5 AND status = 'running'",
        )
        .bind(params.community_id.as_uuid()).bind(params.run_id)
        .bind(params.step_index).bind(trace).bind(params.workflow_id)
        .execute(&mut *tx).await?.rows_affected();
        if changed != 1 {
            return Err(DbError::InvalidData("approval run is not running".into()));
        }
        sqlx::query(
            "INSERT INTO workflow_approvals \
             (community_id, token, workflow_id, run_id, step_id, step_index, approver_spec, expires_at, checkpoint) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(params.community_id.as_uuid()).bind(hash_approval_token(params.token))
        .bind(params.workflow_id).bind(params.run_id).bind(params.step_id)
        .bind(params.step_index).bind(params.approver_spec).bind(params.expires_at)
        .bind(checkpoint).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Resolve a gate in the command's event transaction. Membership, designated
    /// approver, deadline, and waiting step are checked under row locks. Denial
    /// cancels the run in this same transaction; grant remains durably queued.
    pub async fn resolve_workflow_approval_in_transaction(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        community_id: CommunityId,
        token_hash: &[u8],
        status: ApprovalStatus,
        approver: &[u8],
        note: Option<&str>,
    ) -> Result<ApprovalRecord> {
        if !matches!(status, ApprovalStatus::Granted | ApprovalStatus::Denied) {
            return Err(DbError::InvalidData("expected grant or deny".into()));
        }
        let row = sqlx::query(
            "SELECT a.token, a.workflow_id, a.run_id, a.step_id, a.step_index, a.approver_spec, \
             a.status::text AS status, a.approver_pubkey, a.note, a.expires_at, a.created_at, \
             a.expires_at > clock_timestamp() AS unexpired, w.channel_id, \
             r.status::text AS run_status, r.current_step \
             FROM workflow_approvals a \
             JOIN workflow_runs r ON r.community_id = a.community_id AND r.id = a.run_id AND r.workflow_id = a.workflow_id \
             JOIN workflows w ON w.community_id = a.community_id AND w.id = a.workflow_id \
             WHERE a.community_id = $1 AND a.token = $2 FOR UPDATE OF a, r FOR SHARE OF w",
        ).bind(community_id.as_uuid()).bind(token_hash).fetch_optional(&mut **tx).await?
            .ok_or_else(|| DbError::NotFound("approval".into()))?;
        let channel: Option<Uuid> = row.try_get("channel_id")?;
        let channel =
            channel.ok_or_else(|| DbError::AccessDenied("approval has no channel".into()))?;
        let member: Option<bool> = sqlx::query_scalar(
            "SELECT TRUE FROM channel_members m JOIN channels c \
             ON c.community_id = m.community_id AND c.id = m.channel_id \
             WHERE m.community_id = $1 AND m.channel_id = $2 AND m.pubkey = $3 \
             AND m.removed_at IS NULL AND c.deleted_at IS NULL FOR SHARE OF m, c",
        )
        .bind(community_id.as_uuid())
        .bind(channel)
        .bind(approver)
        .fetch_optional(&mut **tx)
        .await?;
        if member != Some(true) {
            return Err(DbError::AccessDenied(
                "approval requires current channel membership".into(),
            ));
        }
        let unexpired: bool = row.try_get("unexpired")?;
        let run_status: String = row.try_get("run_status")?;
        let current_step: i32 = row.try_get("current_step")?;
        let approval = row_to_approval_record(row)?;
        let spec = approval.approver_spec.trim();
        if !(spec.is_empty()
            || spec == "any"
            || (spec.len() == 64 && spec.eq_ignore_ascii_case(&hex::encode(approver))))
        {
            return Err(DbError::AccessDenied("not the designated approver".into()));
        }
        if approval.status != ApprovalStatus::Pending
            || !unexpired
            || run_status != "waiting_approval"
            || current_step != approval.step_index
        {
            return Err(DbError::InvalidData(
                "approval is no longer pending at this step".into(),
            ));
        }
        let changed = sqlx::query(
            "UPDATE workflow_approvals SET status = $3::approval_status, approver_pubkey = $4, note = $5, \
             granted_at = CASE WHEN $3 = 'granted' THEN NOW() ELSE NULL END, \
             denied_at = CASE WHEN $3 = 'denied' THEN NOW() ELSE NULL END \
             WHERE community_id = $1 AND token = $2 AND status = 'pending' AND expires_at > clock_timestamp()",
        ).bind(community_id.as_uuid()).bind(token_hash).bind(status.to_string())
            .bind(approver).bind(note).execute(&mut **tx).await?.rows_affected();
        if changed != 1 {
            return Err(DbError::InvalidData(
                "approval expired during decision".into(),
            ));
        }
        if status == ApprovalStatus::Denied {
            sqlx::query(
                "UPDATE workflow_runs SET status = 'cancelled', completed_at = NOW(), \
                 error_code = 'approval_denied', error_message = 'workflow approval denied' \
                 WHERE community_id = $1 AND id = $2",
            )
            .bind(community_id.as_uuid())
            .bind(approval.run_id)
            .execute(&mut **tx)
            .await?;
        }
        Ok(approval)
    }

    /// List at most 100 waiting gates needing a grant resume or expiration.
    /// This deployment-global scheduler read carries each row's tenant explicitly.
    pub async fn list_actionable_workflow_approvals(&self) -> Result<Vec<(CommunityId, Uuid)>> {
        let rows = sqlx::query(
            "SELECT a.community_id, a.run_id FROM workflow_approvals a \
             JOIN workflow_runs r ON r.community_id = a.community_id AND r.id = a.run_id \
             JOIN communities c ON c.id = a.community_id \
             WHERE c.archived_at IS NULL AND c.deletion_state = 'active' AND r.status = 'waiting_approval' AND r.current_step = a.step_index \
             AND (a.status = 'granted' OR (a.status = 'pending' AND a.expires_at <= NOW())) \
             ORDER BY a.created_at LIMIT 100",
        ).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|row| {
                Ok((
                    CommunityId::from_uuid(row.try_get("community_id")?),
                    row.try_get("run_id")?,
                ))
            })
            .collect()
    }

    /// Claim a granted waiting gate exactly once, or atomically expire its pending
    /// approval and run. Acquire executor capacity before calling this method.
    /// Claimed running work is never replayed automatically after a process crash.
    pub async fn claim_workflow_approval(
        &self,
        community_id: CommunityId,
        run_id: Uuid,
    ) -> Result<Option<ApprovalResume>> {
        let mut tx = self.begin_event_write_transaction().await?;
        let row = sqlx::query(
            "SELECT a.token, a.workflow_id, a.run_id, a.step_id, a.step_index, a.approver_spec, \
             a.status::text AS status, a.approver_pubkey, a.note, a.expires_at, a.created_at, a.checkpoint \
             FROM workflow_approvals a JOIN workflow_runs r \
             ON r.community_id = a.community_id AND r.id = a.run_id AND r.workflow_id = a.workflow_id \
             WHERE a.community_id = $1 AND a.run_id = $2 AND r.status = 'waiting_approval' \
             AND r.current_step = a.step_index \
             AND (a.status = 'granted' OR (a.status = 'pending' AND a.expires_at <= NOW())) \
             FOR UPDATE OF a, r SKIP LOCKED",
        ).bind(community_id.as_uuid()).bind(run_id).fetch_optional(&mut *tx).await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let checkpoint: Option<serde_json::Value> = row.try_get("checkpoint")?;
        let approval = row_to_approval_record(row)?;
        if approval.status == ApprovalStatus::Pending {
            sqlx::query("UPDATE workflow_approvals SET status = 'expired' WHERE community_id = $1 AND token = $2")
                .bind(community_id.as_uuid()).bind(&approval.token).execute(&mut *tx).await?;
            sqlx::query("UPDATE workflow_runs SET status = 'failed', completed_at = NOW(), error_code = 'approval_expired', error_message = 'workflow approval expired' WHERE community_id = $1 AND id = $2")
                .bind(community_id.as_uuid()).bind(run_id).execute(&mut *tx).await?;
            tx.commit().await?;
            return Ok(None);
        }
        sqlx::query(
            "UPDATE workflow_runs SET status = 'running' WHERE community_id = $1 AND id = $2",
        )
        .bind(community_id.as_uuid())
        .bind(run_id)
        .execute(&mut *tx)
        .await?;
        let run = row_to_run_record(sqlx::query(
            "SELECT id, community_id, workflow_id, status::text AS status, trigger_event_id, current_step, execution_trace, \
             trigger_context, started_at, completed_at, error_message, error_code, created_at \
             FROM workflow_runs WHERE community_id = $1 AND id = $2",
        ).bind(community_id.as_uuid()).bind(run_id).fetch_one(&mut *tx).await?)?;
        tx.commit().await?;
        Ok(Some(ApprovalResume {
            run,
            approval,
            checkpoint: checkpoint.unwrap_or(serde_json::Value::Null),
        }))
    }
}
