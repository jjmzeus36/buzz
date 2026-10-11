//! Durable approval gates and restart recovery of granted waiting runs.

use std::collections::HashMap;
use std::sync::Arc;

use buzz_core::CommunityId;
use buzz_db::workflow::{CreateApprovalParams, WorkflowRecord, WorkflowStatus};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    executor::TriggerContext, PartialProgress, WorkflowDef, WorkflowEngine, WorkflowError,
};

#[cfg(test)]
mod postgres_tests;

/// Resolved gate inputs returned by the executor for atomic finalization.
#[derive(Debug)]
pub struct PendingApproval {
    /// Authored step identifier.
    pub step_id: String,
    /// Supported public key restriction or `any`.
    pub approver_spec: String,
    /// Resolved user-facing prompt.
    pub message: String,
    /// Absolute expiration, bounded to thirty days by dispatch.
    pub expires_at: DateTime<Utc>,
    /// Definition actually executed before the gate.
    pub definition: WorkflowDef,
}

#[derive(Serialize, Deserialize)]
struct Checkpoint {
    definition: WorkflowDef,
    owner: Vec<u8>,
    channel: Uuid,
}

impl WorkflowEngine {
    /// Recheck the current owner and exact definition before a resumed action.
    /// Workflow edits invalidate a suspended run instead of executing unapproved
    /// replacement steps. Disabled workflows and revoked owners fail closed.
    pub(crate) async fn approval_authority(
        &self,
        community: CommunityId,
        run_id: Uuid,
        definition: &WorkflowDef,
    ) -> Result<WorkflowRecord, WorkflowError> {
        let run = self.db.get_workflow_run(community, run_id).await?;
        let workflow = self.db.get_workflow(community, run.workflow_id).await?;
        let stored: WorkflowDef = serde_json::from_value(workflow.definition.clone())
            .map_err(|e| WorkflowError::InvalidDefinition(e.to_string()))?;
        if !workflow.enabled
            || workflow.status != WorkflowStatus::Active
            || !definition.enabled
            || serde_json::to_value(&stored).ok() != serde_json::to_value(definition).ok()
        {
            return Err(WorkflowError::Unauthorized(
                "workflow changed or was disabled while waiting".into(),
            ));
        }
        let channel = workflow
            .channel_id
            .ok_or_else(|| WorkflowError::Unauthorized("approval requires a channel".into()))?;
        self.check_owner_authority(community, channel, &workflow.owner_pubkey, definition)
            .await?;
        Ok(workflow)
    }

    pub(crate) async fn persist_approval(
        &self,
        community: CommunityId,
        run_id: Uuid,
        step_index: i32,
        trace: &Value,
        token: &str,
        pending: PendingApproval,
    ) -> Result<(), WorkflowError> {
        let workflow = self
            .approval_authority(community, run_id, &pending.definition)
            .await?;
        let channel = workflow
            .channel_id
            .ok_or_else(|| WorkflowError::Unauthorized("approval requires a channel".into()))?;
        let checkpoint = serde_json::to_value(Checkpoint {
            definition: pending.definition,
            owner: workflow.owner_pubkey,
            channel,
        })
        .map_err(|e| WorkflowError::InvalidDefinition(e.to_string()))?;
        let mut trace = trace.as_array().cloned().unwrap_or_default();
        trace.push(json!({"step_id": pending.step_id, "status": "waiting_approval", "message": pending.message}));
        self.db
            .suspend_workflow_for_approval(
                CreateApprovalParams {
                    community_id: community,
                    token,
                    workflow_id: workflow.id,
                    run_id,
                    step_id: &pending.step_id,
                    step_index,
                    approver_spec: &pending.approver_spec,
                    expires_at: pending.expires_at,
                },
                &Value::Array(trace),
                &checkpoint,
            )
            .await?;
        Ok(())
    }

    /// Scan a bounded durable backlog. A committed grant survives relay restart
    /// before its task starts; saturated capacity leaves it waiting for a tick.
    pub async fn recover_approvals(self: &Arc<Self>) {
        let candidates = match self.db.list_actionable_workflow_approvals().await {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!(%error, "Approval recovery lookup failed");
                return;
            }
        };
        for (community, run_id) in candidates {
            let engine = Arc::clone(self);
            // Capacity is acquired synchronously, before allocating a task or
            // claiming durable work. There are no unbounded semaphore waiters.
            let Ok(permit) = Arc::clone(&self.run_semaphore).try_acquire_owned() else {
                break;
            };
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(error) = engine.resume_claimed_approval(community, run_id).await {
                    tracing::error!(%run_id, %error, "Approval recovery failed");
                }
            });
        }
    }

    /// Resume one granted gate, respecting engine capacity and the durable claim.
    /// A scheduler tick recovers the gate if the immediate wakeup is lost.
    pub async fn resume_approval(self: &Arc<Self>, community: CommunityId, run_id: Uuid) {
        let Ok(_permit) = self.run_semaphore.try_acquire() else {
            return;
        };
        if let Err(error) = self.resume_claimed_approval(community, run_id).await {
            tracing::error!(%run_id, %error, "Approval resume failed");
        }
    }

    async fn resume_claimed_approval(
        &self,
        community: CommunityId,
        run_id: Uuid,
    ) -> Result<(), WorkflowError> {
        let Some(resume) = self.db.claim_workflow_approval(community, run_id).await? else {
            return Ok(());
        };
        let run = resume.run;
        let mut trace = run.execution_trace.as_array().cloned().unwrap_or_default();
        let result = async {
            let checkpoint: Checkpoint = serde_json::from_value(resume.checkpoint)
                .map_err(|e| WorkflowError::InvalidDefinition(format!("invalid approval checkpoint: {e}")))?;
            let workflow = self.approval_authority(community, run_id, &checkpoint.definition).await?;
            if workflow.owner_pubkey != checkpoint.owner || workflow.channel_id != Some(checkpoint.channel) {
                return Err(WorkflowError::Unauthorized("workflow ownership or channel changed while waiting".into()));
            }
            let gate_index = usize::try_from(resume.approval.step_index)
                .map_err(|_| WorkflowError::InvalidDefinition("negative approval step".into()))?;
            let gate = checkpoint.definition.steps.get(gate_index)
                .ok_or_else(|| WorkflowError::InvalidDefinition("approval step outside definition".into()))?;
            if gate.id != resume.approval.step_id || !matches!(gate.action, crate::ActionDef::RequestApproval { .. }) {
                return Err(WorkflowError::InvalidDefinition("approval step differs from checkpoint".into()));
            }
            let context: TriggerContext = serde_json::from_value(run.trigger_context.clone().ok_or_else(||
                WorkflowError::InvalidDefinition("approval trigger context is missing".into()))?)
                .map_err(|e| WorkflowError::InvalidDefinition(format!("invalid approval trigger context: {e}")))?;
            let output = json!({"approved": true, "approver": resume.approval.approver_pubkey.as_ref().map(hex::encode), "note": resume.approval.note});
            if let Some(entry) = trace.iter_mut().rev().find(|entry| entry["step_id"] == gate.id) {
                entry["status"] = json!("completed");
                entry["output"] = output.clone();
            }
            let mut outputs: HashMap<String, Value> = trace.iter().filter_map(|entry|
                Some((entry.get("step_id")?.as_str()?.to_owned(), entry.get("output")?.clone()))).collect();
            outputs.insert(gate.id.clone(), output);
            Ok((checkpoint.definition, context, gate_index + 1, outputs))
        }.await;
        let result = match result {
            Ok((definition, context, index, outputs)) => {
                crate::executor::execute_steps(
                    self,
                    community,
                    run_id,
                    &definition,
                    &context,
                    index,
                    Some(outputs),
                )
                .await
            }
            Err(error) => Err((
                error,
                PartialProgress {
                    step_index: run.current_step as usize,
                    trace: vec![],
                },
            )),
        };
        self.finalize_run(community, run_id, result, Some(trace))
            .await;
        Ok(())
    }
}
