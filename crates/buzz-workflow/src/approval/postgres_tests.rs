use super::*;
use buzz_core::channel::{ChannelType, ChannelVisibility, MemberRole};
use buzz_db::workflow::{ApprovalRecord, ApprovalStatus, RunStatus};
use std::{future::Future, pin::Pin, sync::Mutex};

#[derive(Default)]
struct Sink(Mutex<Vec<String>>);

impl crate::ActionSink for Sink {
    fn set_channel_topic(
        &self,
        _: CommunityId,
        _: &str,
        _: &str,
        _: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), crate::ActionSinkError>> + Send + '_>> {
        Box::pin(async { panic!("approval fixture does not execute topic actions") })
    }

    fn send_message(
        &self,
        _: CommunityId,
        _: &str,
        text: &str,
        _: &str,
        _: &str,
        _: Option<&str>,
    ) -> Pin<Box<dyn Future<Output = Result<String, crate::ActionSinkError>> + Send + '_>> {
        self.0.lock().unwrap().push(text.to_owned());
        Box::pin(async { Ok("test-event".into()) })
    }
}

struct Fixture {
    pool: sqlx::PgPool,
    engine: Arc<WorkflowEngine>,
    sink: Arc<Sink>,
    community: CommunityId,
    channel: Uuid,
    workflow: Uuid,
    run: Uuid,
    owner: Vec<u8>,
    member: Vec<u8>,
    definition: WorkflowDef,
    context: TriggerContext,
}

impl Fixture {
    async fn new(second_gate: bool) -> Self {
        let url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("TEST_DATABASE_URL"))
            .or_else(|_| std::env::var("DATABASE_URL"))
            .expect("isolated test database URL");
        let pool = sqlx::PgPool::connect(&url).await.unwrap();
        let db = buzz_db::Db::from_pool(pool.clone());
        if std::env::var("BUZZ_TEST_SCHEMA_MODE").as_deref() != Ok("desired") {
            db.migrate().await.unwrap();
        }
        let community = db
            .ensure_configured_community(&format!("approval-{}.test", Uuid::new_v4()))
            .await
            .unwrap()
            .id;
        let owner = vec![0x11; 32];
        let member = vec![0x22; 32];
        db.ensure_user(community, &owner).await.unwrap();
        db.ensure_user(community, &member).await.unwrap();
        let channel = db
            .create_channel(
                community,
                "approval-test",
                ChannelType::Stream,
                ChannelVisibility::Private,
                None,
                &owner,
                None,
            )
            .await
            .unwrap()
            .id;
        db.add_member(
            community,
            channel,
            &member,
            MemberRole::Member,
            Some(&owner),
        )
        .await
        .unwrap();
        let mut yaml = "name: approval-test\ntrigger:\n  on: webhook\nsteps:\n  - id: before\n    action: delay\n    duration: 0s\n  - id: gate\n    action: request_approval\n    from: any\n    message: 'Approve {{trigger.text}}?'\n  - id: after\n    action: send_message\n    if: steps_gate_output_approved == true\n    text: '{{trigger.text}}/{{steps.before.output.slept_secs}}/{{steps.gate.output.approved}}'\n".to_owned();
        if second_gate {
            yaml.push_str("  - id: second\n    action: request_approval\n    from: any\n    message: Again?\n  - id: last\n    action: send_message\n    text: '{{trigger.text}}/last'\n");
        }
        let (definition, canonical) = WorkflowEngine::parse_yaml(&yaml).unwrap();
        let workflow = db
            .create_workflow(
                community,
                Some(channel),
                &owner,
                "approval-test",
                &canonical,
                &[1; 32],
            )
            .await
            .unwrap();
        let context = TriggerContext {
            text: "saved trigger".into(),
            channel_id: channel.to_string(),
            ..Default::default()
        };
        let run = db
            .create_workflow_run(
                community,
                workflow,
                None,
                Some(&serde_json::to_value(&context).unwrap()),
            )
            .await
            .unwrap();
        let engine = Arc::new(WorkflowEngine::new(
            db,
            crate::WorkflowConfig {
                max_concurrent: 1,
                ..Default::default()
            },
        ));
        let sink = Arc::new(Sink::default());
        engine.set_action_sink(sink.clone());
        Self {
            pool,
            engine,
            sink,
            community,
            channel,
            workflow,
            run,
            owner,
            member,
            definition,
            context,
        }
    }

    async fn suspend(&self) -> ApprovalRecord {
        let result = crate::executor::execute_run(
            &self.engine,
            self.community,
            self.run,
            &self.definition,
            &self.context,
        )
        .await;
        self.engine
            .finalize_run(self.community, self.run, result, None)
            .await;
        let run = self
            .engine
            .db
            .get_workflow_run(self.community, self.run)
            .await
            .unwrap();
        assert_eq!(run.status, RunStatus::WaitingApproval);
        assert_eq!(run.current_step, 1);
        assert_eq!(run.execution_trace[1]["message"], "Approve saved trigger?");
        self.approvals().await.remove(0)
    }

    async fn approvals(&self) -> Vec<ApprovalRecord> {
        self.engine
            .db
            .get_run_approvals(self.community, self.workflow, self.run)
            .await
            .unwrap()
    }

    async fn decide(
        &self,
        approval: &ApprovalRecord,
        status: ApprovalStatus,
        who: &[u8],
    ) -> buzz_db::Result<()> {
        let mut tx = self.engine.db.begin_event_write_transaction().await?;
        self.engine
            .db
            .resolve_workflow_approval_in_transaction(
                &mut tx,
                self.community,
                &approval.token,
                status,
                who,
                Some("reviewed"),
            )
            .await?;
        tx.commit().await?;
        Ok(())
    }

    fn restart(&self) -> Arc<WorkflowEngine> {
        let engine = Arc::new(WorkflowEngine::new(
            self.engine.db.clone(),
            crate::WorkflowConfig {
                max_concurrent: 1,
                ..Default::default()
            },
        ));
        engine.set_action_sink(self.sink.clone());
        engine
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn templated_approval_inputs_suspend_with_resolved_deadline_and_reject_invalid_values() {
    for (ttl, approver, succeeds) in [
        ("1h", "any", true),
        ("0s", "any", false),
        ("2592001s", "any", false),
        ("1h", "admin", false),
    ] {
        let mut f = Fixture::new(false).await;
        if let crate::ActionDef::RequestApproval { from, timeout, .. } =
            &mut f.definition.steps[1].action
        {
            *from = "{{trigger.approver}}".into();
            *timeout = Some("{{trigger.ttl}}".into());
        }
        f.context.webhook_fields.insert("ttl".into(), ttl.into());
        f.context
            .webhook_fields
            .insert("approver".into(), approver.into());
        f.engine
            .db
            .update_workflow(
                f.community,
                f.workflow,
                &f.definition.name,
                &serde_json::to_string(&f.definition).unwrap(),
                &[2; 32],
            )
            .await
            .unwrap();
        let before = Utc::now();
        let result =
            crate::executor::execute_run(&f.engine, f.community, f.run, &f.definition, &f.context)
                .await;
        f.engine
            .finalize_run(f.community, f.run, result, None)
            .await;
        let after = Utc::now();
        let run = f
            .engine
            .db
            .get_workflow_run(f.community, f.run)
            .await
            .unwrap();
        let approvals = f.approvals().await;
        if succeeds {
            assert_eq!(run.status, RunStatus::WaitingApproval);
            assert_eq!(approvals.len(), 1);
            assert_eq!(approvals[0].approver_spec, "any");
            assert!(approvals[0].expires_at >= before + chrono::Duration::hours(1));
            assert!(approvals[0].expires_at <= after + chrono::Duration::hours(1));
            assert_eq!(run.execution_trace[1]["message"], "Approve saved trigger?");
        } else {
            assert_eq!(run.status, RunStatus::Failed, "{ttl}/{approver}");
            assert!(approvals.is_empty());
        }
        assert!(f.sink.0.lock().unwrap().is_empty());
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn approval_authority_does_not_decode_trace_and_rechecks_current_workflow() {
    let f = Fixture::new(false).await;
    // Valid PostgreSQL JSON beyond serde_json's recursion limit makes a broad
    // run read fail. Authority only needs the workflow ID, never this payload.
    let trace = format!("{}0{}", "[".repeat(160), "]".repeat(160));
    sqlx::query(
        "UPDATE workflow_runs SET execution_trace = $3::jsonb WHERE community_id = $1 AND id = $2",
    )
    .bind(f.community.as_uuid())
    .bind(f.run)
    .bind(trace)
    .execute(&f.pool)
    .await
    .unwrap();
    assert!(f
        .engine
        .db
        .get_workflow_run(f.community, f.run)
        .await
        .is_err());
    assert_eq!(
        f.engine
            .approval_authority(f.community, f.run, &f.definition)
            .await
            .unwrap()
            .id,
        f.workflow
    );
    assert!(f
        .engine
        .approval_authority(CommunityId::from_uuid(Uuid::new_v4()), f.run, &f.definition)
        .await
        .is_err());
    f.engine
        .db
        .set_workflow_enabled(f.community, f.workflow, false)
        .await
        .unwrap();
    assert!(matches!(
        f.engine
            .approval_authority(f.community, f.run, &f.definition)
            .await,
        Err(WorkflowError::Unauthorized(_))
    ));
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn resumed_actions_recheck_authority_after_an_earlier_action() {
    struct DisablingSink {
        db: buzz_db::Db,
        community: CommunityId,
        workflow: Uuid,
        sent: Mutex<Vec<String>>,
    }
    impl crate::ActionSink for DisablingSink {
        fn send_message(
            &self,
            _: CommunityId,
            _: &str,
            text: &str,
            _: &str,
            _: &str,
            _: Option<&str>,
        ) -> Pin<Box<dyn Future<Output = Result<String, crate::ActionSinkError>> + Send + '_>>
        {
            self.sent.lock().unwrap().push(text.into());
            Box::pin(async move {
                self.db
                    .set_workflow_enabled(self.community, self.workflow, false)
                    .await
                    .map_err(|e| crate::ActionSinkError::Database(e.to_string()))?;
                Ok("test-event".into())
            })
        }
    }
    let mut f = Fixture::new(false).await;
    let mut last = f.definition.steps[2].clone();
    last.id = "last".into();
    f.definition.steps.push(last);
    f.engine
        .db
        .update_workflow(
            f.community,
            f.workflow,
            &f.definition.name,
            &serde_json::to_string(&f.definition).unwrap(),
            &[2; 32],
        )
        .await
        .unwrap();
    let approval = f.suspend().await;
    f.decide(&approval, ApprovalStatus::Granted, &f.member)
        .await
        .unwrap();
    let sink = Arc::new(DisablingSink {
        db: f.engine.db.clone(),
        community: f.community,
        workflow: f.workflow,
        sent: Mutex::new(vec![]),
    });
    let engine = Arc::new(WorkflowEngine::new(
        f.engine.db.clone(),
        crate::WorkflowConfig::default(),
    ));
    engine.set_action_sink(sink.clone());
    engine.resume_approval(f.community, f.run).await;
    let run = f
        .engine
        .db
        .get_workflow_run(f.community, f.run)
        .await
        .unwrap();
    assert_eq!(sink.sent.lock().unwrap().len(), 1);
    assert_eq!(run.status, RunStatus::Failed);
    assert_eq!(run.error_code.as_deref(), Some("owner_unauthorized"));
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn grant_survives_restart_preserves_context_and_supports_multiple_gates() {
    let f = Fixture::new(true).await;
    let approval = f.suspend().await;
    f.decide(&approval, ApprovalStatus::Granted, &f.member)
        .await
        .unwrap();
    assert!(f
        .engine
        .db
        .list_actionable_workflow_approvals()
        .await
        .unwrap()
        .contains(&(f.community, f.run)));
    let restarted = f.restart();
    restarted.recover_approvals().await;
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if f.approvals().await.len() == 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(*f.sink.0.lock().unwrap(), vec!["saved trigger/0/true"]);
    let second = f.approvals().await.remove(1);
    assert_eq!(second.step_index, 3);
    f.decide(&second, ApprovalStatus::Granted, &f.member)
        .await
        .unwrap();
    // Separate engines model separate relay pods. Only one may claim the gate.
    let other = f.restart();
    tokio::join!(
        restarted.resume_approval(f.community, f.run),
        other.resume_approval(f.community, f.run)
    );
    let run = f
        .engine
        .db
        .get_workflow_run(f.community, f.run)
        .await
        .unwrap();
    assert_eq!(run.status, RunStatus::Completed);
    assert_eq!(run.execution_trace.as_array().unwrap().len(), 5);
    assert_eq!(run.execution_trace[1]["output"]["approved"], true);
    assert_eq!(
        *f.sink.0.lock().unwrap(),
        vec!["saved trigger/0/true", "saved trigger/last"]
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn capacity_keeps_a_granted_gate_durably_waiting() {
    let f = Fixture::new(false).await;
    let approval = f.suspend().await;
    f.decide(&approval, ApprovalStatus::Granted, &f.member)
        .await
        .unwrap();
    let permit = f.engine.run_semaphore.acquire().await.unwrap();
    f.engine.resume_approval(f.community, f.run).await;
    assert_eq!(
        f.engine
            .db
            .get_workflow_run(f.community, f.run)
            .await
            .unwrap()
            .status,
        RunStatus::WaitingApproval
    );
    drop(permit);
    f.engine.resume_approval(f.community, f.run).await;
    assert_eq!(
        f.engine
            .db
            .get_workflow_run(f.community, f.run)
            .await
            .unwrap()
            .status,
        RunStatus::Completed
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn approval_authorization_binds_tenant_member_designation_and_waiting_step() {
    let f = Fixture::new(false).await;
    let approval = f.suspend().await;
    // Even an unrestricted spec requires current membership, not knowledge of a reference.
    assert!(f
        .decide(&approval, ApprovalStatus::Granted, &[0x33; 32])
        .await
        .is_err());
    let other = f
        .engine
        .db
        .ensure_configured_community(&format!("other-{}.test", Uuid::new_v4()))
        .await
        .unwrap()
        .id;
    let mut tx = f.engine.db.begin_event_write_transaction().await.unwrap();
    assert!(f
        .engine
        .db
        .resolve_workflow_approval_in_transaction(
            &mut tx,
            other,
            &approval.token,
            ApprovalStatus::Granted,
            &f.member,
            None
        )
        .await
        .is_err());
    tx.rollback().await.unwrap();
    sqlx::query(
        "UPDATE workflow_approvals SET approver_spec = $3 WHERE community_id = $1 AND token = $2",
    )
    .bind(f.community.as_uuid())
    .bind(&approval.token)
    .bind(hex::encode(&f.owner))
    .execute(&f.pool)
    .await
    .unwrap();
    assert!(f
        .decide(&approval, ApprovalStatus::Granted, &f.member)
        .await
        .is_err());
    sqlx::query("UPDATE workflow_approvals SET approver_spec = 'any' WHERE community_id = $1 AND token = $2")
        .bind(f.community.as_uuid()).bind(&approval.token).execute(&f.pool).await.unwrap();
    f.engine
        .db
        .remove_member(f.community, f.channel, &f.member, &f.owner)
        .await
        .unwrap();
    assert!(f
        .decide(&approval, ApprovalStatus::Denied, &f.member)
        .await
        .is_err());
    sqlx::query("UPDATE workflow_runs SET current_step = 0 WHERE community_id = $1 AND id = $2")
        .bind(f.community.as_uuid())
        .bind(f.run)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(f
        .decide(&approval, ApprovalStatus::Granted, &f.owner)
        .await
        .is_err());
    assert_eq!(f.approvals().await[0].status, ApprovalStatus::Pending);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn decision_and_denial_cancel_roll_back_together_and_race_once() {
    let f = Fixture::new(false).await;
    let approval = f.suspend().await;
    let mut tx = f.engine.db.begin_event_write_transaction().await.unwrap();
    f.engine
        .db
        .resolve_workflow_approval_in_transaction(
            &mut tx,
            f.community,
            &approval.token,
            ApprovalStatus::Denied,
            &f.member,
            None,
        )
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(f.approvals().await[0].status, ApprovalStatus::Pending);
    assert_eq!(
        f.engine
            .db
            .get_workflow_run(f.community, f.run)
            .await
            .unwrap()
            .status,
        RunStatus::WaitingApproval
    );
    let (a, b) = tokio::join!(
        f.decide(&approval, ApprovalStatus::Granted, &f.member),
        f.decide(&approval, ApprovalStatus::Denied, &f.member)
    );
    assert_ne!(a.is_ok(), b.is_ok(), "only one decision may commit");
    let status = f.approvals().await[0].status.clone();
    let run = f
        .engine
        .db
        .get_workflow_run(f.community, f.run)
        .await
        .unwrap();
    assert_eq!(
        run.status,
        if status == ApprovalStatus::Denied {
            RunStatus::Cancelled
        } else {
            RunStatus::WaitingApproval
        }
    );
    if status == ApprovalStatus::Granted {
        f.engine.resume_approval(f.community, f.run).await;
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn expired_gate_rejects_decisions_and_becomes_terminal_atomically() {
    let f = Fixture::new(false).await;
    let approval = f.suspend().await;
    sqlx::query("UPDATE workflow_approvals SET expires_at = NOW() - INTERVAL '1 second' WHERE community_id = $1 AND token = $2")
        .bind(f.community.as_uuid()).bind(&approval.token).execute(&f.pool).await.unwrap();
    assert!(f
        .decide(&approval, ApprovalStatus::Granted, &f.member)
        .await
        .is_err());
    f.restart().resume_approval(f.community, f.run).await;
    assert_eq!(f.approvals().await[0].status, ApprovalStatus::Expired);
    let run = f
        .engine
        .db
        .get_workflow_run(f.community, f.run)
        .await
        .unwrap();
    assert_eq!(run.status, RunStatus::Failed);
    assert_eq!(run.error_code.as_deref(), Some("approval_expired"));
    assert!(f.sink.0.lock().unwrap().is_empty());
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn revoked_owner_or_edited_definition_cannot_execute_approved_work() {
    for revoke in [true, false] {
        let f = Fixture::new(false).await;
        let approval = f.suspend().await;
        f.decide(&approval, ApprovalStatus::Granted, &f.member)
            .await
            .unwrap();
        if revoke {
            f.engine
                .db
                .add_member(
                    f.community,
                    f.channel,
                    &f.member,
                    MemberRole::Owner,
                    Some(&f.owner),
                )
                .await
                .unwrap();
            f.engine
                .db
                .remove_member(f.community, f.channel, &f.owner, &f.member)
                .await
                .unwrap();
        } else {
            let mut changed = f.definition.clone();
            changed.name = "edited after approval".into();
            f.engine
                .db
                .upsert_workflow(
                    f.community,
                    f.workflow,
                    Some(f.channel),
                    &f.owner,
                    &changed.name,
                    &serde_json::to_string(&changed).unwrap(),
                    &[2; 32],
                )
                .await
                .unwrap();
        }
        f.restart().resume_approval(f.community, f.run).await;
        let run = f
            .engine
            .db
            .get_workflow_run(f.community, f.run)
            .await
            .unwrap();
        assert_eq!(run.status, RunStatus::Failed);
        assert_eq!(run.error_code.as_deref(), Some("owner_unauthorized"));
        assert!(f.sink.0.lock().unwrap().is_empty());
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn restricted_owner_cannot_resume_or_authorize_a_new_run() {
    for restriction in ["ban", "timeout", "inherited_ban", "archive"] {
        let f = Fixture::new(false).await;
        let approval = f.suspend().await;
        f.decide(&approval, ApprovalStatus::Granted, &f.member)
            .await
            .unwrap();
        match restriction {
            "ban" => f
                .engine
                .db
                .ban_community_member(f.community, &f.owner, &f.member, None, None)
                .await
                .unwrap(),
            "timeout" => f
                .engine
                .db
                .timeout_community_member(
                    f.community,
                    &f.owner,
                    &f.member,
                    Utc::now() + chrono::Duration::hours(1),
                    None,
                )
                .await
                .unwrap(),
            "inherited_ban" => {
                f.engine
                    .db
                    .set_agent_owner(f.community, &f.owner, &f.member)
                    .await
                    .unwrap();
                f.engine
                    .db
                    .ban_community_member(f.community, &f.member, &f.member, None, None)
                    .await
                    .unwrap();
            }
            "archive" => f
                .engine
                .db
                .archive_channel(f.community, f.channel)
                .await
                .unwrap(),
            _ => unreachable!(),
        }
        // Membership remains intact: restrictions must independently revoke authority.
        assert!(f
            .engine
            .db
            .get_member_role(f.community, f.channel, &f.owner)
            .await
            .unwrap()
            .is_some());
        assert!(
            f.engine
                .check_owner_authority(f.community, f.channel, &f.owner, &f.definition)
                .await
                .is_err(),
            "{restriction} must deny a new run"
        );
        f.restart().resume_approval(f.community, f.run).await;
        let run = f
            .engine
            .db
            .get_workflow_run(f.community, f.run)
            .await
            .unwrap();
        assert_eq!(run.status, RunStatus::Failed, "{restriction}");
        assert_eq!(run.error_code.as_deref(), Some("owner_unauthorized"));
        assert!(f.sink.0.lock().unwrap().is_empty(), "{restriction}");
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn expired_and_other_tenant_restrictions_do_not_block_approval_resume() {
    let f = Fixture::new(false).await;
    let approval = f.suspend().await;
    f.decide(&approval, ApprovalStatus::Granted, &f.member)
        .await
        .unwrap();
    let past = Utc::now() - chrono::Duration::hours(1);
    f.engine
        .db
        .ban_community_member(f.community, &f.owner, &f.member, None, Some(past))
        .await
        .unwrap();
    f.engine
        .db
        .timeout_community_member(f.community, &f.owner, &f.member, past, None)
        .await
        .unwrap();
    let neighbor = Fixture::new(false).await;
    neighbor
        .engine
        .db
        .ban_community_member(neighbor.community, &f.owner, &neighbor.member, None, None)
        .await
        .unwrap();
    f.restart().resume_approval(f.community, f.run).await;
    let run = f
        .engine
        .db
        .get_workflow_run(f.community, f.run)
        .await
        .unwrap();
    assert_eq!(run.status, RunStatus::Completed);
    assert_eq!(f.sink.0.lock().unwrap().len(), 1);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn failed_approval_insert_rolls_back_run_suspension() {
    let f = Fixture::new(false).await;
    let result =
        crate::executor::execute_run(&f.engine, f.community, f.run, &f.definition, &f.context)
            .await
            .unwrap();
    let token = result.approval_token.clone().unwrap();
    f.engine
        .finalize_run(f.community, f.run, Ok(result), None)
        .await;
    let second_run = f
        .engine
        .db
        .create_workflow_run(f.community, f.workflow, None, None)
        .await
        .unwrap();
    f.engine
        .db
        .update_workflow_run(
            f.community,
            second_run,
            RunStatus::Running,
            0,
            &json!([]),
            None,
        )
        .await
        .unwrap();
    let failed = f
        .engine
        .db
        .suspend_workflow_for_approval(
            CreateApprovalParams {
                community_id: f.community,
                token: &token,
                workflow_id: f.workflow,
                run_id: second_run,
                step_id: "gate",
                step_index: 1,
                approver_spec: "any",
                expires_at: Utc::now() + chrono::Duration::hours(1),
            },
            &json!([{"unexpected":true}]),
            &json!({}),
        )
        .await;
    assert!(failed.is_err(), "duplicate token must fail insertion");
    let run = f
        .engine
        .db
        .get_workflow_run(f.community, second_run)
        .await
        .unwrap();
    assert_eq!(run.status, RunStatus::Running);
    assert_eq!(run.current_step, 0);
    assert_eq!(run.execution_trace, json!([]));
}
