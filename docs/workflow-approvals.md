# Workflow approval gates

`request_approval` persists the waiting run, execution trace, resolved prompt,
deadline, and private execution checkpoint in one transaction. The existing run
and approval read endpoints expose the waiting state and approval reference;
the checkpoint and raw token are not exposed. Runs and approvals remain database
read models, rather than synthetic Nostr events.

```yaml
name: Reviewed announcement
trigger:
  on: webhook
steps:
  - id: review
    action: request_approval
    from: any
    message: "Approve this announcement?"
    timeout: 24h
  - id: publish
    if: steps_review_output_approved == true
    action: send_message
    text: "Approved: {{trigger.text}}"
```

`from` supports `any`, an empty restriction, or an exact 64-character hexadecimal
public key. Every approver must also be a current member of the workflow channel.
Role names and display-name mentions fail explicitly. Approval durations range
from one second to thirty days; the default is twenty-four hours. These fields
are validated after template substitution.

Grant and deny commands use the existing approval-reference `d` tag (or `e` tag)
and kinds 46030/46031. The command event and decision commit together. A rejected
decision leaves neither a command event nor a state change. Exact event replay
returns idempotent success. Concurrent decisions have one winner, and expiry is
checked again at the final update after authorization locks have been acquired.
Denial atomically cancels the run. Expiration marks both the approval and run
terminal on the next available recovery tick.

A grant leaves the run durably waiting until executor capacity is available.
The immediate wakeup is an optimization: the existing sixty-second scheduler
also scans a bounded backlog of granted or expired waiting gates. A database
claim prevents multiple relay instances from resuming the same waiting step.
Trigger context, previous outputs, and the trace survive a restart. The approved
step provides `approved`, `approver`, and `note` output fields. Multiple gates in
one run each create a separate checkpoint.

Resume checks the saved definition, channel, and owner against the current
workflow and rechecks current owner authority before every remaining action.
Edits, disabling, ownership changes, removal from the channel, or loss of the
elevated role required for webhooks fail closed. A missing or malformed checkpoint
or trigger context fails visibly rather than substituting empty execution data.

Recovery covers waiting gates and grants committed before execution is claimed.
Once claimed, the run uses the existing running-workflow crash behavior: a relay
crash during execution does not automatically replay external effects. This
change does not provide delivery retries or exactly-once message delivery.

Apply migration `0046_workflow_approval_checkpoints.sql` before enabling this
executor version. PostgreSQL tests under `approval::postgres_tests` exercise the
production executor and persistence paths; the relay command regression covers
command rollback and exact replay through its production transaction helper.
