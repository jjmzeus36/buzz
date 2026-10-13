import assert from "node:assert/strict";
import test from "node:test";

import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import {
  getRunApprovals,
  getWorkflowRuns,
} from "../../../shared/api/tauriWorkflows.ts";
import { WorkflowRunTrace } from "./WorkflowRunTrace.tsx";

const workflowId = "11111111-1111-4111-8111-111111111111";
const runId = "22222222-2222-4222-8222-222222222222";
const prompt = "Approve saved trigger?\nReview the release.";

async function loadReadModels({ run = {}, approval = {}, trace = {} } = {}) {
  const previousWindow = globalThis.window;
  globalThis.window = {
    __TAURI_INTERNALS__: {
      async invoke(command, args) {
        if (command === "get_workflow_runs") {
          assert.deepEqual(args, { workflowId, limit: null });
          return {
            runs: [
              {
                id: runId,
                workflow_id: workflowId,
                status: "waiting_approval",
                current_step: 0,
                execution_trace: [
                  {
                    step_id: "review",
                    status: "waiting_approval",
                    message: prompt,
                    ...trace,
                  },
                ],
                started_at: 100,
                completed_at: null,
                error_code: null,
                error_message: null,
                created_at: 100,
                ...run,
              },
            ],
            next: null,
          };
        }
        assert.equal(command, "get_run_approvals");
        assert.deepEqual(args, { workflowId, runId });
        return {
          approvals: [
            {
              approval_ref: "ab".repeat(32),
              workflow_id: workflowId,
              run_id: runId,
              step_id: "review",
              step_index: 0,
              approver_spec: "any",
              status: "pending",
              approver_pubkey: null,
              note: null,
              expires_at: "2099-01-01T00:00:00Z",
              created_at: 100,
              ...approval,
            },
          ],
        };
      },
    },
  };
  try {
    return {
      run: (await getWorkflowRuns(workflowId))[0],
      approvals: await getRunApprovals(workflowId, runId),
    };
  } finally {
    globalThis.window = previousWindow;
  }
}

function renderTrace(props) {
  return renderToStaticMarkup(React.createElement(WorkflowRunTrace, props));
}

test("REST-shaped waiting trace preserves and displays the resolved approval question", async () => {
  const models = await loadReadModels();
  assert.equal(models.run.executionTrace[0].message, prompt);
  const html = renderTrace(models);
  assert.match(html, /Approve saved trigger\?\nReview the release\./);
  assert.match(html, /whitespace-pre-wrap/);
  assert.match(html, />waiting approval</);
  assert.match(html, /Approval Required/);
  assert.equal(html.split("Approve saved trigger?").length - 1, 1);
});

test("resolved question remains visible before approval details load", async () => {
  const { run } = await loadReadModels();
  const html = renderTrace({ run });
  assert.match(html, /Approve saved trigger\?/);
  assert.match(html, />waiting approval</);
  assert.doesNotMatch(html, /Approval Required/);
});

test("older traces without an approval question still display their output", async () => {
  const models = await loadReadModels({
    run: { status: "completed" },
    trace: { status: "completed", message: undefined, output: { sent: true } },
    approval: { status: "granted" },
  });
  assert.equal(models.run.executionTrace[0].message, null);
  const html = renderTrace(models);
  assert.match(html, />completed</);
  assert.match(html, /sent/);
  assert.doesNotMatch(html, /waiting approval|Approval Required/);
});

for (const status of ["denied", "expired"]) {
  test(`persisted ${status} decision replaces the historical waiting badge`, async () => {
    // The separate run read may still be waiting when the decision read arrives.
    const models = await loadReadModels({ approval: { status } });
    const html = renderTrace(models);
    assert.match(html, new RegExp(`>${status}<`));
    assert.doesNotMatch(
      html,
      /waiting approval|Pending approval|Approval Required/,
    );
    assert.match(html, /Approve saved trigger\?/);
  });
}

for (const [status, errorCode, label] of [
  ["cancelled", "approval_denied", "denied"],
  ["failed", "approval_expired", "expired"],
  ["failed", "invalid_definition", "failed"],
]) {
  test(`terminal ${errorCode} run overrides a stale pending approval`, async () => {
    const models = await loadReadModels({
      run: { status, error_code: errorCode, completed_at: 101 },
    });
    for (const approvals of [models.approvals, []]) {
      const html = renderTrace({ run: models.run, approvals });
      assert.match(html, new RegExp(`>${label}<`));
      assert.doesNotMatch(
        html,
        /waiting approval|Pending approval|Approval Required/,
      );
    }
  });
}

test("granted gate awaiting executor capacity shows its persisted decision", async () => {
  const models = await loadReadModels({ approval: { status: "granted" } });
  const html = renderTrace(models);
  assert.match(html, />granted</);
  assert.doesNotMatch(
    html,
    /waiting approval|Pending approval|Approval Required/,
  );
});

test("pending card follows persisted status even after its displayed deadline", async () => {
  const models = await loadReadModels({
    approval: { expires_at: "2000-01-01T00:00:00Z" },
  });
  const html = renderTrace(models);
  assert.match(html, /Approval Required/);
  assert.match(html, /Approve saved trigger\?/);
  assert.match(html, />waiting approval</);
});
