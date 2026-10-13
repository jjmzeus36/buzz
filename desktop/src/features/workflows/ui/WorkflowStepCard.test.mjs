import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { WorkflowStepCard } from "./WorkflowStepCard.tsx";
import { SELECTABLE_ACTION_TYPES } from "./workflowFormTypes.ts";

test("supported topic steps expose the topic input without a backend failure warning", () => {
  assert.ok(SELECTABLE_ACTION_TYPES.includes("set_channel_topic"));
  const html = renderToStaticMarkup(
    React.createElement(WorkflowStepCard, {
      index: 0,
      step: { id: "topic", action: "set_channel_topic", topic: "" },
      triggerType: "webhook",
      onUpdate() {},
      onRemove() {},
    }),
  );
  assert.match(html, /id="wf-step-0-topic"/);
  assert.doesNotMatch(
    html,
    /not executed yet|runs fail at this step|Backend note/,
  );
});

test("approval steps explain the waiting run and available decision path", () => {
  const html = renderToStaticMarkup(
    React.createElement(WorkflowStepCard, {
      index: 0,
      step: {
        id: "review",
        action: "request_approval",
        from: "any",
        message: "Approve this announcement?",
        timeout: "24h",
      },
      triggerType: "webhook",
      onUpdate() {},
      onRemove() {},
    }),
  );
  assert.match(html, /id="wf-step-0-from"/);
  assert.match(html, /The run waits for an approval decision\./);
  assert.match(html, /Use the Buzz CLI to approve or deny it\./);
  assert.doesNotMatch(
    html,
    /WF-08|records are not persisted|approval gates still stop runs/,
  );
});
