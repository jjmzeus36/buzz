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
