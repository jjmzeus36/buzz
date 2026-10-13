import assert from "node:assert/strict";
import test from "node:test";

import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { WorkflowStepCard } from "./WorkflowStepCard.tsx";

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
