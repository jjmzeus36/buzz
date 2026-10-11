// A relay rejection addressed to one event must settle that event's pending
// publish *and* arm the rate-limit gate.
//
// History: the relay rejected an over-quota EVENT with a bare
// `["NOTICE", "rate-limited: ..."]`. A NOTICE carries no event id, and
// `pendingEvents` is keyed by event id, so nothing settled — the publish sat
// until PUBLISH_TIMEOUT_MS (25s) and surfaced as a message stuck on
// "Sending…". Startup quota exhaustion made that routine in the first seconds
// after launch. The relay now rejects on the OK channel instead, so the gate
// arming that used to live in the NOTICE branch has to happen here too.
import assert from "node:assert/strict";
import test from "node:test";

const fakeNow = 0;
const pendingTimers = new Map();
let nextTimerId = 1;
const sendAttempts = [];
const deliveredFrames = [];
let sendTransport = async (args) => {
  deliveredFrames.push(args);
};

globalThis.window = {
  setTimeout: (fn, ms) => {
    const id = nextTimerId++;
    pendingTimers.set(id, { fn, fireAt: fakeNow + ms });
    return id;
  },
  clearTimeout: (id) => pendingTimers.delete(id),
  __TAURI_INTERNALS__: {
    invoke: async (command, args) => {
      if (command === "plugin:websocket|send") {
        sendAttempts.push(args);
        return sendTransport(args);
      }
    },
  },
};
Date.now = () => fakeNow;

const { RelayClient } = await import("./relayClientSession.ts");
const { activateRateLimit, isRateLimited, resetRateLimitGate } = await import(
  "./relayRateLimitGate.ts"
);

function reset() {
  resetRateLimitGate();
  pendingTimers.clear();
  nextTimerId = 1;
  sendAttempts.length = 0;
  deliveredFrames.length = 0;
  sendTransport = async (args) => {
    deliveredFrames.push(args);
  };
}

function connectedClient() {
  const client = new RelayClient();
  client.wsId = 7;
  return client;
}

function eventFrames() {
  return deliveredFrames.filter(
    ({ message }) => JSON.parse(message.data)[0] === "EVENT",
  );
}

async function flushUntil(predicate, attempts = 20) {
  for (let attempt = 0; attempt < attempts; attempt++) {
    if (predicate()) return;
    await Promise.resolve();
  }
  assert.fail("condition did not become true before the microtask limit");
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((promiseResolve, promiseReject) => {
    resolve = promiseResolve;
    reject = promiseReject;
  });
  return { promise, resolve, reject };
}

/**
 * Registers a pending publish the way `publishEvent` does, without needing a
 * socket: the OK dispatch under test only reads `pendingEvents`.
 */
function armPendingPublish(client, eventId) {
  const event = { id: eventId };
  const settled = new Promise((resolve, reject) => {
    client.pendingEvents.set(eventId, {
      event,
      resolve,
      reject,
      timeout: window.setTimeout(() => {}, 25_000),
    });
  });
  // Keep the rejection from surfacing as an unhandled rejection.
  return settled.then(
    (value) => ({ status: "resolved", value }),
    (error) => ({ status: "rejected", error }),
  );
}

/** Feeds a raw relay frame through the real inbound dispatch path. */
function deliver(client, frame) {
  return client.handleWsMessage(
    { type: "Text", data: JSON.stringify(frame) },
    client.connectionGeneration,
  );
}

test("a rate-limited OK rejection settles the pending publish", async () => {
  resetRateLimitGate();
  pendingTimers.clear();
  const client = new RelayClient();
  const eventId = "a".repeat(64);
  const settled = armPendingPublish(client, eventId);

  await deliver(client, [
    "OK",
    eventId,
    false,
    "rate-limited: quota exceeded; retry in 4s",
  ]);

  const outcome = await settled;
  assert.equal(
    outcome.status,
    "rejected",
    "an over-quota publish must fail fast, not hang until the 25s publish timeout",
  );
  assert.match(outcome.error.message, /rate-limited/);
  assert.equal(
    client.pendingEvents.has(eventId),
    false,
    "the pending entry must be cleared",
  );
});

test("a rate-limited OK rejection arms the rate-limit gate", async () => {
  resetRateLimitGate();
  pendingTimers.clear();
  const client = new RelayClient();
  const eventId = "b".repeat(64);
  const settled = armPendingPublish(client, eventId);

  assert.equal(isRateLimited(), false, "gate starts closed");

  await deliver(client, [
    "OK",
    eventId,
    false,
    "rate-limited: quota exceeded; retry in 4s",
  ]);
  await settled;

  assert.equal(
    isRateLimited(),
    true,
    "back-pressure now arrives on the OK channel — without arming here the " +
      "client fails the send and immediately retries into the same quota",
  );
});

test("an ordinary OK rejection does not arm the gate", async () => {
  resetRateLimitGate();
  pendingTimers.clear();
  const client = new RelayClient();
  const eventId = "c".repeat(64);
  const settled = armPendingPublish(client, eventId);

  await deliver(client, ["OK", eventId, false, "invalid: bad signature"]);
  const outcome = await settled;

  assert.equal(outcome.status, "rejected");
  assert.equal(
    isRateLimited(),
    false,
    "only `rate-limited:` rejections signal back-pressure",
  );
});

test("an accepted OK still resolves the pending publish", async () => {
  reset();
  const client = new RelayClient();
  const eventId = "d".repeat(64);
  const settled = armPendingPublish(client, eventId);

  await deliver(client, ["OK", eventId, true, ""]);
  const outcome = await settled;

  assert.equal(outcome.status, "resolved");
  assert.equal(outcome.value.id, eventId);
});

test("a publish started during an ordinary outage reconnects once and settles", async () => {
  reset();
  const client = new RelayClient();
  const event = { id: "0".repeat(64), kind: 1 };
  let reconnects = 0;
  client.ensureConnected = async () => {
    reconnects++;
    client.connectionGeneration++;
    client.wsId = 8;
    return client.connectionGeneration;
  };

  const published = client.publishEvent(event, "timed out", "send failed");
  await flushUntil(() => eventFrames().length === 1);

  assert.equal(reconnects, 1);
  assert.equal(sendAttempts.length, 1);
  assert.equal(client.pendingEvents.has(event.id), true);

  await deliver(client, ["OK", event.id, true, ""]);
  assert.equal(await published, event);
  assert.equal(client.pendingEvents.size, 0);
});

test("a community switch while gated cannot publish through its replacement socket", async () => {
  reset();
  activateRateLimit(4);
  const client = connectedClient();
  const event = { id: "e".repeat(64), kind: 1 };

  const published = client.publishEvent(event, "timed out", "send failed");
  await Promise.resolve();
  assert.equal(client.pendingEvents.size, 0);

  client.disconnect();
  resetRateLimitGate();
  client.wsId = 8;

  await assert.rejects(published, /community switch/);
  assert.equal(client.pendingEvents.size, 0);
  assert.equal(eventFrames().length, 0);
});

test("a community switch after send failure cannot retry through its replacement socket", async () => {
  reset();
  const client = connectedClient();
  const event = { id: "f".repeat(64), kind: 1 };
  const reconnect = deferred();
  client.ensureConnected = async () => {
    await reconnect.promise;
    return client.connectionGeneration;
  };
  sendTransport = async () => {
    throw new Error("old socket failed");
  };

  const published = client.publishEvent(event, "timed out", "send failed");
  const outcome = published.then(
    () => ({ status: "resolved" }),
    (error) => ({ status: "rejected", error }),
  );
  await flushUntil(() => client.connectionGeneration === 1);
  assert.equal(sendAttempts.length, 1);
  assert.equal(eventFrames().length, 0);
  assert.equal(
    client.connectionGeneration,
    1,
    "the failed send reset its socket",
  );
  assert.equal(
    client.pendingEvents.has(event.id),
    true,
    "the original publish remains owned while reconnect is pending",
  );

  client.disconnect();
  client.wsId = 8;
  const settledBeforeReconnect = await outcome;
  assert.equal(
    settledBeforeReconnect.status,
    "rejected",
    "community switch must settle the publish without waiting for reconnect",
  );
  assert.match(settledBeforeReconnect.error.message, /community switch/);

  reconnect.resolve();
  await published.catch(() => {});
  await Promise.resolve();
  assert.equal(client.pendingEvents.size, 0);
  assert.equal(
    sendAttempts.length,
    1,
    "the replacement socket must not be used",
  );
  assert.equal(eventFrames().length, 0);
});

// Subscription cancellation uses the real Channel, connection/authentication,
// reconnect coordinator, REQ retry, readiness, and disposer. Only Tauri invoke
// and browser timers are modeled. Native queued sends reject with a JS string.
function subscriptionRig({
  holdFirstReq = true,
  holdReqNumbers = [],
  sendEose = true,
} = {}) {
  resetRateLimitGate();
  const previousWindow = globalThis.window;
  const handles = new Map();
  const timers = new Map();
  const intervals = new Map();
  const calls = [];
  const requests = [];
  const held = [];
  let nextId = 0;
  let nextCallback = 0;
  let nextTimer = 0;
  let holdNext = holdFirstReq;
  const callbacks = new Map();
  const frame = (handle, payload) =>
    handle.onMessage.onmessage({ type: "Text", data: JSON.stringify(payload) });
  globalThis.window = {
    setTimeout(fn, ms) {
      const id = ++nextTimer;
      timers.set(id, { fn, ms });
      return id;
    },
    clearTimeout: (id) => timers.delete(id),
    setInterval(fn, ms) {
      const id = ++nextTimer;
      intervals.set(id, { fn, ms });
      return id;
    },
    clearInterval: (id) => intervals.delete(id),
    __TAURI_INTERNALS__: {
      transformCallback(fn) {
        callbacks.set(++nextCallback, fn);
        return nextCallback;
      },
      unregisterCallback: (id) => callbacks.delete(id),
      async invoke(command, args = {}) {
        calls.push({
          command,
          id: args.id,
          payload: args.message && JSON.parse(args.message.data),
        });
        if (command === "get_relay_ws_url") return "ws://relay-test.invalid";
        if (command === "create_auth_event") {
          return JSON.stringify({
            id: `auth-${nextId}`,
            kind: 22242,
            content: "",
            tags: [],
          });
        }
        if (command === "plugin:websocket|connect") {
          const id = ++nextId;
          const handle = {
            id,
            onMessage: args.onMessage,
            outstanding: new Set(),
          };
          handles.set(id, handle);
          frame(handle, ["AUTH", `challenge-${id}`]);
          return id;
        }
        if (command === "plugin:websocket|disconnect") {
          // Native removal precedes task shutdown and pending send settlement.
          handles.get(args.id)?.outstanding.clear();
          handles.delete(args.id);
          return;
        }
        assert.equal(command, "plugin:websocket|send");
        const handle = handles.get(args.id);
        if (!handle) throw `WebSocket connection ${args.id} not found`;
        const payload = JSON.parse(args.message.data);
        if (payload[0] === "AUTH") {
          frame(handle, ["OK", payload[1].id, true, ""]);
          return;
        }
        if (payload[0] === "CLOSE") {
          handle.outstanding.delete(payload[1]);
          return;
        }
        assert.equal(payload[0], "REQ");
        requests.push({ socket: args.id, subId: payload[1] });
        if (holdNext || holdReqNumbers.includes(requests.length)) {
          holdNext = false;
          const result = deferred();
          held.push({ result, handle, subId: payload[1] });
          await result.promise;
        }
        handle.outstanding.add(payload[1]);
        if (sendEose) frame(handle, ["EOSE", payload[1]]);
      },
    },
  };
  return {
    handles,
    timers,
    intervals,
    calls,
    requests,
    held,
    holdNextReq() {
      holdNext = true;
    },
    rejectHeld(index = 0) {
      held[index].result.reject("WebSocket connection closed");
    },
    resolveHeld(index = 0) {
      held[index].result.resolve();
    },
    emit(id, payload) {
      frame(handles.get(id), payload);
    },
    outage(id) {
      const handle = handles.get(id);
      handle.onMessage.onmessage({
        type: "Close",
        data: { code: 1006, reason: "outage" },
      });
    },
    runTimer(id) {
      const timer = timers.get(id);
      assert.ok(timer, `expected timer ${id}`);
      timers.delete(id);
      timer.fn();
    },
    disconnectedIds() {
      return calls
        .filter(({ command }) => command === "plugin:websocket|disconnect")
        .map(({ id }) => id);
    },
    closeFrames() {
      return calls.filter(({ payload }) => payload?.[0] === "CLOSE");
    },
    async cleanup(client) {
      client.disconnect();
      for (const request of held)
        request.result.reject("WebSocket connection closed");
      for (let i = 0; i < 100; i++) await Promise.resolve();
      try {
        assert.equal(timers.size, 0, "all browser timers must be released");
        assert.equal(intervals.size, 0, "the watchdog must stop");
      } finally {
        globalThis.window = previousWindow;
      }
    },
  };
}

const subscriptionFilter = { kinds: [39000], "#d": ["channel-a"], limit: 0 };
const outcomeOf = (promise) =>
  promise.then(
    (value) => ({ status: "resolved", value }),
    (error) => ({ status: "rejected", error }),
  );
const settleMicrotasks = async () => {
  for (let i = 0; i < 100; i++) await Promise.resolve();
};
const waitFor = (predicate) => flushUntil(predicate, 200);
async function settledOutcome(pending) {
  let outcome;
  void pending.then((value) => {
    outcome = value;
  });
  await waitFor(() => outcome !== undefined);
  return outcome;
}

for (const replacement of [false, true]) {
  test(`a retired REQ rejection cannot ${replacement ? "reset a healthy replacement" : "reopen after disconnect"}`, async () => {
    const rig = subscriptionRig();
    const client = new RelayClient();
    const readiness = [];
    try {
      const pending = outcomeOf(
        client.subscribeLive(
          subscriptionFilter,
          () => {},
          (value) => readiness.push(value),
        ),
      );
      await waitFor(() => rig.held.length === 1);
      client.disconnect();
      const outcome = await settledOutcome(pending);
      assert.equal(
        outcome.status,
        "rejected",
        "disconnect settles before the native send completes",
      );
      assert.match(outcome.error.message, /cancelled/);
      assert.equal(
        rig.timers.size,
        0,
        "disconnect clears readiness immediately",
      );
      assert.equal(client.pendingSubscriptionCancels.size, 0);
      if (replacement) await client.preconnect();
      const generation = client.connectionGeneration;
      rig.rejectHeld();
      await settleMicrotasks();
      assert.equal(client.connectionGeneration, generation);
      assert.equal(client.wsId, replacement ? 2 : null);
      assert.deepEqual(rig.disconnectedIds(), [1]);
      assert.equal(rig.requests.length, 1);
      assert.equal(client.subscriptions.size, 0);
      assert.deepEqual(readiness, []);
      assert.equal(rig.closeFrames().length, 0);
    } finally {
      await rig.cleanup(client);
    }
  });
}

test("subscription connection readiness cannot cross a community switch", async () => {
  const rig = subscriptionRig();
  const client = new RelayClient();
  try {
    await client.preconnect();
    const pending = outcomeOf(
      client.subscribeLive(subscriptionFilter, () => {}),
    );
    client.disconnect();
    await client.preconnect();
    const outcome = await settledOutcome(pending);
    assert.equal(outcome.status, "rejected");
    assert.match(outcome.error.message, /cancelled/);
    assert.equal(rig.requests.length, 0);
    assert.equal(client.subscriptions.size, 0);
    assert.equal(client.wsId, 2);
  } finally {
    await rig.cleanup(client);
  }
});

for (const replacementBeforeFailure of [false, true]) {
  test(`an ordinary outage preserves the desired REQ${replacementBeforeFailure ? " when its old send fails late" : " and reconnects"}`, async () => {
    const rig = subscriptionRig();
    const client = new RelayClient();
    try {
      const pending = outcomeOf(
        client.subscribeLive(subscriptionFilter, () => {}),
      );
      await waitFor(() => rig.held.length === 1);
      const [subId, original] = [...client.subscriptions][0];
      if (replacementBeforeFailure) rig.outage(1);
      else rig.rejectHeld();
      await waitFor(() => client.reconnectTimeout !== null);
      rig.runTimer(client.reconnectTimeout);
      if (replacementBeforeFailure) {
        await waitFor(
          () => client.wsId === 2 && client.connectPromise === null,
        );
        rig.rejectHeld();
      }
      const outcome = await settledOutcome(pending);
      assert.equal(outcome.status, "resolved");
      assert.equal(client.sessionEpoch, 0);
      assert.equal(client.subscriptions.get(subId), original);
      assert.equal(client.wsId, 2);
      assert.deepEqual(rig.disconnectedIds(), [1]);
      assert.ok(rig.handles.get(2).outstanding.has(subId));
      await outcome.value();
      assert.equal(client.subscriptions.size, 0);
      assert.equal(rig.handles.get(2).outstanding.size, 0);
    } finally {
      await rig.cleanup(client);
    }
  });
}

test("a retired successful REQ never sends CLOSE to a newer community socket", async () => {
  const rig = subscriptionRig();
  const client = new RelayClient();
  const readiness = [];
  try {
    const pending = outcomeOf(
      client.subscribeLive(
        subscriptionFilter,
        () => {},
        (value) => readiness.push(value),
      ),
    );
    await waitFor(() => rig.held.length === 1);
    client.disconnect();
    await client.preconnect();
    rig.resolveHeld();
    assert.equal((await settledOutcome(pending)).status, "rejected");
    await settleMicrotasks();
    assert.equal(client.wsId, 2);
    assert.equal(rig.requests.length, 1);
    assert.deepEqual(rig.disconnectedIds(), [1]);
    assert.equal(rig.closeFrames().length, 0);
    assert.deepEqual(readiness, []);
  } finally {
    await rig.cleanup(client);
  }
});

test("a successful REQ retired by terminal CLOSED converges to closed on its socket", async () => {
  const rig = subscriptionRig();
  const client = new RelayClient();
  try {
    const pending = outcomeOf(
      client.subscribeLive(subscriptionFilter, () => {}),
    );
    await waitFor(() => rig.held.length === 1);
    const subId = rig.held[0].subId;
    rig.emit(1, ["CLOSED", subId, "restricted: access denied"]);
    await waitFor(() => client.subscriptions.size === 0);
    rig.resolveHeld();
    assert.equal((await settledOutcome(pending)).status, "rejected");
    assert.equal(rig.handles.get(1).outstanding.size, 0);
    assert.deepEqual(
      rig.closeFrames().map(({ id }) => id),
      [1],
    );
    assert.deepEqual(rig.disconnectedIds(), []);
  } finally {
    await rig.cleanup(client);
  }
});

for (const success of [false, true]) {
  test(`a ${success ? "successful" : "failed"} stale REQ cannot remove or close a replacement subscription object`, async () => {
    const rig = subscriptionRig();
    const client = new RelayClient();
    const readiness = [];
    try {
      const pending = outcomeOf(
        client.subscribeLive(
          subscriptionFilter,
          () => {},
          (value) => readiness.push(value),
        ),
      );
      await waitFor(() => rig.held.length === 1);
      const subId = rig.held[0].subId;
      const replacement = {
        mode: "live",
        filter: subscriptionFilter,
        onEvent() {},
      };
      client.subscriptions.set(subId, replacement);
      if (success) rig.resolveHeld();
      else rig.rejectHeld();
      const outcome = await settledOutcome(pending);
      assert.equal(outcome.status, "rejected");
      assert.equal(client.subscriptions.get(subId), replacement);
      assert.equal(client.wsId, 1);
      assert.equal(rig.requests.length, 1);
      assert.equal(rig.closeFrames().length, 0);
      assert.deepEqual(rig.disconnectedIds(), []);
      assert.deepEqual(readiness, []);
    } finally {
      await rig.cleanup(client);
    }
  });
}

for (const success of [false, true]) {
  test(`a disposed CLOSED retry ${success ? "closes a late successful REQ" : "cannot reconnect on late failure"}`, async () => {
    const rig = subscriptionRig({ holdFirstReq: false });
    const client = new RelayClient();
    try {
      const dispose = await client.subscribeLive(subscriptionFilter, () => {});
      const [subId, subscription] = [...client.subscriptions][0];
      rig.holdNextReq();
      rig.emit(1, ["CLOSED", subId, "error: temporary failure"]);
      await waitFor(() => subscription.closedRetryTimeout !== undefined);
      rig.runTimer(subscription.closedRetryTimeout);
      await waitFor(() => rig.held.length === 1);
      await dispose();
      if (success) rig.resolveHeld();
      else rig.rejectHeld();
      await settleMicrotasks();
      assert.equal(client.subscriptions.size, 0);
      assert.equal(client.wsId, 1);
      assert.equal(rig.requests.length, 2);
      assert.equal(rig.handles.get(1).outstanding.size, 0);
      assert.equal(rig.closeFrames().length, success ? 2 : 1);
      assert.deepEqual(rig.disconnectedIds(), []);
    } finally {
      await rig.cleanup(client);
    }
  });
}

test("readiness timeout preserves the callback for a later EOSE", async () => {
  const rig = subscriptionRig({ holdFirstReq: false, sendEose: false });
  const client = new RelayClient();
  const readiness = [];
  try {
    const pending = client.subscribeLive(
      subscriptionFilter,
      () => {},
      (value) => readiness.push(value),
    );
    await waitFor(() => rig.requests.length === 1);
    const readinessTimer = [...rig.timers].find(
      ([, timer]) => timer.ms === 250,
    )[0];
    rig.runTimer(readinessTimer);
    const dispose = await pending;
    assert.deepEqual(readiness, ["timeout"]);
    rig.emit(1, ["EOSE", rig.requests[0].subId]);
    await waitFor(() => readiness.length === 2);
    assert.deepEqual(readiness, ["timeout", "eose"]);
    await dispose();
  } finally {
    await rig.cleanup(client);
  }
});

for (const communitySwitch of [false, true]) {
  test(`a late retry failure ${communitySwitch ? "cannot reset a replacement community" : "preserves a newer ordinary recovery"}`, async () => {
    const rig = subscriptionRig({ holdReqNumbers: [3] });
    const client = new RelayClient();
    try {
      const pending = outcomeOf(
        client.subscribeLive(subscriptionFilter, () => {}),
      );
      await waitFor(() => rig.held.length === 1);
      const [subId, original] = [...client.subscriptions][0];
      rig.rejectHeld();
      await waitFor(() => client.reconnectTimeout !== null);
      rig.runTimer(client.reconnectTimeout);
      await waitFor(() => rig.held.length === 2);
      assert.equal(
        rig.held[1].handle.id,
        2,
        "the explicit retry used socket 2",
      );
      if (communitySwitch) {
        client.disconnect();
        assert.equal((await settledOutcome(pending)).status, "rejected");
        await client.preconnect();
      } else {
        rig.outage(2);
        await waitFor(() => client.reconnectTimeout !== null);
        rig.runTimer(client.reconnectTimeout);
        await waitFor(
          () => client.wsId === 3 && client.connectPromise === null,
        );
      }
      rig.rejectHeld(1);
      const outcome = await settledOutcome(pending);
      await settleMicrotasks();
      assert.equal(client.wsId, 3);
      assert.deepEqual(rig.disconnectedIds(), [1, 2]);
      if (communitySwitch) {
        assert.equal(outcome.status, "rejected");
        assert.equal(client.subscriptions.size, 0);
        assert.equal(rig.requests.length, 3);
      } else {
        assert.equal(outcome.status, "resolved");
        assert.equal(client.subscriptions.get(subId), original);
        assert.ok(rig.handles.get(3).outstanding.has(subId));
        await outcome.value();
        assert.equal(rig.handles.get(3).outstanding.size, 0);
      }
    } finally {
      await rig.cleanup(client);
    }
  });
}

test("post-reset readiness callback cancellation cannot reopen a socket", async () => {
  const rig = subscriptionRig();
  const client = new RelayClient();
  try {
    const pending = outcomeOf(
      client.subscribeLive(
        subscriptionFilter,
        () => {},
        (readiness) => {
          if (readiness === "closed") client.disconnect();
        },
      ),
    );
    await waitFor(() => rig.held.length === 1);
    rig.rejectHeld();
    assert.equal((await settledOutcome(pending)).status, "rejected");
    await settleMicrotasks();
    assert.equal(client.wsId, null);
    assert.equal(rig.requests.length, 1);
    assert.equal(rig.handles.size, 0);
  } finally {
    await rig.cleanup(client);
  }
});

test("post-reset retired history retry cannot reopen a socket", async () => {
  const rig = subscriptionRig({ holdFirstReq: false, sendEose: false });
  const client = new RelayClient();
  try {
    const pending = outcomeOf(client.fetchEvents(subscriptionFilter));
    await waitFor(() => rig.requests.length === 1);
    rig.holdNextReq();
    rig.emit(1, ["CLOSED", rig.requests[0].subId, "rate-limited: retry in 1s"]);
    await waitFor(
      () => [...client.subscriptions.keys()][0] !== rig.requests[0].subId,
    );
    const subscription = [...client.subscriptions.values()][0];
    rig.runTimer(subscription.timeout);
    await waitFor(() => rig.held.length === 1);
    rig.rejectHeld();
    assert.equal((await settledOutcome(pending)).status, "rejected");
    await settleMicrotasks();
    assert.equal(client.wsId, null);
    assert.equal(client.subscriptions.size, 0);
    assert.equal(rig.requests.length, 2);
    assert.equal(rig.handles.size, 0);
  } finally {
    resetRateLimitGate();
    await rig.cleanup(client);
  }
});

test("retired successful reconnect replay cannot restart the watchdog", async () => {
  const rig = subscriptionRig({ holdReqNumbers: [2] });
  const client = new RelayClient();
  try {
    const pending = outcomeOf(
      client.subscribeLive(subscriptionFilter, () => {}),
    );
    await waitFor(() => rig.held.length === 1);
    rig.rejectHeld();
    await waitFor(() => client.reconnectTimeout !== null);
    rig.runTimer(client.reconnectTimeout);
    await waitFor(() => rig.held.length === 2);
    client.disconnect();
    assert.equal((await settledOutcome(pending)).status, "rejected");
    rig.resolveHeld(1);
    await settleMicrotasks();
    assert.equal(client.wsId, null);
    assert.equal(client.hasConnectedOnce, false);
    assert.equal(rig.intervals.size, 0);
  } finally {
    await rig.cleanup(client);
  }
});

test("retired reconnect replay rejection cannot reset a healthy replacement", async () => {
  const rig = subscriptionRig({ holdReqNumbers: [2] });
  const client = new RelayClient();
  try {
    const pending = outcomeOf(
      client.subscribeLive(subscriptionFilter, () => {}),
    );
    await waitFor(() => rig.held.length === 1);
    rig.rejectHeld();
    await waitFor(() => client.reconnectTimeout !== null);
    rig.runTimer(client.reconnectTimeout);
    await waitFor(() => rig.held.length === 2);
    client.disconnect();
    assert.equal((await settledOutcome(pending)).status, "rejected");
    await client.preconnect();
    const generation = client.connectionGeneration;
    rig.rejectHeld(1);
    await settleMicrotasks();
    assert.equal(client.wsId, 3);
    assert.equal(client.connectionGeneration, generation);
    assert.equal(client.getConnectionState(), "connected");
    assert.deepEqual(rig.disconnectedIds(), [1, 2]);
    assert.equal(rig.requests.length, 2);
    assert.equal(client.subscriptions.size, 0);
  } finally {
    await rig.cleanup(client);
  }
});

for (const bypassBackoff of [false, true]) {
  test(`a retired ${bypassBackoff ? "explicit" : "scheduled"} reconnect cannot settle a new session's waiters`, async () => {
    const rig = subscriptionRig({ holdReqNumbers: [2] });
    const client = new RelayClient();
    try {
      const retired = outcomeOf(
        client.subscribeLive(subscriptionFilter, () => {}),
      );
      await waitFor(() => rig.held.length === 1);
      rig.rejectHeld();
      await waitFor(() => client.reconnectTimeout !== null);
      let oldReconnect;
      if (bypassBackoff) oldReconnect = outcomeOf(client.preconnect());
      else rig.runTimer(client.reconnectTimeout);
      await waitFor(() => rig.held.length === 2);
      client.disconnect();
      assert.equal((await settledOutcome(retired)).status, "rejected");
      await client.preconnect();
      rig.outage(3);
      await waitFor(() => client.reconnectTimeout !== null);
      const recoveryTimer = client.reconnectTimeout;
      const pending = outcomeOf(
        client.subscribeLive(subscriptionFilter, () => {}),
      );
      let replacementOutcome;
      void pending.then((value) => {
        replacementOutcome = value;
      });
      await settleMicrotasks();
      rig.resolveHeld(1);
      await settleMicrotasks();
      assert.equal(
        replacementOutcome,
        undefined,
        "retired connection must leave the new waiter pending",
      );
      assert.equal(client.reconnectTimeout, recoveryTimer);
      if (oldReconnect)
        assert.equal((await settledOutcome(oldReconnect)).status, "rejected");
      rig.runTimer(recoveryTimer);
      const outcome = await settledOutcome(pending);
      assert.equal(outcome.status, "resolved");
      assert.equal(client.wsId, 4);
      assert.equal(client.subscriptions.size, 1);
      assert.equal(rig.requests.length, 3);
      assert.equal(rig.requests[2].socket, 4);
      await outcome.value();
      assert.equal(rig.handles.get(4).outstanding.size, 0);
    } finally {
      await rig.cleanup(client);
    }
  });
}

test("URL retirement cannot overwrite a new session's relay URL", async () => {
  const rig = subscriptionRig({ holdFirstReq: false });
  const client = new RelayClient();
  const oldUrl = deferred();
  const nativeInvoke = window.__TAURI_INTERNALS__.invoke;
  let urlRequests = 0;
  const connectUrls = [];
  window.__TAURI_INTERNALS__.invoke = async (command, args) => {
    if (command === "get_relay_ws_url") {
      urlRequests++;
      return urlRequests === 1 ? oldUrl.promise : "ws://replacement.invalid";
    }
    if (command === "plugin:websocket|connect") connectUrls.push(args.url);
    return nativeInvoke(command, args);
  };
  try {
    const retired = outcomeOf(client.preconnect());
    await waitFor(() => urlRequests === 1);
    client.disconnect();
    await client.preconnect();
    oldUrl.resolve("ws://retired.invalid");
    assert.equal((await settledOutcome(retired)).status, "rejected");
    assert.equal(client.relayUrl, "ws://replacement.invalid");
    assert.deepEqual(connectUrls, ["ws://replacement.invalid"]);
  } finally {
    await rig.cleanup(client);
  }
});

test("retired authentication completion cannot mark a disconnected session connected", async () => {
  const rig = subscriptionRig({ holdFirstReq: false });
  const client = new RelayClient();
  try {
    const retired = outcomeOf(client.preconnect());
    await waitFor(
      () =>
        client.wsId === 1 &&
        client.authRequest === null &&
        client.getConnectionState() === "connecting",
    );
    client.disconnect();
    assert.equal((await settledOutcome(retired)).status, "rejected");
    assert.equal(client.wsId, null);
    assert.equal(client.getConnectionState(), "idle");
    assert.equal(rig.timers.size, 0);
    assert.equal(rig.intervals.size, 0);
    assert.equal(rig.requests.length, 0);
  } finally {
    await rig.cleanup(client);
  }
});
