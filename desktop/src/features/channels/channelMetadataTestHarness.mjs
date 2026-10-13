import assert from "node:assert/strict";
import { mock } from "node:test";
import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { relayClient } from "@/shared/api/relayClient";
import { useLiveChannelUpdates } from "./useLiveChannelUpdates.ts";

export async function mountMetadataBudgetHarness(channels, background = 17) {
  const { renderHook, waitFor } = await import("@testing-library/react");
  const server = new Map();
  const requests = [];
  const coverageErrors = [];
  const invalidations = [];
  let required = new Set();
  let peak = 0;
  let control = () => undefined;
  let closeControl = () => undefined;
  const previousWsId = relayClient.wsId;
  relayClient.wsId = 1;
  const subscribeSpy = mock.method(relayClient, "subscribeLive");
  const metadata = () =>
    [...server].filter(([, filter]) => filter.kinds.includes(39000));
  const covered = () =>
    new Set(metadata().flatMap(([, filter]) => filter["#d"]));
  const checkCoverage = () => {
    const actual = covered();
    for (const id of required) {
      if (!actual.has(id)) coverageErrors.push(id);
    }
  };
  mock.method(relayClient, "ensureConnected", async () => 1);
  mock.method(relayClient, "subscribeToReconnects", () => () => {});
  mock.method(
    relayClient,
    "sendRawWithReconnectRetry",
    async (subId, filter) => {
      const entry = { subId, filter, closed: 0 };
      requests.push(entry);
      const outcome = filter.kinds.includes(39000) ? control(entry) : undefined;
      if (outcome === "throw") throw new Error("metadata send failed");
      // This is one legal relay schedule: each cap check observes preceding
      // registrations. Production also permits concurrent over-admission.
      if (server.size >= 1024 || outcome === "closed") {
        await relayClient.handleWsMessage(
          JSON.stringify([
            "CLOSED",
            subId,
            outcome === "closed"
              ? "error: database error"
              : "error: too many subscriptions",
          ]),
          relayClient.connectionGeneration,
        );
        return;
      }
      server.set(subId, filter);
      peak = Math.max(peak, server.size);
      if (outcome !== "pending") {
        await relayClient.handleWsMessage(
          JSON.stringify(["EOSE", subId]),
          relayClient.connectionGeneration,
        );
      }
    },
  );
  // Preserve the production disposer and closeSubscription async path.
  mock.method(relayClient, "sendRaw", async ([type, subId]) => {
    assert.equal(type, "CLOSE");
    await closeControl(subId);
    server.delete(subId);
    const entry = requests.find((item) => item.subId === subId);
    if (entry) entry.closed++;
    checkCoverage();
  });
  const backgroundDisposers = [];
  for (let index = 0; index < background; index++) {
    backgroundDisposers.push(
      await relayClient.subscribeLive({ kinds: [30315], limit: 0 }, () => {}),
    );
  }
  const client = new QueryClient({
    defaultOptions: { queries: { gcTime: 0 } },
  });
  mock.method(client, "invalidateQueries", async (filter) => {
    invalidations.push(filter.queryKey);
  });
  const options = { currentPubkey: "a".repeat(64), onLiveMention() {} };
  const view = renderHook(
    ({ joined }) => useLiveChannelUpdates(joined, null, options),
    {
      initialProps: { joined: channels },
      wrapper: ({ children }) =>
        React.createElement(QueryClientProvider, { client }, children),
    },
  );
  await waitFor(() =>
    assert.equal(
      server.size,
      2 * channels.length + Math.ceil(channels.length / 128) + background,
    ),
  );
  required = new Set(channels.map((channel) => channel.id));
  return {
    server,
    requests,
    metadata,
    covered,
    invalidations,
    coverageErrors,
    peak: () => peak,
    waitForDisposers: () =>
      Promise.all(
        subscribeSpy.mock.calls
          .filter((call) => call.arguments[0].kinds.includes(39000))
          .map((call) => call.result),
      ),
    closeControl: (next) => {
      closeControl = next;
    },
    control: (next) => {
      control = next;
    },
    update: (next) => {
      const nextIds = new Set(next.map((channel) => channel.id));
      required = new Set([...required].filter((id) => nextIds.has(id)));
      view.rerender({ joined: next });
    },
    settle: async (next) => {
      const expected = new Set(next.map((channel) => channel.id));
      await waitFor(
        () => {
          assert.deepEqual(covered(), expected);
          assert.equal(metadata().length, Math.ceil(next.length / 128));
          assert.equal(
            server.size,
            2 * next.length + Math.ceil(next.length / 128) + background,
          );
        },
        { timeout: 2500 },
      );
      required = expected;
      assert.deepEqual(
        coverageErrors,
        [],
        "a surviving channel lost wire coverage during a swap",
      );
    },
    eose: async (entry) =>
      relayClient.handleWsMessage(
        JSON.stringify(["EOSE", entry.subId]),
        relayClient.connectionGeneration,
      ),
    close: async () => {
      required.clear();
      view.unmount();
      client.clear();
      await Promise.all(backgroundDisposers.map((dispose) => dispose()));
      await waitFor(() => {
        assert.equal(relayClient.subscriptions.size, 0);
        assert.equal(server.size, 0);
      });
      relayClient.wsId = previousWsId;
    },
  };
}
