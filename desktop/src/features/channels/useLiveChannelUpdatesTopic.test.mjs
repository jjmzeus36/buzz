import assert from "node:assert/strict";
import { after, afterEach, before, mock, test } from "node:test";
import { JSDOM } from "jsdom";
import React from "react";
import {
  QueryClient,
  QueryClientProvider,
  useQuery,
} from "@tanstack/react-query";

import { channelsQueryKey, useChannelDetailsQuery } from "./hooks.ts";
import { useLiveChannelUpdates } from "./useLiveChannelUpdates.ts";
import { getChannels, fromRawChannelDetail } from "@/shared/api/tauriChannels";
import { relayClient } from "@/shared/api/relayClient";

const dom = new JSDOM("<!doctype html><html><body></body></html>", {
  url: "http://localhost",
});
const CHANNEL_A = "11111111-1111-4111-8111-111111111111";
const CHANNEL_B = "22222222-2222-4222-8222-222222222222";

before(() => {
  Object.assign(globalThis, {
    document: dom.window.document,
    HTMLElement: dom.window.HTMLElement,
    IS_REACT_ACT_ENVIRONMENT: true,
    window: dom.window,
  });
});
afterEach(async () => {
  const { cleanup } = await import("@testing-library/react");
  cleanup();
  mock.restoreAll();
});
after(() => dom.window.close());

function rawChannel(id, topic, channelType = "stream") {
  return {
    id,
    name: id === CHANNEL_A ? "general" : "other",
    channel_type: channelType,
    visibility: "open",
    description: "",
    topic,
    purpose: null,
    member_count: 1,
    member_pubkeys: [],
    last_message_at: null,
    archived_at: null,
    participants: [],
    participant_pubkeys: [],
    is_member: true,
    ttl_seconds: null,
    ttl_deadline: null,
    created_by: "f".repeat(64),
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    topic_set_by: null,
    topic_set_at: null,
    purpose_set_by: null,
    purpose_set_at: null,
    topic_required: false,
    max_members: null,
    nip29_group_id: null,
  };
}

function topicNotice(topic, index) {
  return {
    id: `notice-${index}`,
    pubkey: "f".repeat(64),
    created_at: Math.floor(Date.now() / 1000),
    kind: 40099,
    tags: [
      ["h", CHANNEL_A],
      ["buzz:workflow", "true"],
      ["buzz:workflow-owner", "a".repeat(64)],
    ],
    content: JSON.stringify({
      type: "topic_changed",
      actor: "a".repeat(64),
      topic,
    }),
    sig: "",
  };
}

for (const channelType of ["stream", "forum"]) {
  for (const activeChannelId of [CHANNEL_A, CHANNEL_B]) {
    test(`live topic notice refreshes ${channelType} list and detail with active ${activeChannelId}`, async () => {
      const { act, renderHook, waitFor } = await import(
        "@testing-library/react"
      );
      let metadata = [
        rawChannel(CHANNEL_A, "old topic", channelType),
        rawChannel(CHANNEL_B, "unrelated topic"),
      ];
      const calls = [];
      window.__TAURI_INTERNALS__ = {
        invoke: async (command, args) => {
          calls.push([command, args]);
          if (command === "get_channel_details") {
            return metadata.find((channel) => channel.id === args.channelId);
          }
          if (command === "get_channels") {
            return { hash: "new-hash", channels: metadata, last_messages: {} };
          }
          throw new Error(`Unexpected Tauri command: ${command}`);
        },
      };
      const callbacks = new Map();
      mock.method(relayClient, "subscribeToReconnects", () => () => {});
      mock.method(
        relayClient,
        "subscribeLive",
        async (filter, onEvent, onReady) => {
          onReady?.("eose");
          if (filter.kinds.includes(39000)) {
            assert.deepEqual(filter["#d"], [CHANNEL_A, CHANNEL_B]);
            return async () => {};
          }
          assert.ok(filter.kinds.includes(40099));
          callbacks.set(filter["#h"][0], onEvent);
          return async () => {};
        },
      );

      const client = new QueryClient({
        defaultOptions: { queries: { retry: false, gcTime: 0 } },
      });
      const initial = metadata.map(fromRawChannelDetail);
      client.setQueryData(channelsQueryKey, initial);
      for (const detail of initial) {
        client.setQueryData(["channels", detail.id, "detail"], detail);
      }
      const view = renderHook(
        () => {
          const list = useQuery({
            queryKey: channelsQueryKey,
            queryFn: async () => (await getChannels(null)).channels,
            staleTime: Infinity,
          });
          useLiveChannelUpdates(list.data ?? [], activeChannelId);
          return {
            list: list.data,
            detail: useChannelDetailsQuery(CHANNEL_A).data,
            unrelated: useChannelDetailsQuery(CHANNEL_B).data,
          };
        },
        {
          wrapper: ({ children }) =>
            React.createElement(QueryClientProvider, { client }, children),
        },
      );
      try {
        await waitFor(() => assert.equal(callbacks.size, 2));
        assert.equal(view.result.current.detail.topic, "old topic");
        // Exercise exact topic preservation and empty-to-null metadata mapping.
        for (const [index, topic] of [
          '  "launch 🐝"  ',
          " \t ",
          "",
        ].entries()) {
          metadata = [
            rawChannel(CHANNEL_A, topic === "" ? null : topic, channelType),
            metadata[1],
          ];
          await act(async () =>
            callbacks.get(CHANNEL_A)(topicNotice(topic, index)),
          );
          const expected = topic === "" ? null : topic;
          await waitFor(() =>
            assert.equal(view.result.current.detail.topic, expected),
          );
          await waitFor(() =>
            assert.equal(view.result.current.list[0].topic, expected),
          );
          assert.equal(view.result.current.unrelated.topic, "unrelated topic");
        }
        assert.ok(calls.some(([command]) => command === "get_channels"));
        assert.ok(
          calls.some(
            ([command, args]) =>
              command === "get_channel_details" && args.channelId === CHANNEL_A,
          ),
        );
        assert.equal(
          calls.some(
            ([command, args]) =>
              command === "get_channel_details" && args.channelId === CHANNEL_B,
          ),
          false,
        );
        assert.equal(callbacks.size, 2);
      } finally {
        view.unmount();
        client.clear();
      }
    });
  }
}
function deferred() {
  let resolve;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function canonicalMetadata(channelId = CHANNEL_A, kind = 39000) {
  return {
    id: `metadata-${channelId}`,
    pubkey: "f".repeat(64),
    created_at: Math.floor(Date.now() / 1000),
    kind,
    tags: [["d", channelId]],
    content: "",
    sig: "",
  };
}

async function mountTopicHarness({
  seedDetail = true,
  detailResponse,
  metadataReady,
} = {}) {
  const { renderHook, waitFor } = await import("@testing-library/react");
  const state = {
    metadata: [
      rawChannel(CHANNEL_A, "old topic"),
      rawChannel(CHANNEL_B, "unrelated topic"),
    ],
    detailCalls: [],
    listCalls: 0,
    subscriptions: [],
  };
  window.__TAURI_INTERNALS__ = {
    invoke: async (command, args) => {
      if (command === "get_channel_details") {
        state.detailCalls.push(args.channelId);
        const raw = state.metadata.find(
          (channel) => channel.id === args.channelId,
        );
        return detailResponse
          ? detailResponse(state.detailCalls.length, raw)
          : raw;
      }
      if (command === "get_channels") {
        state.listCalls++;
        return {
          hash: "new-hash",
          channels: state.metadata,
          last_messages: {},
        };
      }
      throw new Error(`Unexpected Tauri command: ${command}`);
    },
  };
  mock.method(relayClient, "subscribeToReconnects", () => () => {});
  mock.method(
    relayClient,
    "subscribeLive",
    async (filter, onEvent, onReady) => {
      const subscription = { filter, onEvent, disposed: 0 };
      state.subscriptions.push(subscription);
      if (filter.kinds.includes(39000) && metadataReady)
        await metadataReady.promise;
      onReady?.("eose");
      return async () => {
        subscription.disposed++;
      };
    },
  );
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity } },
  });
  const initial = state.metadata.map(fromRawChannelDetail);
  client.setQueryData(channelsQueryKey, initial);
  client.setQueryData(["channels", CHANNEL_B, "detail"], initial[1]);
  if (seedDetail)
    client.setQueryData(["channels", CHANNEL_A, "detail"], initial[0]);
  const view = renderHook(
    ({ ids }) => {
      const list = useQuery({
        queryKey: channelsQueryKey,
        queryFn: async () => (await getChannels(null)).channels,
        staleTime: Infinity,
      });
      useLiveChannelUpdates(
        (list.data ?? []).filter((channel) => ids.includes(channel.id)),
        CHANNEL_A,
      );
      return {
        list: list.data,
        detail: useChannelDetailsQuery(CHANNEL_A).data,
        unrelated: useChannelDetailsQuery(CHANNEL_B).data,
      };
    },
    {
      initialProps: { ids: [CHANNEL_A, CHANNEL_B] },
      wrapper: ({ children }) =>
        React.createElement(QueryClientProvider, { client }, children),
    },
  );
  await waitFor(() => assert.equal(state.subscriptions.length, 3));
  state.message = state.subscriptions.find(
    ({ filter }) => filter["#h"]?.[0] === CHANNEL_A,
  );
  state.canonical = state.subscriptions.find(
    ({ filter }) => filter["#d"]?.[0] === CHANNEL_A,
  );
  return {
    state,
    client,
    view,
    close: () => {
      view.unmount();
      client.clear();
    },
  };
}

for (const nextTopic of ["new topic", null]) {
  test(`topic notice cancels an uncached initial detail request before fetching ${nextTopic}`, async () => {
    const { act, waitFor } = await import("@testing-library/react");
    const initial = deferred();
    const replacement = deferred();
    const harness = await mountTopicHarness({
      seedDetail: false,
      detailResponse: (call, raw) =>
        call === 1 ? initial.promise : call === 2 ? replacement.promise : raw,
    });
    const { state, client, view } = harness;
    try {
      await waitFor(() => assert.equal(state.detailCalls.length, 1));
      const oldRaw = state.metadata[0];
      state.metadata[0] = rawChannel(CHANNEL_A, nextTopic);
      await act(async () =>
        state.message.onEvent(topicNotice(nextTopic ?? "", 100)),
      );
      await waitFor(() => assert.equal(state.detailCalls.length, 2));
      await act(async () => initial.resolve(oldRaw));
      assert.equal(
        client.getQueryData(["channels", CHANNEL_A, "detail"]),
        undefined,
      );
      await act(async () => replacement.resolve(state.metadata[0]));
      await waitFor(() =>
        assert.equal(view.result.current.detail?.topic, nextTopic),
      );
      await waitFor(() =>
        assert.equal(view.result.current.list[0].topic, nextTopic),
      );
      assert.deepEqual(state.detailCalls, [CHANNEL_A, CHANNEL_A]);
      assert.equal(view.result.current.unrelated.topic, "unrelated topic");
    } finally {
      initial.resolve(state.metadata[0]);
      replacement.resolve(state.metadata[0]);
      harness.close();
    }
  });

  test(`canonical metadata converges after a human notice fetched old ${nextTopic}`, async () => {
    const { act, waitFor } = await import("@testing-library/react");
    const harness = await mountTopicHarness();
    const { state, client, view } = harness;
    try {
      // Human edits publish this notice before the replacement metadata exists.
      const notice = topicNotice(nextTopic ?? "", 200);
      notice.tags = [["h", CHANNEL_A]];
      await act(async () => state.message.onEvent(notice));
      await waitFor(() => assert.equal(state.detailCalls.length, 1));
      await waitFor(() =>
        assert.equal(
          client.getQueryState(["channels", CHANNEL_A, "detail"]).fetchStatus,
          "idle",
        ),
      );
      assert.equal(view.result.current.detail.topic, "old topic");
      state.metadata[0] = rawChannel(CHANNEL_A, nextTopic);
      await act(async () => state.canonical.onEvent(canonicalMetadata()));
      await waitFor(() =>
        assert.equal(view.result.current.detail.topic, nextTopic),
      );
      await waitFor(() =>
        assert.equal(view.result.current.list[0].topic, nextTopic),
      );
      assert.deepEqual(state.detailCalls, [CHANNEL_A, CHANNEL_A]);
      assert.deepEqual(state.canonical.filter, {
        kinds: [39000],
        "#d": [CHANNEL_A, CHANNEL_B],
        limit: 0,
      });
      assert.equal(view.result.current.unrelated.topic, "unrelated topic");
    } finally {
      harness.close();
    }
  });
}

test("canonical subscription ignores wrong filters and retired channel callbacks", async () => {
  const { act, waitFor } = await import("@testing-library/react");
  const harness = await mountTopicHarness();
  const { state, view } = harness;
  try {
    await act(async () => {
      state.canonical.onEvent(
        canonicalMetadata("33333333-3333-4333-8333-333333333333"),
      );
      state.canonical.onEvent(canonicalMetadata(CHANNEL_A, 40099));
    });
    assert.equal(state.detailCalls.length, 0);
    view.rerender({ ids: [CHANNEL_B] });
    await waitFor(() => assert.equal(state.canonical.disposed, 1));
    assert.equal(state.message.disposed, 1);
    await act(async () => {
      state.canonical.onEvent(canonicalMetadata());
      state.message.onEvent(topicNotice("after removal", 300));
    });
    assert.equal(state.detailCalls.length, 0);
    view.unmount();
    assert.ok(
      state.subscriptions.every((subscription) => subscription.disposed === 1),
    );
    await act(async () => state.canonical.onEvent(canonicalMetadata()));
    assert.equal(state.detailCalls.length, 0);
  } finally {
    harness.close();
  }
});

test("unmount retires message callbacks while canonical subscription readiness is pending", async () => {
  const { act, waitFor } = await import("@testing-library/react");
  const ready = deferred();
  const harness = await mountTopicHarness({ metadataReady: ready });
  const { state, view, client } = harness;
  try {
    view.unmount();
    assert.equal(state.message.disposed, 1);
    await act(async () => {
      state.message.onEvent(topicNotice("after unmount", 400));
      state.canonical.onEvent(canonicalMetadata());
      ready.resolve();
    });
    await waitFor(() =>
      assert.ok(
        state.subscriptions.every(
          (subscription) => subscription.disposed === 1,
        ),
      ),
    );
    assert.equal(state.detailCalls.length, 0);
    assert.equal(
      client.getQueryState(["channels", CHANNEL_A, "detail"]).isInvalidated,
      false,
    );
  } finally {
    ready.resolve();
    harness.close();
  }
});

function joinedChannels(count) {
  return Array.from({ length: count }, (_, index) =>
    fromRawChannelDetail(
      rawChannel(
        `00000000-0000-4000-8000-${String(index).padStart(12, "0")}`,
        "topic",
      ),
    ),
  );
}

test("400 joined channels with AppShell mentions keep metadata REQs within the relay budget", async () => {
  const { act, renderHook, waitFor } = await import("@testing-library/react");
  const channels = joinedChannels(400);
  const subscriptions = [];
  let replacementReady;
  let peakActive = 0;
  const active = () => subscriptions.filter((entry) => !entry.disposed);
  const metadata = () => active().filter((entry) => entry.type === "metadata");
  mock.method(relayClient, "subscribeToReconnects", () => () => {});
  mock.method(
    relayClient,
    "subscribeLive",
    async (filter, onEvent, onReady) => {
      const type = filter.kinds.includes(39000) ? "metadata" : "events";
      const entry = { type, filter, onEvent, disposed: 0 };
      subscriptions.push(entry);
      peakActive = Math.max(peakActive, active().length);
      if (type === "metadata" && replacementReady)
        await replacementReady.promise;
      onReady?.("eose");
      return async () => {
        entry.disposed++;
      };
    },
  );
  mock.method(
    relayClient,
    "subscribeToChannelMentionEvents",
    async (channelId, pubkey, onEvent) => {
      const entry = {
        type: "mentions",
        channelId,
        pubkey,
        onEvent,
        disposed: 0,
      };
      subscriptions.push(entry);
      peakActive = Math.max(peakActive, active().length);
      return async () => {
        entry.disposed++;
      };
    },
  );
  const client = new QueryClient();
  const invalidations = [];
  mock.method(client, "invalidateQueries", async (filter) => {
    if (filter.queryKey.length === 3) invalidations.push(filter);
  });
  const options = { currentPubkey: "a".repeat(64), onLiveMention() {} };
  const view = renderHook(
    ({ joined }) =>
      useLiveChannelUpdates(joined, joined[0]?.id ?? null, options),
    {
      initialProps: { joined: channels },
      wrapper: ({ children }) =>
        React.createElement(QueryClientProvider, { client }, children),
    },
  );
  try {
    await waitFor(() => {
      assert.equal(
        active().filter((entry) => entry.type === "events").length,
        400,
      );
      assert.equal(
        active().filter((entry) => entry.type === "mentions").length,
        400,
      );
    });
    await act(async () => {});
    assert.ok(
      active().length <= 1024,
      `requests ${active().length} subscriptions above the relay cap`,
    );
    assert.equal(active().length, 804);
    assert.equal(
      active().filter((entry) => entry.type === "events").length,
      400,
    );
    assert.equal(
      active().filter((entry) => entry.type === "mentions").length,
      400,
    );
    assert.equal(metadata().length, 4);
    assert.deepEqual(
      metadata().map((entry) => entry.filter["#d"].length),
      [128, 128, 128, 16],
    );
    assert.deepEqual(
      new Set(metadata().flatMap((entry) => entry.filter["#d"])),
      new Set(channels.map((channel) => channel.id)),
    );
    for (const entry of metadata()) {
      assert.deepEqual(entry.filter.kinds, [39000]);
      assert.equal(entry.filter["#h"], undefined);
      assert.equal(entry.filter.limit, 0);
    }
    // Fresh channel objects with the same membership must issue zero new REQs.
    view.rerender({ joined: channels.map((channel) => ({ ...channel })) });
    await act(async () => {});
    assert.equal(subscriptions.length, 804);
    const oldMetadata = [...metadata()];
    const remaining = channels.slice(128);
    replacementReady = deferred();
    view.rerender({ joined: remaining });
    await waitFor(() =>
      assert.equal(
        subscriptions.filter((entry) => entry.type === "metadata").length,
        7,
      ),
    );
    assert.ok(oldMetadata.every((entry) => entry.disposed === 0));
    assert.equal(metadata().length, 7);
    assert.equal(
      active().filter((entry) => entry.type === "events").length,
      remaining.length,
    );
    assert.equal(
      active().filter((entry) => entry.type === "mentions").length,
      remaining.length,
    );
    await act(async () =>
      oldMetadata[0].onEvent(canonicalMetadata(channels[0].id)),
    );
    assert.equal(invalidations.length, 0);
    // The prior generation still covers remaining members while replacements wait.
    await act(async () =>
      oldMetadata[1].onEvent(canonicalMetadata(remaining[0].id)),
    );
    assert.deepEqual(
      invalidations.map((filter) => filter.queryKey),
      [["channels", remaining[0].id, "detail"]],
    );
    // Membership flaps must not open further generations while readiness waits.
    view.rerender({ joined: remaining.slice(1) });
    view.rerender({ joined: remaining });
    await act(async () => {});
    assert.equal(metadata().length, 7);
    await act(async () => replacementReady.resolve());
    await waitFor(() =>
      assert.ok(oldMetadata.every((entry) => entry.disposed === 1)),
    );
    assert.equal(metadata().length, 3);
    assert.deepEqual(
      new Set(metadata().flatMap((entry) => entry.filter["#d"])),
      new Set(remaining.map((channel) => channel.id)),
    );
    const beforeRetired = invalidations.length;
    await act(async () =>
      oldMetadata[1].onEvent(canonicalMetadata(remaining[0].id)),
    );
    assert.equal(invalidations.length, beforeRetired);
    // Removing every member retires both kinds of scoped filters and mentions.
    const latestMetadata = [...metadata()];
    view.rerender({ joined: [] });
    await waitFor(() => assert.equal(active().length, 0));
    await act(async () =>
      latestMetadata[0].onEvent(canonicalMetadata(remaining[0].id)),
    );
    assert.equal(invalidations.length, beforeRetired);
    view.unmount();
    assert.ok(subscriptions.every((entry) => entry.disposed === 1));
    assert.ok(
      peakActive <= 808,
      `peak ${peakActive} exceeds bounded metadata overlap`,
    );
    assert.ok(peakActive <= 1024, "exceeds relay persistent subscription cap");
  } finally {
    replacementReady?.resolve();
    view.unmount();
    client.clear();
  }
});

test("failed metadata generation retires partial chunks and preserves previous coverage", async () => {
  const { act, renderHook, waitFor } = await import("@testing-library/react");
  const channels = joinedChannels(129);
  const metadata = [];
  let failReplacement = false;
  const ready = deferred();
  mock.method(console, "error", () => {});
  mock.method(relayClient, "subscribeToReconnects", () => () => {});
  mock.method(
    relayClient,
    "subscribeLive",
    async (filter, onEvent, onReady) => {
      if (!filter.kinds.includes(39000)) return async () => {};
      const entry = { filter, onEvent, disposed: 0 };
      metadata.push(entry);
      if (failReplacement) {
        if (filter["#d"].length === 128) await ready.promise;
        else throw new Error("replacement metadata admission failed");
      }
      onReady?.("eose");
      return async () => {
        entry.disposed++;
      };
    },
  );
  const client = new QueryClient();
  const invalidations = [];
  mock.method(client, "invalidateQueries", async (filter) => {
    if (filter.queryKey.length === 3) invalidations.push(filter);
  });
  const view = renderHook(({ joined }) => useLiveChannelUpdates(joined, null), {
    initialProps: { joined: channels },
    wrapper: ({ children }) =>
      React.createElement(QueryClientProvider, { client }, children),
  });
  try {
    await waitFor(() => assert.equal(metadata.length, 2));
    await act(async () => {});
    failReplacement = true;
    view.rerender({ joined: [...channels, ...joinedChannels(130).slice(129)] });
    await waitFor(() => assert.equal(metadata.length, 4));
    await act(async () => ready.resolve());
    await waitFor(() => assert.equal(metadata[2].disposed, 1));
    assert.equal(metadata[0].disposed, 0);
    assert.equal(metadata[1].disposed, 0);
    await act(async () =>
      metadata[0].onEvent(canonicalMetadata(channels[0].id)),
    );
    assert.equal(invalidations.length, 1);
    await act(async () =>
      metadata[2].onEvent(canonicalMetadata(channels[0].id)),
    );
    assert.equal(invalidations.length, 1);
  } finally {
    ready.resolve();
    view.unmount();
    client.clear();
  }
});

async function mountProductionMetadataHarness(rejection) {
  const { renderHook, waitFor } = await import("@testing-library/react");
  const channels = joinedChannels(129);
  const metadata = [];
  const server = new Map();
  const invalidations = [];
  let failReplacement = false;
  const client = new QueryClient();
  mock.method(client, "invalidateQueries", async (filter) => {
    if (filter.queryKey.length === 3) invalidations.push(filter);
  });
  mock.method(relayClient, "ensureConnected", async () => 1);
  mock.method(relayClient, "subscribeToReconnects", () => () => {});
  const subscribeSpy = mock.method(relayClient, "subscribeLive");
  // Keep production subscribeLive, readiness, CLOSED policy, recovery timers,
  // event dispatch and disposers. Replace only connection establishment/wire.
  mock.method(relayClient, "sendRawWithReconnectRetry", async (payload) => {
    assert.equal(payload[0], "REQ");
    const [, subId, filter] = payload;
    if (filter.kinds.includes(39000)) {
      const entry = { subId, filter, closed: 0 };
      metadata.push(entry);
      if (failReplacement && filter["#d"].length < 128) {
        if (rejection !== "timeout") {
          await relayClient.handleWsMessage(
            JSON.stringify(["CLOSED", subId, rejection]),
            relayClient.connectionGeneration,
          );
        }
        return;
      }
    }
    server.set(subId, filter);
    await relayClient.handleWsMessage(
      JSON.stringify(["EOSE", subId]),
      relayClient.connectionGeneration,
    );
  });
  mock.method(relayClient, "closeSubscription", async (subId) => {
    server.delete(subId);
    const entry = metadata.find((item) => item.subId === subId);
    if (entry) entry.closed++;
  });
  const view = renderHook(({ joined }) => useLiveChannelUpdates(joined, null), {
    initialProps: { joined: channels },
    wrapper: ({ children }) =>
      React.createElement(QueryClientProvider, { client }, children),
  });
  await waitFor(() => assert.equal(metadata.length, 2));
  const old = metadata.slice();
  const activeMetadata = () =>
    [...server].filter(([, filter]) => filter.kinds.includes(39000));
  const emitCanonical = async (channelId) => {
    for (const [subId, filter] of activeMetadata()) {
      if (filter["#d"].includes(channelId)) {
        await relayClient.handleWsMessage(
          JSON.stringify(["EVENT", subId, canonicalMetadata(channelId)]),
          relayClient.connectionGeneration,
        );
      }
    }
    relayClient.flushEventBuffer();
  };
  return {
    channels,
    view,
    metadata,
    old,
    invalidations,
    activeMetadata,
    emitCanonical,
    waitForDisposers: () =>
      Promise.all(
        subscribeSpy.mock.calls
          .filter((call) => call.arguments[0].kinds.includes(39000))
          .map((call) => call.result),
      ),
    admitPending: async () => {
      const entry = metadata.at(-1);
      server.set(entry.subId, entry.filter);
      await relayClient.handleWsMessage(
        JSON.stringify(["EOSE", entry.subId]),
        relayClient.connectionGeneration,
      );
    },
    beginFailure: () => {
      failReplacement = true;
      view.rerender({ joined: joinedChannels(130) });
    },
    recover: () => {
      failReplacement = false;
    },
    close: () => {
      view.unmount();
      client.clear();
    },
  };
}

for (const rejection of [
  "error: database error",
  "restricted: too many subscriptions",
]) {
  test(`production metadata replacement ${rejection} retains prior coverage until fresh EOSE`, async () => {
    const { act, waitFor } = await import("@testing-library/react");
    const harness = await mountProductionMetadataHarness(rejection);
    try {
      assert.equal(harness.activeMetadata().length, 2);
      harness.beginFailure();
      await waitFor(() => assert.equal(harness.metadata.length, 4));
      // One candidate really reached EOSE; the other fulfilled its disposer
      // promise on production CLOSED.
      await act(async () => harness.waitForDisposers());
      assert.deepEqual(
        harness.old.map((entry) => entry.closed),
        [0, 0],
      );
      await waitFor(() => assert.equal(harness.metadata[2].closed, 1));
      assert.equal(harness.activeMetadata().length, 2);
      assert.ok(
        harness.metadata
          .slice(2)
          .every((entry) => !relayClient.subscriptions.has(entry.subId)),
        "retired candidates must not retain per-subscription retry timers",
      );
      await act(async () => harness.emitCanonical(harness.channels[0].id));
      assert.deepEqual(
        harness.invalidations.map((filter) => filter.queryKey),
        [["channels", harness.channels[0].id, "detail"]],
        "canonical updates remain covered during admission failure",
      );
      harness.recover();
      await waitFor(
        () => assert.ok(harness.old.every((entry) => entry.closed === 1)),
        { timeout: 2000 },
      );
      assert.equal(harness.metadata.length, 6);
      assert.equal(harness.activeMetadata().length, 2);
      assert.ok(
        harness.metadata.slice(4).every((entry) => entry.filter.limit === 0),
      );
      await act(async () => harness.emitCanonical(joinedChannels(130)[129].id));
      assert.equal(harness.invalidations.length, 2);
      // Production dispatch ignores retired subscription IDs after promotion.
      await act(async () => {
        await relayClient.handleWsMessage(
          JSON.stringify([
            "EVENT",
            harness.old[0].subId,
            canonicalMetadata(harness.channels[0].id),
          ]),
          relayClient.connectionGeneration,
        );
        relayClient.flushEventBuffer();
      });
      assert.equal(harness.invalidations.length, 2);
      harness.view.rerender({ joined: [] });
      await waitFor(() => assert.equal(harness.activeMetadata().length, 0));
      assert.equal(relayClient.subscriptions.size, 0);
    } finally {
      harness.close();
    }
  });
}

test("unmount after production CLOSED cancels failed-generation retry and previous chunks", async () => {
  const { waitFor } = await import("@testing-library/react");
  const scheduled = [];
  const cancelled = [];
  const setTimeout = window.setTimeout.bind(window);
  const clearTimeout = window.clearTimeout.bind(window);
  mock.method(window, "setTimeout", (callback, delay, ...args) => {
    const id = setTimeout(callback, delay, ...args);
    scheduled.push({ id, delay });
    return id;
  });
  mock.method(window, "clearTimeout", (id) => {
    cancelled.push(id);
    clearTimeout(id);
  });
  const harness = await mountProductionMetadataHarness("error: database error");
  try {
    harness.beginFailure();
    await waitFor(() => assert.equal(harness.metadata[2]?.closed, 1));
    const retries = scheduled.filter(({ delay }) => delay === 1000);
    assert.equal(
      retries.length,
      2,
      "production CLOSED and hook generation retries both arm",
    );
    harness.close();
    await waitFor(() => assert.equal(relayClient.subscriptions.size, 0));
    assert.deepEqual(
      harness.old.map((entry) => entry.closed),
      [1, 1],
    );
    assert.ok(retries.every(({ id }) => cancelled.includes(id)));
  } finally {
    harness.close();
  }
});

test("production readiness timeout retains previous chunks until late EOSE", async () => {
  const { act, waitFor } = await import("@testing-library/react");
  const harness = await mountProductionMetadataHarness("timeout");
  try {
    harness.beginFailure();
    await waitFor(() => assert.equal(harness.metadata.length, 4));
    // Await the real subscribeLive promises, including its 250 ms fallback.
    // This is disposer availability, not confirmation that the REQ was admitted.
    await act(async () => harness.waitForDisposers());
    assert.deepEqual(
      harness.old.map((entry) => entry.closed),
      [0, 0],
    );
    assert.equal(harness.activeMetadata().length, 3);
    await act(async () => harness.emitCanonical(harness.channels[0].id));
    assert.equal(harness.invalidations.length, 2);
    await act(async () => harness.admitPending());
    await waitFor(() =>
      assert.ok(harness.old.every((entry) => entry.closed === 1)),
    );
    assert.equal(
      harness.metadata.length,
      4,
      "late EOSE admits the original candidates without a fresh generation",
    );
    assert.equal(harness.activeMetadata().length, 2);
    await act(async () => harness.emitCanonical(joinedChannels(130)[129].id));
    assert.equal(harness.invalidations.length, 3);
  } finally {
    harness.close();
  }
});

test("unmount cancels an unknown production admission wait and both metadata generations", async () => {
  const { act, waitFor } = await import("@testing-library/react");
  const harness = await mountProductionMetadataHarness("timeout");
  try {
    harness.beginFailure();
    await waitFor(() => assert.equal(harness.metadata.length, 4));
    await act(async () => harness.waitForDisposers());
    assert.deepEqual(
      harness.old.map((entry) => entry.closed),
      [0, 0],
    );
    harness.close();
    await waitFor(() => assert.equal(relayClient.subscriptions.size, 0));
    assert.ok(harness.metadata.every((entry) => entry.closed === 1));
    await act(async () => harness.admitPending());
    assert.equal(relayClient.subscriptions.size, 0);
    assert.ok(harness.metadata.every((entry) => entry.closed === 1));
  } finally {
    harness.close();
  }
});

test("membership change cancels unknown admission before opening the next metadata generation", async () => {
  const { act, waitFor } = await import("@testing-library/react");
  const harness = await mountProductionMetadataHarness("timeout");
  try {
    harness.beginFailure();
    await waitFor(() => assert.equal(harness.metadata.length, 4));
    await act(async () => harness.waitForDisposers());
    const cancelledGeneration = harness.metadata.slice(2);
    harness.recover();
    harness.view.rerender({ joined: harness.channels });
    await waitFor(() => assert.equal(harness.metadata.length, 6));
    await waitFor(() =>
      assert.ok(harness.old.every((entry) => entry.closed === 1)),
    );
    assert.ok(cancelledGeneration.every((entry) => entry.closed === 1));
    assert.equal(harness.activeMetadata().length, 2);
    assert.deepEqual(
      new Set(harness.activeMetadata().flatMap(([, filter]) => filter["#d"])),
      new Set(harness.channels.map((channel) => channel.id)),
    );
    await act(async () => harness.emitCanonical(harness.channels[0].id));
    assert.equal(harness.invalidations.length, 1);
  } finally {
    harness.close();
  }
});
