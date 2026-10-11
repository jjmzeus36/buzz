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
      mock.method(relayClient, "subscribeLive", async (filter, onEvent) => {
        assert.ok(filter.kinds.includes(40099));
        callbacks.set(filter["#h"][0], onEvent);
        return async () => {};
      });

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
