import {
  MAX_EXPLICIT_CHANNEL_VALUES,
  type LiveSubscriptionReadiness,
  type RelaySubscriptionFilter,
} from "@/shared/api/relayClientShared";
import type { RelayEvent } from "@/shared/api/types";

type Dispose = () => Promise<void>;
type Chunk = {
  ids: string[];
  retire: Dispose;
};
type Subscribe = (
  filter: RelaySubscriptionFilter,
  onEvent: (event: RelayEvent) => void,
  onReady: (readiness: LiveSubscriptionReadiness) => void,
) => Promise<Dispose>;

/** Keeps admitted coverage while opening at most one replacement chunk. */
export function createChannelMetadataSubscriptions(
  subscribe: Subscribe,
  onEvent: (event: RelayEvent, ids: ReadonlySet<string>) => void,
) {
  const chunks: Chunk[] = [];
  let cancelPending: (() => void) | undefined;

  const replace = async (
    previous: Chunk | undefined,
    ids: string[],
    cancelled: () => boolean,
  ): Promise<boolean> => {
    if (cancelled()) return false;
    if (ids.length === 0) {
      if (previous) {
        chunks.splice(chunks.indexOf(previous), 1);
        await previous.retire();
      }
      return true;
    }
    let retired = false;
    let unsubscribe: Dispose | undefined;
    let resolveAdmission = (_admitted: boolean) => {};
    const admission = new Promise<boolean>((resolve) => {
      resolveAdmission = resolve;
    });
    let retirement: Promise<void> | undefined;
    const retire = () => {
      retired = true;
      resolveAdmission(false);
      if (!retirement && unsubscribe) {
        const dispose = unsubscribe;
        unsubscribe = undefined;
        // Cancellation and the awaiting sync must join the same CLOSE. Clearing
        // the disposer alone would let the next candidate overtake its cleanup.
        retirement = Promise.allSettled([dispose()]).then(() => {});
      }
      return retirement ?? Promise.resolve();
    };
    const cancel = () => {
      void retire();
    };
    cancelPending = cancel;
    try {
      const subscribedIds = new Set(ids);
      unsubscribe = await subscribe(
        { kinds: [39000], "#d": ids, limit: 0 },
        (event) => {
          if (!retired) onEvent(event, subscribedIds);
        },
        (readiness) => {
          if (readiness === "eose") resolveAdmission(true);
          if (readiness === "closed") resolveAdmission(false);
        },
      );
      // The client's fallback returns a disposer, but does not prove admission.
      const admitted = await admission;
      if (retired || cancelled() || !admitted) {
        await retire();
        return false;
      }
      // Once committed, this chunk belongs to the manager, not the pending
      // effect. Cancelling that effect must not retire its admitted coverage.
      if (cancelPending === cancel) cancelPending = undefined;
      const next = { ids, retire };
      if (previous) {
        chunks[chunks.indexOf(previous)] = next;
        await previous.retire();
      } else {
        chunks.push(next);
      }
      return true;
    } catch (error) {
      await retire();
      console.error("Failed to subscribe to channel metadata", error);
      return false;
    } finally {
      if (cancelPending === cancel) cancelPending = undefined;
    }
  };

  return {
    cancelPending: () => cancelPending?.(),
    dispose: async () => {
      cancelPending?.();
      await Promise.allSettled(chunks.splice(0).map((chunk) => chunk.retire()));
    },
    sync: async (ids: readonly string[], cancelled: () => boolean) => {
      const target = new Set(ids);
      const seen = new Set<string>();
      // Keep surviving assignments stable. Dedupe also finishes a donor shrink
      // if its recipient was admitted before an earlier attempt was cancelled.
      for (const chunk of [...chunks]) {
        if (cancelled()) return false;
        const retained = chunk.ids.filter((id) => {
          if (!target.has(id) || seen.has(id)) return false;
          seen.add(id);
          return true;
        });
        if (retained.length !== chunk.ids.length) {
          if (!(await replace(chunk, retained, cancelled))) return false;
        }
      }

      // Pack sparse chunks without a coverage gap: admit the recipient before
      // shrinking its donor. Each swap has only one extra live subscription.
      for (let index = 0; index < chunks.length; index++) {
        while (
          !cancelled() &&
          index < chunks.length - 1 &&
          chunks[index].ids.length < MAX_EXPLICIT_CHANNEL_VALUES
        ) {
          const recipient = chunks[index];
          const donor = chunks[chunks.length - 1];
          const moved = donor.ids.slice(
            0,
            MAX_EXPLICIT_CHANNEL_VALUES - recipient.ids.length,
          );
          if (
            !(await replace(recipient, [...recipient.ids, ...moved], cancelled))
          )
            return false;
          if (!(await replace(donor, donor.ids.slice(moved.length), cancelled)))
            return false;
        }
      }

      const additions = ids.filter((id) => !seen.has(id));
      for (const chunk of [...chunks]) {
        const room = MAX_EXPLICIT_CHANNEL_VALUES - chunk.ids.length;
        if (room === 0 || additions.length === 0) continue;
        const added = additions.splice(0, room);
        if (!(await replace(chunk, [...chunk.ids, ...added], cancelled)))
          return false;
      }
      while (additions.length > 0) {
        if (
          !(await replace(
            undefined,
            additions.splice(0, MAX_EXPLICIT_CHANNEL_VALUES),
            cancelled,
          ))
        )
          return false;
      }
      return !cancelled();
    },
  };
}
