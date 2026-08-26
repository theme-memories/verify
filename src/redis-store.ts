// Replay protection store backed by Redis.
//
// The store records a token's `jti` with `SET key 1 NX EX <ttl>` so that the
// FIRST sighting of a jti succeeds and any later reuse is rejected (replay).
// `record()` returns `true` only for the first sighting.
//
// Design points:
// - Connections are opened lazily and shared (a single client per store).
// - All Redis work is wrapped in `withTimeout` so a slow/hung Redis cannot
//   block the request thread indefinitely.
// - The store is FAIL-CLOSED: if Redis is unavailable the caller (auth
//   middleware) refuses the request rather than skipping the replay check.

import { createClient } from "redis";
import type { ReplayStore, RedisConnectionConfig } from "./types.js";
import {
  REDIS_CONNECT_TIMEOUT_MS,
  REDIS_MAX_RECONNECT_ATTEMPTS,
  REDIS_RECORD_TIMEOUT_MS,
} from "./config.js";

export function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`redis command timed out after ${ms}ms`)),
      ms,
    );
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error instanceof Error ? error : new Error(String(error)));
      },
    );
  });
}

export function createRedisStore(config: RedisConnectionConfig): ReplayStore {
  const client = createClient({
    socket: {
      host: config.host,
      port: config.port,
      tls: false,
      connectTimeout: REDIS_CONNECT_TIMEOUT_MS,
      reconnectStrategy: (retries) => {
        if (retries >= REDIS_MAX_RECONNECT_ATTEMPTS) return false;
        return Math.min(100 * 2 ** retries, 1_000);
      },
    },
    username: "default",
    password: config.password,
  });
  client.on("error", (error) => {
    console.error(
      JSON.stringify({
        event: "replay_store_error",
        name: error instanceof Error ? error.name : "UnknownError",
      }),
    );
  });

  let connecting: Promise<void> | null = null;
  async function ensureConnected(): Promise<void> {
    if (client.isOpen) return;
    connecting ??= client
      .connect()
      .then(() => undefined)
      .finally(() => {
        connecting = null;
      });
    await withTimeout(connecting, REDIS_CONNECT_TIMEOUT_MS);
  }

  return {
    async record(jti: string, ttlSeconds: number): Promise<boolean> {
      // `true` => key was set (first sighting); `false`/`null` => already seen.
      try {
        const result = await withTimeout(
          (async () => {
            await ensureConnected();
            return client.set(`jti:${jti}`, "1", {
              condition: "NX",
              expiration: {
                type: "EX",
                value: Math.max(1, Math.ceil(ttlSeconds)),
              },
            });
          })(),
          REDIS_RECORD_TIMEOUT_MS,
        );
        return result === "OK";
      } catch (error) {
        client.destroy();
        connecting = null;
        throw error;
      }
    },
  };
}
