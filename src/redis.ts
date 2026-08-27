import { createClient } from "redis";
import {
  REDIS_CONNECT_TIMEOUT_MS,
  REDIS_RECORD_TIMEOUT_MS,
  REDIS_MAX_RECONNECT_ATTEMPTS,
} from "./constants.js";
import type { RedisConnectionConfig } from "./config.js";

export interface ReplayStore {
  record(jti: string, ttlSeconds: number): Promise<boolean>;
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
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

  let connectionPromise: Promise<void> | null = null;
  async function ensureConnected(): Promise<void> {
    if (client.isOpen) return;
    connectionPromise ??= client
      .connect()
      .then(() => undefined)
      .finally(() => {
        connectionPromise = null;
      });
    await withTimeout(connectionPromise, REDIS_CONNECT_TIMEOUT_MS);
  }

  return {
    async record(jti: string, ttlSeconds: number): Promise<boolean> {
      try {
        const setResult = await withTimeout(
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
        return setResult === "OK";
      } catch (error) {
        client.destroy();
        connectionPromise = null;
        throw error;
      }
    },
  };
}
