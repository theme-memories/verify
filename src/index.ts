// Service bootstrap (Vercel function entry point).
//
// Responsibilities at import time:
//   1. Load & validate configuration from `process.env` (throws on misconfig).
//   2. Construct the singleton replay store and Argon2 concurrency limiter.
//   3. Build the Hono app via `buildApp`.
//
// The Hono `app` instance itself is NOT a valid Vercel entry: Vercel's Node
// runtime requires the default export to be a callable handler (function or
// server). We wrap it with `hono/vercel`'s `handle()` so `export default`
// becomes a request handler. The raw `app` is also exported as a NAMED export
// so the test suite (which calls `app.request(...)`) keeps working.
//
// Note: configuration is read once at cold-start. Values required by tests are
// also re-exported (e.g. JWT_ISSUER, ARGON2_PHC_PREFIX, EXPECTED_ARGON2,
// Semaphore, loadConfig) so the test suite and consumers can import them.

import {
  ARGON2_LIMITER_MAX_QUEUE,
  ARGON2_LIMITER_PERMITS,
  ARGON2_PHC_PREFIX,
  loadConfig,
} from "./config.js";
import { createRedisStore } from "./redis-store.js";
import { Semaphore } from "./semaphore.js";
import { EXPECTED_ARGON2 } from "./phc.js";
import { buildApp } from "./app.js";
import { handle } from "hono/vercel";
import type { AppConfig } from "./types.js";

let config: AppConfig;
try {
  config = loadConfig(process.env);
} catch (error) {
  console.error(
    JSON.stringify({
      event: "config_error",
      reason: error instanceof Error ? error.message : "unknown",
    }),
  );
  throw error;
}

export const JWT_ISSUER = config.jwtIssuer;
export const JWT_AUDIENCE = config.jwtAudience;
export const VERIFY_PATH = config.verifyPath;
export { ARGON2_PHC_PREFIX, EXPECTED_ARGON2, Semaphore, loadConfig };

export const argon2Limiter = new Semaphore(
  ARGON2_LIMITER_PERMITS,
  ARGON2_LIMITER_MAX_QUEUE,
);

export const replayStore = createRedisStore(config.redis);

console.info(
  JSON.stringify({
    event: "config_loaded",
    replay_protection: true,
  }),
);

const app = buildApp(config, { replayStore, argon2Limiter });

// Named export: used by the test suite (app.request(...)).
export { app };
// Default export: the Vercel-compatible handler (a function, not the Hono instance).
export default handle(app);
