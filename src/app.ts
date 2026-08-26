// Application composition: builds the Hono app from config + dependencies.
//
// This module owns no global state. `buildApp(config, deps)` wires:
//   - global security headers (secureHeaders)
//   - the verify route with its ordered middleware chain
//   - 405 / 404 / error handlers (all returning the JSON envelope)
//
// The middleware order on the POST route matters:
//   1. auth (jwt, exp, subject, replay) short-circuits unauthorized callers
//   2. request guards (content-type, timeout, content-length, body size)
//   3. body validation (shape + Argon2 PHC format)
//   4. replay-checked handler that performs the actual verification
// Validation middlewares may RETURN a Response to short-circuit the chain
// (Hono supports a validator callback returning a Response).

import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import { bodyLimit } from "hono/body-limit";
import { timeout } from "hono/timeout";
import { validator } from "hono/validator";
import { secureHeaders } from "hono/secure-headers";
import { methodNotAllowed } from "hono/method-not-allowed";
import { handle } from "hono/vercel";
import type { MiddlewareHandler } from "hono";
import type { AppConfig, ReplayStore } from "./types.js";
import {
  ARGON2_LIMITER_MAX_QUEUE,
  ARGON2_LIMITER_PERMITS,
  loadConfig,
} from "./config.js";
import { createRedisStore } from "./redis-store.js";
import { Semaphore } from "./semaphore.js";
import { EXPECTED_ARGON2 } from "./phc.js";
import {
  ARGON2_PHC_PREFIX,
  MAX_BODY_BYTES,
  MAX_INPUT_LENGTH,
  MAX_TARGET_LENGTH,
} from "./config.js";
import { isValidArgon2Phc } from "./phc.js";
import { invalidInput } from "./responses.js";
import {
  createRequireFreshJti,
  createRequireExpClaim,
  createRequireJwt,
  createRequireSubject,
} from "./middleware/auth.js";
import {
  requireJsonContentType,
  validateContentLength,
} from "./middleware/request.js";
import { createVerifyHandler } from "./verify-handler.js";

export interface BuildAppDeps {
  replayStore: ReplayStore;
  argon2Limiter: Semaphore;
}

export function buildApp(config: AppConfig, deps: BuildAppDeps): Hono {
  const app = new Hono();

  app.use(
    "*",
    secureHeaders({
      xFrameOptions: "DENY",
      contentSecurityPolicy: {
        defaultSrc: ["'none'"],
        frameAncestors: ["'none'"],
      },
      permissionsPolicy: {
        accelerometer: [],
        camera: [],
        geolocation: [],
        gyroscope: [],
        magnetometer: [],
        microphone: [],
        payment: [],
        usb: [],
      },
    }),
  );

  // Body validator. Returning a Response here short-circuits the chain with
  // that response (Hono behavior), so invalid input never reaches Argon2.
  const validateBody: MiddlewareHandler = validator("json", (value, c) => {
    if (
      typeof value !== "object" ||
      value === null ||
      typeof (value as { input?: unknown }).input !== "string" ||
      typeof (value as { target?: unknown }).target !== "string"
    ) {
      return invalidInput(c);
    }

    const input = value.input as string;
    const target = value.target as string;

    if (
      input.length === 0 ||
      target.length === 0 ||
      input.length > MAX_INPUT_LENGTH ||
      target.length > MAX_TARGET_LENGTH ||
      !target.startsWith(ARGON2_PHC_PREFIX) ||
      !isValidArgon2Phc(target)
    ) {
      return invalidInput(c);
    }

    return {
      input,
      target,
    };
  });

  app.post(
    config.verifyPath,
    createRequireJwt({
      jwtSecret: config.jwtSecret,
      jwtIssuer: config.jwtIssuer,
      jwtAudience: config.jwtAudience,
    }),
    createRequireExpClaim(),
    createRequireSubject(),
    (c, next) => {
      c.header("Cache-Control", "no-store");
      return next();
    },
    requireJsonContentType,
    timeout(10_000),
    validateContentLength,
    bodyLimit({ maxSize: MAX_BODY_BYTES }),
    validateBody,
    createRequireFreshJti({ replayStore: deps.replayStore }),
    createVerifyHandler({
      argon2Secret: config.argon2Secret,
      argon2Limiter: deps.argon2Limiter,
    }),
  );

  app.use(
    methodNotAllowed({
      app,
      onMethodNotAllowed: (c, methods) =>
        c.json({ success: false, errcode: "METHOD_NOT_ALLOWED" }, 405, {
          Allow: methods.join(", "),
          "Cache-Control": "no-store",
        }),
    }),
  );

  app.notFound((c) =>
    c.json({ success: false, errcode: "NOT_FOUND" }, 404, {
      "Cache-Control": "no-store",
    }),
  );

  app.onError((err, c) => {
    c.header("Cache-Control", "no-store");

    if (err instanceof HTTPException) {
      const errcode =
        (
          {
            400: "INVALID_REQUEST",
            401: "UNAUTHORIZED",
            403: "FORBIDDEN",
            404: "NOT_FOUND",
            408: "REQUEST_CANCELLED",
            413: "PAYLOAD_TOO_LARGE",
            429: "TOO_MANY_REQUESTS",
            504: "TIMEOUT",
          } as Record<number, string>
        )[err.status] ?? "REQUEST_FAILED";

      const headers: Record<string, string> = {};
      const auth = err.res?.headers.get("WWW-Authenticate");
      if (auth) {
        headers["WWW-Authenticate"] = auth;
      }

      return c.json({ success: false, errcode }, err.status, headers);
    }

    console.error(
      JSON.stringify({
        event: "request_error",
        name: err.name,
        status: err instanceof HTTPException ? err.status : 500,
      }),
    );
    return c.json({ success: false, errcode: "INTERNAL_ERROR" }, 500);
  });

  return app;
}

// ---------------------------------------------------------------------------
// Service bootstrap (Vercel function entry point).
//
// Responsibilities at import time:
//   1. Load & validate configuration from `process.env` (throws on misconfig).
//   2. Construct the singleton replay store and Argon2 concurrency limiter.
//   3. Build the Hono app via `buildApp`.
//
// A Hono `app` instance is NOT a valid Vercel entry: Vercel's Node runtime
// requires the default export to be a callable handler (function or server).
// We wrap it with `hono/vercel`'s `handle()` so `export default` becomes a
// request handler. The raw `app` is also exported as a NAMED export so the test
// suite (which calls `app.request(...)`) keeps working.
//
// Note: configuration is read once at cold-start. The values required by the
// test suite are re-exported below so consumers/tests can import them from this
// module (or from `./index.js`, which re-exports them).
// ---------------------------------------------------------------------------

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
