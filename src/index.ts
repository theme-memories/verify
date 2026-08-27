/**
 * Hono application wiring.
 *
 * This file is intentionally thin: it composes the guards from ./middleware
 * and the route handler that performs the actual argon2 verification. All
 * business logic (config, redis, concurrency, hashing, per-request guards)
 * lives in the sibling modules so each piece can be read and tested in
 * isolation.
 */

import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import { bodyLimit } from "hono/body-limit";
import { timeout } from "hono/timeout";
import { validator } from "hono/validator";
import { secureHeaders } from "hono/secure-headers";
import { methodNotAllowed } from "hono/method-not-allowed";
import argon2 from "argon2";

import {
  MAX_INPUT_LENGTH,
  MAX_TARGET_LENGTH,
  MAX_BODY_BYTES,
  ARGON2_VERIFY_TIMEOUT_MS,
  ARGON2_RELEASE_WATCHDOG_MS,
} from "./constants.js";
import { redisConfig, verifyPath, argon2Secret } from "./config.js";
import { createRedisStore } from "./redis.js";
import { argon2Limiter, EXPECTED_ARGON2 } from "./concurrency.js";
import { ARGON2_PHC_PREFIX, isValidArgon2Phc } from "./argon2.js";
import {
  invalidInput,
  verifyFailed,
  setNoStore,
  requireJwt,
  requireExpClaim,
  requireSubject,
  requireFreshJti,
  auditVerify,
  requireJsonContentType,
  validateContentLength,
} from "./middleware.js";
import { errorCodeForStatus } from "./errors.js";

// Single replay store instance for the whole function.
const replayStore = createRedisStore(redisConfig);

const app = new Hono();

// Defence-in-depth security headers on every response.
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

// The only real endpoint. Middleware order matters:
//   1. authenticate (JWT)                 -> requireJwt
//   2. authorize (exp/iat/subject)        -> requireExpClaim, requireSubject
//   3. stamp no-store + enforce JSON      -> setNoStore, requireJsonContentType
//   4. bound runtime (timeout, size)      -> timeout, validateContentLength, bodyLimit
//   5. validate + replay-check the body   -> validator, requireFreshJti
app.post(
  verifyPath,
  requireJwt,
  requireExpClaim,
  requireSubject,
  setNoStore,
  requireJsonContentType,
  timeout(ARGON2_VERIFY_TIMEOUT_MS),
  validateContentLength,
  bodyLimit({ maxSize: MAX_BODY_BYTES }),
  validator("json", (value, c) => {
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
  }),
  requireFreshJti(replayStore),
  async (c) => {
    const { input, target } = c.req.valid("json" as never) as {
      input: string;
      target: string;
    };

    // Reject hashes whose cost parameters differ from EXPECTED_ARGON2.
    let needsRehash: boolean;
    try {
      needsRehash = argon2.needsRehash(target, EXPECTED_ARGON2);
    } catch {
      return invalidInput(c);
    }

    if (needsRehash) {
      auditVerify(c, false, "VERIFY_FAILED");
      return verifyFailed(c);
    }

    const signal = c.req.raw.signal;
    if (signal.aborted) {
      return c.json({ success: false, errcode: "REQUEST_CANCELLED" }, 408);
    }

    // Acquire a concurrency slot; shed load with 429 when exhausted.
    let success: boolean;
    try {
      await argon2Limiter.acquire();
    } catch {
      return c.json({ success: false, errcode: "TOO_MANY_REQUESTS" }, 429, {
        "Retry-After": "1",
      });
    }

    // Guarantee the semaphore slot is released even if the native call hangs
    // (the watchdog) or the request is aborted mid-verify.
    let released = false;
    const releaseOnce = (): void => {
      if (released) {
        return;
      }
      released = true;
      clearTimeout(watchdog);
      argon2Limiter.release();
    };
    const watchdog = setTimeout(releaseOnce, ARGON2_RELEASE_WATCHDOG_MS);

    try {
      const verifyPromise = argon2.verify(target, input, {
        secret: Buffer.from(argon2Secret, "utf8"),
      });
      void verifyPromise.then(releaseOnce, releaseOnce);

      // Race the verification against request cancellation so we never keep a
      // slot busy for an already-dead client.
      let onAbort: (() => void) | undefined;
      const abortPromise = new Promise<"aborted">((resolve) => {
        onAbort = () => resolve("aborted");
        signal.addEventListener("abort", onAbort, { once: true });
      });

      const result = await Promise.race([verifyPromise, abortPromise]);

      if (onAbort) {
        signal.removeEventListener("abort", onAbort);
      }

      if (result === "aborted") {
        return c.json({ success: false, errcode: "REQUEST_CANCELLED" }, 408);
      }

      success = result;
    } catch (error) {
      console.error(
        JSON.stringify({
          event: "argon2_verify_error",
          name: error instanceof Error ? error.name : "UnknownError",
        }),
      );
      auditVerify(c, false, "INTERNAL_ERROR");
      return c.json({ success: false, errcode: "INTERNAL_ERROR" }, 500);
    }

    auditVerify(c, success, success ? null : "VERIFY_FAILED");
    return c.json({
      success,
      errcode: success ? null : "VERIFY_FAILED",
    });
  },
);

// Everything else (wrong method, unknown path, unhandled error) gets a polite
// JSON envelope with no-store.
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
    const errcode = errorCodeForStatus(err.status);

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

export default app;
