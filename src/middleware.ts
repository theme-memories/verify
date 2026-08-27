/**
 * Hono middleware pipeline. Each export is a small, single-purpose guard that
 * runs (in order) before the verify handler in index.ts. The replay check
 * (`requireFreshJti`) is a factory: it takes the ReplayStore so the store can
 * be created once at startup and injected here.
 */

import { type Context, type MiddlewareHandler } from "hono";
import { HTTPException } from "hono/http-exception";
import { jwt } from "hono/jwt";
import { jwtSecret, jwtIssuer, jwtAudience } from "./config.js";
import {
  MAX_AUTHORIZATION_LENGTH,
  MAX_BODY_BYTES,
  JWT_MAX_LIFETIME,
  JWT_CLOCK_SKEW_TOLERANCE,
} from "./constants.js";
import type { ReplayStore } from "./redis.js";

// 400 with a stable machine-readable error code.
export function invalidInput(c: Context): Response {
  return c.json({ success: false, errcode: "INVALID_INPUT" }, 400) as Response;
}

// Password-verify failures deliberately return 200 so callers cannot
// distinguish "wrong password" from "bad hash" (avoid oracle side channels).
export function verifyFailed(c: Context) {
  return c.json({ success: false, errcode: "VERIFY_FAILED" }, 200);
}

// Stamp every response on this route as non-cacheable.
export const setNoStore: MiddlewareHandler = async (c, next) => {
  c.header("Cache-Control", "no-store");
  await next();
};

// Validates the Bearer JWT signature + issuer + audience, and enforces HS256
// only (the hono/jwt middleware honours the `alg` we pass). Oversized
// Authorization headers are rejected before parsing to avoid abuse.
export const requireJwt: MiddlewareHandler = async (c, next) => {
  const authorization = c.req.header("Authorization");
  if (authorization && authorization.length > MAX_AUTHORIZATION_LENGTH) {
    throw new HTTPException(401, {
      message: "authorization header is too long",
      res: new Response(null, {
        status: 401,
        headers: {
          "WWW-Authenticate": 'Bearer realm="verify", error="invalid_request"',
        },
      }),
    });
  }

  await jwt({
    secret: jwtSecret,
    alg: "HS256",
    verification: { iss: jwtIssuer, aud: jwtAudience, iat: false },
  })(c, next);
};

// Enforces token lifetime bounds: not expired, has `iat`, not issued in the
// future beyond skew, exp > iat, and total lifetime <= JWT_MAX_LIFETIME.
export const requireExpClaim: MiddlewareHandler = async (c, next) => {
  const payload = c.get("jwtPayload") as
    { exp?: number; iat?: number } | undefined;

  const now = Math.floor(Date.now() / 1000);

  if (!Number.isSafeInteger(payload?.exp) || payload!.exp! <= now) {
    throw new HTTPException(401, { message: "token has expired" });
  }

  if (!Number.isSafeInteger(payload?.iat)) {
    throw new HTTPException(401, { message: "iat claim is required" });
  }

  const iat = payload!.iat!;

  if (iat > now + JWT_CLOCK_SKEW_TOLERANCE) {
    throw new HTTPException(401, { message: "token issued in the future" });
  }

  if (payload!.exp! <= iat) {
    throw new HTTPException(401, { message: "token exp must be after iat" });
  }

  if (payload!.exp! - iat > JWT_MAX_LIFETIME) {
    throw new HTTPException(401, {
      message: `token lifetime exceeds maximum of ${JWT_MAX_LIFETIME}s`,
    });
  }

  await next();
};

// `sub` identifies the calling worker; keep it to a tight, safe character set.
export const requireSubject: MiddlewareHandler = async (c, next) => {
  const payload = c.get("jwtPayload") as { sub?: unknown } | undefined;
  if (
    typeof payload?.sub !== "string" ||
    !/^[A-Za-z0-9_-]{1,128}$/.test(payload.sub)
  ) {
    throw new HTTPException(403, { message: "token subject is invalid" });
  }
  await next();
};

// Only accepts 8-64 char, base64-ish jti values (sha-style UUIDs qualify).
const JTI_PATTERN = /^[A-Za-z0-9_-]{8,64}$/;

// Replay protection: records the jti in Redis (NX). First sighting proceeds;
// a repeat hits REPLAY_DETECTED; any store error fails closed with 503.
export function requireFreshJti(replayStore: ReplayStore): MiddlewareHandler {
  return async (c, next) => {
    const payload = c.get("jwtPayload") as
      { jti?: unknown; exp?: number } | undefined;
    const now = Math.floor(Date.now() / 1000);
    const { jti, exp } = payload ?? {};

    if (
      typeof jti !== "string" ||
      !JTI_PATTERN.test(jti) ||
      typeof exp !== "number" ||
      !Number.isSafeInteger(exp)
    ) {
      auditVerify(c, false, "REPLAY_CHECK_FAILED");
      return c.json({ success: false, errcode: "UNAUTHORIZED" }, 401);
    }

    // Keep the Redis key alive for the remainder of the token's validity
    // (plus skew), so replays are blocked until the token would expire anyway.
    const ttlSeconds = Math.min(
      exp + JWT_CLOCK_SKEW_TOLERANCE - now,
      JWT_MAX_LIFETIME + JWT_CLOCK_SKEW_TOLERANCE,
    );

    let isFirstSighting: boolean;
    try {
      isFirstSighting = await replayStore.record(jti, ttlSeconds);
    } catch {
      console.error(
        JSON.stringify({
          event: "replay_store_unavailable",
          action: "fail_closed",
        }),
      );
      auditVerify(c, false, "STORE_UNAVAILABLE");
      return c.json(
        { success: false, errcode: "SERVICE_UNAVAILABLE" },
        503,
      ) as Response;
    }

    if (!isFirstSighting) {
      auditVerify(c, false, "REPLAY_DETECTED");
      return c.json({ success: false, errcode: "REPLAY_DETECTED" }, 401);
    }

    await next();
  };
}

// Structured audit line emitted for every verify outcome.
export function auditVerify(
  c: Context,
  success: boolean,
  errcode: string | null,
) {
  const sub =
    (c.get("jwtPayload") as { sub?: string } | undefined)?.sub ?? "unknown";
  console.info(JSON.stringify({ event: "verify", sub, success, errcode }));
}

// Reject anything that isn't exactly application/json (ignoring parameters).
export const requireJsonContentType: MiddlewareHandler = async (c, next) => {
  const contentType = (c.req.header("Content-Type") ?? "")
    .split(";", 1)[0]
    .trim()
    .toLowerCase();
  if (contentType !== "application/json") return invalidInput(c);
  await next();
};

// Pre-flight the declared Content-Length so we reject oversized payloads
// before streaming the body in.
export const validateContentLength: MiddlewareHandler = async (c, next) => {
  const rawLength = c.req.header("Content-Length");
  if (rawLength !== undefined) {
    if (!/^(0|[1-9]\d*)$/.test(rawLength)) return invalidInput(c);
    const length = Number(rawLength);
    if (!Number.isSafeInteger(length) || length > MAX_BODY_BYTES) {
      return c.json(
        { success: false, errcode: "PAYLOAD_TOO_LARGE" },
        413,
      ) as Response;
    }
  }
  await next();
};
