// Authentication & authorization middleware factories for the verify route.
//
// Each export is a factory that closes over its dependencies (secrets, the
// replay store, etc.) and returns a Hono `MiddlewareHandler`. This keeps the
// auth logic pure and unit-testable without module-level global state.
//
// Middleware chain order (wired in app.ts):
//   createRequireJwt -> createRequireExpClaim -> createRequireSubject
//                     -> createRequireFreshJti (replay check)

import { HTTPException } from "hono/http-exception";
import { jwt } from "hono/jwt";
import type { MiddlewareHandler } from "hono";
import type { ReplayStore } from "../types.js";
import {
  JWT_CLOCK_SKEW_TOLERANCE,
  JWT_MAX_LIFETIME,
  MAX_AUTHORIZATION_LENGTH,
} from "../config.js";
import { auditVerify } from "../audit.js";

interface JwtDeps {
  jwtSecret: string;
  jwtIssuer: string;
  jwtAudience: string;
}

export function createRequireJwt({
  jwtSecret,
  jwtIssuer,
  jwtAudience,
}: JwtDeps): MiddlewareHandler {
  return async (c, next) => {
    const authorization = c.req.header("Authorization");
    if (authorization && authorization.length > MAX_AUTHORIZATION_LENGTH) {
      throw new HTTPException(401, {
        message: "authorization header is too long",
        res: new Response(null, {
          status: 401,
          headers: {
            "WWW-Authenticate":
              'Bearer realm="verify", error="invalid_request"',
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
}

export function createRequireExpClaim(): MiddlewareHandler {
  return async (c, next) => {
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
}

export function createRequireSubject(): MiddlewareHandler {
  return async (c, next) => {
    const payload = c.get("jwtPayload") as { sub?: unknown } | undefined;
    if (
      typeof payload?.sub !== "string" ||
      !/^[A-Za-z0-9_-]{1,128}$/.test(payload.sub)
    ) {
      throw new HTTPException(403, { message: "token subject is invalid" });
    }
    await next();
  };
}

const JTI_PATTERN = /^[A-Za-z0-9_-]{8,64}$/;

interface FreshJtiDeps {
  replayStore: ReplayStore;
}

export function createRequireFreshJti({
  replayStore,
}: FreshJtiDeps): MiddlewareHandler {
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

    const ttlSeconds = Math.min(
      exp + JWT_CLOCK_SKEW_TOLERANCE - now,
      JWT_MAX_LIFETIME + JWT_CLOCK_SKEW_TOLERANCE,
    );

    let firstSighting: boolean;
    try {
      firstSighting = await replayStore.record(jti, ttlSeconds);
    } catch {
      // Redis failed: fail CLOSED (refuse the request) rather than skip replay
      // protection. Surfaced to the client as 503 SERVICE_UNAVAILABLE.
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

    if (!firstSighting) {
      auditVerify(c, false, "REPLAY_DETECTED");
      return c.json({ success: false, errcode: "REPLAY_DETECTED" }, 401);
    }

    await next();
  };
}
