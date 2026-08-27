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

export function invalidInput(c: Context): Response {
  return c.json({ success: false, errcode: "INVALID_INPUT" }, 400) as Response;
}

export function verifyFailed(c: Context) {
  return c.json({ success: false, errcode: "VERIFY_FAILED" }, 200);
}

export const setNoStore: MiddlewareHandler = async (c, next) => {
  c.header("Cache-Control", "no-store");
  await next();
};

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

const JTI_PATTERN = /^[A-Za-z0-9_-]{8,64}$/;

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

export function auditVerify(
  c: Context,
  success: boolean,
  errcode: string | null,
) {
  const sub =
    (c.get("jwtPayload") as { sub?: string } | undefined)?.sub ?? "unknown";
  console.info(JSON.stringify({ event: "verify", sub, success, errcode }));
}

export const requireJsonContentType: MiddlewareHandler = async (c, next) => {
  const contentType = (c.req.header("Content-Type") ?? "")
    .split(";", 1)[0]
    .trim()
    .toLowerCase();
  if (contentType !== "application/json") return invalidInput(c);
  await next();
};

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
