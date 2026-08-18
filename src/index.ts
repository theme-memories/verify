import { Hono, type Context, type MiddlewareHandler } from "hono";
import { HTTPException } from "hono/http-exception";
import { bodyLimit } from "hono/body-limit";
import { timeout } from "hono/timeout";
import { validator } from "hono/validator";
import { jwt } from "hono/jwt";
import { secureHeaders } from "hono/secure-headers";
import { methodNotAllowed } from "hono/method-not-allowed";
import argon2 from "argon2";

export const ARGON2_PHC_PREFIX = "$argon2id$";
export const MAX_INPUT_LENGTH = 1024;
export const MAX_TARGET_LENGTH = 512;
const SECRET_MIN_LENGTH = 32;

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is not set`);
  }
  return value;
}

function requireStrongEnv(name: string): string {
  const value = requireEnv(name);
  if (value.length < SECRET_MIN_LENGTH) {
    throw new Error(
      `${name} must be at least ${SECRET_MIN_LENGTH} characters (got ${value.length})`,
    );
  }
  return value;
}

function requireHttpsUrl(name: string): string {
  const value = requireEnv(name);
  try {
    const url = new URL(value);
    if (url.protocol !== "https:") {
      throw new Error();
    }
  } catch {
    throw new Error(`${name} must be a valid HTTPS URL (got "${value}")`);
  }
  return value;
}

export const JWT_ISSUER = requireHttpsUrl("JWT_ISSUER");
export const JWT_AUDIENCE = requireHttpsUrl("JWT_AUDIENCE");

const rawVerifyPath = requireEnv("VERIFY_PATH");
if (
  !rawVerifyPath.startsWith("/") ||
  rawVerifyPath.includes("?") ||
  rawVerifyPath.includes("#") ||
  rawVerifyPath === "/"
) {
  throw new Error(
    `VERIFY_PATH must be a strict path starting with "/" with no query/fragment (got "${rawVerifyPath}")`,
  );
}
export const VERIFY_PATH = rawVerifyPath;

export const JWT_SECRET = requireStrongEnv("JWT_SECRET");
export const ARGON2_SECRET = requireStrongEnv("ARGON2_SECRET");
const JWT_MAX_LIFETIME = 120;
const JWT_CLOCK_SKEW_TOLERANCE = 30;

function invalidInput(c: Context) {
  return c.json({ success: false, errcode: "INVALID_INPUT" }, 400);
}

function verifyFailed(c: Context) {
  return c.json({ success: false, errcode: "VERIFY_FAILED" }, 200);
}

const app = new Hono();

app.use("*", secureHeaders());

const requireJwt: MiddlewareHandler = async (c, next) => {
  await jwt({
    secret: JWT_SECRET,
    alg: "HS256",
    verification: { iss: JWT_ISSUER, aud: JWT_AUDIENCE },
  })(c, next);
};

export class Semaphore {
  private queue: Array<() => void> = [];
  private permits: number;
  private maxQueue: number;
  constructor(permits: number, maxQueue = 50) {
    this.permits = permits;
    this.maxQueue = maxQueue;
  }
  get waiting(): number {
    return this.queue.length;
  }
  tryAcquire(): boolean {
    if (this.permits > 0) {
      this.permits--;
      return true;
    }
    if (this.queue.length >= this.maxQueue) {
      return false;
    }
    this.queue.push(() => {});
    return true;
  }
  acquire(): Promise<void> {
    if (this.permits > 0) {
      this.permits--;
      return Promise.resolve();
    }
    if (this.queue.length >= this.maxQueue) {
      return Promise.reject(new Error("queue full"));
    }
    return new Promise<void>((resolve) => {
      this.queue.push(resolve);
    });
  }
  release(): void {
    const next = this.queue.shift();
    if (next) {
      next();
    } else {
      this.permits++;
    }
  }
}

const argon2Limiter = new Semaphore(2);

const requireExpClaim: MiddlewareHandler = async (c, next) => {
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

app.post(
  VERIFY_PATH,
  requireJwt,
  requireExpClaim,
  (c, next) => {
    c.header("Cache-Control", "no-store");
    return next();
  },
  timeout(10_000),
  bodyLimit({ maxSize: 32 * 1024 }),
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
      !target.startsWith(ARGON2_PHC_PREFIX)
    ) {
      return invalidInput(c);
    }

    return {
      input,
      target,
    };
  }),
  async (c) => {
    const { input, target } = c.req.valid("json");

    let needsRehash: boolean;
    try {
      needsRehash = argon2.needsRehash(target);
    } catch {
      return invalidInput(c);
    }

    if (needsRehash) {
      return verifyFailed(c);
    }

    let success: boolean;
    if (!argon2Limiter.tryAcquire()) {
      return c.json({ success: false, errcode: "TOO_MANY_REQUESTS" }, 429);
    }
    try {
      success = await argon2.verify(target, input, {
        secret: Buffer.from(ARGON2_SECRET, "utf8"),
      });
    } catch {
      return verifyFailed(c);
    } finally {
      argon2Limiter.release();
    }

    return c.json({
      success,
      errcode: success ? null : "VERIFY_FAILED",
    });
  },
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
          404: "NOT_FOUND",
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

export default app;
