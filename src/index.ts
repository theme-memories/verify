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
export const MAX_TARGET_LENGTH = 128;
const MAX_BODY_BYTES = 32 * 1024;
const MAX_AUTHORIZATION_LENGTH = 4096;
const SECRET_MIN_LENGTH = 32;
const VERIFY_PATH_PATTERN = /^\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/;

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is not set`);
  }
  return value;
}

function requireStrongEnv(name: string): string {
  const value = requireEnv(name);
  if (Buffer.byteLength(value, "utf8") < SECRET_MIN_LENGTH) {
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
if (!VERIFY_PATH_PATTERN.test(rawVerifyPath) || rawVerifyPath.length > 256) {
  throw new Error(
    `VERIFY_PATH must be a literal path containing only letters, numbers, "_", "-", and "/" (got "${rawVerifyPath}")`,
  );
}
export const VERIFY_PATH = rawVerifyPath;

const JWT_SECRET = requireStrongEnv("JWT_SECRET");
const ARGON2_SECRET = requireStrongEnv("ARGON2_SECRET");
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
    secret: JWT_SECRET,
    alg: "HS256",
    // Hono's default iat check rejects any future timestamp. The custom check
    // below intentionally allows a small clock-skew window.
    verification: { iss: JWT_ISSUER, aud: JWT_AUDIENCE, iat: false },
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
    return false;
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

const requireSubject: MiddlewareHandler = async (c, next) => {
  const payload = c.get("jwtPayload") as { sub?: unknown } | undefined;
  if (
    typeof payload?.sub !== "string" ||
    !/^[A-Za-z0-9_-]{1,128}$/.test(payload.sub)
  ) {
    throw new HTTPException(403, { message: "token subject is invalid" });
  }
  await next();
};

const requireJsonContentType: MiddlewareHandler = async (c, next) => {
  const contentType = (c.req.header("Content-Type") ?? "")
    .split(";", 1)[0]
    .trim()
    .toLowerCase();
  if (contentType !== "application/json") return invalidInput(c);
  await next();
};

const validateContentLength: MiddlewareHandler = async (c, next) => {
  const rawLength = c.req.header("Content-Length");
  if (rawLength !== undefined) {
    if (!/^(0|[1-9]\d*)$/.test(rawLength)) return invalidInput(c);
    const length = Number(rawLength);
    if (!Number.isSafeInteger(length) || length > MAX_BODY_BYTES) {
      return c.json({ success: false, errcode: "PAYLOAD_TOO_LARGE" }, 413);
    }
  }
  await next();
};

function isCanonicalBase64(value: string): boolean {
  if (!/^[A-Za-z0-9+/]+$/.test(value)) return false;
  const decoded = Buffer.from(value, "base64");
  return decoded.toString("base64").replace(/=+$/, "") === value;
}

function isValidArgon2Phc(target: string): boolean {
  const parts = target.split("$");
  if (parts.length !== 6) return false;

  const [, algorithm, version, rawParams, salt, digest] = parts;
  if (algorithm !== "argon2id" || !/^v=\d+$/.test(version)) return false;
  if (!isCanonicalBase64(salt) || !isCanonicalBase64(digest)) return false;

  const params = new Map<string, string>();
  for (const rawParam of rawParams.split(",")) {
    const match = /^(m|t|p)=(\d+)$/.exec(rawParam);
    if (!match || params.has(match[1])) return false;
    params.set(match[1], match[2]);
  }
  return params.size === 3;
}

app.post(
  VERIFY_PATH,
  requireJwt,
  requireExpClaim,
  requireSubject,
  (c, next) => {
    c.header("Cache-Control", "no-store");
    return next();
  },
  timeout(10_000),
  requireJsonContentType,
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

    const signal = c.req.raw.signal;
    if (signal.aborted) {
      return c.json({ success: false, errcode: "REQUEST_CANCELLED" }, 408);
    }

    let success: boolean;
    if (!argon2Limiter.tryAcquire()) {
      return c.json({ success: false, errcode: "TOO_MANY_REQUESTS" }, 429, {
        "Retry-After": "1",
      });
    }
    try {
      const verifyPromise = argon2.verify(target, input, {
        secret: Buffer.from(ARGON2_SECRET, "utf8"),
      });

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
      return c.json({ success: false, errcode: "INTERNAL_ERROR" }, 500);
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

export default app;
