import { Hono, type Context, type MiddlewareHandler } from "hono";
import { HTTPException } from "hono/http-exception";
import { bodyLimit } from "hono/body-limit";
import { timeout } from "hono/timeout";
import { validator } from "hono/validator";
import { jwt } from "hono/jwt";
import { secureHeaders } from "hono/secure-headers";
import { methodNotAllowed } from "hono/method-not-allowed";
import argon2 from "argon2";
import { createClient } from "redis";

export const ARGON2_PHC_PREFIX = "$argon2id$";
export const MAX_INPUT_LENGTH = 1024;
export const MAX_TARGET_LENGTH = 128;
const MAX_BODY_BYTES = 32 * 1024;
const MAX_AUTHORIZATION_LENGTH = 4096;
const SECRET_MIN_LENGTH = 32;
const VERIFY_PATH_PATTERN = /^\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/;
const VERIFY_PATH_MAX_LENGTH = 256;
const ARGON2_RELEASE_WATCHDOG_MS = 15_000;
const REDIS_CONNECT_TIMEOUT_MS = 3_000;
const REDIS_RECORD_TIMEOUT_MS = 3_000;

type EnvSource = Record<string, string | undefined>;

export interface ReplayStore {
  record(jti: string, ttlSeconds: number): Promise<boolean>;
}

export interface RedisConnectionConfig {
  host: string;
  port: number;
  password: string;
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
      reconnectStrategy: (retries) =>
        Math.min(retries * 100, REDIS_CONNECT_TIMEOUT_MS),
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
    },
  };
}

export interface AppConfig {
  jwtIssuer: string;
  jwtAudience: string;
  verifyPath: string;
  jwtSecret: string;
  argon2Secret: string;
  redis: RedisConnectionConfig;
}

function requireEnv(env: EnvSource, name: string): string {
  const raw = env[name];
  if (!raw) {
    throw new Error(`${name} is not set`);
  }
  const value = raw.trim();
  if (value.length === 0) {
    throw new Error(`${name} is not set`);
  }
  return value;
}

function requireStrongEnv(env: EnvSource, name: string): string {
  const value = requireEnv(env, name);
  if (Buffer.byteLength(value, "utf8") < SECRET_MIN_LENGTH) {
    throw new Error(`${name} must be at least ${SECRET_MIN_LENGTH} bytes long`);
  }
  return value;
}

function requireHttpsUrl(env: EnvSource, name: string): string {
  const value = requireEnv(env, name);
  try {
    if (new URL(value).protocol !== "https:") {
      throw new Error();
    }
  } catch {
    throw new Error(`${name} must be a valid HTTPS URL`);
  }
  return value;
}

export function loadConfig(env: EnvSource): AppConfig {
  const jwtIssuer = requireHttpsUrl(env, "JWT_ISSUER");
  const jwtAudience = requireHttpsUrl(env, "JWT_AUDIENCE");

  const verifyPath = requireEnv(env, "VERIFY_PATH");
  if (verifyPath.length > VERIFY_PATH_MAX_LENGTH) {
    throw new Error(
      `VERIFY_PATH must be at most ${VERIFY_PATH_MAX_LENGTH} characters`,
    );
  }
  if (verifyPath.endsWith("/")) {
    throw new Error('VERIFY_PATH must not end with "/"');
  }
  if (!VERIFY_PATH_PATTERN.test(verifyPath)) {
    throw new Error(
      'VERIFY_PATH must start with "/" and contain only letters, numbers, "_", "-", and "/"',
    );
  }

  const redisHost = requireEnv(env, "REDIS_HOST");
  const redisPortRaw = requireEnv(env, "REDIS_PORT");
  const redisPort = Number(redisPortRaw);
  if (!Number.isInteger(redisPort) || redisPort < 1 || redisPort > 65535) {
    throw new Error("REDIS_PORT must be an integer between 1 and 65535");
  }

  return {
    jwtIssuer,
    jwtAudience,
    verifyPath,
    jwtSecret: requireStrongEnv(env, "JWT_SECRET"),
    argon2Secret: requireStrongEnv(env, "ARGON2_SECRET"),
    redis: {
      host: redisHost,
      port: redisPort,
      password: requireEnv(env, "REDIS_PASSWORD"),
    },
  };
}

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

const JWT_SECRET = config.jwtSecret;
const ARGON2_SECRET = config.argon2Secret;
const JWT_MAX_LIFETIME = 120;
const JWT_CLOCK_SKEW_TOLERANCE = 30;

export const replayStore: ReplayStore = createRedisStore(config.redis);

console.info(
  JSON.stringify({
    event: "config_loaded",
    replay_protection: true,
  }),
);

function invalidInput(c: Context): Response {
  return c.json({ success: false, errcode: "INVALID_INPUT" }, 400) as Response;
}

function verifyFailed(c: Context) {
  return c.json({ success: false, errcode: "VERIFY_FAILED" }, 200);
}

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
  get available(): number {
    return this.permits;
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

export const EXPECTED_ARGON2 = {
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
};

export const argon2Limiter = new Semaphore(2, 16);
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

const JTI_PATTERN = /^[A-Za-z0-9_-]{8,64}$/;

const requireFreshJti: MiddlewareHandler = async (c, next) => {
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

function auditVerify(c: Context, success: boolean, errcode: string | null) {
  const sub =
    (c.get("jwtPayload") as { sub?: string } | undefined)?.sub ?? "unknown";
  console.info(JSON.stringify({ event: "verify", sub, success, errcode }));
}

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
      return c.json(
        { success: false, errcode: "PAYLOAD_TOO_LARGE" },
        413,
      ) as Response;
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
  requireJsonContentType,
  timeout(10_000),
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
  requireFreshJti,
  async (c) => {
    const { input, target } = c.req.valid("json" as never) as {
      input: string;
      target: string;
    };

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

    let success: boolean;
    try {
      await argon2Limiter.acquire();
    } catch {
      return c.json({ success: false, errcode: "TOO_MANY_REQUESTS" }, 429, {
        "Retry-After": "1",
      });
    }

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
        secret: Buffer.from(ARGON2_SECRET, "utf8"),
      });
      void verifyPromise.then(releaseOnce, releaseOnce);

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
