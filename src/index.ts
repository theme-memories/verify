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

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is not set`);
  }
  return value;
}

export const JWT_ISSUER = requireEnv("JWT_ISSUER");
export const JWT_AUDIENCE = requireEnv("JWT_AUDIENCE");
export const VERIFY_PATH = requireEnv("VERIFY_PATH");

function invalidInput(c: Context) {
  return c.json({ success: false, errcode: "INVALID_INPUT" }, 400);
}

function verifyFailed(c: Context) {
  return c.json({ success: false, errcode: "VERIFY_FAILED" }, 200);
}

const app = new Hono();

app.use("*", secureHeaders());

const requireJwt: MiddlewareHandler = async (c, next) => {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error("JWT_SECRET is not set");
  }

  await jwt({
    secret,
    alg: "HS256",
    verification: { iss: JWT_ISSUER, aud: JWT_AUDIENCE },
  })(c, next);
};

const requireExpClaim: MiddlewareHandler = async (c, next) => {
  const payload = c.get("jwtPayload") as { exp?: number } | undefined;
  if (payload?.exp === undefined) {
    throw new HTTPException(401, { message: "exp claim is required" });
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

    const secret = process.env.ARGON2_SECRET;
    if (!secret) {
      throw new Error("ARGON2_SECRET is not set");
    }

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
    try {
      success = await argon2.verify(target, input, {
        secret: Buffer.from(secret, "utf8"),
      });
    } catch {
      return verifyFailed(c);
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

  console.error(err);
  return c.json({ success: false, errcode: "INTERNAL_ERROR" }, 500);
});

export default app;
