import { describe, expect, it, beforeEach, afterEach, vi } from "vitest";
import argon2 from "argon2";
import { sign } from "hono/jwt";
import app, {
  ARGON2_PHC_PREFIX,
  EXPECTED_ARGON2,
  JWT_AUDIENCE,
  JWT_ISSUER,
  Semaphore,
} from "./index.js";

vi.mock("@vercel/firewall", () => ({
  checkRateLimit: vi.fn(async () => ({ rateLimited: false })),
}));

const TEST_PEPPER = "test-pepper-secret-1234567890123456";
const TEST_JWT_SECRET = "test-jwt-secret-1234567890123456";

const SUCCESS_BODY = { success: true, errcode: null };
const INVALID_INPUT_BODY = { success: false, errcode: "INVALID_INPUT" };
const VERIFY_FAILED_BODY = { success: false, errcode: "VERIFY_FAILED" };

async function createHash(password: string, pepper = TEST_PEPPER) {
  return argon2.hash(password, {
    secret: Buffer.from(pepper, "utf8"),
    ...EXPECTED_ARGON2,
  });
}

describe("POST /test-path", () => {
  beforeEach(() => {
    process.env.ARGON2_SECRET = TEST_PEPPER;
    process.env.JWT_SECRET = TEST_JWT_SECRET;
    process.env.JWT_ISSUER = "https://test.example";
    process.env.JWT_AUDIENCE = "https://test-verify.example";
    process.env.VERIFY_PATH = "/test-path";
  });

  afterEach(() => {
    delete process.env.ARGON2_SECRET;
    delete process.env.JWT_SECRET;
    delete process.env.JWT_ISSUER;
    delete process.env.JWT_AUDIENCE;
    delete process.env.VERIFY_PATH;
  });

  async function createToken(payload: Record<string, unknown> = {}) {
    const now = Math.floor(Date.now() / 1000);
    return sign(
      {
        sub: "test-worker",
        iat: now,
        exp: now + 60,
        iss: JWT_ISSUER,
        aud: JWT_AUDIENCE,
        ...payload,
      },
      process.env.JWT_SECRET!,
      "HS256",
    );
  }

  function phcString(
    m: number,
    t: number,
    p: number,
    prefix = "$argon2id$",
    version = 0x13,
  ) {
    const salt = Buffer.from("0123456789abcdef")
      .toString("base64")
      .replace(/=+$/, "");
    const digest = Buffer.from("0123456789abcdef0123456789abcdef")
      .toString("base64")
      .replace(/=+$/, "");
    return `${prefix}v=${version}$m=${m},t=${t},p=${p}$${salt}$${digest}`;
  }

  async function postVerify(
    input: unknown,
    target: unknown,
    token?: string | null,
  ) {
    const authorization = token === undefined ? await createToken() : token;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (authorization !== null) {
      headers.Authorization = `Bearer ${authorization}`;
    }
    return app.request("/test-path", {
      method: "POST",
      headers,
      body: JSON.stringify({ input, target }),
    });
  }

  async function expectVerify(
    input: unknown,
    target: unknown,
    status: number,
    body?: Record<string, unknown>,
    token?: string | null,
  ) {
    const response = await postVerify(input, target, token);
    expect(response.status).toBe(status);
    if (body !== undefined) {
      await expect(response.json()).resolves.toEqual(body);
    }
  }

  it("returns success=true for the correct password and pepper", async () => {
    const password = "correct-password";
    const hash = await createHash(password);

    await expectVerify(password, hash, 200, SUCCESS_BODY);
  });

  it("returns success=false for the wrong password", async () => {
    const hash = await createHash("correct-password");

    await expectVerify("wrong-password", hash, 200, VERIFY_FAILED_BODY);
  });

  it("returns success=false when the server uses the wrong pepper", async () => {
    const hash = await createHash("correct-password", "wrong-pepper");

    await expectVerify("correct-password", hash, 200, VERIFY_FAILED_BODY);
  });

  it("returns 400 for missing input", async () => {
    const hash = await createHash("correct-password");

    await expectVerify(undefined, hash, 400, INVALID_INPUT_BODY);
  });

  it("returns 400 for missing target", async () => {
    await expectVerify("password", undefined, 400, INVALID_INPUT_BODY);
  });

  it("returns 400 when input is not a string", async () => {
    const hash = await createHash("correct-password");

    await expectVerify(12345, hash, 400, INVALID_INPUT_BODY);
  });

  it("returns 400 when target is not a string", async () => {
    await expectVerify("password", 12345, 400, INVALID_INPUT_BODY);
  });

  it("returns 400 for invalid JSON", async () => {
    const token = await createToken();

    const response = await app.request("/test-path", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: "this is not json",
    });

    expect(response.status).toBe(400);

    await expect(response.json()).resolves.toEqual({
      success: false,
      errcode: "INVALID_REQUEST",
    });
  });

  it("returns 400 when the content type is not exactly JSON", async () => {
    const token = await createToken();
    const response = await app.request("/test-path", {
      method: "POST",
      headers: {
        "Content-Type": "text/plain",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ input: "password", target: "hash" }),
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual(INVALID_INPUT_BODY);
  });

  it("returns 400 for a null JSON body", async () => {
    const token = await createToken();

    const response = await app.request("/test-path", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: "null",
    });

    expect(response.status).toBe(400);

    await expect(response.json()).resolves.toEqual(INVALID_INPUT_BODY);
  });

  it("returns 400 for an invalid Argon2 hash", async () => {
    await expectVerify(
      "correct-password",
      "not-a-valid-argon2-hash",
      400,
      INVALID_INPUT_BODY,
    );
  });

  it("returns 400 for an argon2id-prefixed but malformed hash", async () => {
    await expectVerify(
      "correct-password",
      "$argon2id$v=19$m=65536$c2FsdHNhbHQ$ZGF0YQ$extra",
      400,
      INVALID_INPUT_BODY,
    );
  });

  it("returns VERIFY_FAILED for an Argon2 hash with a short digest", async () => {
    const salt = Buffer.from("0123456789abcdef")
      .toString("base64")
      .replace(/=+$/, "");
    await expectVerify(
      "correct-password",
      `${ARGON2_PHC_PREFIX}v=19$m=65536,t=3,p=4$${salt}$ZGF0YQ`,
      200,
      VERIFY_FAILED_BODY,
    );
  });

  it("returns 400 for an argon2i hash with default cost parameters", async () => {
    await expectVerify(
      "correct-password",
      phcString(65_536, 3, 4, "$argon2i$"),
      400,
      INVALID_INPUT_BODY,
    );
  });

  it("returns 400 for an oversized input string", async () => {
    const hash = await createHash("correct-password");

    await expectVerify("x".repeat(2048), hash, 400, INVALID_INPUT_BODY);
  });

  it("returns 400 for an empty input string", async () => {
    const hash = await createHash("correct-password");

    await expectVerify("", hash, 400, INVALID_INPUT_BODY);
  });

  it("returns 400 for an empty target string", async () => {
    await expectVerify("correct-password", "", 400, INVALID_INPUT_BODY);
  });

  it("returns 400 for an oversized target string", async () => {
    await expectVerify(
      "correct-password",
      `${ARGON2_PHC_PREFIX}${"x".repeat(512)}`,
      400,
      INVALID_INPUT_BODY,
    );
  });

  it("returns VERIFY_FAILED for a hash with non-default cost parameters", async () => {
    await expectVerify(
      "correct-password",
      phcString(32768, 3, 4),
      200,
      VERIFY_FAILED_BODY,
    );
  });

  it("returns VERIFY_FAILED for a hash with excessive memory cost", async () => {
    await expectVerify(
      "correct-password",
      phcString(2 ** 21, 3, 4),
      200,
      VERIFY_FAILED_BODY,
    );
  });

  it("returns VERIFY_FAILED for a hash with excessive time cost", async () => {
    await expectVerify(
      "correct-password",
      phcString(65_536, 100_000, 4),
      200,
      VERIFY_FAILED_BODY,
    );
  });

  it("returns VERIFY_FAILED for a hash with a parallelism mismatch only", async () => {
    await expectVerify(
      "correct-password",
      phcString(19_456, 2, 4),
      200,
      VERIFY_FAILED_BODY,
    );
  });

  it("returns VERIFY_FAILED for a hash with a memory-cost mismatch only", async () => {
    await expectVerify(
      "correct-password",
      phcString(65_536, 2, 1),
      200,
      VERIFY_FAILED_BODY,
    );
  });

  it("returns VERIFY_FAILED for a hash with a time-cost mismatch only", async () => {
    await expectVerify(
      "correct-password",
      phcString(19_456, 3, 1),
      200,
      VERIFY_FAILED_BODY,
    );
  });

  it("returns VERIFY_FAILED for a hash with a non-default version", async () => {
    await expectVerify(
      "correct-password",
      phcString(19_456, 2, 1, "$argon2id$", 0x10),
      200,
      VERIFY_FAILED_BODY,
    );
  });

  it("returns 413 for an oversized body", async () => {
    const hash = await createHash("correct-password");

    const response = await app.request("/test-path", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${await createToken()}`,
      },
      body: JSON.stringify({
        input: "x".repeat(64 * 1024),
        target: hash,
      }),
    });

    expect(response.status).toBe(413);

    await expect(response.json()).resolves.toEqual({
      success: false,
      errcode: "PAYLOAD_TOO_LARGE",
    });
  });

  it("returns 401 when the Authorization header is missing", async () => {
    const hash = await createHash("correct-password");

    await expectVerify("correct-password", hash, 401, undefined, null);
  });

  it("sets a WWW-Authenticate header on 401 responses", async () => {
    const hash = await createHash("correct-password");

    const response = await postVerify("correct-password", hash, null);

    expect(response.status).toBe(401);
    expect(response.headers.get("WWW-Authenticate")).toContain(
      'error="invalid_request"',
    );
  });

  it("accepts a lowercase bearer token", async () => {
    const hash = await createHash("correct-password");
    const token = await createToken();

    const response = await app.request("/test-path", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `bearer ${token}`,
      },
      body: JSON.stringify({ input: "correct-password", target: hash }),
    });

    expect(response.status).toBe(200);

    await expect(response.json()).resolves.toEqual(SUCCESS_BODY);
  });

  it("returns 401 when the token has no exp claim", async () => {
    const hash = await createHash("correct-password");
    const token = await sign(
      {
        sub: "test-worker",
        iat: Math.floor(Date.now() / 1000),
        iss: JWT_ISSUER,
        aud: JWT_AUDIENCE,
      },
      process.env.JWT_SECRET!,
      "HS256",
    );

    await expectVerify("correct-password", hash, 401, undefined, token);
  });

  it("returns 403 when a valid token has no subject", async () => {
    const hash = await createHash("correct-password");
    const now = Math.floor(Date.now() / 1000);
    const token = await sign(
      {
        iat: now,
        exp: now + 60,
        iss: JWT_ISSUER,
        aud: JWT_AUDIENCE,
      },
      process.env.JWT_SECRET!,
      "HS256",
    );

    await expectVerify(
      "correct-password",
      hash,
      403,
      { success: false, errcode: "FORBIDDEN" },
      token,
    );
  });

  it("returns 401 for a token with a non-numeric exp claim", async () => {
    const hash = await createHash("correct-password");
    const token = await sign(
      {
        sub: "test-worker",
        iat: Math.floor(Date.now() / 1000),
        exp: "not-a-number" as unknown as number,
      },
      process.env.JWT_SECRET!,
      "HS256",
    );

    await expectVerify("correct-password", hash, 401, undefined, token);
  });

  it("returns 401 for a token missing the issuer or audience", async () => {
    const hash = await createHash("correct-password");
    const token = await sign(
      {
        sub: "test-worker",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 60,
      },
      process.env.JWT_SECRET!,
      "HS256",
    );

    await expectVerify("correct-password", hash, 401, undefined, token);
  });

  it("returns 401 for a malformed token", async () => {
    const hash = await createHash("correct-password");

    await expectVerify("correct-password", hash, 401, undefined, "not-a-jwt");
  });

  it("returns 401 for a token signed with the wrong secret", async () => {
    const hash = await createHash("correct-password");
    const token = await sign(
      {
        sub: "test-worker",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 60,
      },
      "wrong-secret",
      "HS256",
    );

    await expectVerify("correct-password", hash, 401, undefined, token);
  });

  it("returns 401 for an expired token", async () => {
    const hash = await createHash("correct-password");
    const now = Math.floor(Date.now() / 1000);
    const token = await createToken({ iat: now - 120, exp: now - 60 });

    await expectVerify("correct-password", hash, 401, undefined, token);
  });

  it("returns 401 for a token issued in the future beyond clock skew", async () => {
    const hash = await createHash("correct-password");
    const now = Math.floor(Date.now() / 1000);
    const token = await createToken({ iat: now + 60, exp: now + 120 });

    await expectVerify("correct-password", hash, 401, undefined, token);
  });

  it("accepts a token issued slightly in the future within clock skew", async () => {
    const password = "correct-password";
    const hash = await createHash(password);
    const now = Math.floor(Date.now() / 1000);
    const token = await createToken({ iat: now + 10, exp: now + 70 });

    await expectVerify(password, hash, 200, SUCCESS_BODY, token);
  });

  it("returns 401 for a token with non-numeric iat", async () => {
    const hash = await createHash("correct-password");
    const token = await sign(
      {
        sub: "test-worker",
        iat: "not-a-number" as unknown as number,
        exp: Math.floor(Date.now() / 1000) + 60,
        iss: JWT_ISSUER,
        aud: JWT_AUDIENCE,
      },
      process.env.JWT_SECRET!,
      "HS256",
    );

    await expectVerify("correct-password", hash, 401, undefined, token);
  });

  it("returns 401 for a token with exp <= iat", async () => {
    const hash = await createHash("correct-password");
    const now = Math.floor(Date.now() / 1000);
    const token = await createToken({ iat: now + 10, exp: now + 5 });

    await expectVerify("correct-password", hash, 401, undefined, token);
  });

  it("sets Cache-Control: no-store on the verify endpoint", async () => {
    const hash = await createHash("correct-password");

    const response = await postVerify("correct-password", hash);

    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  it("sets Cache-Control: no-store on error responses", async () => {
    const response = await postVerify("correct-password", "hash", null);

    expect(response.status).toBe(401);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  it("sets security headers on responses", async () => {
    const response = await app.request("/nonexistent");

    expect(response.status).toBe(404);
    expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
  });

  it("returns 404 JSON for an unknown path", async () => {
    const response = await app.request("/nonexistent");

    expect(response.status).toBe(404);
    expect(response.headers.get("Cache-Control")).toBe("no-store");

    await expect(response.json()).resolves.toEqual({
      success: false,
      errcode: "NOT_FOUND",
    });
  });

  it("returns 405 with an Allow header for a non-POST method", async () => {
    const response = await app.request("/test-path", { method: "GET" });

    expect(response.status).toBe(405);
    expect(response.headers.get("Allow")).toBe("POST");
    expect(response.headers.get("Cache-Control")).toBe("no-store");

    await expect(response.json()).resolves.toEqual({
      success: false,
      errcode: "METHOD_NOT_ALLOWED",
    });
  });

  it("returns 401 when token lifetime exceeds JWT_MAX_LIFETIME", async () => {
    const hash = await createHash("correct-password");
    const now = Math.floor(Date.now() / 1000);
    const token = await createToken({ iat: now, exp: now + 200 });

    await expectVerify("correct-password", hash, 401, undefined, token);
  });

  it("returns 401 for a token with valid exp but no iat", async () => {
    const hash = await createHash("correct-password");
    const token = await sign(
      {
        sub: "test-worker",
        exp: Math.floor(Date.now() / 1000) + 60,
        iss: JWT_ISSUER,
        aud: JWT_AUDIENCE,
      },
      process.env.JWT_SECRET!,
      "HS256",
    );

    await expectVerify("correct-password", hash, 401, undefined, token);
  });

  it("sanitizes error responses - does not leak tokens in body", async () => {
    const hash = await createHash("correct-password");
    const response = await postVerify("correct-password", hash, "not-a-jwt");

    const body = await response.json();
    const bodyStr = JSON.stringify(body);
    expect(bodyStr).not.toContain("not-a-jwt");
    expect(bodyStr).not.toContain("Authorization");
    expect(bodyStr).not.toContain("Bearer");
    expect(bodyStr).not.toContain("JWT_SECRET");
    expect(response.status).toBe(401);
  });

  it("returns 401 for a token with a trailing-slash issuer", async () => {
    const hash = await createHash("correct-password");
    const token = await sign(
      {
        sub: "test-worker",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 60,
        iss: `${JWT_ISSUER}/`,
        aud: JWT_AUDIENCE,
      },
      process.env.JWT_SECRET!,
      "HS256",
    );

    await expectVerify("correct-password", hash, 401, undefined, token);
  });

  it("returns 401 for a token with a non-HTTPS issuer", async () => {
    const hash = await createHash("correct-password");
    const token = await sign(
      {
        sub: "test-worker",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 60,
        iss: "http://test.example",
        aud: JWT_AUDIENCE,
      },
      process.env.JWT_SECRET!,
      "HS256",
    );

    await expectVerify("correct-password", hash, 401, undefined, token);
  });

  it("returns 401 for a token with a mismatched audience", async () => {
    const hash = await createHash("correct-password");
    const token = await sign(
      {
        sub: "test-worker",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 60,
        iss: JWT_ISSUER,
        aud: "https://wrong-audience.example",
      },
      process.env.JWT_SECRET!,
      "HS256",
    );

    await expectVerify("correct-password", hash, 401, undefined, token);
  });

  it("returns 200 for the root health endpoint", async () => {
    const response = await app.request("/");

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ ok: true });
  });
});

describe("JWT algorithm restrictions", () => {
  beforeEach(() => {
    process.env.ARGON2_SECRET = TEST_PEPPER;
    process.env.JWT_SECRET = TEST_JWT_SECRET;
    process.env.JWT_ISSUER = "https://test.example";
    process.env.JWT_AUDIENCE = "https://test-verify.example";
    process.env.VERIFY_PATH = "/test-path";
  });

  afterEach(() => {
    delete process.env.ARGON2_SECRET;
    delete process.env.JWT_SECRET;
    delete process.env.JWT_ISSUER;
    delete process.env.JWT_AUDIENCE;
    delete process.env.VERIFY_PATH;
  });

  async function postWithToken(token: string) {
    const hash = await createHash("correct-password");
    return app.request("/test-path", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ input: "correct-password", target: hash }),
    });
  }

  async function tokenWithAlg(alg: "HS256" | "HS384" | "HS512") {
    const now = Math.floor(Date.now() / 1000);
    return sign(
      {
        sub: "test-worker",
        iat: now,
        exp: now + 60,
        iss: JWT_ISSUER,
        aud: JWT_AUDIENCE,
      },
      process.env.JWT_SECRET!,
      alg,
    );
  }

  it("returns 401 for a token signed with HS384", async () => {
    const res = await postWithToken(await tokenWithAlg("HS384"));
    expect(res.status).toBe(401);
  });

  it("returns 401 for a token signed with HS512", async () => {
    const res = await postWithToken(await tokenWithAlg("HS512"));
    expect(res.status).toBe(401);
  });

  it("returns 401 for a token with alg=none", async () => {
    const now = Math.floor(Date.now() / 1000);
    const header = Buffer.from(
      JSON.stringify({ alg: "none", typ: "JWT" }),
    ).toString("base64url");
    const payload = Buffer.from(
      JSON.stringify({
        sub: "test-worker",
        iat: now,
        exp: now + 60,
        iss: JWT_ISSUER,
        aud: JWT_AUDIENCE,
      }),
    ).toString("base64url");
    const token = `${header}.${payload}.`;
    const res = await postWithToken(token);
    expect(res.status).toBe(401);
  });
});

describe("Semaphore", () => {
  it("tryAcquire returns true when permits are available", () => {
    const sem = new Semaphore(2, 10);
    expect(sem.tryAcquire()).toBe(true);
    expect(sem.tryAcquire()).toBe(true);
  });

  it("tryAcquire returns false when permits are exhausted", () => {
    const sem = new Semaphore(2, 10);
    expect(sem.tryAcquire()).toBe(true);
    expect(sem.tryAcquire()).toBe(true);
    expect(sem.tryAcquire()).toBe(false);
    expect(sem.waiting).toBe(0);
  });

  it("tryAcquire returns false when queue is full", () => {
    const sem = new Semaphore(0, 2);
    sem.acquire();
    sem.acquire();
    expect(sem.tryAcquire()).toBe(false);
  });

  it("release frees a waiting acquirer", async () => {
    const sem = new Semaphore(1, 10);
    sem.acquire();
    let resolved = false;
    const p = sem.acquire().then(() => {
      resolved = true;
    });
    expect(resolved).toBe(false);
    sem.release();
    await p;
    expect(resolved).toBe(true);
  });
});
