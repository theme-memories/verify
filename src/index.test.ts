import {
  describe,
  expect,
  it,
  beforeEach,
  afterEach,
  vi,
  type MockInstance,
} from "vitest";
import argon2 from "argon2";
import { sign } from "hono/jwt";

const redisMocks = vi.hoisted(() => {
  const set =
    vi.fn<
      (key: string, value: string, options: unknown) => Promise<"OK" | null>
    >();
  set.mockResolvedValue("OK");
  return { set };
});

vi.mock("redis", () => ({
  createClient: () => {
    const client = {
      isOpen: false,
      on: () => client,
      connect: async () => {},
      set: redisMocks.set,
    };
    return client;
  },
}));

import app, {
  ARGON2_PHC_PREFIX,
  argon2Limiter,
  EXPECTED_ARGON2,
  JWT_AUDIENCE,
  JWT_ISSUER,
  loadConfig,
  Semaphore,
} from "./index.js";

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
        jti: crypto.randomUUID(),
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

const TEST_ENV: Record<string, string> = {
  ARGON2_SECRET: TEST_PEPPER,
  JWT_SECRET: TEST_JWT_SECRET,
  JWT_ISSUER: "https://test.example",
  JWT_AUDIENCE: "https://test-verify.example",
  VERIFY_PATH: "/test-path",
  REDIS_HOST: "localhost",
  REDIS_PORT: "6379",
  REDIS_PASSWORD: "test-password",
};
const applyTestEnv = () => Object.assign(process.env, TEST_ENV);
const clearTestEnv = () => {
  for (const key of Object.keys(TEST_ENV)) delete process.env[key];
};
const SUCCESS_BODY_SHAPE = { ok: { success: true, errcode: null } } as const;

afterEach(() => {
  redisMocks.set.mockReset();
  redisMocks.set.mockResolvedValue("OK");
});

async function makeHash(password = "correct-password"): Promise<string> {
  return argon2.hash(password, {
    secret: Buffer.from(TEST_PEPPER, "utf8"),
    ...EXPECTED_ARGON2,
  });
}

async function makeToken(overrides: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000);
  return sign(
    {
      sub: "test-worker",
      jti: crypto.randomUUID(),
      iat: now,
      exp: now + 60,
      iss: JWT_ISSUER,
      aud: JWT_AUDIENCE,
      ...overrides,
    },
    process.env.JWT_SECRET!,
    "HS256",
  );
}

async function postJson(
  body: unknown,
  headers: Record<string, string> = {},
  signal?: AbortSignal,
) {
  return app.request("/test-path", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${await makeToken()}`,
      ...headers,
    },
    body:
      typeof body === "string" || body instanceof ReadableStream
        ? body
        : JSON.stringify(body),
    ...(signal ? { signal } : {}),
  });
}

async function postWithToken(token: string, body: unknown) {
  return app.request("/test-path", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(body),
  });
}

function hangVerify(): Array<(value: boolean) => void> {
  const resolvers: Array<(value: boolean) => void> = [];
  vi.spyOn(argon2, "verify").mockImplementation(
    () =>
      new Promise<boolean>((resolve) => {
        resolvers.push(resolve);
      }),
  );
  return resolvers;
}

async function drainVerify(resolvers: Array<(value: boolean) => void>) {
  for (let i = 0; i < 100; i += 1) {
    const batch = resolvers.splice(0);
    if (
      batch.length === 0 &&
      resolvers.length === 0 &&
      argon2Limiter.waiting === 0 &&
      argon2Limiter.available === 2
    ) {
      return;
    }
    batch.forEach((resolve) => resolve(true));
    await new Promise((resolveTimer) => setTimeout(resolveTimer, 0));
  }
}

const realSetTimeout = setTimeout.bind(globalThis);
const realTick = () =>
  new Promise<void>((resolve) => {
    realSetTimeout(resolve, 0);
  });

describe("loadConfig", () => {
  it("parses a valid environment", () => {
    expect(loadConfig(TEST_ENV)).toEqual({
      jwtIssuer: TEST_ENV.JWT_ISSUER,
      jwtAudience: TEST_ENV.JWT_AUDIENCE,
      verifyPath: "/test-path",
      jwtSecret: TEST_JWT_SECRET,
      argon2Secret: TEST_PEPPER,
      redis: {
        host: "localhost",
        port: 6379,
        password: "test-password",
      },
    });
  });

  it.each(Object.keys(TEST_ENV))("rejects when %s is missing", (key) => {
    const env = { ...TEST_ENV };
    delete env[key];
    expect(() => loadConfig(env)).toThrow(key);
  });

  it("rejects blank values", () => {
    expect(() => loadConfig({ ...TEST_ENV, JWT_SECRET: "   " })).toThrow(
      "JWT_SECRET",
    );
  });

  it("rejects secrets shorter than 32 bytes", () => {
    expect(() =>
      loadConfig({ ...TEST_ENV, ARGON2_SECRET: "too-short" }),
    ).toThrow(/at least 32/);
  });

  it.each(["JWT_ISSUER", "JWT_AUDIENCE"])("rejects non-HTTPS %s", (key) => {
    expect(() =>
      loadConfig({ ...TEST_ENV, [key]: "http://test.example" }),
    ).toThrow(key);
  });

  it.each(["JWT_ISSUER", "JWT_AUDIENCE"])("rejects malformed %s", (key) => {
    expect(() =>
      loadConfig({ ...TEST_ENV, [key]: "not a url at all" }),
    ).toThrow(key);
  });

  it("rejects VERIFY_PATH without a leading slash", () => {
    expect(() => loadConfig({ ...TEST_ENV, VERIFY_PATH: "test-path" })).toThrow(
      "/",
    );
  });

  it("rejects VERIFY_PATH ending with a slash", () => {
    expect(() =>
      loadConfig({ ...TEST_ENV, VERIFY_PATH: "/test-path/" }),
    ).toThrow('must not end with "/"');
  });

  it("rejects VERIFY_PATH longer than 256 characters", () => {
    expect(() =>
      loadConfig({ ...TEST_ENV, VERIFY_PATH: `/${"a".repeat(300)}` }),
    ).toThrow();
  });

  it("rejects VERIFY_PATH with characters outside the allowlist", () => {
    expect(() => loadConfig({ ...TEST_ENV, VERIFY_PATH: "/te st" })).toThrow();
  });

  it.each(["abc", "0", "-1", "65536", "6379.5"])(
    "rejects an invalid REDIS_PORT (%s)",
    (port) => {
      expect(() => loadConfig({ ...TEST_ENV, REDIS_PORT: port })).toThrow(
        "REDIS_PORT",
      );
    },
  );
});

describe("app-owned security headers", () => {
  it("sets X-Frame-Options DENY", async () => {
    const res = await app.request("/nonexistent");
    expect(res.headers.get("X-Frame-Options")).toBe("DENY");
  });

  it("sets a deny-all CSP", async () => {
    const res = await app.request("/nonexistent");
    expect(res.headers.get("Content-Security-Policy")).toBe(
      "default-src 'none'; frame-ancestors 'none'",
    );
  });

  it("sets the Permissions-Policy deny list", async () => {
    const res = await app.request("/nonexistent");
    expect(res.headers.get("Permissions-Policy")).toBe(
      "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
    );
  });

  it("keeps no-referrer and nosniff defaults", async () => {
    const res = await app.request("/nonexistent");
    expect(res.headers.get("Referrer-Policy")).toBe("no-referrer");
    expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
  });
});

describe("request edge cases", () => {
  beforeEach(applyTestEnv);
  afterEach(clearTestEnv);

  it("returns 401 UNAUTHORIZED with WWW-Authenticate when Authorization is too long", async () => {
    const res = await app.request("/test-path", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${"a".repeat(4300)}`,
      },
      body: JSON.stringify({ input: "x", target: "y" }),
    });
    expect(res.status).toBe(401);
    await expect(res.json()).resolves.toEqual({
      success: false,
      errcode: "UNAUTHORIZED",
    });
    expect(res.headers.get("WWW-Authenticate")).toContain(
      'error="invalid_request"',
    );
  });

  it("accepts application/json with parameters (charset suffix)", async () => {
    const hash = await makeHash();
    const res = await postJson(
      { input: "correct-password", target: hash },
      { "Content-Type": "application/json; charset=utf-8" },
    );
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual(SUCCESS_BODY_SHAPE.ok);
  });

  it("rejects HEAD on the verify path", async () => {
    const res = await app.request("/test-path", { method: "HEAD" });
    expect(res.status).toBe(405);
    expect(res.headers.get("Allow")).toBe("POST");
  });

  it("rejects a non-numeric Content-Length header", async () => {
    const res = await postJson({}, { "Content-Length": "abc" });
    expect(res.status).toBe(400);
    await expect(res.json()).resolves.toEqual({
      success: false,
      errcode: "INVALID_INPUT",
    });
  });

  it("rejects an oversized declared Content-Length", async () => {
    const res = await postJson({}, { "Content-Length": String(32 * 1024 + 1) });
    expect(res.status).toBe(413);
    await expect(res.json()).resolves.toEqual({
      success: false,
      errcode: "PAYLOAD_TOO_LARGE",
    });
  });

  it("rejects oversized chunked bodies without Content-Length", async () => {
    const hash = await makeHash();
    const big = JSON.stringify({
      input: "x".repeat(40_000),
      target: hash,
    });
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(big));
        controller.close();
      },
    });
    const res = await app.request("/test-path", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${await makeToken()}`,
      },
      body: stream,
      duplex: "half",
    } as unknown as RequestInit);
    expect(res.status).toBe(413);
    await expect(res.json()).resolves.toEqual({
      success: false,
      errcode: "PAYLOAD_TOO_LARGE",
    });
  });

  it("returns 408 REQUEST_CANCELLED when the request arrives already aborted", async () => {
    const hash = await makeHash();
    const controller = new AbortController();
    controller.abort();
    const res = await postJson(
      { input: "correct-password", target: hash },
      {},
      controller.signal,
    );
    expect(res.status).toBe(408);
    await expect(res.json()).resolves.toEqual({
      success: false,
      errcode: "REQUEST_CANCELLED",
    });
  });
});

describe("cancellation and semaphore backpressure", () => {
  beforeEach(applyTestEnv);
  afterEach(clearTestEnv);
  afterEach(async () => {
    vi.restoreAllMocks();
    await vi.waitFor(
      () => {
        expect(argon2Limiter.waiting).toBe(0);
        expect(argon2Limiter.available).toBe(2);
      },
      { timeout: 10_000 },
    );
  });

  it("releases the permit only after the native verify settles, even on abort", async () => {
    const resolvers = hangVerify();
    const hash = await makeHash();
    const controller = new AbortController();

    const pending = postJson(
      { input: "correct-password", target: hash },
      {},
      controller.signal,
    );
    await vi.waitFor(() => expect(argon2Limiter.available).toBe(1));
    controller.abort();

    const res = await pending;
    expect(res.status).toBe(408);
    await expect(res.json()).resolves.toEqual({
      success: false,
      errcode: "REQUEST_CANCELLED",
    });
    expect(argon2Limiter.available).toBe(1);

    await drainVerify(resolvers);
    expect(argon2Limiter.available).toBe(2);
  }, 15_000);

  it("sheds load with 429 when permits and queue are exhausted", async () => {
    const resolvers = hangVerify();
    const hash = await makeHash();

    const responses: Array<Response | undefined> = [];
    void Array.from({ length: 19 }, (_, i) =>
      postJson({ input: "correct-password", target: hash }).then((r) => {
        responses[i] = r;
        return r;
      }),
    );

    await vi.waitFor(() => {
      const settled = responses.filter((r) => r !== undefined);
      expect(settled.length).toBeGreaterThanOrEqual(1);
      expect(settled.some((r) => r!.status === 429)).toBe(true);
    });

    const rejected = responses.find((r) => r?.status === 429)!;
    expect(rejected.headers.get("Retry-After")).toBe("1");
    await expect(rejected.json()).resolves.toEqual({
      success: false,
      errcode: "TOO_MANY_REQUESTS",
    });
    expect(responses.filter((r) => r !== undefined)).toHaveLength(1);

    await drainVerify(resolvers);
    for (const r of responses) {
      if (r && r.status === 200) {
        await expect(r.json()).resolves.toEqual(SUCCESS_BODY_SHAPE.ok);
      }
    }
    expect(argon2Limiter.waiting).toBe(0);
    expect(argon2Limiter.available).toBe(2);
  }, 20_000);

  it("maps a failing verify to 500 INTERNAL_ERROR", async () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(argon2, "verify").mockRejectedValueOnce(new TypeError("boom"));
    const hash = await makeHash();

    const res = await postJson({ input: "correct-password", target: hash });

    expect(res.status).toBe(500);
    await expect(res.json()).resolves.toEqual({
      success: false,
      errcode: "INTERNAL_ERROR",
    });
    expect(errorSpy).toHaveBeenCalled();
  }, 10_000);

  it("aborts hung verifications with 504 TIMEOUT", async () => {
    const resolvers = hangVerify();
    vi.useFakeTimers();
    try {
      const hash = await makeHash();
      let settled: Response | null = null;
      void postJson({ input: "correct-password", target: hash }).then((r) => {
        settled = r;
        return r;
      });
      for (let i = 0; i < 40 && !settled; i += 1) {
        await vi.advanceTimersByTimeAsync(1_000);
        await realTick();
      }
      expect(settled).not.toBeNull();
      expect(settled!.status).toBe(504);
      await expect(settled!.json()).resolves.toEqual({
        success: false,
        errcode: "TIMEOUT",
      });
    } finally {
      vi.useRealTimers();
    }
    await drainVerify(resolvers);
    expect(argon2Limiter.available).toBe(2);
  }, 20_000);
});

describe("claim boundaries", () => {
  beforeEach(applyTestEnv);
  afterEach(clearTestEnv);

  it("accepts a lifetime of exactly JWT_MAX_LIFETIME seconds", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await makeToken({ iat: now, exp: now + 120 });
    const res = await postWithToken(token, {
      input: "correct-password",
      target: await makeHash(),
    });
    expect(res.status).toBe(200);
  });

  it("rejects a lifetime one second past the maximum", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await makeToken({ iat: now, exp: now + 121 });
    const res = await postWithToken(token, {
      input: "correct-password",
      target: await makeHash(),
    });
    expect(res.status).toBe(401);
  });

  it("accepts iat exactly at the clock-skew limit (+30s)", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await makeToken({ iat: now + 30, exp: now + 90 });
    const res = await postWithToken(token, {
      input: "correct-password",
      target: await makeHash(),
    });
    expect(res.status).toBe(200);
  });

  it("rejects iat one second past the skew limit (+31s)", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await makeToken({ iat: now + 31, exp: now + 91 });
    const res = await postWithToken(token, {
      input: "correct-password",
      target: await makeHash(),
    });
    expect(res.status).toBe(401);
  });

  it("accepts a subject of exactly 128 characters", async () => {
    const token = await makeToken({ sub: "a".repeat(128) });
    const res = await postWithToken(token, {
      input: "correct-password",
      target: await makeHash(),
    });
    expect(res.status).toBe(200);
  });

  it("rejects a subject of 129 characters", async () => {
    const token = await makeToken({ sub: "a".repeat(129) });
    const res = await postWithToken(token, {
      input: "correct-password",
      target: await makeHash(),
    });
    expect(res.status).toBe(403);
  });

  it("rejects a subject with characters outside the allowlist", async () => {
    const token = await makeToken({ sub: "bad*sub" });
    const res = await postWithToken(token, {
      input: "correct-password",
      target: await makeHash(),
    });
    expect(res.status).toBe(403);
  });
});

describe("audit logging", () => {
  beforeEach(applyTestEnv);
  afterEach(clearTestEnv);

  function auditEvents(infoSpy: MockInstance): Array<Record<string, unknown>> {
    const lines: Array<Record<string, unknown>> = [];
    for (const call of infoSpy.mock.calls) {
      try {
        const parsed = JSON.parse(String(call[0])) as Record<string, unknown>;
        if (parsed && typeof parsed === "object" && parsed.event === "verify") {
          lines.push(parsed);
        }
      } catch {
        /* skip non-JSON lines */
      }
    }
    return lines;
  }

  it("logs successful verifications with the token subject", async () => {
    const infoSpy = vi.spyOn(console, "info").mockImplementation(() => {});
    try {
      const res = await postJson({
        input: "correct-password",
        target: await makeHash(),
      });
      expect(res.status).toBe(200);
      const audits = auditEvents(infoSpy);
      expect(audits.length).toBeGreaterThanOrEqual(1);
      expect(audits.at(-1)).toMatchObject({
        event: "verify",
        sub: "test-worker",
        success: true,
        errcode: null,
      });
    } finally {
      infoSpy.mockRestore();
    }
  });

  it("logs failed verifications as VERIFY_FAILED", async () => {
    const infoSpy = vi.spyOn(console, "info").mockImplementation(() => {});
    try {
      const res = await postJson({
        input: "wrong-password",
        target: await makeHash(),
      });
      expect(res.status).toBe(200);
      const audits = auditEvents(infoSpy);
      expect(audits.length).toBeGreaterThanOrEqual(1);
      expect(audits.at(-1)).toMatchObject({
        event: "verify",
        success: false,
        errcode: "VERIFY_FAILED",
      });
    } finally {
      infoSpy.mockRestore();
    }
  });
});

describe("replay protection (Redis required)", () => {
  beforeEach(applyTestEnv);
  afterEach(clearTestEnv);

  it("accepts a fresh jti and stores it under the expected key and TTL", async () => {
    const res = await postJson({
      input: "correct-password",
      target: await makeHash(),
    });
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual(SUCCESS_BODY_SHAPE.ok);

    expect(redisMocks.set).toHaveBeenCalledTimes(1);
    const [key, value, rawOptions] = redisMocks.set.mock.calls[0]!;
    expect(key).toMatch(/^jti:[0-9a-f-]{36}$/);
    expect(value).toBe("1");
    const options = rawOptions as {
      condition: string;
      expiration: { type: string; value: number };
    };
    expect(options.condition).toBe("NX");
    expect(options.expiration.type).toBe("EX");
    expect(options.expiration.value).toBeLessThanOrEqual(150);
    expect(options.expiration.value).toBeGreaterThan(60);
  });

  it("rejects a replayed token with REPLAY_DETECTED", async () => {
    const first = await postJson({
      input: "correct-password",
      target: await makeHash(),
    });
    expect(first.status).toBe(200);

    redisMocks.set.mockResolvedValue(null);
    const second = await postJson({
      input: "correct-password",
      target: await makeHash(),
    });
    expect(second.status).toBe(401);
    await expect(second.json()).resolves.toEqual({
      success: false,
      errcode: "REPLAY_DETECTED",
    });
  });

  it("rejects tokens without a jti claim", async () => {
    const token = await makeToken({ jti: undefined });
    const res = await postWithToken(token, {
      input: "correct-password",
      target: await makeHash(),
    });
    expect(res.status).toBe(401);
    await expect(res.json()).resolves.toEqual({
      success: false,
      errcode: "UNAUTHORIZED",
    });
    expect(redisMocks.set).not.toHaveBeenCalled();
  });

  it("rejects tokens whose jti is outside the accepted shape", async () => {
    const token = await makeToken({ jti: "short" });
    const res = await postWithToken(token, {
      input: "correct-password",
      target: await makeHash(),
    });
    expect(res.status).toBe(401);
    await expect(res.json()).resolves.toEqual({
      success: false,
      errcode: "UNAUTHORIZED",
    });
    expect(redisMocks.set).not.toHaveBeenCalled();
  });

  it("fails closed with 503 when the store errors, with an alert log", async () => {
    redisMocks.set.mockRejectedValue(new Error("connection refused"));
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const res = await postJson({
        input: "correct-password",
        target: await makeHash(),
      });
      expect(res.status).toBe(503);
      expect(res.headers.get("Cache-Control")).toBe("no-store");
      await expect(res.json()).resolves.toEqual({
        success: false,
        errcode: "SERVICE_UNAVAILABLE",
      });
      expect(errorSpy).toHaveBeenCalled();
    } finally {
      errorSpy.mockRestore();
    }
  });

  it("fails closed with 503 when the store hangs past the record timeout", async () => {
    redisMocks.set.mockImplementation(() => new Promise<"OK">(() => {}));
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const res = await postJson({
        input: "correct-password",
        target: await makeHash(),
      });
      expect(res.status).toBe(503);
      expect(res.headers.get("Cache-Control")).toBe("no-store");
      await expect(res.json()).resolves.toEqual({
        success: false,
        errcode: "SERVICE_UNAVAILABLE",
      });
      expect(errorSpy).toHaveBeenCalled();
    } finally {
      errorSpy.mockRestore();
    }
  }, 15_000);

  it("does not touch the store for a valid token with a bad Content-Type", async () => {
    const hash = await makeHash();
    const res = await postJson(
      { input: "correct-password", target: hash },
      { "Content-Type": "text/plain" },
    );
    expect(res.status).toBe(400);
    await expect(res.json()).resolves.toEqual({
      success: false,
      errcode: "INVALID_INPUT",
    });
    expect(redisMocks.set).not.toHaveBeenCalled();
  });

  it("does not touch the store when earlier validation fails", async () => {
    const now = Math.floor(Date.now() / 1000);
    const expired = await makeToken({ iat: now - 120, exp: now - 60 });
    const res = await postWithToken(expired, {
      input: "x",
      target: "y",
    });
    expect(res.status).toBe(401);
    expect(redisMocks.set).not.toHaveBeenCalled();
  });
});
