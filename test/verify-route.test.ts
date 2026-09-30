import { beforeAll, describe, expect, it, vi } from "vitest";

vi.hoisted(() => {
  process.env.ARGON2_VERIFY_ROUTE = "verify";
  process.env.ARGON2_HMAC_SECRET = Buffer.alloc(32, 1).toString("base64");
});

import { hash } from "argon2";
import type { Hono } from "hono";
import {
  ARGON2_VERIFY_OPTIONS,
  MAX_HASH_LENGTH,
  SIGNATURE_HEADER,
  TIMESTAMP_HEADER,
} from "../src/config.js";
import { ErrCode } from "../src/errcode.js";
import { computeSignature } from "../src/hmac.js";
import { createApp } from "../src/index.js";
import type { AppConfig } from "../src/types.js";

const HMAC_SECRET = Buffer.alloc(32, 1).toString("base64");
const OTHER_SECRET = Buffer.alloc(32, 2).toString("base64");
const PEPPER = Buffer.alloc(32, 3).toString("base64");
const ROUTE = "/verify";
const USER_INPUT = "CorrectHorse12!";
const WRONG_USER_INPUT = "WrongPassword12!";

const config: AppConfig = { verifyRoute: ROUTE, hmacSecret: HMAC_SECRET };
const app = createApp(config);

let validHash: string;

beforeAll(async () => {
  validHash = await hash(USER_INPUT, ARGON2_VERIFY_OPTIONS);
});

type PostOptions = {
  body?: string;
  timestamp?: string;
  signature?: string;
  secret?: string;
  contentType?: string | null;
};

type VerifyBody = { success: boolean; errcode: number };

function createClient(target: Hono) {
  return async function post(payload: unknown, options: PostOptions = {}) {
    const body = options.body ?? JSON.stringify(payload);
    const timestamp =
      options.timestamp ?? Math.floor(Date.now() / 1000).toString();
    const signature =
      options.signature ??
      computeSignature(options.secret ?? HMAC_SECRET, timestamp, body);

    const headers = new Headers();

    if (options.contentType !== null) {
      headers.set("content-type", options.contentType ?? "application/json");
    }

    headers.set(TIMESTAMP_HEADER, timestamp);
    headers.set(SIGNATURE_HEADER, signature);

    const res = await target.request(ROUTE, { method: "POST", headers, body });

    return { status: res.status, body: (await res.json()) as VerifyBody };
  };
}

const post = createClient(app);

describe("verify route registration", () => {
  it("is not mounted when the route is unconfigured", async () => {
    const disabled = createApp(undefined);
    const res = await disabled.request(ROUTE, { method: "POST" });

    expect(res.status).toBe(404);
  });

  it("is mounted only at the configured path", async () => {
    const res = await app.request("/not-verify", { method: "POST" });

    expect(res.status).toBe(404);
  });

  it("keeps the root placeholder route", async () => {
    const res = await app.request("/");

    expect(res.status).toBe(200);
    expect(await res.text()).toContain("Hello Hono!");
  });
});

describe("HMAC authorization", () => {
  it("rejects a request without a signature", async () => {
    const res = await post(
      { desired_hash: validHash, user_input: USER_INPUT },
      { signature: "" },
    );

    expect(res.status).toBe(401);
    expect(res.body.errcode).toBe(ErrCode.UNAUTHORIZED);
  });

  it("rejects a signature computed with another secret", async () => {
    const res = await post(
      { desired_hash: validHash, user_input: USER_INPUT },
      { secret: OTHER_SECRET },
    );

    expect(res.status).toBe(401);
    expect(res.body.errcode).toBe(ErrCode.UNAUTHORIZED);
  });

  it("rejects a stale timestamp", async () => {
    const timestamp = (Math.floor(Date.now() / 1000) - 120).toString();
    const res = await post(
      { desired_hash: validHash, user_input: USER_INPUT },
      { timestamp },
    );

    expect(res.status).toBe(401);
    expect(res.body.errcode).toBe(ErrCode.UNAUTHORIZED);
  });

  it("rejects a body that does not match the signature", async () => {
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const signature = computeSignature(
      HMAC_SECRET,
      timestamp,
      JSON.stringify({ desired_hash: validHash, user_input: USER_INPUT }),
    );
    const res = await post(
      { desired_hash: validHash, user_input: "tampered" },
      { timestamp, signature },
    );

    expect(res.status).toBe(401);
    expect(res.body.errcode).toBe(ErrCode.UNAUTHORIZED);
  });
});

describe("verification results", () => {
  it("returns success for a matching password", async () => {
    const res = await post({ desired_hash: validHash, user_input: USER_INPUT });

    expect(res).toEqual({
      status: 200,
      body: { success: true, errcode: ErrCode.OK },
    });
  });

  it("returns mismatch for a wrong password", async () => {
    const res = await post({
      desired_hash: validHash,
      user_input: WRONG_USER_INPUT,
    });

    expect(res).toEqual({
      status: 200,
      body: { success: false, errcode: ErrCode.MISMATCH },
    });
  });
});

describe("response headers", () => {
  it("sets no-store, CSP, and nosniff without adding a conflicting HSTS header", async () => {
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const body = JSON.stringify({
      desired_hash: validHash,
      user_input: USER_INPUT,
    });
    const res = await app.request(ROUTE, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        [TIMESTAMP_HEADER]: timestamp,
        [SIGNATURE_HEADER]: computeSignature(HMAC_SECRET, timestamp, body),
      },
      body,
    });

    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("content-security-policy")).toBe(
      "default-src 'none'",
    );
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    expect(res.headers.get("strict-transport-security")).toBeNull();
  });
});

describe("optional pepper", () => {
  const pepperedApp = createApp({
    verifyRoute: ROUTE,
    hmacSecret: HMAC_SECRET,
    argon2Pepper: PEPPER,
  });
  const postPeppered = createClient(pepperedApp);

  it("verifies a hash created with the same pepper", async () => {
    const pepperedHash = await hash(USER_INPUT, {
      ...ARGON2_VERIFY_OPTIONS,
      secret: Buffer.from(PEPPER, "utf8"),
    });
    const res = await postPeppered({
      desired_hash: pepperedHash,
      user_input: USER_INPUT,
    });

    expect(res).toEqual({
      status: 200,
      body: { success: true, errcode: ErrCode.OK },
    });
  });

  it("rejects a hash created without the pepper", async () => {
    const res = await postPeppered({
      desired_hash: validHash,
      user_input: USER_INPUT,
    });

    expect(res).toEqual({
      status: 200,
      body: { success: false, errcode: ErrCode.MISMATCH },
    });
  });
});

describe("method handling", () => {
  it("returns 405 with Allow: POST for other methods on the verify route", async () => {
    for (const method of ["GET", "PUT", "PATCH", "DELETE", "OPTIONS"]) {
      const res = await app.request(ROUTE, { method });

      expect(res.status).toBe(405);
      expect(res.headers.get("allow")).toBe("POST");
      expect((await res.json()) as VerifyBody).toEqual({
        success: false,
        errcode: ErrCode.METHOD_NOT_ALLOWED,
      });
    }
  });

  it("returns 405 with Allow: GET, HEAD for other methods on the root route", async () => {
    const res = await app.request("/", { method: "DELETE" });

    expect(res.status).toBe(405);
    expect(res.headers.get("allow")).toBe("GET, HEAD");
  });

  it("returns 404 for unknown paths", async () => {
    const res = await app.request("/nope", { method: "PUT" });

    expect(res.status).toBe(404);
  });
});

describe("request hardening", () => {
  it("rejects a hash over MAX_HASH_LENGTH", async () => {
    for (const desired_hash of [
      "x".repeat(MAX_HASH_LENGTH + 1),
      `$argon2id$${"x".repeat(MAX_HASH_LENGTH)}`,
    ]) {
      const res = await post({ desired_hash, user_input: WRONG_USER_INPUT });

      expect(res.status).toBe(400);
      expect(res.body.errcode).toBe(ErrCode.INVALID_REQUEST);
    }
  });

  it("rejects a hash that is not a parseable PHC string", async () => {
    for (const desired_hash of ["not-a-phc-string", "$argon2id$not-valid"]) {
      const res = await post({ desired_hash, user_input: WRONG_USER_INPUT });

      expect(res.status).toBe(400);
      expect(res.body.errcode).toBe(ErrCode.INVALID_HASH);
    }
  });

  it("rejects a hash whose PHC prefix is not argon2id", async () => {
    const desired_hash = validHash.replace("$argon2id$", "$argon2ix$");
    const res = await post({ desired_hash, user_input: WRONG_USER_INPUT });

    expect(res.status).toBe(400);
    expect(res.body.errcode).toBe(ErrCode.INVALID_HASH);
  });

  it("rejects hashes with unpinned cost parameters", async () => {
    const expensiveHash = await hash("x", {
      timeCost: 3,
      memoryCost: 1 << 16,
      parallelism: 4,
    });
    const res = await post({
      desired_hash: expensiveHash,
      user_input: WRONG_USER_INPUT,
    });

    expect(res.status).toBe(400);
    expect(res.body.errcode).toBe(ErrCode.INVALID_HASH);
  });

  it("rejects a malformed argon2id hash", async () => {
    const desired_hash = `$argon2id$${"x".repeat(87)}`;
    const res = await post({ desired_hash, user_input: WRONG_USER_INPUT });

    expect(res.status).toBe(400);
    expect(res.body.errcode).toBe(ErrCode.INVALID_HASH);
  });

  it("rejects a payload with a missing field", async () => {
    const res = await post({ desired_hash: validHash });

    expect(res.status).toBe(400);
    expect(res.body.errcode).toBe(ErrCode.INVALID_REQUEST);
  });

  it("rejects a payload with a too-short user_input", async () => {
    for (const user_input of ["abcd", "a".repeat(14)]) {
      const res = await post({ desired_hash: validHash, user_input });

      expect(res.status).toBe(400);
      expect(res.body.errcode).toBe(ErrCode.INVALID_REQUEST);
    }
  });

  it("accepts a user_input at the minimum length", async () => {
    const res = await post({
      desired_hash: validHash,
      user_input: "a".repeat(15),
    });

    expect(res.status).toBe(200);
    expect(res.body.errcode).toBe(ErrCode.MISMATCH);
  });

  it("rejects a payload with an over-long user_input", async () => {
    const res = await post({
      desired_hash: validHash,
      user_input: "a".repeat(2000),
    });

    expect(res.status).toBe(400);
    expect(res.body.errcode).toBe(ErrCode.INVALID_REQUEST);
  });

  it("rejects a user_input containing disallowed characters", async () => {
    for (const user_input of [
      "has space in it",
      "hyphen-ated-value",
      "under_score_value",
      "semi;colon;value",
      "emoji😀abcdefghij",
    ]) {
      const res = await post({ desired_hash: validHash, user_input });

      expect(res.status).toBe(400);
      expect(res.body.errcode).toBe(ErrCode.INVALID_REQUEST);
    }
  });

  it("accepts a user_input using every allowed character", async () => {
    const res = await post({
      desired_hash: validHash,
      user_input: "AaZz09!@#$%^&*0",
    });

    expect(res.status).toBe(200);
    expect(res.body.errcode).toBe(ErrCode.MISMATCH);
  });

  it("rejects a body over the size limit", async () => {
    const res = await post({
      desired_hash: validHash,
      user_input: "a".repeat(5000),
    });

    expect(res.status).toBe(413);
    expect(res.body.errcode).toBe(ErrCode.INVALID_REQUEST);
  });

  it("rejects a content-type with parameters", async () => {
    const res = await post(
      { desired_hash: validHash, user_input: USER_INPUT },
      { contentType: "application/json; charset=utf-8" },
    );

    expect(res.status).toBe(415);
    expect(res.body.errcode).toBe(ErrCode.INVALID_REQUEST);
  });

  it("rejects a content-type lookalike", async () => {
    const res = await post(
      { desired_hash: validHash, user_input: USER_INPUT },
      { contentType: "application/jsonp" },
    );

    expect(res.status).toBe(415);
    expect(res.body.errcode).toBe(ErrCode.INVALID_REQUEST);
  });

  it("rejects an unsupported content-type", async () => {
    const res = await post(
      { desired_hash: validHash, user_input: USER_INPUT },
      { contentType: "text/plain" },
    );

    expect(res.status).toBe(415);
    expect(res.body.errcode).toBe(ErrCode.INVALID_REQUEST);
  });

  it("rejects an unsigned request even when the content-type is wrong", async () => {
    const res = await post(
      { desired_hash: validHash, user_input: USER_INPUT },
      { contentType: "text/plain", signature: "" },
    );

    expect(res.status).toBe(401);
    expect(res.body.errcode).toBe(ErrCode.UNAUTHORIZED);
  });

  it("rejects a signed body that is not valid JSON", async () => {
    const res = await post(null, { body: "{oops" });

    expect(res.status).toBe(400);
    expect(res.body.errcode).toBe(ErrCode.INVALID_REQUEST);
  });
});
