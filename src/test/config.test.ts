/**
 * Unit tests for loadConfig: a valid environment parses as expected, and every
 * missing / malformed / under-strength value is rejected with the offending
 * variable name in the thrown error (so the caller can surface which key failed).
 */

import { describe, expect, it } from "vitest";
import { loadConfig } from "../config.js";

const TEST_ENV: Record<string, string> = {
  ARGON2_SECRET: "test-pepper-secret-1234567890123456",
  JWT_SECRET: "test-jwt-secret-1234567890123456",
  JWT_ISSUER: "https://test.example",
  JWT_AUDIENCE: "https://test-verify.example",
  VERIFY_PATH: "/test-path",
  REDIS_HOST: "localhost",
  REDIS_PORT: "6379",
  REDIS_PASSWORD: "test-password",
};

describe("loadConfig", () => {
  it("parses a valid environment", () => {
    expect(loadConfig(TEST_ENV)).toEqual({
      jwtIssuer: TEST_ENV.JWT_ISSUER,
      jwtAudience: TEST_ENV.JWT_AUDIENCE,
      verifyPath: "/test-path",
      jwtSecret: TEST_ENV.JWT_SECRET,
      argon2Secret: TEST_ENV.ARGON2_SECRET,
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
