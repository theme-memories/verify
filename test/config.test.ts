import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MIN_SECRET_BYTES, loadConfig } from "../src/config.js";

const VALID_SECRET = Buffer.alloc(MIN_SECRET_BYTES, 1).toString("base64");
const VALID_PEPPER = Buffer.alloc(MIN_SECRET_BYTES, 2).toString("base64");
const SHORT_SECRET = Buffer.alloc(MIN_SECRET_BYTES - 1, 3).toString("base64");
const NON_BASE64_SECRET = "test-hmac-secret-0123456789abcdef";

const validEnv = {
  ARGON2_VERIFY_ROUTE: "verify",
  ARGON2_HMAC_SECRET: VALID_SECRET,
};

let warn: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  warn = vi.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("loadConfig", () => {
  it("disables the endpoint when the route is missing", () => {
    const config = loadConfig({ ARGON2_HMAC_SECRET: VALID_SECRET });

    expect(config).toBeUndefined();
    expect(warn).toHaveBeenCalledOnce();
  });

  it("disables the endpoint when the route is not lowercase alphanumeric", () => {
    for (const route of ["/verify", "Verify", "ver-ify", ""]) {
      expect(
        loadConfig({ ...validEnv, ARGON2_VERIFY_ROUTE: route }),
      ).toBeUndefined();
    }
  });

  it("disables the endpoint when the HMAC secret is missing, not base64, or below 32 bytes", () => {
    expect(loadConfig({ ARGON2_VERIFY_ROUTE: "verify" })).toBeUndefined();
    expect(
      loadConfig({ ...validEnv, ARGON2_HMAC_SECRET: NON_BASE64_SECRET }),
    ).toBeUndefined();
    expect(
      loadConfig({ ...validEnv, ARGON2_HMAC_SECRET: SHORT_SECRET }),
    ).toBeUndefined();
  });

  it("builds the route path from a valid route name", () => {
    const config = loadConfig(validEnv);

    expect(config).toEqual({
      verifyRoute: "/verify",
      hmacSecret: VALID_SECRET,
    });
  });

  it("accepts the unpadded base64 form of a 32-byte secret", () => {
    const unpadded = VALID_SECRET.replace(/=+$/, "");

    expect(loadConfig({ ...validEnv, ARGON2_HMAC_SECRET: unpadded })).toEqual({
      verifyRoute: "/verify",
      hmacSecret: unpadded,
    });
  });

  it("includes the pepper when it is set", () => {
    const config = loadConfig({ ...validEnv, ARGON2_PEPPER: VALID_PEPPER });

    expect(config).toEqual({
      verifyRoute: "/verify",
      hmacSecret: VALID_SECRET,
      argon2Pepper: VALID_PEPPER,
    });
  });

  it("disables the endpoint when the pepper is too short or not base64", () => {
    expect(loadConfig({ ...validEnv, ARGON2_PEPPER: "short" })).toBeUndefined();
    expect(
      loadConfig({ ...validEnv, ARGON2_PEPPER: NON_BASE64_SECRET }),
    ).toBeUndefined();
  });
});
