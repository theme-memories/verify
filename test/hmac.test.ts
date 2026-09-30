import { describe, expect, it } from "vitest";
import { computeSignature, isSignatureValid } from "../src/hmac.js";

const SECRET = "test-hmac-secret-0123456789abcdef";
const OTHER_SECRET = "another-secret-0123456789abcdefgh";
const TIMESTAMP = "1700000000";
const BODY = JSON.stringify({ desired_hash: "abc", user_input: "def" });
const NOW = Number(TIMESTAMP) * 1000;
const SIGNATURE = computeSignature(SECRET, TIMESTAMP, BODY);

describe("computeSignature", () => {
  it("matches a known HMAC-SHA256 vector", () => {
    expect(SIGNATURE).toBe(
      "900eeb7bca84db0c267a8caa43c5e48bd85ca7814054458a0f8bb94374ff5493",
    );
  });

  it("is deterministic for the same inputs", () => {
    expect(computeSignature(SECRET, TIMESTAMP, BODY)).toBe(SIGNATURE);
  });

  it("changes when any input changes", () => {
    expect(computeSignature(OTHER_SECRET, TIMESTAMP, BODY)).not.toBe(SIGNATURE);
    expect(computeSignature(SECRET, "1700000001", BODY)).not.toBe(SIGNATURE);
    expect(computeSignature(SECRET, TIMESTAMP, `${BODY} `)).not.toBe(SIGNATURE);
  });
});

describe("isSignatureValid", () => {
  const valid = {
    secret: SECRET,
    timestamp: TIMESTAMP,
    signature: SIGNATURE,
    body: BODY,
    toleranceSeconds: 60,
    now: NOW,
  };

  it("accepts a matching signature", () => {
    expect(isSignatureValid(valid)).toBe(true);
  });

  it("accepts an upper-case hex signature", () => {
    expect(
      isSignatureValid({ ...valid, signature: SIGNATURE.toUpperCase() }),
    ).toBe(true);
  });

  it("rejects a tampered body", () => {
    expect(isSignatureValid({ ...valid, body: `${BODY} ` })).toBe(false);
  });

  it("rejects a signature made with another secret", () => {
    expect(isSignatureValid({ ...valid, secret: OTHER_SECRET })).toBe(false);
  });

  it("accepts a timestamp at the tolerance boundary", () => {
    expect(isSignatureValid({ ...valid, now: NOW + 60_000 })).toBe(true);
  });

  it("rejects a timestamp beyond the tolerance", () => {
    expect(isSignatureValid({ ...valid, now: NOW + 61_000 })).toBe(false);
    expect(isSignatureValid({ ...valid, now: NOW - 61_000 })).toBe(false);
  });

  it("rejects malformed signatures", () => {
    for (const signature of ["", "zz", "00", "9".repeat(63), "9".repeat(65)]) {
      expect(isSignatureValid({ ...valid, signature })).toBe(false);
    }
  });

  it("rejects malformed timestamps", () => {
    for (const timestamp of ["", "abc", "-1", "17e9", "1.5", "1".repeat(12)]) {
      expect(isSignatureValid({ ...valid, timestamp })).toBe(false);
    }
  });
});
