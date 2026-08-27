/**
 * Unit tests for the PHC string helpers.
 *
 * `isValidArgon2Phc` is *structural only*: it accepts any well-formed argon2id
 * hash (including non-default cost/version) and rejects only malformed ones.
 * Cost/version enforcement happens later via argon2.needsRehash().
 */

import { describe, expect, it } from "vitest";
import { ARGON2_PHC_PREFIX, isValidArgon2Phc } from "../argon2.js";
import { EXPECTED_ARGON2 } from "../concurrency.js";

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

describe("argon2 cost parameters", () => {
  it("expects the documented cost parameters", () => {
    expect(EXPECTED_ARGON2).toEqual({
      memoryCost: 19456,
      timeCost: 2,
      parallelism: 1,
    });
  });
});

describe("isValidArgon2Phc", () => {
  it("accepts the expected cost parameters", () => {
    expect(isValidArgon2Phc(phcString(19_456, 2, 1))).toBe(true);
  });

  it("accepts non-default cost parameters (cost is enforced by needsRehash)", () => {
    expect(isValidArgon2Phc(phcString(65_536, 3, 4))).toBe(true);
  });

  it("accepts a non-default version (version is enforced by needsRehash)", () => {
    expect(isValidArgon2Phc(phcString(19_456, 2, 1, "$argon2id$", 0x10))).toBe(
      true,
    );
  });

  it("rejects a non-argon2id algorithm", () => {
    expect(isValidArgon2Phc(phcString(65_536, 3, 4, "$argon2i$"))).toBe(false);
  });

  it("rejects a malformed hash", () => {
    expect(isValidArgon2Phc("not-a-valid-argon2-hash")).toBe(false);
  });

  it("rejects an argon2id-prefixed but malformed hash", () => {
    expect(
      isValidArgon2Phc("$argon2id$v=19$m=65536$c2FsdHNhbHQ$ZGF0YQ$extra"),
    ).toBe(false);
  });

  it("rejects a salt that is not canonical base64", () => {
    const digest = Buffer.from("0123456789abcdef0123456789abcdef")
      .toString("base64")
      .replace(/=+$/, "");
    expect(
      isValidArgon2Phc(
        `${ARGON2_PHC_PREFIX}v=19$m=65536,t=3,p=4$not_base64!${digest}`,
      ),
    ).toBe(false);
  });

  it("rejects a digest that is not canonical base64", () => {
    const salt = Buffer.from("0123456789abcdef")
      .toString("base64")
      .replace(/=+$/, "");
    expect(
      isValidArgon2Phc(
        `${ARGON2_PHC_PREFIX}v=19$m=65536,t=3,p=4$${salt}$not_base64!`,
      ),
    ).toBe(false);
  });

  it("rejects a missing parameter", () => {
    const salt = Buffer.from("0123456789abcdef")
      .toString("base64")
      .replace(/=+$/, "");
    const digest = Buffer.from("0123456789abcdef0123456789abcdef")
      .toString("base64")
      .replace(/=+$/, "");
    expect(
      isValidArgon2Phc(
        `${ARGON2_PHC_PREFIX}v=19$m=65536,t=3$${salt}$${digest}`,
      ),
    ).toBe(false);
  });

  it("rejects an unknown parameter key", () => {
    const salt = Buffer.from("0123456789abcdef")
      .toString("base64")
      .replace(/=+$/, "");
    const digest = Buffer.from("0123456789abcdef0123456789abcdef")
      .toString("base64")
      .replace(/=+$/, "");
    expect(
      isValidArgon2Phc(
        `${ARGON2_PHC_PREFIX}v=19$x=1,m=65536,t=3,p=4$${salt}$${digest}`,
      ),
    ).toBe(false);
  });
});
