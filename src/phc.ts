// Argon2 PHC (PHC string format) handling.
//
// EXPECTED_ARGON2 pins the cost parameters we accept. Any hash whose cost
// differs (memoryCost / timeCost / parallelism / version) is treated as a
// failed verification via `argon2.needsRehash`, forcing callers to re-hash
// with the approved parameters. This prevents downgrade attacks.

export const EXPECTED_ARGON2 = {
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
};

// Validates that `value` is canonical (non-padded, standard-alphabet) Base64,
// matching the encoding Argon2 uses for salt/digest so we reject tampered input.
function isCanonicalBase64(value: string): boolean {
  if (!/^[A-Za-z0-9+/]+$/.test(value)) return false;
  const decoded = Buffer.from(value, "base64");
  return decoded.toString("base64").replace(/=+$/, "") === value;
}

export function isValidArgon2Phc(target: string): boolean {
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
