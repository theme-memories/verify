export const ARGON2_PHC_PREFIX = "$argon2id$";

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
