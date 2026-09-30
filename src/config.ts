import type { AppConfig } from "./types.js";

const ROUTE_NAME_PATTERN = /^[a-z0-9]{1,64}$/;

export const MAX_BODY_BYTES = 4 * 1024;
export const MAX_HASH_LENGTH = 512;
export const MIN_USER_INPUT_LENGTH = 15;
export const MAX_USER_INPUT_LENGTH = 128;
export const USER_INPUT_PATTERN = /^[A-Za-z0-9!@#$%^&*]*$/;
export const MIN_SECRET_BYTES = 32;
export const HMAC_TIMESTAMP_TOLERANCE_SECONDS = 30;
export const SIGNATURE_HEADER = "Request-Signature";
export const TIMESTAMP_HEADER = "Request-Timestamp";
export const CONTENT_TYPE = "application/json";
export const ARGON2ID_PREFIX = "$argon2id$";

const BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;

export const ARGON2_VERIFY_OPTIONS = {
  timeCost: 2,
  memoryCost: 19456,
  parallelism: 1,
} as const;

// Secrets are decoded only to measure their byte length. The raw env value (the
// base64 text from `openssl rand -base64 32`) is what is used as the HMAC key
// and the Argon2 secret, so the Worker must consume that exact same string.
function hasSufficientEntropy(secret: string): boolean {
  return (
    BASE64_PATTERN.test(secret) &&
    Buffer.from(secret, "base64").length >= MIN_SECRET_BYTES
  );
}

export function loadConfig(env: NodeJS.ProcessEnv): AppConfig | undefined {
  const routeName = env.ARGON2_VERIFY_ROUTE?.trim();

  if (routeName === undefined || !ROUTE_NAME_PATTERN.test(routeName)) {
    console.warn(
      "ARGON2_VERIFY_ROUTE must be 1-64 lowercase alphanumeric characters; the verification endpoint is disabled.",
    );
    return undefined;
  }

  const hmacSecret = env.ARGON2_HMAC_SECRET;

  if (hmacSecret === undefined || !hasSufficientEntropy(hmacSecret)) {
    console.warn(
      "ARGON2_HMAC_SECRET must be base64 encoding at least 32 bytes (256-bit); generate with `openssl rand -base64 32`; the verification endpoint is disabled.",
    );
    return undefined;
  }

  const argon2Pepper = env.ARGON2_PEPPER;

  if (argon2Pepper !== undefined && !hasSufficientEntropy(argon2Pepper)) {
    console.warn(
      "ARGON2_PEPPER must be base64 encoding at least 32 bytes (256-bit) when set; generate with `openssl rand -base64 32`; the verification endpoint is disabled.",
    );
    return undefined;
  }

  return { verifyRoute: `/${routeName}`, hmacSecret, argon2Pepper };
}
