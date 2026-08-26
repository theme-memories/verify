// Configuration constants and environment parsing for the verify service.
//
// `loadConfig` is a PURE function: it takes an env source (e.g. `process.env`)
// and returns a validated `AppConfig`, or throws if any required value is
// missing/invalid. It is called once at startup from `index.ts`.
//
// Security notes:
// - JWT verification secret and the Argon2 pepper MUST be >= 32 bytes (see SECRET_MIN_LENGTH).
// - JWT_ISSUER / JWT_AUDIENCE must be HTTPS URLs (used to pin the token audience).
// - VERIFY_PATH is the only route this service exposes; it is validated against
//   a strict allowlist pattern so it cannot break routing or inject path segments.

import type { AppConfig, EnvSource } from "./types.js";

export const ARGON2_PHC_PREFIX = "$argon2id$";
export const MAX_INPUT_LENGTH = 1024;
export const MAX_TARGET_LENGTH = 128;
export const MAX_BODY_BYTES = 32 * 1024;
export const MAX_AUTHORIZATION_LENGTH = 4096;
export const SECRET_MIN_LENGTH = 32;
export const VERIFY_PATH_PATTERN = /^\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/;
export const VERIFY_PATH_MAX_LENGTH = 256;
export const REDIS_CONNECT_TIMEOUT_MS = 2_000;
export const REDIS_RECORD_TIMEOUT_MS = 3_000;
export const REDIS_MAX_RECONNECT_ATTEMPTS = 2;
export const JWT_MAX_LIFETIME = 120;
export const JWT_CLOCK_SKEW_TOLERANCE = 30;
export const ARGON2_RELEASE_WATCHDOG_MS = 15_000;
export const ARGON2_LIMITER_PERMITS = 2;
export const ARGON2_LIMITER_MAX_QUEUE = 16;

function requireEnv(env: EnvSource, name: string): string {
  const raw = env[name];
  if (!raw) {
    throw new Error(`${name} is not set`);
  }
  const value = raw.trim();
  if (value.length === 0) {
    throw new Error(`${name} is not set`);
  }
  return value;
}

function requireStrongEnv(env: EnvSource, name: string): string {
  const value = requireEnv(env, name);
  if (Buffer.byteLength(value, "utf8") < SECRET_MIN_LENGTH) {
    throw new Error(`${name} must be at least ${SECRET_MIN_LENGTH} bytes long`);
  }
  return value;
}

function requireHttpsUrl(env: EnvSource, name: string): string {
  const value = requireEnv(env, name);
  try {
    if (new URL(value).protocol !== "https:") {
      throw new Error();
    }
  } catch {
    throw new Error(`${name} must be a valid HTTPS URL`);
  }
  return value;
}

export function loadConfig(env: EnvSource): AppConfig {
  const jwtIssuer = requireHttpsUrl(env, "JWT_ISSUER");
  const jwtAudience = requireHttpsUrl(env, "JWT_AUDIENCE");

  const verifyPath = requireEnv(env, "VERIFY_PATH");
  if (verifyPath.length > VERIFY_PATH_MAX_LENGTH) {
    throw new Error(
      `VERIFY_PATH must be at most ${VERIFY_PATH_MAX_LENGTH} characters`,
    );
  }
  if (verifyPath.endsWith("/")) {
    throw new Error('VERIFY_PATH must not end with "/"');
  }
  if (!VERIFY_PATH_PATTERN.test(verifyPath)) {
    throw new Error(
      'VERIFY_PATH must start with "/" and contain only letters, numbers, "_", "-", and "/"',
    );
  }

  const redisHost = requireEnv(env, "REDIS_HOST");
  const redisPortRaw = requireEnv(env, "REDIS_PORT");
  const redisPort = Number(redisPortRaw);
  if (!Number.isInteger(redisPort) || redisPort < 1 || redisPort > 65535) {
    throw new Error("REDIS_PORT must be an integer between 1 and 65535");
  }

  return {
    jwtIssuer,
    jwtAudience,
    verifyPath,
    jwtSecret: requireStrongEnv(env, "JWT_VERIFICATION_SECRET"),
    argon2Secret: requireStrongEnv(env, "ARGON2_PEPPER"),
    redis: {
      host: redisHost,
      port: redisPort,
      password: requireEnv(env, "REDIS_PASSWORD"),
    },
  };
}
