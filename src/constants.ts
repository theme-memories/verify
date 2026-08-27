/**
 * Shared limits, patterns and tunables.
 *
 * These are defensive, attack-surface constants. They bound request sizes,
 * token lifetimes and the argon2/redis timeouts so the verification endpoint
 * fails safe under load or abuse.
 */

// Argon2 inputs. Kept small because the hashing cost lives in the hash itself.
export const MAX_INPUT_LENGTH = 1024;
export const MAX_TARGET_LENGTH = 128;

// Request body / header ceilings (the route also enforces these via bodyLimit).
export const MAX_BODY_BYTES = 32 * 1024;
export const MAX_AUTHORIZATION_LENGTH = 4096;

// Minimum length for the two high-entropy secrets (bytes, not chars).
export const SECRET_MIN_LENGTH = 32;

// VERIFY_PATH validation: must look like "/a/b/c" with a safe character set.
export const VERIFY_PATH_PATTERN = /^\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/;
export const VERIFY_PATH_MAX_LENGTH = 256;

// JWT claim bounds. Tokens are short-lived, single-use (replay-protected) and
// may only drift within a small clock-skew window.
export const JWT_MAX_LIFETIME = 120;
export const JWT_CLOCK_SKEW_TOLERANCE = 30;

// How long the hono route waits for argon2 before answering 504, and how long
// we keep a semaphore permit reserved if the native call never settles.
export const ARGON2_VERIFY_TIMEOUT_MS = 10_000;
export const ARGON2_RELEASE_WATCHDOG_MS = 15_000;

// Redis SLA: connect + record must finish quickly or we fail closed.
export const REDIS_CONNECT_TIMEOUT_MS = 2_000;
export const REDIS_RECORD_TIMEOUT_MS = 3_000;
export const REDIS_MAX_RECONNECT_ATTEMPTS = 2;
