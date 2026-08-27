export const MAX_INPUT_LENGTH = 1024;
export const MAX_TARGET_LENGTH = 128;

export const MAX_BODY_BYTES = 32 * 1024;
export const MAX_AUTHORIZATION_LENGTH = 4096;

export const SECRET_MIN_LENGTH = 32;

export const VERIFY_PATH_PATTERN = /^\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/;
export const VERIFY_PATH_MAX_LENGTH = 256;

export const JWT_MAX_LIFETIME = 120;
export const JWT_CLOCK_SKEW_TOLERANCE = 30;

export const ARGON2_VERIFY_TIMEOUT_MS = 10_000;
export const ARGON2_RELEASE_WATCHDOG_MS = 15_000;

export const REDIS_CONNECT_TIMEOUT_MS = 2_000;
export const REDIS_RECORD_TIMEOUT_MS = 3_000;
export const REDIS_MAX_RECONNECT_ATTEMPTS = 2;
