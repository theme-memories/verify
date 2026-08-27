import {
  SECRET_MIN_LENGTH,
  VERIFY_PATH_PATTERN,
  VERIFY_PATH_MAX_LENGTH,
} from "./constants.js";

export type EnvSource = Record<string, string | undefined>;

export interface RedisConnectionConfig {
  host: string;
  port: number;
  password: string;
}

export interface AppConfig {
  jwtIssuer: string;
  jwtAudience: string;
  verifyPath: string;
  jwtSecret: string;
  argon2Secret: string;
  redis: RedisConnectionConfig;
}

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
    jwtSecret: requireStrongEnv(env, "JWT_SECRET"),
    argon2Secret: requireStrongEnv(env, "ARGON2_SECRET"),
    redis: {
      host: redisHost,
      port: redisPort,
      password: requireEnv(env, "REDIS_PASSWORD"),
    },
  };
}

let config: AppConfig;
try {
  config = loadConfig(process.env);
} catch (error) {
  console.error(
    JSON.stringify({
      event: "config_error",
      reason: error instanceof Error ? error.message : "unknown",
    }),
  );
  throw error;
}

export const redisConfig = config.redis;
export const jwtIssuer = config.jwtIssuer;
export const jwtAudience = config.jwtAudience;
export const verifyPath = config.verifyPath;
export const jwtSecret = config.jwtSecret;
export const argon2Secret = config.argon2Secret;

console.info(
  JSON.stringify({
    event: "config_loaded",
    replay_protection: true,
  }),
);
