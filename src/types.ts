// Shared type definitions used across the verify service.
// Kept in one place to avoid circular imports between feature modules.

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

export interface ReplayStore {
  record(jti: string, ttlSeconds: number): Promise<boolean>;
}
