import { defineConfig } from "vitest/config";

// Test configuration.
//
// `test.env` injects these values into `process.env` BEFORE the module graph
// is imported. This is essential because `src/index.ts` reads configuration
// once at import time (cold-start semantics), so the verify app is built with
// VERIFY_PATH="/test-path" and the test secrets below.
//
// The Redis client is mocked in tests/index.test.ts, so REDIS_* here only need
// to be present/valid for `loadConfig`; no real Redis is contacted.
export default defineConfig({
  test: {
    env: {
      ARGON2_SECRET: "test-pepper-secret-1234567890123456",
      JWT_SECRET: "test-jwt-secret-1234567890123456",
      JWT_ISSUER: "https://test.example",
      JWT_AUDIENCE: "https://test-verify.example",
      VERIFY_PATH: "/test-path",
      REDIS_HOST: "localhost",
      REDIS_PORT: "6379",
      REDIS_PASSWORD: "test-password",
    },
  },
});
