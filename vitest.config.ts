import { defineConfig } from "vitest/config";

// Test environment. These values mirror a valid production environment so the
// config singleton in src/config.ts can load at import time. `argon2` runs
// against its real native bindings in tests; only the `redis` client is mocked
// (see src/test/app.test.ts) so replay protection can be exercised without a
// live Redis.
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
