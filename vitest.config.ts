import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    env: {
      ARGON2_SECRET: "test-pepper-secret-1234567890123456",
      JWT_SECRET: "test-jwt-secret-1234567890123456",
      JWT_ISSUER: "https://test.example",
      JWT_AUDIENCE: "https://test-verify.example",
      VERIFY_PATH: "/test-path",
    },
  },
});
