import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    env: {
      ARGON2_SECRET: "test-pepper-secret-123456789",
      JWT_SECRET: "test-jwt-secret-123456789",
      JWT_ISSUER: "https://test.example",
      JWT_AUDIENCE: "https://test-verify.example",
      VERIFY_PATH: "/test-path",
    },
  },
});
