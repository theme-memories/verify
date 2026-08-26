// Re-export shim.
//
// `src/app.ts` is the actual Vercel entry (it owns the bootstrap and the
// `export default` handler). This module re-exports its named bindings so the
// test suite (and any consumer) can keep importing from `./index.js`.

export {
  app,
  argon2Limiter,
  replayStore,
  JWT_ISSUER,
  JWT_AUDIENCE,
  VERIFY_PATH,
  ARGON2_PHC_PREFIX,
  EXPECTED_ARGON2,
  Semaphore,
  loadConfig,
} from "./app.js";
export { default } from "./app.js";
