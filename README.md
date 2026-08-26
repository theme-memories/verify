# theme-memories/verify

Argon2 password-verification service, deployed as a [Vercel](https://vercel.com)
Serverless Function. It offloads the expensive CPU work of `argon2.verify`
(and the associated replay protection) from the main application.

The service exposes **a single POST endpoint** (configurable via
`VERIFY_PATH`) protected by an HS256 JWT, performs the Argon2 check with a
bounded concurrency limiter, and returns a simple `{ success, errcode }`
JSON envelope.

---

## Architecture

The code is split into small, dependency-injecting modules under `src/`:

| File                        | Responsibility                                                                                      |
| --------------------------- | --------------------------------------------------------------------------------------------------- |
| `src/index.ts`              | Bootstrap: load config, build store + limiter, assemble app, export default handler (Vercel entry). |
| `src/config.ts`             | Constants + `loadConfig(env)` (validates env, pure function).                                       |
| `src/types.ts`              | Shared TypeScript types (`AppConfig`, `ReplayStore`, …).                                            |
| `src/redis-store.ts`        | Replay protection via Redis `SET jti 1 NX EX`; fail-closed, lazy connect, timeout-wrapped.          |
| `src/semaphore.ts`          | `Semaphore` bounding concurrent Argon2 verifications.                                               |
| `src/phc.ts`                | Argon2 PHC format validation + `EXPECTED_ARGON2` cost parameters.                                   |
| `src/responses.ts`          | Common `{ success, errcode }` response helpers.                                                     |
| `src/audit.ts`              | Structured JSON audit logging of every verification attempt.                                        |
| `src/middleware/auth.ts`    | JWT verification chain factories (jwt, exp/iat, subject, replay).                                   |
| `src/middleware/request.ts` | Content-type and content-length request guards.                                                     |
| `src/verify-handler.ts`     | The Argon2 orchestration: rehash check, semaphore, abort race, watchdog.                            |
| `src/app.ts`                | `buildApp(config, deps)` — wires security headers, route chain, error handlers.                     |

Tests live in `tests/` (same level as `src/`).

---

## Local development

```bash
pnpm install
cp .env.example .env      # fill in real values (or use the defaults for tests)
pnpm test                 # runs the vitest suite
```

`vitest.config.ts` injects a test environment (`VERIFY_PATH=/test-path` and
test secrets) **before** the module graph is imported, so `loadConfig` works
without a real Redis (the `redis` client is mocked in the tests).

---

## Deploying to Vercel

### Prerequisites

1. A **Redis** instance reachable from Vercel (e.g. [Upstash Redis](https://upstash.com/)
   or your own). This is used only for replay (`jti`) protection.
2. The calling service must issue **HS256 JWTs** with the claims/values this
   service expects (see _Security model_ below).

### Steps

1. **Import the repository** into Vercel.
2. **Set the Root Directory to `verify/`** (this folder), since it is a
   standalone package within the `theme-memories` monorepo.
3. **Framework preset:** choose **Other** (no framework). The function is
   plain Node.
4. **Build & Install:**
   - Install Command: `pnpm install` (or leave default).
   - Build Command: _none_ (the function is run directly from `src/index.ts`).
   - Output Directory: _none_.
5. **Function runtime:** Node.js (the default). `vercel.json` already maps the
   handler:
   ```json
   {
     "functions": {
       "src/index.ts": { "maxDuration": 15, "supportsCancellation": true }
     }
   }
   ```
   - `maxDuration: 15` keeps the function within the Hobby/Pro limit and matches
     the internal `argon2` watchdog (15 s) and request `timeout(10 s)`.
   - `supportsCancellation: true` enables request-abort propagation (the handler
     races `argon2.verify` against the abort signal to stop CPU work when a
     client disconnects).
   - **Entry shape:** `src/index.ts` default-exports `handle(app)` from
     `hono/vercel`, i.e. a _callable handler_ (Vercel requires the default
     export to be a function or server — a raw Hono instance is rejected with
     "Invalid export found"). The Hono `app` is also exported as a named export
     for the test suite.
6. **Set Environment Variables** (see table below). They are required; the
   function throws at startup if any are missing/invalid.

### Environment variables

| Variable                  | Description                                                                                                   |
| ------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `ARGON2_PEPPER`           | Server-side pepper mixed into every hash. **≥ 32 bytes.** Must match the value used when hashes were created. |
| `JWT_VERIFICATION_SECRET` | HMAC secret (HS256) to verify caller JWTs. **≥ 32 bytes.**                                                    |
| `JWT_ISSUER`              | Expected `iss` of JWTs. Must be a valid **HTTPS** URL.                                                        |
| `JWT_AUDIENCE`            | Expected `aud` of JWTs. Must be a valid **HTTPS** URL.                                                        |
| `VERIFY_PATH`             | Path of the endpoint, e.g. `/verify`. Must start with `/`, allowlist chars only, no trailing slash.           |
| `REDIS_HOST`              | Redis hostname/IP.                                                                                            |
| `REDIS_PORT`              | Redis port (1–65535).                                                                                         |
| `REDIS_PASSWORD`          | Redis password (store connects as the `default` user).                                                        |

---

## Important notes / gotchas

- **Argon2 is a native module.** `argon2` ships prebuilt binaries for common
  platforms. On Vercel this generally works with the Node runtime, but verify a
  cold start succeeds in your target region/architecture; if you hit native
  binding errors, ensure the module is **not** bundled (keep it in
  `node_modules`) and that `pnpm` installs it for the deployed platform.
- **Redis TLS.** The current `src/redis-store.ts` sets `tls: false`. This is
  fine for an in-VPC/plaintext Redis, but most managed Redis (e.g. Upstash over
  the public internet) **requires TLS**. Flip `tls: true` (and adjust auth) in
  `createRedisStore` if your provider uses a `rediss://` endpoint.
- **Fail-closed replay check.** If Redis is unreachable the service responds
  `503 SERVICE_UNAVAILABLE` rather than skipping replay protection.
- **Concurrency.** Only `2` Argon2 verifications run concurrently (with a small
  wait queue); overflow returns `429 TOO_MANY_REQUESTS`.
- **Reject-on-rehash.** Hashes whose cost parameters differ from
  `EXPECTED_ARGON2` are rejected (`VERIFY_FAILED`) so clients re-hash with the
  approved parameters.

---

## Security model

1. **JWT auth:** caller must present `Authorization: Bearer <jwt>` signed with
   `JWT_VERIFICATION_SECRET` (HS256 only — `alg=none`/HS384/HS512 are rejected), with a
   matching `iss`/`aud`, a required `iat`, and `exp` after `iat`. Token lifetime
   is capped (`JWT_MAX_LIFETIME = 120s`) with a small clock-skew tolerance.
2. **Subject check:** `sub` must match `^[A-Za-z0-9_-]{1,128}$` (else `403`).
3. **Replay protection:** each token's `jti` is recorded in Redis with a TTL;
   reuse is rejected (`REPLAY_DETECTED`). Missing/invalid `jti` ⇒ `401`.
4. **Input validation:** body must be JSON with string `input`/`target`, the
   target must be a well-formed `$argon2id$` PHC hash, sizes are bounded.
5. **Hardening headers:** `secureHeaders` (DENY frame, deny-all CSP, no
   referrer), `Cache-Control: no-store` on all responses, body size/time limits.

---

## API contract

`POST {VERIFY_PATH}` with `Content-Type: application/json`:

```json
{ "input": "<candidate password>", "target": "<argon2id PHC hash>" }
```

Responses (all `{ "success": boolean, "errcode": string | null }`):

| Status | errcode                             | Meaning                                                   |
| ------ | ----------------------------------- | --------------------------------------------------------- |
| 200    | `null`                              | Verification succeeded (`success: true`).                 |
| 200    | `VERIFY_FAILED`                     | Hash valid but password/pepper mismatch, or needs rehash. |
| 400    | `INVALID_INPUT` / `INVALID_REQUEST` | Malformed body / JSON / validation failure.               |
| 401    | `UNAUTHORIZED`                      | Bad/missing/expired JWT, or replayed/missing `jti`.       |
| 403    | `FORBIDDEN`                         | Invalid token `sub`.                                      |
| 405    | `METHOD_NOT_ALLOWED`                | Non-POST method.                                          |
| 408    | `REQUEST_CANCELLED`                 | Client disconnected before verification finished.         |
| 413    | `PAYLOAD_TOO_LARGE`                 | Body exceeds the 32 KiB limit.                            |
| 429    | `TOO_MANY_REQUESTS`                 | Argon2 concurrency/queue exhausted.                       |
| 500    | `INTERNAL_ERROR`                    | Implemented as a generic server error.                    |
| 503    | `SERVICE_UNAVAILABLE`               | Replay store (Redis) unreachable (fail-closed).           |
