# theme-memories/verify

Argon2 verification module

## Introduction

Argon2 password-verification endpoint, deployed on **Vercel**, that offloads the
expensive `argon2.verify()` from Cloudflare Workers (which have no native Argon2
support). A Cloudflare Worker mints a short-lived HS256 JWT and POSTs the
plaintext password + Argon2 PHC hash here; this service verifies it and returns
`{ "success": true | false }`.

## How it fits together

```
Cloudflare Worker ──JWT (HS256)──▶ Vercel /verify ──▶ argon2.verify()
        │                                  │
        └── same ARGON2_SECRET (pepper) ────┘
        └── same JWT_SECRET (signs tokens)─┘
```

- **`ARGON2_SECRET`** is the pepper mixed into every hash. It must be **byte-for-byte
  identical** between the Worker that originally hashed the password and this
  verifier, or every verification fails.
- **`JWT_SECRET`** must be shared with the Worker that signs the bearer tokens.

## Endpoint contract

`POST ${VERIFY_PATH}` with `Content-Type: application/json`:

```json
{ "input": "<plaintext password>", "target": "<argon2id$... PHC hash>" }
```

Headers: `Authorization: Bearer <HS256 JWT>` (iss/aud/jti/exp/iat/sub enforced).

Responses are always JSON `{ "success": boolean, "errcode": string | null }`:

| errcode               | HTTP | meaning                                      |
| --------------------- | ---- | -------------------------------------------- |
| `success:true`        | 200  | password matched                             |
| `VERIFY_FAILED`       | 200  | password did **not** match / bad hash cost   |
| `INVALID_INPUT`       | 400  | malformed JSON / body / hash                 |
| `INVALID_REQUEST`     | 400  | unparseable JSON                             |
| `UNAUTHORIZED`        | 401  | missing/expired/bad JWT, bad jti             |
| `FORBIDDEN`           | 403  | invalid `sub`                                |
| `REQUEST_CANCELLED`   | 408  | client disconnected                          |
| `PAYLOAD_TOO_LARGE`   | 413  | body/Content-Length over limit               |
| `TOO_MANY_REQUESTS`   | 429  | concurrency limit reached (`Retry-After: 1`) |
| `REPLAY_DETECTED`     | 401  | jti already used (Redis)                     |
| `SERVICE_UNAVAILABLE` | 503  | Redis store failed -> fail closed            |
| `TIMEOUT`             | 504  | verification exceeded the deadline           |
| `INTERNAL_ERROR`      | 500  | unexpected error                             |

## Vercel dashboard checklist

### 1. Environment Variables (required)

Create **all eight** under **Settings → Environment Variables** (Production,
Preview, and Development). The **names are fixed** — renaming them breaks the
code. Values mirror `.env.example`:

| Variable         | Notes                                                          |
| ---------------- | -------------------------------------------------------------- |
| `ARGON2_SECRET`  | ≥ 32 bytes. Must match the hashing Worker's pepper. **Secret** |
| `JWT_SECRET`     | ≥ 32 bytes. Must match the token-signing Worker. **Secret**    |
| `JWT_ISSUER`     | `https://…` URL the tokens are issued from                     |
| `JWT_AUDIENCE`   | `https://…` URL this service identifies as                     |
| `VERIFY_PATH`    | route path, e.g. `/verify`; `/`-prefixed, no trailing slash    |
| `REDIS_HOST`     | hostname only (no `redis://` scheme)                           |
| `REDIS_PORT`     | usually `6379`                                                 |
| `REDIS_PASSWORD` | Redis password / token                                         |

> The service reads these **once at cold start** and refuses to boot if any are
> missing or invalid, so a misconfigured deploy fails loudly instead of serving
> traffic.

### 2. Runtime: use **Node.js**, not Edge

`argon2` is a **native module** and the `redis` client is Node-only. Set the
function's runtime to **Node.js** (the default for `src/index.ts` via
`vercel.json`). The **Edge runtime will not work** here.

### 3. Function settings (`vercel.json`)

`vercel.json` already pins:

- `maxDuration: 15` — the function may run up to 15s. **Check your plan's cap:**
  Hobby plans limit function duration (often ≤ 10s); if deploys fail or time out,
  either lower this value or upgrade the plan.
- `supportsCancellation: true` — lets in-flight verifications be aborted when the
  client disconnects (only effective on the Node runtime).

### 4. Region & Redis latency

Place the function and the Redis instance in the **same Vercel region** so the
replay-check (`REDIS_CONNECT_TIMEOUT_MS = 2s`, `REDIS_RECORD_TIMEOUT_MS = 3s`)
doesn't trip under normal latency. The store is **fail-closed**: if Redis is
unreachable the endpoint returns `503`, never "allow".

### 5. Redis TLS (likely needed)

The code connects with `tls: false`. Managed Redis on Vercel (e.g. **Upstash**)
is **TLS-only**. If you use such a provider, change `socket.tls` to `true` in
[`src/redis.ts`](src/redis.ts) before deploying (this is a code change, not an
env change). The host/port/password come from the env vars above.

### 6. Routing to the function

`vercel.json` declares `functions["src/index.ts"]`, but Vercel also needs
requests to actually reach it. Either:

- keep the handler at a path Vercel treats as a function (e.g. `api/index.ts`),
  **or**
- add a `rewrites` rule so all (or the relevant) paths dispatch to this function.

Make sure `VERIFY_PATH` matches the path the Cloudflare Worker actually calls.

## Local development & tests

```bash
pnpm install
cp .env.example .env   # fill in real values (or rely on vitest.config.ts env)
pnpm test              # vitest, real argon2 + mocked redis
```

`vitest.config.ts` seeds a valid test environment so the config singleton loads
at import. The Redis client is mocked per-file so replay protection can be
asserted without a live Redis; `argon2` itself runs against its real native
bindings.

## Source layout

| File                 | Responsibility                                        |
| -------------------- | ----------------------------------------------------- |
| `src/index.ts`       | Hono wiring: routes, guards, the verify handler       |
| `src/config.ts`      | env validation + resolved config singletons           |
| `src/redis.ts`       | `ReplayStore` (Redis) — fail-closed jti recording     |
| `src/concurrency.ts` | `Semaphore`, expected Argon2 cost, verify limiter     |
| `src/argon2.ts`      | PHC string shape validation                           |
| `src/middleware.ts`  | per-request guards (JWT, claims, content, audit)      |
| `src/errors.ts`      | status → `errcode` mapping                            |
| `src/constants.ts`   | limits, patterns, timeouts                            |
| `src/test/*`         | mirrors the above (config / semaphore / argon2 / app) |
