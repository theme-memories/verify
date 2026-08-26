// The actual Argon2 verification handler (final link in the route chain).
//
// Responsibilities:
// - Reject hashes that need rehash (cost mismatch) as VERIFY_FAILED.
// - Bound concurrency via the injected `argon2Limiter` semaphore; 429 on overflow.
// - Race the native `argon2.verify` against request cancellation (abort signal)
//   so a disconnected client does not keep burning CPU.
// - A watchdog releases the semaphore permit even if `argon2.verify` hangs,
//   preventing a stuck verification from starving the whole function.

import argon2 from "argon2";
import type { MiddlewareHandler } from "hono";
import type { Semaphore } from "./semaphore.js";
import { ARGON2_RELEASE_WATCHDOG_MS } from "./config.js";
import { EXPECTED_ARGON2 } from "./phc.js";
import { auditVerify } from "./audit.js";
import { invalidInput, verifyFailed } from "./responses.js";

interface VerifyHandlerDeps {
  argon2Secret: string;
  argon2Limiter: Semaphore;
}

export function createVerifyHandler({
  argon2Secret,
  argon2Limiter,
}: VerifyHandlerDeps): MiddlewareHandler {
  return async (c) => {
    const { input, target } = c.req.valid("json" as never) as {
      input: string;
      target: string;
    };

    let needsRehash: boolean;
    try {
      needsRehash = argon2.needsRehash(target, EXPECTED_ARGON2);
    } catch {
      return invalidInput(c);
    }

    if (needsRehash) {
      auditVerify(c, false, "VERIFY_FAILED");
      return verifyFailed(c);
    }

    const signal = c.req.raw.signal;
    if (signal.aborted) {
      return c.json({ success: false, errcode: "REQUEST_CANCELLED" }, 408);
    }

    let success: boolean;
    try {
      await argon2Limiter.acquire();
    } catch {
      return c.json({ success: false, errcode: "TOO_MANY_REQUESTS" }, 429, {
        "Retry-After": "1",
      });
    }

    let released = false;
    // Idempotent release: frees the semaphore permit exactly once, whether
    // verification resolves, rejects, or the watchdog fires.
    const releaseOnce = (): void => {
      if (released) {
        return;
      }
      released = true;
      clearTimeout(watchdog);
      argon2Limiter.release();
    };
    // Safety net: if Argon2 hangs past the watchdog, still release the permit
    // so the limiter cannot deadlock the function.
    const watchdog = setTimeout(releaseOnce, ARGON2_RELEASE_WATCHDOG_MS);

    try {
      const verifyPromise = argon2.verify(target, input, {
        secret: Buffer.from(argon2Secret, "utf8"),
      });
      void verifyPromise.then(releaseOnce, releaseOnce);

      let onAbort: (() => void) | undefined;
      const abortPromise = new Promise<"aborted">((resolve) => {
        onAbort = () => resolve("aborted");
        signal.addEventListener("abort", onAbort, { once: true });
      });

      const result = await Promise.race([verifyPromise, abortPromise]);

      if (onAbort) {
        signal.removeEventListener("abort", onAbort);
      }

      if (result === "aborted") {
        return c.json({ success: false, errcode: "REQUEST_CANCELLED" }, 408);
      }

      success = result;
    } catch (error) {
      console.error(
        JSON.stringify({
          event: "argon2_verify_error",
          name: error instanceof Error ? error.name : "UnknownError",
        }),
      );
      auditVerify(c, false, "INTERNAL_ERROR");
      return c.json({ success: false, errcode: "INTERNAL_ERROR" }, 500);
    }

    auditVerify(c, success, success ? null : "VERIFY_FAILED");
    return c.json({
      success,
      errcode: success ? null : "VERIFY_FAILED",
    });
  };
}
