/**
 * Unit tests for the Semaphore used to bound concurrent argon2 verifications.
 */

import { describe, expect, it } from "vitest";
import { Semaphore } from "../concurrency.js";

describe("Semaphore", () => {
  it("tryAcquire returns true when permits are available", () => {
    const sem = new Semaphore(2, 10);
    expect(sem.tryAcquire()).toBe(true);
    expect(sem.tryAcquire()).toBe(true);
  });

  it("tryAcquire returns false when permits are exhausted", () => {
    const sem = new Semaphore(2, 10);
    expect(sem.tryAcquire()).toBe(true);
    expect(sem.tryAcquire()).toBe(true);
    expect(sem.tryAcquire()).toBe(false);
    expect(sem.waiting).toBe(0);
  });

  it("tryAcquire returns false when queue is full", () => {
    const sem = new Semaphore(0, 2);
    sem.acquire();
    sem.acquire();
    expect(sem.tryAcquire()).toBe(false);
  });

  it("release frees a waiting acquirer", async () => {
    const sem = new Semaphore(1, 10);
    sem.acquire();
    let resolved = false;
    const p = sem.acquire().then(() => {
      resolved = true;
    });
    expect(resolved).toBe(false);
    sem.release();
    await p;
    expect(resolved).toBe(true);
  });
});
