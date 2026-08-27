/**
 * Concurrency primitives and argon2 cost policy.
 *
 * argon2.verify() is CPU-heavy (the whole point of the algorithm) and runs on
 * the Node event loop. We therefore cap how many verifications run in parallel
 * with a semaphore so a burst of requests can't starve the function or OOM it.
 */

export class Semaphore {
  private queue: Array<() => void> = [];
  private permits: number;
  private maxQueue: number;
  constructor(permits: number, maxQueue = 50) {
    this.permits = permits;
    this.maxQueue = maxQueue;
  }
  get waiting(): number {
    return this.queue.length;
  }
  get available(): number {
    return this.permits;
  }
  tryAcquire(): boolean {
    if (this.permits > 0) {
      this.permits--;
      return true;
    }
    return false;
  }
  acquire(): Promise<void> {
    if (this.permits > 0) {
      this.permits--;
      return Promise.resolve();
    }
    // Reject rather than grow unbounded when the queue is full.
    if (this.queue.length >= this.maxQueue) {
      return Promise.reject(new Error("queue full"));
    }
    return new Promise<void>((resolve) => {
      this.queue.push(resolve);
    });
  }
  release(): void {
    const next = this.queue.shift();
    if (next) {
      next();
    } else {
      this.permits++;
    }
  }
}

// The exact cost parameters every accepted hash must use. Hashes whose
// parameters differ are rejected at verify time via argon2.needsRehash().
export const EXPECTED_ARGON2 = {
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
};

// Allow at most 2 concurrent verifications, with a small overflow queue.
export const argon2Limiter = new Semaphore(2, 16);
