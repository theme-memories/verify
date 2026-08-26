// Bounding semaphore used to cap concurrent Argon2 verifications.
//
// Argon2 is intentionally CPU/memory heavy, so we limit how many verifications
// run at once (permits) and how many requests may wait in line (maxQueue).
// When the queue is full, `acquire()` rejects so the handler can answer 429
// instead of exhausting the function's CPU budget on Vercel.

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
