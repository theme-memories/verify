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

export const EXPECTED_ARGON2 = {
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
};

export const argon2Limiter = new Semaphore(2, 16);
