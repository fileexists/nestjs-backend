interface Entry<T> {
  result: Promise<T>;
  familyId: string;
  userId: string;
  expiresAt: number;
}

/** Hard cap so a burst of refreshes cannot grow the map without limit. */
const MAX_ENTRIES = 5000;

/**
 * Short-lived, in-memory cache (per process) of the outcome of a refresh rotation, keyed by the
 * `jti` of the refresh token that was rotated. While an entry lives, presenting the same refresh
 * token again returns the same pair of tokens instead of an error, so parallel requests made with
 * the same cookie (several tabs, many API calls after the access token expired) all succeed.
 *
 * It stores the promise, not the value: requests that arrive while the rotation is still in
 * progress share it. Entries expire lazily after `ttlMs` (the reuse grace period) and are dropped
 * explicitly when the session they belong to is revoked. With `ttlMs = 0` it is disabled.
 */
export class RefreshResultCache<T> {
  private readonly entries = new Map<string, Entry<T>>();

  constructor(
    private readonly ttlMs: number,
    private readonly now: () => number = () => Date.now(),
  ) {}

  get enabled(): boolean {
    return this.ttlMs > 0;
  }

  get size(): number {
    return this.entries.size;
  }

  get(jti: string): Promise<T> | undefined {
    const entry = this.entries.get(jti);
    if (!entry) return undefined;
    if (entry.expiresAt <= this.now()) {
      this.entries.delete(jti);
      return undefined;
    }
    return entry.result;
  }

  set(
    jti: string,
    result: Promise<T>,
    owner: { familyId: string; userId: string },
  ): void {
    if (!this.enabled) return;
    this.sweep();
    this.entries.set(jti, {
      result,
      ...owner,
      expiresAt: this.now() + this.ttlMs,
    });
    // Map keeps insertion order: when over the cap the oldest entries go first.
    for (const key of this.entries.keys()) {
      if (this.entries.size <= MAX_ENTRIES) break;
      this.entries.delete(key);
    }
  }

  delete(jti: string): void {
    this.entries.delete(jti);
  }

  /** The session (family) was revoked: its results must not be handed out any more. */
  invalidateFamily(familyId: string): void {
    this.deleteWhere((entry) => entry.familyId === familyId);
  }

  /** All the sessions of the user were revoked (logout-all, password reset). */
  invalidateUser(userId: string): void {
    this.deleteWhere((entry) => entry.userId === userId);
  }

  private sweep(): void {
    const now = this.now();
    this.deleteWhere((entry) => entry.expiresAt <= now);
  }

  private deleteWhere(predicate: (entry: Entry<T>) => boolean): void {
    for (const [key, entry] of this.entries) {
      if (predicate(entry)) this.entries.delete(key);
    }
  }
}
