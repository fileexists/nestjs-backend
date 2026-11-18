/**
 * Global guard order (real PostgreSQL): the rate limit runs BEFORE authentication.
 * Before: ThrottlerGuard was registered last, so a request rejected with 401 by AuthGuard never
 * reached it and anonymous traffic on protected routes was never limited.
 */
import { createHarness, Harness } from './support/harness';
import { http } from './support/api';

describe('Global guard order (e2e, real PostgreSQL)', () => {
  let h: Harness;

  beforeAll(async () => {
    h = await createHarness({ throttle: true });
  });
  afterAll(async () => {
    await h?.close();
  });

  it('anonymous requests to a protected route are rate limited (401 first, then 429)', async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 110; i++) {
      statuses.push((await http(h).get('/api/user/me')).status);
    }

    const firstLimited = statuses.indexOf(429);
    // The global limit is 100 a minute per IP: the 101st request is the first one refused.
    expect(firstLimited).toBe(100);
    expect(new Set(statuses.slice(0, firstLimited))).toEqual(new Set([401]));
    expect(new Set(statuses.slice(firstLimited))).toEqual(new Set([429]));
  });
});
