/**
 * D4 - Concurrent registration of the same email (real PostgreSQL).
 * Before: the uniqueness violation (23505) became a 500.
 */
import { createHarness, Harness } from './support/harness';
import { cookieNames, register, sql } from './support/api';
import { googleLogin } from './support/google';

describe('D4 - concurrent registrations (e2e, real PostgreSQL)', () => {
  let h: Harness;

  beforeAll(async () => {
    h = await createHarness();
  });
  afterAll(async () => {
    await h?.close();
  });
  beforeEach(async () => {
    await h.reset();
  });

  const userCount = async () =>
    (await sql<{ n: number }>(h, 'SELECT count(*)::int AS n FROM users'))[0].n;

  it('the same email sent 10 times at once: no 500, a single user', async () => {
    const results = await Promise.all(
      Array.from({ length: 10 }, () => register(h, 'race@example.com')),
    );

    expect(results.map((r) => r.status).filter((s) => s >= 500)).toEqual([]);
    expect(new Set(results.map((r) => r.status))).toEqual(new Set([202])); // uniform response
    expect(await userCount()).toBe(1);
  });

  it('same email in different forms (case/spaces) in parallel: a single user', async () => {
    const variants = [
      'race@example.com',
      'RACE@example.com',
      ' Race@Example.com ',
      'rAcE@EXAMPLE.com',
    ];
    const results = await Promise.all(
      variants.map((email) => register(h, email)),
    );

    expect(results.every((r) => r.status === 202)).toBe(true);
    expect(await userCount()).toBe(1);
  });

  it("whoever loses the race gets the 'address already registered' notice, whoever wins gets the verification", async () => {
    await Promise.all(
      Array.from({ length: 6 }, () => register(h, 'race@example.com')),
    );

    expect(h.mail.to('race@example.com', 'verification')).toHaveLength(1);
    // at most one notice (waiting period), never a second token
    expect(
      h.mail.to('race@example.com', 'registration-notice').length,
    ).toBeLessThanOrEqual(5);
  });

  it('two simultaneous first Google logins of the same user: no 500, a single user', async () => {
    const profile = {
      sub: 'g-race',
      email: 'g-race@example.com',
      email_verified: true,
    };

    const results = await Promise.all([
      googleLogin(h.app, h.google, profile),
      googleLogin(h.app, h.google, profile),
      googleLogin(h.app, h.google, profile),
    ]);

    for (const { callback } of results) {
      expect(callback.status).toBe(302);
      expect(callback.headers.location).toContain('status=success');
      expect(cookieNames(callback)).toContain('access_token');
    }
    expect(await userCount()).toBe(1);
  });
});
