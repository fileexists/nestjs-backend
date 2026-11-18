/**
 * D2 - Per-account lock after failed attempts (real PostgreSQL), on top of the per-IP limit.
 * Temporary, progressive lock, without being able to lock someone else's account forever.
 */
import { createHarness, Harness } from './support/harness';
import {
  PASSWORD,
  cookieNames,
  cookieValue,
  createVerifiedUser,
  http,
  login,
  sql,
} from './support/api';

const EMAIL = 'mario@example.com';
const WRONG = 'Wrong-Passw0rd!';

interface AttemptRow {
  identifier: string;
  failedCount: number;
  lockLevel: number;
  lockedUntil: Date | null;
}

describe('D2 - per-account lock (e2e, real PostgreSQL)', () => {
  let h: Harness;

  beforeAll(async () => {
    h = await createHarness();
  });
  afterAll(async () => {
    await h?.close();
  });
  beforeEach(async () => {
    await h.reset();
    await createVerifiedUser(h, EMAIL);
  });

  const failN = async (n: number, email = EMAIL) => {
    for (let i = 0; i < n; i++) await login(h, email, WRONG);
  };
  const attempts = () => sql<AttemptRow>(h, 'SELECT * FROM login_attempts');
  const secondsLeft = (row: AttemptRow) =>
    (new Date(row.lockedUntil!).getTime() - Date.now()) / 1000;

  it('the first 4 failed attempts do not lock; the 5th does (even with the right password)', async () => {
    await failN(4);
    expect((await login(h, EMAIL)).status).toBe(200);

    await failN(5);
    const locked = await login(h, EMAIL);
    expect(locked.status).toBe(429);
    expect(cookieNames(locked)).toEqual([]);
  });

  it('the lock is the same for a nonexistent email: it does not reveal whether the account exists', async () => {
    await failN(5, 'ghost@example.com');
    const res = await login(h, 'ghost@example.com', WRONG);
    expect(res.status).toBe(429);
    const real = await (async () => {
      await failN(5);
      return login(h, EMAIL, WRONG);
    })();
    expect((res.body as { message: string }).message).toBe(
      (real.body as { message: string }).message,
    );
  });

  it('the first lock lasts about 1 minute and attempts during the lock do NOT extend it', async () => {
    await failN(5);
    const [first] = await attempts();
    expect(secondsLeft(first)).toBeGreaterThan(50);
    expect(secondsLeft(first)).toBeLessThanOrEqual(61);

    for (let i = 0; i < 5; i++)
      expect((await login(h, EMAIL, WRONG)).status).toBe(429);
    const [after] = await attempts();
    expect(new Date(after.lockedUntil!).getTime()).toBe(
      new Date(first.lockedUntil!).getTime(),
    );
    expect(after.lockLevel).toBe(1);
  });

  it('it is progressive: each following lock doubles, up to a maximum', async () => {
    const expire = () =>
      h.db.query(
        `UPDATE login_attempts SET "lockedUntil" = now() - interval '1 second'`,
      );
    const expected = [60, 120, 240, 480, 900, 900];

    for (const seconds of expected) {
      await failN(5);
      const [row] = await attempts();
      expect(secondsLeft(row)).toBeGreaterThan(seconds - 12);
      expect(secondsLeft(row)).toBeLessThanOrEqual(seconds + 1);
      await expire();
    }
  });

  it('after the expiry 5 errors are needed again for a new lock (1 is not enough)', async () => {
    await failN(5);
    await h.db.query(
      `UPDATE login_attempts SET "lockedUntil" = now() - interval '1 second'`,
    );

    await failN(4);
    expect((await login(h, EMAIL, WRONG)).status).toBe(401);
    expect((await login(h, EMAIL, WRONG)).status).toBe(429);
  });

  it('a successful login resets the counter', async () => {
    await failN(4);
    expect((await login(h, EMAIL)).status).toBe(200);
    expect(await attempts()).toHaveLength(0);

    await failN(4);
    expect((await login(h, EMAIL)).status).toBe(200);
  });

  it('old failures leave the window: the counter starts again from zero', async () => {
    await failN(4);
    await h.db.query(
      `UPDATE login_attempts SET "lastFailedAt" = now() - interval '2 hours'`,
    );

    await failN(1);
    const [row] = await attempts();
    expect(row.failedCount).toBe(1);
    expect(row.lockedUntil).toBeNull();
  });

  it('accounts are independent', async () => {
    await createVerifiedUser(h, 'other@example.com');
    await failN(5);
    expect((await login(h, EMAIL)).status).toBe(429);
    expect((await login(h, 'other@example.com')).status).toBe(200);
  });

  it('uppercase emails or ones with spaces count as the same account', async () => {
    await failN(3);
    await login(h, ' MARIO@Example.COM ', WRONG);
    await login(h, 'Mario@example.com', WRONG);
    expect((await login(h, EMAIL)).status).toBe(429);
  });

  it('the database holds only the hash of the identifier, not the email', async () => {
    await failN(1);
    const [row] = await attempts();
    expect(row.identifier).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(row)).not.toContain('mario');
  });

  describe('an attacker cannot keep the owner out indefinitely', () => {
    it('the owner with an already recognized device gets in even during the lock; whoever has no cookie does not', async () => {
      const owner = await login(h, EMAIL);
      const trusted = cookieValue(owner, 'trusted_device');
      expect(trusted).toBeDefined();

      await failN(5); // the attacker locks the account
      expect((await login(h, EMAIL)).status).toBe(429); // even with the right password, but without the cookie

      const ownerAgain = await http(h)
        .post('/api/auth/login')
        .set('Cookie', `trusted_device=${trusted}`)
        .send({ email: EMAIL, password: PASSWORD });
      expect(ownerAgain.status).toBe(200);
    });

    it('the cookie is bound to the account: it does not unlock another account', async () => {
      await createVerifiedUser(h, 'other@example.com');
      const trusted = cookieValue(
        await login(h, 'other@example.com'),
        'trusted_device',
      )!;

      await failN(5);
      const res = await http(h)
        .post('/api/auth/login')
        .set('Cookie', `trusted_device=${trusted}`)
        .send({ email: EMAIL, password: PASSWORD });
      expect(res.status).toBe(429);
    });

    it('a forged or tampered cookie unlocks nothing', async () => {
      const trusted = cookieValue(await login(h, EMAIL), 'trusted_device')!;
      await failN(5);

      for (const forged of [
        `${trusted}x`,
        // Always a different last character: replacing it with a fixed one leaves the cookie
        // untouched (and valid) whenever the signature already ends with it.
        trusted.slice(0, -1) + (trusted.endsWith('A') ? 'B' : 'A'),
        'garbage',
        `${trusted.split('.')[0]}.9999999999999.AAAA`,
      ]) {
        const res = await http(h)
          .post('/api/auth/login')
          .set('Cookie', `trusted_device=${forged}`)
          .send({ email: EMAIL, password: PASSWORD });
        expect(res.status).toBe(429);
      }
    });

    it('the cookie does not skip the password check: with the wrong password it stays 401', async () => {
      const trusted = cookieValue(await login(h, EMAIL), 'trusted_device')!;
      await failN(5);

      const res = await http(h)
        .post('/api/auth/login')
        .set('Cookie', `trusted_device=${trusted}`)
        .send({ email: EMAIL, password: WRONG });
      expect(res.status).toBe(401);
    });

    it('the cookie is httpOnly, SameSite=Lax and limited to /api/auth', async () => {
      const res = await login(h, EMAIL);
      const cookie = (res.headers['set-cookie'] as unknown as string[]).find(
        (c) => c.startsWith('trusted_device='),
      )!;
      expect(cookie).toMatch(/HttpOnly/i);
      expect(cookie).toMatch(/SameSite=Lax/i);
      expect(cookie).toMatch(/Path=\/api\/auth/);
    });
  });

  it('with parallel requests at most 5 attempts get through: the others are blocked without checking the password', async () => {
    const results = await Promise.all(
      Array.from({ length: 30 }, () => login(h, EMAIL, WRONG)),
    );

    const checked = results.filter((r) => r.status === 401).length;
    const blocked = results.filter((r) => r.status === 429).length;
    expect(checked).toBe(5);
    expect(blocked).toBe(25);
  });

  it('the right password is not one more attempt: with 4 errors pending, a successful login resets everything even in parallel with the errors', async () => {
    await Promise.all([
      login(h, EMAIL, WRONG),
      login(h, EMAIL, WRONG),
      login(h, EMAIL, WRONG),
    ]);
    expect((await login(h, EMAIL)).status).toBe(200);
    expect(await attempts()).toHaveLength(0);
  });

  it('parallel requests with wrong passwords break nothing and the lock triggers', async () => {
    const results = await Promise.all(
      Array.from({ length: 10 }, () => login(h, EMAIL, WRONG)),
    );
    expect(results.every((r) => [401, 429].includes(r.status))).toBe(true);

    const [row] = await attempts();
    expect(row.lockLevel).toBeGreaterThanOrEqual(1);
    expect((await login(h, EMAIL)).status).toBe(429);
  });
});
