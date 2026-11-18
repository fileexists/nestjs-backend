/**
 * B2 - Email normalization (real PostgreSQL).
 * Before: `Mario.Rossi@Example.com` and `mario.rossi@example.com` created two accounts.
 */
import { createHarness, Harness } from './support/harness';
import {
  PASSWORD,
  createVerifiedUser,
  http,
  login,
  register,
  settle,
  sql,
  userRow,
  verifyEmail,
} from './support/api';
import { googleLogin } from './support/google';

const MIXED = 'Mario.Rossi@Example.com';
const LOWER = 'mario.rossi@example.com';

describe('B2 - case-insensitive email (e2e, real PostgreSQL)', () => {
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

  it('registration stores the email in lowercase and without spaces', async () => {
    const res = await register(h, `  ${MIXED}  `);
    expect(res.status).toBeLessThan(300);

    const rows = await sql<{ email: string }>(h, 'SELECT email FROM users');
    expect(rows).toEqual([{ email: LOWER }]);
  });

  it('two registrations that differ only in case create ONE account', async () => {
    await register(h, MIXED);
    const second = await register(h, LOWER);

    expect(second.status).toBeLessThan(500);
    expect(await userCount()).toBe(1);
  });

  it('login works with any combination of case and spaces', async () => {
    await createVerifiedUser(h, MIXED);

    for (const variant of [MIXED, LOWER, LOWER.toUpperCase(), `  ${LOWER} `]) {
      const res = await login(h, variant);
      expect(res.status).toBe(200);
    }
  });

  it('email verification and resend accept the email in any form', async () => {
    await register(h, LOWER);
    const token = h.mail.lastToken(LOWER, 'verification');

    const resend = await http(h)
      .post('/api/auth/resend-verification')
      .send({ email: MIXED });
    expect(resend.status).toBe(202);
    await settle(h);
    expect((await verifyEmail(h, token)).status).toBe(200);
    expect((await userRow(h, LOWER))?.emailVerifiedAt).not.toBeNull();
  });

  it('Google with an uppercase email links the existing account instead of creating a second one', async () => {
    await createVerifiedUser(h, LOWER);

    await googleLogin(h.app, h.google, {
      sub: 'g-1',
      email: 'MARIO.ROSSI@EXAMPLE.COM',
      email_verified: true,
    });

    expect(await userCount()).toBe(1);
    expect((await userRow(h, LOWER))?.googleId).toBe('g-1');
  });

  it('a user created by Google has the normalized email', async () => {
    await googleLogin(h.app, h.google, {
      sub: 'g-2',
      email: 'New.User@Example.COM',
      email_verified: true,
    });
    expect((await userRow(h, 'new.user@example.com'))?.googleId).toBe('g-2');
  });

  describe('database constraint (unique index on lower(email))', () => {
    it('rejects a second user that differs only in case, even with direct SQL', async () => {
      await register(h, LOWER);

      await expect(
        h.db.query(`INSERT INTO users (email) VALUES ($1)`, [MIXED]),
      ).rejects.toMatchObject({ code: '23505' });
      expect(await userCount()).toBe(1);
    });

    it('the index is the expected one (functional and unique)', async () => {
      const rows = await sql<{ indexdef: string }>(
        h,
        `SELECT indexdef FROM pg_indexes WHERE tablename = 'users' AND indexname = 'UQ_users_email_lower'`,
      );
      expect(rows).toHaveLength(1);
      expect(rows[0].indexdef).toMatch(/UNIQUE INDEX/i);
      expect(rows[0].indexdef).toMatch(/lower\(\(?email\)?::text\)/i);
    });
  });

  it('(sanity) the password is still valid', async () => {
    await createVerifiedUser(h, LOWER, PASSWORD);
    expect((await login(h, LOWER, PASSWORD)).status).toBe(200);
  });
});
