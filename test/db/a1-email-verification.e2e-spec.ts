/**
 * A1 - Email verification: registration, confirmation, login, resend (real PostgreSQL).
 */
import { createHash } from 'crypto';
import { createHarness, Harness } from './support/harness';
import {
  PASSWORD,
  cookieNames,
  http,
  login,
  register,
  settle,
  userRow,
  verifyEmail,
} from './support/api';

const EMAIL = 'mario@example.com';

describe('A1 - email verification (e2e, real PostgreSQL)', () => {
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

  describe('registration', () => {
    it('creates an UNVERIFIED account and sends a single verification email', async () => {
      const res = await register(h, EMAIL);
      expect(res.status).toBeLessThan(300);

      const row = await userRow(h, EMAIL);
      expect(row?.emailVerifiedAt).toBeNull();
      expect(row?.password).not.toBe(PASSWORD);
      expect(h.mail.to(EMAIL, 'verification')).toHaveLength(1);
    });

    it('the database holds only the SHA-256 of the token, never the token', async () => {
      await register(h, EMAIL);
      const token = h.mail.lastToken(EMAIL, 'verification');

      const rows: { tokenHash: string; type: string }[] = await h.db.query(
        'SELECT "tokenHash", type FROM auth_tokens',
      );
      expect(rows).toHaveLength(1);
      expect(rows[0].tokenHash).toBe(
        createHash('sha256').update(token).digest('hex'),
      );
      expect(rows[0].tokenHash).not.toBe(token);
      expect(rows[0].type).toBe('email_verification');
    });
  });

  describe('login before and after verification', () => {
    beforeEach(async () => {
      await register(h, EMAIL);
    });

    it('correct password but unverified email -> 403 and no cookie', async () => {
      const res = await login(h, EMAIL);
      expect(res.status).toBe(403);
      expect(cookieNames(res)).toEqual([]);
    });

    it('wrong password with an unverified email -> 401 (not 403)', async () => {
      const res = await login(h, EMAIL, 'Wrong-Passw0rd!');
      expect(res.status).toBe(401);
    });

    it('after confirmation the login works and sets the cookies', async () => {
      const verified = await verifyEmail(
        h,
        h.mail.lastToken(EMAIL, 'verification'),
      );
      expect(verified.status).toBe(200);
      expect((await userRow(h, EMAIL))?.emailVerifiedAt).not.toBeNull();

      const res = await login(h, EMAIL);
      expect(res.status).toBe(200);
      expect(cookieNames(res)).toEqual(
        expect.arrayContaining(['access_token', 'refresh_token']),
      );
    });
  });

  describe('verification token', () => {
    beforeEach(async () => {
      await register(h, EMAIL);
    });

    it('is single-use: the second use fails with 400', async () => {
      const token = h.mail.lastToken(EMAIL, 'verification');
      expect((await verifyEmail(h, token)).status).toBe(200);
      expect((await verifyEmail(h, token)).status).toBe(400);
    });

    it('expired -> 400 and the account stays unverified', async () => {
      await h.db.query(
        `UPDATE auth_tokens SET "expiresAt" = now() - interval '1 minute'`,
      );
      const res = await verifyEmail(h, h.mail.lastToken(EMAIL, 'verification'));
      expect(res.status).toBe(400);
      expect((await userRow(h, EMAIL))?.emailVerifiedAt).toBeNull();
    });

    it('unknown -> 400; too short or missing -> 400 from validation', async () => {
      expect((await verifyEmail(h, 'x'.repeat(43))).status).toBe(400);
      expect((await verifyEmail(h, 'short')).status).toBe(400);
      expect(
        (await http(h).post('/api/auth/verify-email').send({})).status,
      ).toBe(400);
    });

    it('two concurrent confirmations with the same token: only one succeeds', async () => {
      const token = h.mail.lastToken(EMAIL, 'verification');
      const results = await Promise.all([
        verifyEmail(h, token),
        verifyEmail(h, token),
        verifyEmail(h, token),
      ]);
      expect(results.map((r) => r.status).sort()).toEqual([200, 400, 400]);
    });
  });

  describe('resend', () => {
    const body = (res: { body: unknown }) => JSON.stringify(res.body);

    it('for an unverified account sends a new token and invalidates the old one (after the wait period)', async () => {
      await register(h, EMAIL);
      const oldToken = h.mail.lastToken(EMAIL, 'verification');
      await h.db.query(
        `UPDATE auth_tokens SET "createdAt" = now() - interval '5 minutes'`,
      );

      const res = await http(h)
        .post('/api/auth/resend-verification')
        .send({ email: EMAIL });
      expect(res.status).toBe(202);
      await settle(h);
      expect(h.mail.to(EMAIL, 'verification')).toHaveLength(2);

      const newToken = h.mail.lastToken(EMAIL, 'verification');
      expect(newToken).not.toBe(oldToken);
      expect((await verifyEmail(h, oldToken)).status).toBe(400);
      expect((await verifyEmail(h, newToken)).status).toBe(200);
    });

    it('within the wait period it does not send a second email', async () => {
      await register(h, EMAIL);
      const res = await http(h)
        .post('/api/auth/resend-verification')
        .send({ email: EMAIL });
      expect(res.status).toBe(202);
      await settle(h);
      expect(h.mail.to(EMAIL, 'verification')).toHaveLength(1);
    });

    it('identical response (and no email) for a nonexistent address and for an already verified account', async () => {
      await register(h, EMAIL);
      await verifyEmail(h, h.mail.lastToken(EMAIL, 'verification'));
      h.mail.clear();

      const unknown = await http(h)
        .post('/api/auth/resend-verification')
        .send({ email: 'ghost@example.com' });
      const verified = await http(h)
        .post('/api/auth/resend-verification')
        .send({ email: EMAIL });

      await settle(h);
      expect(unknown.status).toBe(202);
      expect(verified.status).toBe(202);
      expect(body(unknown)).toBe(body(verified));
      expect(h.mail.sent).toHaveLength(0);
    });
  });
});
