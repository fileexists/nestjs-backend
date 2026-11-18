/**
 * E - Password reset (real PostgreSQL): request via email, single-use token with
 * an expiry, invalidation of all the sessions after the reset.
 */
import { createHash } from 'crypto';
import { createHarness, Harness } from './support/harness';
import {
  PASSWORD,
  cookieHeader,
  cookieNames,
  cookieValue,
  createVerifiedUser,
  forgotPassword,
  http,
  login,
  loginSession,
  refresh,
  register,
  resetPassword,
  settle,
  sql,
  userRow,
} from './support/api';
import { googleLogin } from './support/google';

const EMAIL = 'mario@example.com';
const NEW_PASSWORD = 'Brand-New-Passw0rd!';

describe('E - password reset (e2e, real PostgreSQL)', () => {
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
  afterEach(() => {
    h.mail.delayMs = 0;
  });

  /** Requests the reset and returns the token "received" by email. */
  async function requestReset(email = EMAIL): Promise<string> {
    expect((await forgotPassword(h, email)).status).toBe(202);
    await settle(h);
    return h.mail.lastToken(email, 'password-reset');
  }

  describe('request (POST /auth/forgot-password)', () => {
    beforeEach(async () => {
      await createVerifiedUser(h, EMAIL);
    });

    it('for an existing account sends the email with a single-use token', async () => {
      await requestReset();
      expect(h.mail.to(EMAIL, 'password-reset')).toHaveLength(1);
    });

    it('identical response (202, same body) for an existing and a nonexistent address, and no email for the nonexistent one', async () => {
      const known = await forgotPassword(h, EMAIL);
      const unknown = await forgotPassword(h, 'ghost@example.com');
      await settle(h);

      expect(known.status).toBe(202);
      expect(unknown.status).toBe(202);
      expect(JSON.stringify(known.body)).toBe(JSON.stringify(unknown.body));
      expect(h.mail.to('ghost@example.com')).toHaveLength(0);
      expect(h.mail.to(EMAIL, 'password-reset')).toHaveLength(1);
    });

    it('the response does not wait for the work (no observable timing difference): it is a background job', async () => {
      h.mail.delayMs = 400; // slow SMTP: it must not delay the response

      const start = Date.now();
      const res = await forgotPassword(h, EMAIL);
      const elapsed = Date.now() - start;
      await settle(h);

      expect(res.status).toBe(202);
      expect(elapsed).toBeLessThan(300); // the slow send (400 ms) does not delay the response
      expect(h.mail.to(EMAIL, 'password-reset')).toHaveLength(1);
    });

    it('the database holds only the SHA-256 of the token', async () => {
      const token = await requestReset();
      const rows = await sql<{ tokenHash: string; type: string }>(
        h,
        `SELECT "tokenHash", type FROM auth_tokens WHERE type = 'password_reset'`,
      );
      expect(rows).toEqual([
        {
          tokenHash: createHash('sha256').update(token).digest('hex'),
          type: 'password_reset',
        },
      ]);
    });

    it('within the wait period it does not send a second email; after it, yes, and the old token stops being valid', async () => {
      const first = await requestReset();
      await forgotPassword(h, EMAIL);
      await settle(h);
      expect(h.mail.to(EMAIL, 'password-reset')).toHaveLength(1);

      await h.db.query(
        `UPDATE auth_tokens SET "createdAt" = now() - interval '5 minutes'`,
      );
      const second = await requestReset();

      expect(second).not.toBe(first);
      expect((await resetPassword(h, first, NEW_PASSWORD)).status).toBe(400);
      expect((await resetPassword(h, second, NEW_PASSWORD)).status).toBe(200);
    });

    it('accepts the email in any form (case/spaces)', async () => {
      expect((await forgotPassword(h, '  MARIO@Example.COM ')).status).toBe(
        202,
      );
      await settle(h);
      expect(h.mail.to(EMAIL, 'password-reset')).toHaveLength(1);
    });

    it('invalid email -> 400 from validation', async () => {
      expect(
        (
          await http(h)
            .post('/api/auth/forgot-password')
            .send({ email: 'not-an-email' })
        ).status,
      ).toBe(400);
    });
  });

  describe('reset (POST /auth/reset-password)', () => {
    beforeEach(async () => {
      await createVerifiedUser(h, EMAIL);
    });

    it('sets the new password: the old one stops working, the new one works', async () => {
      const token = await requestReset();

      const res = await resetPassword(h, token, NEW_PASSWORD);

      expect(res.status).toBe(200);
      expect((await login(h, EMAIL, PASSWORD)).status).toBe(401);
      expect((await login(h, EMAIL, NEW_PASSWORD)).status).toBe(200);
    });

    it('the token is single-use: the second use fails with 400', async () => {
      const token = await requestReset();
      expect((await resetPassword(h, token, NEW_PASSWORD)).status).toBe(200);
      expect((await resetPassword(h, token, 'Another-Passw0rd!')).status).toBe(
        400,
      );
      expect((await login(h, EMAIL, NEW_PASSWORD)).status).toBe(200);
    });

    it('expired, unknown or other-type token -> 400', async () => {
      const token = await requestReset();
      await h.db.query(
        `UPDATE auth_tokens SET "expiresAt" = now() - interval '1 minute'`,
      );
      expect((await resetPassword(h, token, NEW_PASSWORD)).status).toBe(400);
      expect(
        (await resetPassword(h, 'x'.repeat(43), NEW_PASSWORD)).status,
      ).toBe(400);

      // an email verification token cannot be used to reset the password
      await register(h, 'other@example.com');
      const verificationToken = h.mail.lastToken(
        'other@example.com',
        'verification',
      );
      expect(
        (await resetPassword(h, verificationToken, NEW_PASSWORD)).status,
      ).toBe(400);
    });

    it('the new password must follow the rules (8-72 characters) and the token is not consumed', async () => {
      const token = await requestReset();
      expect((await resetPassword(h, token, 'short')).status).toBe(400);
      expect((await resetPassword(h, token, 'x'.repeat(73))).status).toBe(400);
      expect(
        (await http(h).post('/api/auth/reset-password').send({ token })).status,
      ).toBe(400);
      expect((await resetPassword(h, token, NEW_PASSWORD)).status).toBe(200);
    });

    it('with several concurrent requests with the same token only one succeeds', async () => {
      const token = await requestReset();
      const results = await Promise.all(
        ['A-Passw0rd-one!', 'B-Passw0rd-two!', 'C-Passw0rd-three!'].map((p) =>
          resetPassword(h, token, p),
        ),
      );
      expect(results.map((r) => r.status).sort()).toEqual([200, 400, 400]);
    });

    it('the new password is hashed (never in clear) and does not change the email', async () => {
      const token = await requestReset();
      await resetPassword(h, token, NEW_PASSWORD);
      const row = await userRow(h, EMAIL);
      expect(row?.password).toMatch(/^\$2[aby]\$\d{2}\$/);
      expect(row?.password).not.toContain(NEW_PASSWORD);
    });

    describe('invalidates all sessions', () => {
      it('refresh tokens and access tokens issued earlier no longer work', async () => {
        const laptop = await loginSession(h, EMAIL);
        const phone = await loginSession(h, EMAIL);
        const before = await userRow(h, EMAIL);
        const token = await requestReset();

        await resetPassword(h, token, NEW_PASSWORD);

        expect((await refresh(h, laptop.refresh)).status).toBe(401);
        expect((await refresh(h, phone.refresh)).status).toBe(401);
        for (const session of [laptop, phone]) {
          const me = await http(h)
            .get('/api/user/me')
            .set('Cookie', cookieHeader({ access: session.access }));
          expect(me.status).toBe(401);
        }
        expect((await userRow(h, EMAIL))?.tokenVersion).toBe(
          (before?.tokenVersion ?? 0) + 1,
        );
        const revoked = await sql<{ n: number }>(
          h,
          'SELECT count(*)::int AS n FROM refresh_tokens WHERE "revokedAt" IS NULL',
        );
        expect(revoked[0].n).toBe(0);
      });

      it('a new session after the reset works normally', async () => {
        await requestReset().then((token) =>
          resetPassword(h, token, NEW_PASSWORD),
        );
        const session = await loginSession(h, EMAIL, NEW_PASSWORD);
        expect(
          (
            await http(h)
              .get('/api/user/me')
              .set('Cookie', cookieHeader({ access: session.access }))
          ).status,
        ).toBe(200);
      });

      it('also invalidates the recognized devices (trusted_device cookie)', async () => {
        const trusted = cookieValue(await login(h, EMAIL), 'trusted_device')!;
        const token = await requestReset();
        await resetPassword(h, token, NEW_PASSWORD);

        for (let i = 0; i < 5; i++) await login(h, EMAIL, 'Wrong-Passw0rd!');
        const res = await http(h)
          .post('/api/auth/login')
          .set('Cookie', `trusted_device=${trusted}`)
          .send({ email: EMAIL, password: NEW_PASSWORD });
        expect(res.status).toBe(429);
      });
    });

    it('unlocks the account locked for too many attempts (a way out for the owner)', async () => {
      for (let i = 0; i < 5; i++) await login(h, EMAIL, 'Wrong-Passw0rd!');
      expect((await login(h, EMAIL, PASSWORD)).status).toBe(429);

      const token = await requestReset();
      await resetPassword(h, token, NEW_PASSWORD);

      expect((await login(h, EMAIL, NEW_PASSWORD)).status).toBe(200);
      expect(await sql(h, 'SELECT * FROM login_attempts')).toHaveLength(0);
    });

    it('deletes the verification and reset tokens still pending', async () => {
      await register(h, 'pending@example.com');
      const token = await requestReset('pending@example.com');
      await resetPassword(h, token, NEW_PASSWORD);
      const [{ n }] = await sql<{ n: number }>(
        h,
        `SELECT count(*)::int AS n FROM auth_tokens WHERE "usedAt" IS NULL AND type <> 'registration_notice'`,
      );
      expect(n).toBe(0);
    });
  });

  describe('whoever owns the mailbox recovers the account', () => {
    it("pre-hijacking: the attacker registers the victim's email; the victim resets the password and the account becomes theirs", async () => {
      await register(h, EMAIL, 'Attacker-Passw0rd!'); // unverified account with the attacker's password
      expect((await login(h, EMAIL, 'Attacker-Passw0rd!')).status).toBe(403);

      const token = await requestReset();
      expect((await resetPassword(h, token, NEW_PASSWORD)).status).toBe(200);

      expect((await login(h, EMAIL, 'Attacker-Passw0rd!')).status).toBe(401); // the attacker's password is no longer valid
      expect((await login(h, EMAIL, NEW_PASSWORD)).status).toBe(200);
      expect((await userRow(h, EMAIL))?.emailVerifiedAt).not.toBeNull(); // the reset proves ownership of the mailbox
    });

    it('a Google-only account can set a password: it becomes combined and Google keeps working', async () => {
      await googleLogin(h.app, h.google, {
        sub: 'g-1',
        email: EMAIL,
        email_verified: true,
      });
      expect((await login(h, EMAIL, NEW_PASSWORD)).status).toBe(401);

      const token = await requestReset();
      await resetPassword(h, token, NEW_PASSWORD);

      expect((await login(h, EMAIL, NEW_PASSWORD)).status).toBe(200);
      expect((await userRow(h, EMAIL))?.provider).toBe('combined');
      const { callback } = await googleLogin(h.app, h.google, {
        sub: 'g-1',
        email: EMAIL,
        email_verified: true,
      });
      expect(cookieNames(callback)).toContain('access_token');
    });
  });
});
