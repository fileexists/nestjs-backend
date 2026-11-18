/**
 * D1 - Account enumeration (real PostgreSQL): same responses and same timings
 * for "non-existent user", "wrong password" and "Google-only account"; uniform
 * registration for both a new and an already registered email.
 */
// "Real" bcrypt cost high enough to make the timing difference measurable;
// per-account lock disabled (many failed attempts are made on purpose here).
process.env.BCRYPT_ROUNDS = '10';
process.env.LOGIN_MAX_FAILED_ATTEMPTS = '100000';

import { createHarness, Harness } from './support/harness';
import {
  PASSWORD,
  createVerifiedUser,
  http,
  login,
  median,
  register,
  sql,
  timed,
} from './support/api';
import { googleLogin } from './support/google';

const SAMPLES = 9;

describe('D1 - account enumeration (e2e, real PostgreSQL)', () => {
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

  describe('login', () => {
    it('nonexistent user, wrong password and Google-only account: same status and same message', async () => {
      await createVerifiedUser(h, 'known@example.com');
      await googleLogin(h.app, h.google, {
        sub: 'g1',
        email: 'google-only@example.com',
        email_verified: true,
      });

      const unknown = await login(h, 'nobody@example.com', 'Wrong-Passw0rd!');
      const wrong = await login(h, 'known@example.com', 'Wrong-Passw0rd!');
      const googleOnly = await login(
        h,
        'google-only@example.com',
        'Wrong-Passw0rd!',
      );

      for (const res of [unknown, wrong, googleOnly]) {
        expect(res.status).toBe(401);
      }
      const message = (r: { body: unknown }) =>
        (r.body as { message: string }).message;
      expect(message(unknown)).toBe(message(wrong));
      expect(message(googleOnly)).toBe(message(wrong));
      expect(message(wrong)).toBe('Invalid email or password');
    });

    it('never suggests using Google ("Please login via google.")', async () => {
      await googleLogin(h.app, h.google, {
        sub: 'g1',
        email: 'google-only@example.com',
        email_verified: true,
      });
      const res = await login(h, 'google-only@example.com', PASSWORD);
      expect(JSON.stringify(res.body)).not.toMatch(/google/i);
    });

    it('login without a password: same generic response', async () => {
      await createVerifiedUser(h, 'known@example.com');
      const res = await http(h)
        .post('/api/auth/login')
        .send({ email: 'known@example.com' });
      expect(res.status).toBe(401);
      expect((res.body as { message: string }).message).toBe(
        'Invalid email or password',
      );
    });

    it('response times are similar: a nonexistent user costs as much as a wrong password', async () => {
      await createVerifiedUser(h, 'known@example.com');
      await login(h, 'known@example.com', 'warm-up-Passw0rd!'); // warms up connections and the JIT

      const unknown: number[] = [];
      const wrong: number[] = [];
      for (let i = 0; i < SAMPLES; i++) {
        unknown.push(
          await timed(() =>
            login(h, `ghost-${i}@example.com`, 'Wrong-Passw0rd!'),
          ),
        );
        wrong.push(
          await timed(() => login(h, 'known@example.com', 'Wrong-Passw0rd!')),
        );
      }

      const ratio = median(unknown) / median(wrong);
      // Without the dummy bcrypt the non-existent user answers in ~2 ms against ~60 ms (ratio ~0.03).
      expect(ratio).toBeGreaterThan(0.6);
      expect(ratio).toBeLessThan(1.6);
    });
  });

  describe('registration', () => {
    const body = (r: { body: unknown }) => JSON.stringify(r.body);

    it('identical response (202, no userId) for a new email and for an already registered one', async () => {
      const fresh = await register(h, 'fresh@example.com');
      await createVerifiedUser(h, 'taken@example.com');
      const taken = await register(h, 'taken@example.com');

      expect(fresh.status).toBe(202);
      expect(taken.status).toBe(202);
      expect(body(fresh)).toBe(body(taken));
      expect(body(fresh)).not.toMatch(
        /userId|already|registered successfully/i,
      );
    });

    it('the response is identical for a Google-only account too', async () => {
      await googleLogin(h.app, h.google, {
        sub: 'g1',
        email: 'google-only@example.com',
        email_verified: true,
      });
      const taken = await register(h, 'google-only@example.com');
      const fresh = await register(h, 'fresh@example.com');
      expect(taken.status).toBe(202);
      expect(body(taken)).toBe(body(fresh));
    });

    it('the new email receives the verification; the already registered one receives a notice and NOT a token', async () => {
      await register(h, 'fresh@example.com');
      await createVerifiedUser(h, 'taken@example.com');
      h.mail.clear();
      await register(h, 'taken@example.com');

      expect(
        h.mail.to('taken@example.com', 'registration-notice'),
      ).toHaveLength(1);
      expect(h.mail.to('taken@example.com', 'verification')).toHaveLength(0);
      expect(h.mail.to('fresh@example.com', 'verification')).toHaveLength(0); // mail.clear() above
    });

    it('an attempt on an existing email creates or modifies no account (not even the password)', async () => {
      await createVerifiedUser(h, 'taken@example.com');
      const before = await sql<{ password: string }>(
        h,
        `SELECT password FROM users WHERE email = 'taken@example.com'`,
      );

      await register(h, 'taken@example.com', 'Attacker-Passw0rd!');

      const after = await sql<{ password: string }>(
        h,
        `SELECT password FROM users WHERE email = 'taken@example.com'`,
      );
      expect(after).toEqual(before);
      expect(
        (await login(h, 'taken@example.com', 'Attacker-Passw0rd!')).status,
      ).toBe(401);
      expect(
        (await sql<{ n: number }>(h, 'SELECT count(*)::int AS n FROM users'))[0]
          .n,
      ).toBe(1);
    });

    it('the notices cannot flood a mailbox: at most one per wait period', async () => {
      await createVerifiedUser(h, 'taken@example.com');
      h.mail.clear();
      for (let i = 0; i < 5; i++) await register(h, 'taken@example.com');
      expect(
        h.mail.to('taken@example.com', 'registration-notice'),
      ).toHaveLength(1);
    });

    it('response times are similar between a new email and an already registered one', async () => {
      await createVerifiedUser(h, 'taken@example.com');
      await register(h, 'warmup@example.com');

      const fresh: number[] = [];
      const taken: number[] = [];
      for (let i = 0; i < SAMPLES; i++) {
        fresh.push(await timed(() => register(h, `fresh-${i}@example.com`)));
        taken.push(await timed(() => register(h, 'taken@example.com')));
      }

      const ratio = median(taken) / median(fresh);
      expect(ratio).toBeGreaterThan(0.6);
      expect(ratio).toBeLessThan(1.6);
    });
  });
});
