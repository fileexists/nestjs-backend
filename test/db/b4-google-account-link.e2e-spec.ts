/**
 * B4 - Google: googleId comparison (real PostgreSQL).
 * Before: a user with a googleId different from the incoming one got in anyway
 * (and for accounts with a password the googleId was even overwritten).
 */
import { createHarness, Harness } from './support/harness';
import {
  cookieHeader,
  cookieNames,
  cookieValue,
  createVerifiedUser,
  http,
  sql,
  userRow,
} from './support/api';
import { googleLogin } from './support/google';

describe('B4 - googleId (e2e, real PostgreSQL)', () => {
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

  it('rejects (401) a googleId different from the one already linked and does not overwrite it', async () => {
    await googleLogin(h.app, h.google, {
      sub: 'g-original',
      email: 'mario@example.com',
      email_verified: true,
    });

    const { callback } = await googleLogin(h.app, h.google, {
      sub: 'g-other',
      email: 'mario@example.com',
      email_verified: true,
    });

    expect(cookieNames(callback)).not.toContain('access_token');
    expect((await userRow(h, 'mario@example.com'))?.googleId).toBe(
      'g-original',
    );
    expect(await userCount()).toBe(1);
  });

  it('a combined account (with a password) does not allow replacing the googleId', async () => {
    await createVerifiedUser(h, 'mario@example.com');
    await googleLogin(h.app, h.google, {
      sub: 'g-original',
      email: 'mario@example.com',
      email_verified: true,
    });

    const { callback } = await googleLogin(h.app, h.google, {
      sub: 'g-attacker',
      email: 'mario@example.com',
      email_verified: true,
    });

    expect(cookieNames(callback)).not.toContain('access_token');
    const row = await userRow(h, 'mario@example.com');
    expect(row?.googleId).toBe('g-original');
    expect(row?.provider).toBe('combined');
  });

  it('with the same googleId but a different email (changed on Google) gets into the same account, without creating a second one or 500 errors', async () => {
    await googleLogin(h.app, h.google, {
      sub: 'g-1',
      email: 'old@example.com',
      email_verified: true,
    });

    const { callback } = await googleLogin(h.app, h.google, {
      sub: 'g-1',
      email: 'new@example.com',
      email_verified: true,
    });

    expect(callback.status).toBeLessThan(400);
    expect(await userCount()).toBe(1);
    const access = cookieValue(callback, 'access_token')!;
    const me = await http(h)
      .get('/api/user/me')
      .set('Cookie', cookieHeader({ access }));
    expect(me.status).toBe(200);
    expect((me.body as { email: string }).email).toBe('old@example.com');
  });

  it('the Google identity (sub) wins over the email: the sub of A with the email of B gets into A, not B', async () => {
    await googleLogin(h.app, h.google, {
      sub: 'g-a',
      email: 'a@example.com',
      email_verified: true,
    });
    await createVerifiedUser(h, 'b@example.com');

    const { callback } = await googleLogin(h.app, h.google, {
      sub: 'g-a',
      email: 'b@example.com',
      email_verified: true,
    });

    expect(callback.status).toBeLessThan(400);
    const access = cookieValue(callback, 'access_token')!;
    const me = await http(h)
      .get('/api/user/me')
      .set('Cookie', cookieHeader({ access }));
    expect((me.body as { email: string }).email).toBe('a@example.com');
    expect((await userRow(h, 'b@example.com'))?.googleId).toBeNull();
  });
});
