/**
 * A1 - Account pre-hijacking (real PostgreSQL, Google strategy with stubbed network).
 *
 * Scenario: the attacker registers the victim's address with email+password
 * (the email is not verified); the victim then logs in with Google. The attacker's
 * password must NOT stay valid.
 */
import { createHarness, Harness } from './support/harness';
import { googleLogin } from './support/google';
import {
  PASSWORD,
  cookieNames,
  createVerifiedUser,
  http,
  login,
  register,
  sql,
  userRow,
} from './support/api';

const VICTIM = 'victim@example.com';
const ATTACKER_PASSWORD = 'AttackerPassw0rd!';

describe('A1 - pre-hijacking (e2e, real PostgreSQL)', () => {
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

  it("the attacker's password does not work after the victim's Google login", async () => {
    const registered = await register(h, VICTIM, ATTACKER_PASSWORD);
    expect(registered.status).toBeLessThan(300);

    const { callback } = await googleLogin(h.app, h.google, {
      sub: 'google-sub-victim',
      email: VICTIM,
      email_verified: true,
    });
    expect(callback.status).toBeLessThan(400);

    const attackerLogin = await login(h, VICTIM, ATTACKER_PASSWORD);
    expect(attackerLogin.status).toBe(401);
  });

  it('claims the account: password reset, Google linked, email verified, sessions invalidated', async () => {
    await register(h, VICTIM, ATTACKER_PASSWORD);
    const before = await userRow(h, VICTIM);
    expect(before?.emailVerifiedAt).toBeNull();

    const { callback } = await googleLogin(h.app, h.google, {
      sub: 'google-sub-victim',
      email: VICTIM,
      email_verified: true,
    });
    expect(cookieNames(callback)).toContain('access_token');

    const after = await userRow(h, VICTIM);
    expect(after).toMatchObject({
      id: before?.id,
      password: null,
      googleId: 'google-sub-victim',
      provider: 'google',
      tokenVersion: (before?.tokenVersion ?? 0) + 1,
    });
    expect(after?.emailVerifiedAt).not.toBeNull();

    // The pending verification tokens of the claimed account are no longer needed.
    const [{ pending }] = await sql<{ pending: number }>(
      h,
      'SELECT count(*)::int AS pending FROM auth_tokens WHERE "userId" = $1',
      [before?.id],
    );
    expect(pending).toBe(0);
  });

  it('even with the email already verified via link, the attacker cannot get in with the stolen verification token after the claim', async () => {
    await register(h, VICTIM, ATTACKER_PASSWORD);
    const staleToken = h.mail.lastToken(VICTIM, 'verification');

    await googleLogin(h.app, h.google, {
      sub: 'google-sub-victim',
      email: VICTIM,
      email_verified: true,
    });

    const res = await http(h)
      .post('/api/auth/verify-email')
      .send({ token: staleToken, password: 'Takeover-Passw0rd-1!' });
    expect(res.status).toBe(400);
  });

  it('links Google to an ALREADY verified local account without touching the password', async () => {
    await createVerifiedUser(h, 'owner@example.com');

    const { callback } = await googleLogin(h.app, h.google, {
      sub: 'google-sub-owner',
      email: 'owner@example.com',
      email_verified: true,
    });
    expect(cookieNames(callback)).toContain('access_token');

    const row = await userRow(h, 'owner@example.com');
    expect(row).toMatchObject({
      googleId: 'google-sub-owner',
      provider: 'combined',
      tokenVersion: 0,
    });
    expect(row?.password).not.toBeNull();
    expect((await login(h, 'owner@example.com', PASSWORD)).status).toBe(200);
  });

  it('creates a new, already verified user from Google', async () => {
    const { callback } = await googleLogin(h.app, h.google, {
      sub: 'google-sub-new',
      email: 'new@example.com',
      email_verified: true,
    });
    expect(cookieNames(callback)).toContain('access_token');
    const row = await userRow(h, 'new@example.com');
    expect(row?.emailVerifiedAt).not.toBeNull();
    expect(row?.password).toBeNull();
  });

  describe('unacceptable Google profiles', () => {
    it.each([
      [
        'email_verified=false',
        { sub: 's1', email: 'x@example.com', email_verified: false },
      ],
      ['email_verified missing', { sub: 's2', email: 'x@example.com' }],
      ['email missing', { sub: 's3', email_verified: true }],
    ])('%s: no session, no user created and no 500', async (_label, info) => {
      const { callback } = await googleLogin(h.app, h.google, info);

      expect(callback.status).toBeGreaterThanOrEqual(300);
      expect(callback.status).toBeLessThan(500);
      expect(cookieNames(callback)).not.toContain('access_token');
      const [{ count }] = await sql<{ count: number }>(
        h,
        'SELECT count(*)::int AS count FROM users',
      );
      expect(count).toBe(0);
    });

    it('the unverified email is NOT linked to an existing account', async () => {
      await createVerifiedUser(h, 'owner@example.com');

      await googleLogin(h.app, h.google, {
        sub: 'evil-sub',
        email: 'owner@example.com',
        email_verified: false,
      });

      const row = await userRow(h, 'owner@example.com');
      expect(row?.googleId).toBeNull();
      expect(row?.provider).toBe('local');
    });

    it('the unverified email goes back to the frontend with a clear reason (the 401 with a message belongs to the strategy: see google-profile.spec)', async () => {
      const { callback } = await googleLogin(h.app, h.google, {
        sub: 's9',
        email: 'x@example.com',
        email_verified: false,
      });

      expect(callback.status).toBe(302);
      const url = new URL(callback.headers.location);
      expect(url.searchParams.get('status')).toBe('error');
      expect(url.searchParams.get('reason')).toBe('email_unverified');
    });
  });
});
