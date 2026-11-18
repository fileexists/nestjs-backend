/**
 * C1 - The Google callback sets the cookies and redirects to the frontend (FRONTEND_URL),
 * with a success or error outcome, never with open redirects. (real PostgreSQL)
 */
import { createHarness, Harness } from './support/harness';
import {
  browser,
  cookieNames,
  cookieValue,
  createVerifiedUser,
  findSetCookie,
  http,
  sql,
} from './support/api';
import { googleLogin } from './support/google';

const FRONTEND = 'http://localhost:3000';
const OK = { sub: 'g-1', email: 'mario@example.com', email_verified: true };

describe('C1 - Google callback redirect (e2e, real PostgreSQL)', () => {
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

  const location = (res: { headers: Record<string, unknown> }) =>
    new URL(res.headers.location as string);

  describe('success', () => {
    it('answers 302 to FRONTEND_URL with status=success and no JSON', async () => {
      const { callback } = await googleLogin(h.app, h.google, OK);

      expect(callback.status).toBe(302);
      const url = location(callback);
      expect(url.origin).toBe(FRONTEND);
      expect(url.pathname).toBe('/auth/callback');
      expect(url.searchParams.get('status')).toBe('success');
      expect(url.searchParams.get('reason')).toBeNull();
      expect(callback.body).toEqual({});
    });

    it('sets the session cookies (httpOnly) and no token appears in the redirect URL', async () => {
      const { callback } = await googleLogin(h.app, h.google, OK);

      expect(cookieNames(callback)).toEqual(
        expect.arrayContaining(['access_token', 'refresh_token']),
      );
      expect(findSetCookie(callback, 'access_token')).toMatch(/HttpOnly/i);
      expect(findSetCookie(callback, 'refresh_token')).toMatch(/HttpOnly/i);
      const target = callback.headers.location;
      expect(target).not.toContain(cookieValue(callback, 'access_token')!);
      expect(target).not.toContain(cookieValue(callback, 'refresh_token')!);
    });

    it('the obtained session works on the APIs', async () => {
      const { agent } = await googleLogin(h.app, h.google, OK);

      expect((await agent.get('/api/user/me')).status).toBe(200);
    });
  });

  describe('errors: redirect with status=error and a reason, never sessions', () => {
    const expectError = (
      res: { status: number; headers: Record<string, unknown> },
      reason: string,
    ) => {
      expect(res.status).toBe(302);
      const url = location(res);
      expect(url.origin).toBe(FRONTEND);
      expect(url.pathname).toBe('/auth/callback');
      expect(url.searchParams.get('status')).toBe('error');
      expect(url.searchParams.get('reason')).toBe(reason);
      expect(cookieNames(res as never)).not.toContain('access_token');
      expect(cookieNames(res as never)).not.toContain('refresh_token');
    };

    it('email not verified by Google', async () => {
      const { callback } = await googleLogin(h.app, h.google, {
        sub: 'g',
        email: 'x@example.com',
        email_verified: false,
      });
      expectError(callback, 'email_unverified');
    });

    it('profile without an email', async () => {
      const { callback } = await googleLogin(h.app, h.google, {
        sub: 'g',
        email_verified: true,
      });
      expectError(callback, 'email_missing');
    });

    it('missing or invalid state', async () => {
      const client = browser(h);
      await client.get('/api/auth/google');
      const res = await client
        .get('/api/auth/google/callback')
        .query({ code: h.google.codeFor(OK) });
      expectError(res, 'state_invalid');
    });

    it('googleId different from the linked one', async () => {
      await googleLogin(h.app, h.google, OK);
      const { callback } = await googleLogin(h.app, h.google, {
        ...OK,
        sub: 'g-other',
      });
      expectError(callback, 'account_conflict');
    });

    it('the user denies consent on Google (?error=access_denied)', async () => {
      const client = browser(h);
      const init = await client.get('/api/auth/google');
      const state = new URL(init.headers.location).searchParams.get('state')!;
      const res = await client
        .get('/api/auth/google/callback')
        .query({ error: 'access_denied', state });
      expectError(res, 'failed');
    });

    it('no user is created when the login fails', async () => {
      await googleLogin(h.app, h.google, {
        sub: 'g',
        email: 'x@example.com',
        email_verified: false,
      });
      const [{ n }] = await sql<{ n: number }>(
        h,
        'SELECT count(*)::int AS n FROM users',
      );
      expect(n).toBe(0);
    });
  });

  describe('no open redirect', () => {
    it('the destination does not depend on Host, Referer, X-Forwarded-Host or on callback parameters', async () => {
      const client = browser(h);
      const init = await client.get('/api/auth/google');
      const state = new URL(init.headers.location).searchParams.get('state')!;

      const res = await client
        .get('/api/auth/google/callback')
        .set('Host', 'evil.example.com')
        .set('Referer', 'https://evil.example.com/')
        .set('X-Forwarded-Host', 'evil.example.com')
        .query({
          code: h.google.codeFor(OK),
          state,
          redirect_to: 'https://evil.example.com',
          next: 'https://evil.example.com',
          returnTo: 'https://evil.example.com',
        });

      expect(res.status).toBe(302);
      expect(location(res).origin).toBe(FRONTEND);
    });

    it('/auth/google rejects a redirect_to outside the whitelist with 400 and does not start the flow', async () => {
      for (const evil of [
        'https://evil.example.com',
        'http://localhost:3000.evil.com',
        'http://localhost:3000@evil.com',
        '//evil.example.com',
        'javascript:alert(1)',
      ]) {
        const res = await http(h)
          .get('/api/auth/google')
          .query({ redirect_to: evil });
        expect(res.status).toBe(400);
        expect(cookieNames(res)).not.toContain('oauth_state');
      }
    });

    it('/auth/google accepts a redirect_to equal to an origin in the whitelist', async () => {
      const res = await http(h)
        .get('/api/auth/google')
        .query({ redirect_to: FRONTEND });
      expect(res.status).toBe(302);
    });
  });

  it('a user with a password who signs in from Google still gets the success redirect', async () => {
    await createVerifiedUser(h, 'mario@example.com');
    const { callback } = await googleLogin(h.app, h.google, OK);
    expect(callback.status).toBe(302);
    expect(location(callback).searchParams.get('status')).toBe('success');
  });
});
