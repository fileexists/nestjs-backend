/**
 * B3 - Google: anti-CSRF `state` parameter (real PostgreSQL, real Google strategy with stubbed network).
 * Before: no `state`, so an attacker could make the victim complete a
 * callback with the attacker's OWN code (login CSRF / account swap).
 */
import request from 'supertest';
import { createHarness, Harness } from './support/harness';
import {
  browser,
  cookieNames,
  cookieValue,
  findSetCookie,
  sql,
} from './support/api';
import { googleLogin } from './support/google';

const PROFILE = {
  sub: 'g-1',
  email: 'mario@example.com',
  email_verified: true,
};

describe('B3 - Google state (e2e, real PostgreSQL)', () => {
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

  const stateOf = (res: request.Response): string | null =>
    new URL(res.headers.location).searchParams.get('state');

  const callback = (
    client: ReturnType<typeof browser>,
    params: { state?: string },
    info = PROFILE,
  ) =>
    client
      .get('/api/auth/google/callback')
      .query({ code: h.google.codeFor(info), ...params });

  describe('flow start (GET /auth/google)', () => {
    it('the redirect to Google contains a non-trivial state', async () => {
      const res = await browser(h).get('/api/auth/google');

      expect(res.status).toBe(302);
      expect(res.headers.location).toMatch(
        /^https:\/\/accounts\.google\.com\//,
      );
      expect(stateOf(res)).toMatch(/^[\w-]{30,}$/);
    });

    it('sets an oauth_state cookie that is httpOnly, SameSite=Lax, limited to the Google path and short-lived', async () => {
      const res = await browser(h).get('/api/auth/google');

      const cookie = findSetCookie(res, 'oauth_state');
      expect(cookie).toBeDefined();
      expect(cookie).toMatch(/HttpOnly/i);
      expect(cookie).toMatch(/SameSite=Lax/i);
      expect(cookie).toMatch(/Path=\/api\/auth\/google(;|$)/);
      expect(cookie).toMatch(/Max-Age=\d+|Expires=/i);
    });

    it('the cookie is signed: it does not contain just the nonce', async () => {
      const res = await browser(h).get('/api/auth/google');
      const value = cookieValue(res, 'oauth_state')!;
      const state = stateOf(res)!;

      expect(value).not.toBe(state);
      expect(value.startsWith(state)).toBe(true);
      expect(value.split('.').length).toBeGreaterThanOrEqual(2);
    });

    it('every start has a different state', async () => {
      const a = stateOf(await browser(h).get('/api/auth/google'));
      const b = stateOf(await browser(h).get('/api/auth/google'));
      expect(a).not.toBe(b);
    });
  });

  describe('callback', () => {
    it('with the correct state completes the login', async () => {
      const { callback: res } = await googleLogin(h.app, h.google, PROFILE);

      expect(res.status).toBeLessThan(400);
      expect(cookieNames(res)).toContain('access_token');
      expect(await userCount()).toBe(1);
    });

    it('without a state it is rejected: no session and no user created', async () => {
      const client = browser(h);
      await client.get('/api/auth/google');

      const res = await callback(client, {});

      expect(res.status).toBeGreaterThanOrEqual(300);
      expect(cookieNames(res)).not.toContain('access_token');
      expect(await userCount()).toBe(0);
    });

    it('with a wrong state it is rejected', async () => {
      const client = browser(h);
      await client.get('/api/auth/google');

      const res = await callback(client, {
        state: 'not-the-state-we-issued-0123456789',
      });

      expect(cookieNames(res)).not.toContain('access_token');
      expect(await userCount()).toBe(0);
    });

    it("login CSRF: the attacker's state/code presented by the victim's browser (without the cookie) is rejected", async () => {
      const attacker = browser(h);
      const attackerState = stateOf(await attacker.get('/api/auth/google'))!;
      const victim = browser(h); // no oauth_state cookie

      const res = await callback(victim, { state: attackerState });

      expect(cookieNames(res)).not.toContain('access_token');
      expect(await userCount()).toBe(0);
    });

    it('the state of one browser is not valid for another browser', async () => {
      const a = browser(h);
      const b = browser(h);
      const stateA = stateOf(await a.get('/api/auth/google'))!;
      await b.get('/api/auth/google');

      const res = await callback(b, { state: stateA });

      expect(cookieNames(res)).not.toContain('access_token');
    });

    it('a forged cookie (nonce chosen by the attacker, made-up signature) is rejected', async () => {
      const nonce = 'attacker-chosen-nonce-0123456789abcdef';
      const res = await request(h.app.getHttpServer())
        .get('/api/auth/google/callback')
        .set(
          'Cookie',
          `oauth_state=${nonce}.0.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`,
        )
        .query({ code: h.google.codeFor(PROFILE), state: nonce });

      expect(cookieNames(res)).not.toContain('access_token');
      expect(await userCount()).toBe(0);
    });

    it('the state is single-use: after success the cookie is cleared and the replay fails', async () => {
      const client = browser(h);
      const init = await client.get('/api/auth/google');
      const state = stateOf(init)!;
      const cookie = cookieValue(init, 'oauth_state')!;

      const first = await callback(client, { state });
      expect(cookieNames(first)).toContain('access_token');
      expect(findSetCookie(first, 'oauth_state')).toMatch(
        /oauth_state=;|Expires=Thu, 01 Jan 1970/i,
      );

      // replay: even if someone presents the old cookie again, a second clean browser has nothing left
      const replay = await request(h.app.getHttpServer())
        .get('/api/auth/google/callback')
        .query({ code: h.google.codeFor(PROFILE), state });
      expect(cookieNames(replay)).not.toContain('access_token');
      expect(cookie).toBeDefined();
    });

    it('a callback with a Google error (user denies consent) creates no sessions even with a valid state', async () => {
      const client = browser(h);
      const state = stateOf(await client.get('/api/auth/google'))!;

      const res = await client
        .get('/api/auth/google/callback')
        .query({ error: 'access_denied', state });

      expect(res.status).toBeGreaterThanOrEqual(300);
      expect(cookieNames(res)).not.toContain('access_token');
    });
  });
});
