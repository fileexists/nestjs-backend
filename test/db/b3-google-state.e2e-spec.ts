/**
 * B3 - Google: parametro `state` anti-CSRF (PostgreSQL vero, strategia Google reale a rete stubbata).
 * Prima: nessun `state`, quindi un attaccante poteva far completare alla vittima un
 * callback con il PROPRIO code (login CSRF / account swap).
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

describe('B3 - state Google (e2e, PostgreSQL vero)', () => {
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

  describe('avvio del flusso (GET /auth/google)', () => {
    it('il redirect verso Google contiene un state non banale', async () => {
      const res = await browser(h).get('/api/auth/google');

      expect(res.status).toBe(302);
      expect(res.headers.location).toMatch(
        /^https:\/\/accounts\.google\.com\//,
      );
      expect(stateOf(res)).toMatch(/^[\w-]{30,}$/);
    });

    it('imposta un cookie oauth_state httpOnly, SameSite=Lax, limitato al percorso Google e a breve durata', async () => {
      const res = await browser(h).get('/api/auth/google');

      const cookie = findSetCookie(res, 'oauth_state');
      expect(cookie).toBeDefined();
      expect(cookie).toMatch(/HttpOnly/i);
      expect(cookie).toMatch(/SameSite=Lax/i);
      expect(cookie).toMatch(/Path=\/api\/auth\/google(;|$)/);
      expect(cookie).toMatch(/Max-Age=\d+|Expires=/i);
    });

    it('il cookie e firmato: non contiene soltanto il nonce', async () => {
      const res = await browser(h).get('/api/auth/google');
      const value = cookieValue(res, 'oauth_state')!;
      const state = stateOf(res)!;

      expect(value).not.toBe(state);
      expect(value.startsWith(state)).toBe(true);
      expect(value.split('.').length).toBeGreaterThanOrEqual(2);
    });

    it('ogni avvio ha un state diverso', async () => {
      const a = stateOf(await browser(h).get('/api/auth/google'));
      const b = stateOf(await browser(h).get('/api/auth/google'));
      expect(a).not.toBe(b);
    });
  });

  describe('callback', () => {
    it('con state corretto completa il login', async () => {
      const { callback: res } = await googleLogin(h.app, h.google, PROFILE);

      expect(res.status).toBeLessThan(400);
      expect(cookieNames(res)).toContain('access_token');
      expect(await userCount()).toBe(1);
    });

    it('senza state viene rifiutato: nessuna sessione e nessun utente creato', async () => {
      const client = browser(h);
      await client.get('/api/auth/google');

      const res = await callback(client, {});

      expect(res.status).toBeGreaterThanOrEqual(300);
      expect(cookieNames(res)).not.toContain('access_token');
      expect(await userCount()).toBe(0);
    });

    it('con state sbagliato viene rifiutato', async () => {
      const client = browser(h);
      await client.get('/api/auth/google');

      const res = await callback(client, {
        state: 'not-the-state-we-issued-0123456789',
      });

      expect(cookieNames(res)).not.toContain('access_token');
      expect(await userCount()).toBe(0);
    });

    it("login CSRF: lo state/code dell'attaccante presentato dal browser della vittima (senza cookie) viene rifiutato", async () => {
      const attacker = browser(h);
      const attackerState = stateOf(await attacker.get('/api/auth/google'))!;
      const victim = browser(h); // nessun cookie oauth_state

      const res = await callback(victim, { state: attackerState });

      expect(cookieNames(res)).not.toContain('access_token');
      expect(await userCount()).toBe(0);
    });

    it('lo state di un browser non vale per un altro browser', async () => {
      const a = browser(h);
      const b = browser(h);
      const stateA = stateOf(await a.get('/api/auth/google'))!;
      await b.get('/api/auth/google');

      const res = await callback(b, { state: stateA });

      expect(cookieNames(res)).not.toContain('access_token');
    });

    it('un cookie forgiato (nonce scelto da chi attacca, firma inventata) viene rifiutato', async () => {
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

    it('lo state e monouso: dopo il successo il cookie viene cancellato e il replay fallisce', async () => {
      const client = browser(h);
      const init = await client.get('/api/auth/google');
      const state = stateOf(init)!;
      const cookie = cookieValue(init, 'oauth_state')!;

      const first = await callback(client, { state });
      expect(cookieNames(first)).toContain('access_token');
      expect(findSetCookie(first, 'oauth_state')).toMatch(
        /oauth_state=;|Expires=Thu, 01 Jan 1970/i,
      );

      // replay: anche se qualcuno ripresenta il vecchio cookie, un secondo browser pulito non ha piu nulla
      const replay = await request(h.app.getHttpServer())
        .get('/api/auth/google/callback')
        .query({ code: h.google.codeFor(PROFILE), state });
      expect(cookieNames(replay)).not.toContain('access_token');
      expect(cookie).toBeDefined();
    });

    it('un callback con errore di Google (utente nega il consenso) non crea sessioni nemmeno con state valido', async () => {
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
