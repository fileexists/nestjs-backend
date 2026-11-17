/**
 * C1 - Il callback Google imposta i cookie e fa redirect al frontend (FRONTEND_URL),
 * con esito di successo o di errore, senza mai redirect aperti. (PostgreSQL vero)
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

describe('C1 - redirect del callback Google (e2e, PostgreSQL vero)', () => {
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

  describe('successo', () => {
    it('risponde 302 verso FRONTEND_URL con status=success e senza JSON', async () => {
      const { callback } = await googleLogin(h.app, h.google, OK);

      expect(callback.status).toBe(302);
      const url = location(callback);
      expect(url.origin).toBe(FRONTEND);
      expect(url.pathname).toBe('/auth/callback');
      expect(url.searchParams.get('status')).toBe('success');
      expect(url.searchParams.get('reason')).toBeNull();
      expect(callback.body).toEqual({});
    });

    it('imposta i cookie di sessione (httpOnly) e nessun token compare nell URL di redirect', async () => {
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

    it('la sessione ottenuta funziona sulle API', async () => {
      const { agent } = await googleLogin(h.app, h.google, OK);

      expect((await agent.get('/api/user/me')).status).toBe(200);
    });
  });

  describe('errori: redirect con status=error e un motivo, mai sessioni', () => {
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

    it('email non verificata da Google', async () => {
      const { callback } = await googleLogin(h.app, h.google, {
        sub: 'g',
        email: 'x@example.com',
        email_verified: false,
      });
      expectError(callback, 'email_unverified');
    });

    it('profilo senza email', async () => {
      const { callback } = await googleLogin(h.app, h.google, {
        sub: 'g',
        email_verified: true,
      });
      expectError(callback, 'email_missing');
    });

    it('state mancante o non valido', async () => {
      const client = browser(h);
      await client.get('/api/auth/google');
      const res = await client
        .get('/api/auth/google/callback')
        .query({ code: h.google.codeFor(OK) });
      expectError(res, 'state_invalid');
    });

    it('googleId diverso da quello collegato', async () => {
      await googleLogin(h.app, h.google, OK);
      const { callback } = await googleLogin(h.app, h.google, {
        ...OK,
        sub: 'g-other',
      });
      expectError(callback, 'account_conflict');
    });

    it("l'utente nega il consenso su Google (?error=access_denied)", async () => {
      const client = browser(h);
      const init = await client.get('/api/auth/google');
      const state = new URL(init.headers.location).searchParams.get('state')!;
      const res = await client
        .get('/api/auth/google/callback')
        .query({ error: 'access_denied', state });
      expectError(res, 'failed');
    });

    it('nessun utente viene creato quando il login fallisce', async () => {
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

  describe('nessun open redirect', () => {
    it('la destinazione non dipende da Host, Referer, X-Forwarded-Host ne da parametri del callback', async () => {
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

    it('/auth/google rifiuta un redirect_to fuori whitelist con 400 e non avvia il flusso', async () => {
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

    it("/auth/google accetta redirect_to uguale a un'origine della whitelist", async () => {
      const res = await http(h)
        .get('/api/auth/google')
        .query({ redirect_to: FRONTEND });
      expect(res.status).toBe(302);
    });
  });

  it("l'utente con password che entra da Google riceve comunque il redirect di successo", async () => {
    await createVerifiedUser(h, 'mario@example.com');
    const { callback } = await googleLogin(h.app, h.google, OK);
    expect(callback.status).toBe(302);
    expect(location(callback).searchParams.get('status')).toBe('success');
  });
});
