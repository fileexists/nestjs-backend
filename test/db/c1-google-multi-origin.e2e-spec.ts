/**
 * C1 - FRONTEND_URL con piu origini: il redirect finale e' scelto SOLO tra quelle
 * della whitelist. (PostgreSQL vero)
 */
// Prima di importare AppModule: ConfigModule legge l'ambiente al caricamento del modulo.
process.env.FRONTEND_URL = 'http://localhost:3000, http://admin.localhost:3001';

import { createHarness, Harness } from './support/harness';
import { browser, cookieNames } from './support/api';

const OK = { sub: 'g-1', email: 'mario@example.com', email_verified: true };

describe('C1 - piu origini in FRONTEND_URL (e2e)', () => {
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

  async function login(redirectTo?: string) {
    const client = browser(h);
    const init = await client
      .get('/api/auth/google')
      .query(redirectTo ? { redirect_to: redirectTo } : {});
    if (init.status !== 302) return { init, callback: undefined };
    const state = new URL(init.headers.location).searchParams.get('state')!;
    const callback = await client
      .get('/api/auth/google/callback')
      .query({ code: h.google.codeFor(OK), state });
    return { init, callback };
  }

  it('senza redirect_to usa la prima origine', async () => {
    const { callback } = await login();
    expect(new URL(callback!.headers.location).origin).toBe(
      'http://localhost:3000',
    );
  });

  it('con redirect_to uguale alla seconda origine ci torna', async () => {
    const { callback } = await login('http://admin.localhost:3001');
    expect(callback!.status).toBe(302);
    expect(new URL(callback!.headers.location).origin).toBe(
      'http://admin.localhost:3001',
    );
    expect(cookieNames(callback as never)).toContain('access_token');
  });

  it("anche gli errori tornano all'origine scelta", async () => {
    const client = browser(h);
    await client
      .get('/api/auth/google')
      .query({ redirect_to: 'http://admin.localhost:3001' });
    const res = await client
      .get('/api/auth/google/callback')
      .query({ code: h.google.codeFor(OK) });
    const url = new URL(res.headers.location);
    expect(url.origin).toBe('http://localhost:3000'); // state mancante: indice non verificabile -> default
    expect(url.searchParams.get('reason')).toBe('state_invalid');
  });

  it.each([
    'http://admin.localhost:3001.evil.com',
    'http://admin.localhost:3002',
    'https://admin.localhost:3001',
    'http://evil.com',
  ])('rifiuta %s (non e nella whitelist)', async (evil) => {
    const { init } = await login(evil);
    expect(init.status).toBe(400);
  });

  it('il redirect scelto non puo essere cambiato al ritorno: il cookie e firmato', async () => {
    const client = browser(h);
    const init = await client
      .get('/api/auth/google')
      .query({ redirect_to: 'http://localhost:3000' });
    const state = new URL(init.headers.location).searchParams.get('state')!;
    const cookie = init.headers['set-cookie'] as unknown as string[];
    const value = cookie[0].split(';')[0].split('=')[1];
    const [nonce, , signature] = value.split('.');

    const res = await browser(h)
      .get('/api/auth/google/callback')
      .set('Cookie', `oauth_state=${nonce}.1.${signature}`) // indice alterato verso l'altra origine
      .query({ code: h.google.codeFor(OK), state });

    expect(cookieNames(res)).not.toContain('access_token');
    expect(new URL(res.headers.location).searchParams.get('reason')).toBe(
      'state_invalid',
    );
  });
});
