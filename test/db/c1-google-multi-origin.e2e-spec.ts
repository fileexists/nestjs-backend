/**
 * C1 - FRONTEND_URL with several origins: the final redirect is chosen ONLY among those
 * in the whitelist. (real PostgreSQL)
 */
// Before importing AppModule: ConfigModule reads the environment when the module loads.
process.env.FRONTEND_URL = 'http://localhost:3000, http://admin.localhost:3001';

import { createHarness, Harness } from './support/harness';
import { browser, cookieNames } from './support/api';

const OK = { sub: 'g-1', email: 'mario@example.com', email_verified: true };

describe('C1 - several origins in FRONTEND_URL (e2e)', () => {
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

  it('without redirect_to uses the first origin', async () => {
    const { callback } = await login();
    expect(new URL(callback!.headers.location).origin).toBe(
      'http://localhost:3000',
    );
  });

  it('with redirect_to equal to the second origin it goes back there', async () => {
    const { callback } = await login('http://admin.localhost:3001');
    expect(callback!.status).toBe(302);
    expect(new URL(callback!.headers.location).origin).toBe(
      'http://admin.localhost:3001',
    );
    expect(cookieNames(callback as never)).toContain('access_token');
  });

  it('errors also go back to the chosen origin', async () => {
    const client = browser(h);
    await client
      .get('/api/auth/google')
      .query({ redirect_to: 'http://admin.localhost:3001' });
    const res = await client
      .get('/api/auth/google/callback')
      .query({ code: h.google.codeFor(OK) });
    const url = new URL(res.headers.location);
    expect(url.origin).toBe('http://localhost:3000'); // missing state: the index cannot be verified -> default
    expect(url.searchParams.get('reason')).toBe('state_invalid');
  });

  it.each([
    'http://admin.localhost:3001.evil.com',
    'http://admin.localhost:3002',
    'https://admin.localhost:3001',
    'http://evil.com',
  ])('rejects %s (it is not in the whitelist)', async (evil) => {
    const { init } = await login(evil);
    expect(init.status).toBe(400);
  });

  it('the chosen redirect cannot be changed on return: the cookie is signed', async () => {
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
      .set('Cookie', `oauth_state=${nonce}.1.${signature}`) // tampered index towards the other origin
      .query({ code: h.google.codeFor(OK), state });

    expect(cookieNames(res)).not.toContain('access_token');
    expect(new URL(res.headers.location).searchParams.get('reason')).toBe(
      'state_invalid',
    );
  });
});
