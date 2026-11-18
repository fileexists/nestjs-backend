/**
 * C2 - If GOOGLE_* are not configured the provider is disabled: the Google endpoints
 * answer 501 and no strategy with `placeholder-client-id` is registered.
 */
// Before importing AppModule: ConfigModule reads the environment when the module loads.
process.env.GOOGLE_CLIENT_ID = '';
process.env.GOOGLE_CLIENT_SECRET = '';
process.env.GOOGLE_CALLBACK_URL = '';

import passport from 'passport';
import { createHarness, Harness } from './support/harness';
import { createVerifiedUser, http, login } from './support/api';

describe('C2 - Google not configured (e2e)', () => {
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

  it('GET /auth/google answers 501 with a clear message', async () => {
    const res = await http(h).get('/api/auth/google');
    expect(res.status).toBe(501);
    expect(JSON.stringify(res.body)).toMatch(/not configured/i);
    expect(res.headers.location).toBeUndefined();
  });

  it('GET /auth/google/callback answers 501 (not a redirect, not a 500)', async () => {
    const res = await http(h)
      .get('/api/auth/google/callback')
      .query({ code: 'x', state: 'y' });
    expect(res.status).toBe(501);
  });

  it('does not register any "google" Passport strategy (no placeholder-client-id)', () => {
    const strategy = (
      passport as unknown as { _strategy(n: string): unknown }
    )._strategy('google');
    expect(strategy).toBeUndefined();
  });

  it('the rest of the app works: the password login is untouched', async () => {
    await createVerifiedUser(h, 'mario@example.com');
    expect((await login(h, 'mario@example.com')).status).toBe(200);
  });
});
