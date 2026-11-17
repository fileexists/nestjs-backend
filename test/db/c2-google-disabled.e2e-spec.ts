/**
 * C2 - Se GOOGLE_* non sono configurate il provider e' disattivato: gli endpoint Google
 * rispondono 501 e non viene registrata nessuna strategia con `placeholder-client-id`.
 */
// Prima di importare AppModule: ConfigModule legge l'ambiente al caricamento del modulo.
process.env.GOOGLE_CLIENT_ID = '';
process.env.GOOGLE_CLIENT_SECRET = '';
process.env.GOOGLE_CALLBACK_URL = '';

import passport from 'passport';
import { createHarness, Harness } from './support/harness';
import { createVerifiedUser, http, login } from './support/api';

describe('C2 - Google non configurato (e2e)', () => {
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

  it('GET /auth/google risponde 501 con un messaggio chiaro', async () => {
    const res = await http(h).get('/api/auth/google');
    expect(res.status).toBe(501);
    expect(JSON.stringify(res.body)).toMatch(/not configured/i);
    expect(res.headers.location).toBeUndefined();
  });

  it('GET /auth/google/callback risponde 501 (non un redirect, non un 500)', async () => {
    const res = await http(h)
      .get('/api/auth/google/callback')
      .query({ code: 'x', state: 'y' });
    expect(res.status).toBe(501);
  });

  it('non registra nessuna strategia Passport "google" (niente placeholder-client-id)', () => {
    const strategy = (
      passport as unknown as { _strategy(n: string): unknown }
    )._strategy('google');
    expect(strategy).toBeUndefined();
  });

  it("il resto dell'app funziona: il login con password non e' toccato", async () => {
    await createVerifiedUser(h, 'mario@example.com');
    expect((await login(h, 'mario@example.com')).status).toBe(200);
  });
});
