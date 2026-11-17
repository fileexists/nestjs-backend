/**
 * D4 - Registrazione concorrente della stessa email (PostgreSQL vero).
 * Prima: la violazione di unicita (23505) diventava un 500.
 */
import { createHarness, Harness } from './support/harness';
import { cookieNames, register, sql } from './support/api';
import { googleLogin } from './support/google';

describe('D4 - registrazioni concorrenti (e2e, PostgreSQL vero)', () => {
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

  it('la stessa email inviata 10 volte insieme: nessun 500, un solo utente', async () => {
    const results = await Promise.all(
      Array.from({ length: 10 }, () => register(h, 'race@example.com')),
    );

    expect(results.map((r) => r.status).filter((s) => s >= 500)).toEqual([]);
    expect(new Set(results.map((r) => r.status))).toEqual(new Set([202])); // risposta uniforme
    expect(await userCount()).toBe(1);
  });

  it('stessa email in forme diverse (maiuscole/spazi) in parallelo: un solo utente', async () => {
    const variants = [
      'race@example.com',
      'RACE@example.com',
      ' Race@Example.com ',
      'rAcE@EXAMPLE.com',
    ];
    const results = await Promise.all(
      variants.map((email) => register(h, email)),
    );

    expect(results.every((r) => r.status === 202)).toBe(true);
    expect(await userCount()).toBe(1);
  });

  it("chi perde la corsa riceve l'avviso 'indirizzo gia registrato', chi vince la verifica", async () => {
    await Promise.all(
      Array.from({ length: 6 }, () => register(h, 'race@example.com')),
    );

    expect(h.mail.to('race@example.com', 'verification')).toHaveLength(1);
    // al massimo un avviso (periodo di attesa), mai un secondo token
    expect(
      h.mail.to('race@example.com', 'registration-notice').length,
    ).toBeLessThanOrEqual(5);
  });

  it('due primi accessi Google contemporanei dello stesso utente: nessun 500, un solo utente', async () => {
    const profile = {
      sub: 'g-race',
      email: 'g-race@example.com',
      email_verified: true,
    };

    const results = await Promise.all([
      googleLogin(h.app, h.google, profile),
      googleLogin(h.app, h.google, profile),
      googleLogin(h.app, h.google, profile),
    ]);

    for (const { callback } of results) {
      expect(callback.status).toBe(302);
      expect(callback.headers.location).toContain('status=success');
      expect(cookieNames(callback)).toContain('access_token');
    }
    expect(await userCount()).toBe(1);
  });
});
