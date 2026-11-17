/**
 * A1 - La password si sceglie alla CONFERMA dell'email.
 *
 * Senza questo, chi registra l'email di un altro con una password sua (pre-hijacking)
 * otterrebbe un account verificato appena la vittima clicca il link ricevuto: la password
 * dell'attaccante resterebbe valida. Chi conferma (il proprietario della casella) imposta
 * la propria password, che sostituisce quella inserita alla registrazione.
 */
import { createHarness, Harness } from './support/harness';
import { PASSWORD, http, login, register, sql, userRow } from './support/api';

const VICTIM = 'victim@example.com';
const ATTACKER_PASSWORD = 'Attacker-Passw0rd!';
const VICTIM_PASSWORD = 'Victim-Chosen-Passw0rd!';

describe('A1 - password alla conferma (e2e, PostgreSQL vero)', () => {
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

  const confirm = (token: string, password?: string) =>
    http(h)
      .post('/api/auth/verify-email')
      .send(password === undefined ? { token } : { token, password });

  it("pre-hijacking: la vittima conferma con la sua password e quella dell'attaccante smette di valere", async () => {
    await register(h, VICTIM, ATTACKER_PASSWORD);
    const token = h.mail.lastToken(VICTIM, 'verification');

    expect((await confirm(token, VICTIM_PASSWORD)).status).toBe(200);

    expect((await login(h, VICTIM, ATTACKER_PASSWORD)).status).toBe(401);
    expect((await login(h, VICTIM, VICTIM_PASSWORD)).status).toBe(200);
  });

  it("l'utente che si e registrato da solo puo riconfermare la stessa password e accedere", async () => {
    await register(h, VICTIM, PASSWORD);
    const token = h.mail.lastToken(VICTIM, 'verification');

    expect((await confirm(token, PASSWORD)).status).toBe(200);
    expect((await login(h, VICTIM, PASSWORD)).status).toBe(200);
  });

  it('senza password la conferma e rifiutata e il token resta valido', async () => {
    await register(h, VICTIM, ATTACKER_PASSWORD);
    const token = h.mail.lastToken(VICTIM, 'verification');

    expect((await confirm(token)).status).toBe(400);
    expect((await userRow(h, VICTIM))?.emailVerifiedAt).toBeNull();

    expect((await confirm(token, VICTIM_PASSWORD)).status).toBe(200);
  });

  it.each([
    ['troppo corta', 'short'],
    ['oltre 72 caratteri', 'x'.repeat(73)],
    ['oltre 72 byte', '€'.repeat(25)],
  ])('password %s: 400 e il token non viene consumato', async (_label, bad) => {
    await register(h, VICTIM, ATTACKER_PASSWORD);
    const token = h.mail.lastToken(VICTIM, 'verification');

    expect((await confirm(token, bad)).status).toBe(400);
    expect((await confirm(token, VICTIM_PASSWORD)).status).toBe(200);
  });

  it('nel database finisce solo un hash bcrypt della nuova password', async () => {
    await register(h, VICTIM, ATTACKER_PASSWORD);
    await confirm(h.mail.lastToken(VICTIM, 'verification'), VICTIM_PASSWORD);

    const row = await userRow(h, VICTIM);
    expect(row?.password).toMatch(/^\$2[aby]\$\d{2}\$/);
    expect(row?.password).not.toContain(VICTIM_PASSWORD);
    expect(row?.emailVerifiedAt).not.toBeNull();
  });

  it('con token non valido risponde 400 come con password errata nel formato (nessuna differenza osservabile)', async () => {
    const unknown = await confirm('x'.repeat(43), VICTIM_PASSWORD);
    expect(unknown.status).toBe(400);
    expect(unknown.body).toMatchObject({
      message: 'Invalid or expired token',
    });
  });

  it('il token e monouso anche con la password: due conferme concorrenti, ne riesce una sola e vince una sola password', async () => {
    await register(h, VICTIM, ATTACKER_PASSWORD);
    const token = h.mail.lastToken(VICTIM, 'verification');

    const results = await Promise.all([
      confirm(token, 'First-Passw0rd-one!'),
      confirm(token, 'Second-Passw0rd-two!'),
    ]);

    expect(results.map((r) => r.status).sort()).toEqual([200, 400]);
    const winner =
      results[0].status === 200
        ? 'First-Passw0rd-one!'
        : 'Second-Passw0rd-two!';
    const loser =
      results[0].status === 200
        ? 'Second-Passw0rd-two!'
        : 'First-Passw0rd-one!';
    expect((await login(h, VICTIM, winner)).status).toBe(200);
    expect((await login(h, VICTIM, loser)).status).toBe(401);
  });

  it('un token di verifica non cambia mai la password di un account gia verificato', async () => {
    await register(h, VICTIM, ATTACKER_PASSWORD);
    const token = h.mail.lastToken(VICTIM, 'verification');
    // L'account risulta verificato per altra via (es. un amministratore) ma il token e ancora in tabella.
    await h.db.query(
      `UPDATE users SET "emailVerifiedAt" = now(), password = $2 WHERE email = $1`,
      [VICTIM, await bcryptHash('Already-Verified-Passw0rd!')],
    );

    expect((await confirm(token, 'Takeover-Passw0rd-1!')).status).toBe(400);

    expect((await login(h, VICTIM, 'Already-Verified-Passw0rd!')).status).toBe(
      200,
    );
    expect((await login(h, VICTIM, 'Takeover-Passw0rd-1!')).status).toBe(401);
    const [{ n }] = await sql<{ n: number }>(
      h,
      `SELECT count(*)::int AS n FROM auth_tokens WHERE type = 'email_verification' AND "usedAt" IS NULL`,
    );
    expect(n).toBe(0); // il token e comunque consumato: non resta in giro
  });
});

async function bcryptHash(password: string): Promise<string> {
  const bcrypt = await import('bcrypt');
  return bcrypt.hash(password, 4);
}
