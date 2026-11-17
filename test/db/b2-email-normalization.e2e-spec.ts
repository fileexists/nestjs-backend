/**
 * B2 - Normalizzazione delle email (PostgreSQL vero).
 * Prima: `Mario.Rossi@Example.com` e `mario.rossi@example.com` creavano due account.
 */
import { createHarness, Harness } from './support/harness';
import {
  PASSWORD,
  createVerifiedUser,
  http,
  login,
  register,
  sql,
  userRow,
  verifyEmail,
} from './support/api';
import { googleLogin } from './support/google';

const MIXED = 'Mario.Rossi@Example.com';
const LOWER = 'mario.rossi@example.com';

describe('B2 - email case-insensitive (e2e, PostgreSQL vero)', () => {
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

  it('la registrazione salva l email in minuscolo e senza spazi', async () => {
    const res = await register(h, `  ${MIXED}  `);
    expect(res.status).toBeLessThan(300);

    const rows = await sql<{ email: string }>(h, 'SELECT email FROM users');
    expect(rows).toEqual([{ email: LOWER }]);
  });

  it('due registrazioni che differiscono solo per maiuscole creano UN solo account', async () => {
    await register(h, MIXED);
    const second = await register(h, LOWER);

    expect(second.status).toBeLessThan(500);
    expect(await userCount()).toBe(1);
  });

  it('il login funziona con qualsiasi combinazione di maiuscole e spazi', async () => {
    await createVerifiedUser(h, MIXED);

    for (const variant of [MIXED, LOWER, LOWER.toUpperCase(), `  ${LOWER} `]) {
      const res = await login(h, variant);
      expect(res.status).toBe(200);
    }
  });

  it('verifica email e reinvio accettano l email in qualsiasi forma', async () => {
    await register(h, LOWER);
    const token = h.mail.lastToken(LOWER, 'verification');

    const resend = await http(h)
      .post('/api/auth/resend-verification')
      .send({ email: MIXED });
    expect(resend.status).toBe(202);
    expect((await verifyEmail(h, token)).status).toBe(200);
    expect((await userRow(h, LOWER))?.emailVerifiedAt).not.toBeNull();
  });

  it('Google con email in maiuscolo collega l account esistente invece di crearne un secondo', async () => {
    await createVerifiedUser(h, LOWER);

    await googleLogin(h.app, h.google, {
      sub: 'g-1',
      email: 'MARIO.ROSSI@EXAMPLE.COM',
      email_verified: true,
    });

    expect(await userCount()).toBe(1);
    expect((await userRow(h, LOWER))?.googleId).toBe('g-1');
  });

  it('un utente creato da Google ha l email normalizzata', async () => {
    await googleLogin(h.app, h.google, {
      sub: 'g-2',
      email: 'New.User@Example.COM',
      email_verified: true,
    });
    expect((await userRow(h, 'new.user@example.com'))?.googleId).toBe('g-2');
  });

  describe('vincolo nel database (indice univoco su lower(email))', () => {
    it('rifiuta un secondo utente che differisce solo per maiuscole, anche con SQL diretto', async () => {
      await register(h, LOWER);

      await expect(
        h.db.query(`INSERT INTO users (email) VALUES ($1)`, [MIXED]),
      ).rejects.toMatchObject({ code: '23505' });
      expect(await userCount()).toBe(1);
    });

    it("l'indice e' quello atteso (funzionale e univoco)", async () => {
      const rows = await sql<{ indexdef: string }>(
        h,
        `SELECT indexdef FROM pg_indexes WHERE tablename = 'users' AND indexname = 'UQ_users_email_lower'`,
      );
      expect(rows).toHaveLength(1);
      expect(rows[0].indexdef).toMatch(/UNIQUE INDEX/i);
      expect(rows[0].indexdef).toMatch(/lower\(\(?email\)?::text\)/i);
    });
  });

  it('(sanity) la password resta valida', async () => {
    await createVerifiedUser(h, LOWER, PASSWORD);
    expect((await login(h, LOWER, PASSWORD)).status).toBe(200);
  });
});
