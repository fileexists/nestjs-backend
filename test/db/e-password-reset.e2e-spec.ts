/**
 * E - Reset della password (PostgreSQL vero): richiesta via email, token monouso con
 * scadenza, invalidazione di tutte le sessioni dopo il reset.
 */
import { createHash } from 'crypto';
import { createHarness, Harness } from './support/harness';
import {
  PASSWORD,
  cookieHeader,
  cookieNames,
  cookieValue,
  createVerifiedUser,
  forgotPassword,
  http,
  login,
  loginSession,
  refresh,
  register,
  resetPassword,
  settle,
  sql,
  userRow,
} from './support/api';
import { googleLogin } from './support/google';

const EMAIL = 'mario@example.com';
const NEW_PASSWORD = 'Brand-New-Passw0rd!';

describe('E - reset password (e2e, PostgreSQL vero)', () => {
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
  afterEach(() => {
    h.mail.delayMs = 0;
  });

  /** Richiede il reset e ritorna il token "ricevuto" via email. */
  async function requestReset(email = EMAIL): Promise<string> {
    expect((await forgotPassword(h, email)).status).toBe(202);
    await settle(h);
    return h.mail.lastToken(email, 'password-reset');
  }

  describe('richiesta (POST /auth/forgot-password)', () => {
    beforeEach(async () => {
      await createVerifiedUser(h, EMAIL);
    });

    it("per un account esistente invia l'email con un token monouso", async () => {
      await requestReset();
      expect(h.mail.to(EMAIL, 'password-reset')).toHaveLength(1);
    });

    it("risposta identica (202, stesso corpo) per indirizzo esistente e inesistente, e nessuna email per l'inesistente", async () => {
      const known = await forgotPassword(h, EMAIL);
      const unknown = await forgotPassword(h, 'ghost@example.com');
      await settle(h);

      expect(known.status).toBe(202);
      expect(unknown.status).toBe(202);
      expect(JSON.stringify(known.body)).toBe(JSON.stringify(unknown.body));
      expect(h.mail.to('ghost@example.com')).toHaveLength(0);
      expect(h.mail.to(EMAIL, 'password-reset')).toHaveLength(1);
    });

    it('la risposta non aspetta il lavoro (nessuna differenza di tempi osservabile): e un lavoro in background', async () => {
      h.mail.delayMs = 400; // SMTP lento: non deve ritardare la risposta

      const start = Date.now();
      const res = await forgotPassword(h, EMAIL);
      const elapsed = Date.now() - start;
      await settle(h);

      expect(res.status).toBe(202);
      expect(elapsed).toBeLessThan(300); // l'invio lento (400 ms) non ritarda la risposta
      expect(h.mail.to(EMAIL, 'password-reset')).toHaveLength(1);
    });

    it("nel database c'e' solo lo SHA-256 del token", async () => {
      const token = await requestReset();
      const rows = await sql<{ tokenHash: string; type: string }>(
        h,
        `SELECT "tokenHash", type FROM auth_tokens WHERE type = 'password_reset'`,
      );
      expect(rows).toEqual([
        {
          tokenHash: createHash('sha256').update(token).digest('hex'),
          type: 'password_reset',
        },
      ]);
    });

    it('entro il periodo di attesa non invia una seconda email; dopo si, e il vecchio token smette di valere', async () => {
      const first = await requestReset();
      await forgotPassword(h, EMAIL);
      await settle(h);
      expect(h.mail.to(EMAIL, 'password-reset')).toHaveLength(1);

      await h.db.query(
        `UPDATE auth_tokens SET "createdAt" = now() - interval '5 minutes'`,
      );
      const second = await requestReset();

      expect(second).not.toBe(first);
      expect((await resetPassword(h, first, NEW_PASSWORD)).status).toBe(400);
      expect((await resetPassword(h, second, NEW_PASSWORD)).status).toBe(200);
    });

    it("accetta l'email in qualsiasi forma (maiuscole/spazi)", async () => {
      expect((await forgotPassword(h, '  MARIO@Example.COM ')).status).toBe(
        202,
      );
      await settle(h);
      expect(h.mail.to(EMAIL, 'password-reset')).toHaveLength(1);
    });

    it('email non valida -> 400 di validazione', async () => {
      expect(
        (
          await http(h)
            .post('/api/auth/forgot-password')
            .send({ email: 'not-an-email' })
        ).status,
      ).toBe(400);
    });
  });

  describe('reimpostazione (POST /auth/reset-password)', () => {
    beforeEach(async () => {
      await createVerifiedUser(h, EMAIL);
    });

    it('imposta la nuova password: la vecchia non vale piu, la nuova si', async () => {
      const token = await requestReset();

      const res = await resetPassword(h, token, NEW_PASSWORD);

      expect(res.status).toBe(200);
      expect((await login(h, EMAIL, PASSWORD)).status).toBe(401);
      expect((await login(h, EMAIL, NEW_PASSWORD)).status).toBe(200);
    });

    it('il token e monouso: il secondo utilizzo fallisce con 400', async () => {
      const token = await requestReset();
      expect((await resetPassword(h, token, NEW_PASSWORD)).status).toBe(200);
      expect((await resetPassword(h, token, 'Another-Passw0rd!')).status).toBe(
        400,
      );
      expect((await login(h, EMAIL, NEW_PASSWORD)).status).toBe(200);
    });

    it('token scaduto, sconosciuto o di un altro tipo -> 400', async () => {
      const token = await requestReset();
      await h.db.query(
        `UPDATE auth_tokens SET "expiresAt" = now() - interval '1 minute'`,
      );
      expect((await resetPassword(h, token, NEW_PASSWORD)).status).toBe(400);
      expect(
        (await resetPassword(h, 'x'.repeat(43), NEW_PASSWORD)).status,
      ).toBe(400);

      // un token di verifica email non puo essere usato per reimpostare la password
      await register(h, 'other@example.com');
      const verificationToken = h.mail.lastToken(
        'other@example.com',
        'verification',
      );
      expect(
        (await resetPassword(h, verificationToken, NEW_PASSWORD)).status,
      ).toBe(400);
    });

    it('la password nuova deve rispettare le regole (8-72 caratteri) e il token non viene consumato', async () => {
      const token = await requestReset();
      expect((await resetPassword(h, token, 'short')).status).toBe(400);
      expect((await resetPassword(h, token, 'x'.repeat(73))).status).toBe(400);
      expect(
        (await http(h).post('/api/auth/reset-password').send({ token })).status,
      ).toBe(400);
      expect((await resetPassword(h, token, NEW_PASSWORD)).status).toBe(200);
    });

    it('con piu richieste concorrenti con lo stesso token ne riesce una sola', async () => {
      const token = await requestReset();
      const results = await Promise.all(
        ['A-Passw0rd-one!', 'B-Passw0rd-two!', 'C-Passw0rd-three!'].map((p) =>
          resetPassword(h, token, p),
        ),
      );
      expect(results.map((r) => r.status).sort()).toEqual([200, 400, 400]);
    });

    it("la nuova password e hashata (mai in chiaro) e non cambia l'email", async () => {
      const token = await requestReset();
      await resetPassword(h, token, NEW_PASSWORD);
      const row = await userRow(h, EMAIL);
      expect(row?.password).toMatch(/^\$2[aby]\$\d{2}\$/);
      expect(row?.password).not.toContain(NEW_PASSWORD);
    });

    describe('invalida tutte le sessioni', () => {
      it('refresh token e access token emessi prima non funzionano piu', async () => {
        const laptop = await loginSession(h, EMAIL);
        const phone = await loginSession(h, EMAIL);
        const before = await userRow(h, EMAIL);
        const token = await requestReset();

        await resetPassword(h, token, NEW_PASSWORD);

        expect((await refresh(h, laptop.refresh)).status).toBe(401);
        expect((await refresh(h, phone.refresh)).status).toBe(401);
        for (const session of [laptop, phone]) {
          const me = await http(h)
            .get('/api/user/me')
            .set('Cookie', cookieHeader({ access: session.access }));
          expect(me.status).toBe(401);
        }
        expect((await userRow(h, EMAIL))?.tokenVersion).toBe(
          (before?.tokenVersion ?? 0) + 1,
        );
        const revoked = await sql<{ n: number }>(
          h,
          'SELECT count(*)::int AS n FROM refresh_tokens WHERE "revokedAt" IS NULL',
        );
        expect(revoked[0].n).toBe(0);
      });

      it('una nuova sessione dopo il reset funziona normalmente', async () => {
        await requestReset().then((token) =>
          resetPassword(h, token, NEW_PASSWORD),
        );
        const session = await loginSession(h, EMAIL, NEW_PASSWORD);
        expect(
          (
            await http(h)
              .get('/api/user/me')
              .set('Cookie', cookieHeader({ access: session.access }))
          ).status,
        ).toBe(200);
      });

      it('invalida anche i dispositivi riconosciuti (cookie trusted_device)', async () => {
        const trusted = cookieValue(await login(h, EMAIL), 'trusted_device')!;
        const token = await requestReset();
        await resetPassword(h, token, NEW_PASSWORD);

        for (let i = 0; i < 5; i++) await login(h, EMAIL, 'Wrong-Passw0rd!');
        const res = await http(h)
          .post('/api/auth/login')
          .set('Cookie', `trusted_device=${trusted}`)
          .send({ email: EMAIL, password: NEW_PASSWORD });
        expect(res.status).toBe(429);
      });
    });

    it("sblocca l'account bloccato per troppi tentativi (via d'uscita per il proprietario)", async () => {
      for (let i = 0; i < 5; i++) await login(h, EMAIL, 'Wrong-Passw0rd!');
      expect((await login(h, EMAIL, PASSWORD)).status).toBe(429);

      const token = await requestReset();
      await resetPassword(h, token, NEW_PASSWORD);

      expect((await login(h, EMAIL, NEW_PASSWORD)).status).toBe(200);
      expect(await sql(h, 'SELECT * FROM login_attempts')).toHaveLength(0);
    });

    it('elimina i token di verifica e di reset ancora pendenti', async () => {
      await register(h, 'pending@example.com');
      const token = await requestReset('pending@example.com');
      await resetPassword(h, token, NEW_PASSWORD);
      const [{ n }] = await sql<{ n: number }>(
        h,
        `SELECT count(*)::int AS n FROM auth_tokens WHERE "usedAt" IS NULL AND type <> 'registration_notice'`,
      );
      expect(n).toBe(0);
    });
  });

  describe("chi possiede la casella recupera l'account", () => {
    it("pre-hijacking: l'attaccante registra l'email della vittima; la vittima reimposta la password e l'account diventa suo", async () => {
      await register(h, EMAIL, 'Attacker-Passw0rd!'); // account non verificato con la password dell'attaccante
      expect((await login(h, EMAIL, 'Attacker-Passw0rd!')).status).toBe(403);

      const token = await requestReset();
      expect((await resetPassword(h, token, NEW_PASSWORD)).status).toBe(200);

      expect((await login(h, EMAIL, 'Attacker-Passw0rd!')).status).toBe(401); // la password dell'attaccante non vale piu
      expect((await login(h, EMAIL, NEW_PASSWORD)).status).toBe(200);
      expect((await userRow(h, EMAIL))?.emailVerifiedAt).not.toBeNull(); // il reset dimostra il possesso della casella
    });

    it('un account solo-Google puo impostare una password: diventa combined e Google continua a funzionare', async () => {
      await googleLogin(h.app, h.google, {
        sub: 'g-1',
        email: EMAIL,
        email_verified: true,
      });
      expect((await login(h, EMAIL, NEW_PASSWORD)).status).toBe(401);

      const token = await requestReset();
      await resetPassword(h, token, NEW_PASSWORD);

      expect((await login(h, EMAIL, NEW_PASSWORD)).status).toBe(200);
      expect((await userRow(h, EMAIL))?.provider).toBe('combined');
      const { callback } = await googleLogin(h.app, h.google, {
        sub: 'g-1',
        email: EMAIL,
        email_verified: true,
      });
      expect(cookieNames(callback)).toContain('access_token');
    });
  });
});
