/**
 * A1 - Verifica dell'email: registrazione, conferma, login, reinvio (PostgreSQL vero).
 */
import { createHash } from 'crypto';
import { createHarness, Harness } from './support/harness';
import {
  PASSWORD,
  cookieNames,
  http,
  login,
  register,
  settle,
  userRow,
  verifyEmail,
} from './support/api';

const EMAIL = 'mario@example.com';

describe('A1 - verifica email (e2e, PostgreSQL vero)', () => {
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

  describe('registrazione', () => {
    it('crea un account NON verificato e invia una sola email di verifica', async () => {
      const res = await register(h, EMAIL);
      expect(res.status).toBeLessThan(300);

      const row = await userRow(h, EMAIL);
      expect(row?.emailVerifiedAt).toBeNull();
      expect(row?.password).not.toBe(PASSWORD);
      expect(h.mail.to(EMAIL, 'verification')).toHaveLength(1);
    });

    it('nel database c e solo lo SHA-256 del token, mai il token', async () => {
      await register(h, EMAIL);
      const token = h.mail.lastToken(EMAIL, 'verification');

      const rows: { tokenHash: string; type: string }[] = await h.db.query(
        'SELECT "tokenHash", type FROM auth_tokens',
      );
      expect(rows).toHaveLength(1);
      expect(rows[0].tokenHash).toBe(
        createHash('sha256').update(token).digest('hex'),
      );
      expect(rows[0].tokenHash).not.toBe(token);
      expect(rows[0].type).toBe('email_verification');
    });
  });

  describe('login prima e dopo la verifica', () => {
    beforeEach(async () => {
      await register(h, EMAIL);
    });

    it('password corretta ma email non verificata -> 403 e nessun cookie', async () => {
      const res = await login(h, EMAIL);
      expect(res.status).toBe(403);
      expect(cookieNames(res)).toEqual([]);
    });

    it('password sbagliata con email non verificata -> 401 (non 403)', async () => {
      const res = await login(h, EMAIL, 'Wrong-Passw0rd!');
      expect(res.status).toBe(401);
    });

    it('dopo la conferma il login funziona e imposta i cookie', async () => {
      const verified = await verifyEmail(
        h,
        h.mail.lastToken(EMAIL, 'verification'),
      );
      expect(verified.status).toBe(200);
      expect((await userRow(h, EMAIL))?.emailVerifiedAt).not.toBeNull();

      const res = await login(h, EMAIL);
      expect(res.status).toBe(200);
      expect(cookieNames(res)).toEqual(
        expect.arrayContaining(['access_token', 'refresh_token']),
      );
    });
  });

  describe('token di verifica', () => {
    beforeEach(async () => {
      await register(h, EMAIL);
    });

    it('e monouso: il secondo utilizzo fallisce con 400', async () => {
      const token = h.mail.lastToken(EMAIL, 'verification');
      expect((await verifyEmail(h, token)).status).toBe(200);
      expect((await verifyEmail(h, token)).status).toBe(400);
    });

    it('scaduto -> 400 e l account resta non verificato', async () => {
      await h.db.query(
        `UPDATE auth_tokens SET "expiresAt" = now() - interval '1 minute'`,
      );
      const res = await verifyEmail(h, h.mail.lastToken(EMAIL, 'verification'));
      expect(res.status).toBe(400);
      expect((await userRow(h, EMAIL))?.emailVerifiedAt).toBeNull();
    });

    it('sconosciuto -> 400; troppo corto o assente -> 400 di validazione', async () => {
      expect((await verifyEmail(h, 'x'.repeat(43))).status).toBe(400);
      expect((await verifyEmail(h, 'short')).status).toBe(400);
      expect(
        (await http(h).post('/api/auth/verify-email').send({})).status,
      ).toBe(400);
    });

    it('due conferme concorrenti con lo stesso token: ne riesce una sola', async () => {
      const token = h.mail.lastToken(EMAIL, 'verification');
      const results = await Promise.all([
        verifyEmail(h, token),
        verifyEmail(h, token),
        verifyEmail(h, token),
      ]);
      expect(results.map((r) => r.status).sort()).toEqual([200, 400, 400]);
    });
  });

  describe('reinvio', () => {
    const body = (res: { body: unknown }) => JSON.stringify(res.body);

    it('per un account non verificato invia un token nuovo e invalida il vecchio (oltre il periodo di attesa)', async () => {
      await register(h, EMAIL);
      const oldToken = h.mail.lastToken(EMAIL, 'verification');
      await h.db.query(
        `UPDATE auth_tokens SET "createdAt" = now() - interval '5 minutes'`,
      );

      const res = await http(h)
        .post('/api/auth/resend-verification')
        .send({ email: EMAIL });
      expect(res.status).toBe(202);
      await settle(h);
      expect(h.mail.to(EMAIL, 'verification')).toHaveLength(2);

      const newToken = h.mail.lastToken(EMAIL, 'verification');
      expect(newToken).not.toBe(oldToken);
      expect((await verifyEmail(h, oldToken)).status).toBe(400);
      expect((await verifyEmail(h, newToken)).status).toBe(200);
    });

    it('entro il periodo di attesa non invia una seconda email', async () => {
      await register(h, EMAIL);
      const res = await http(h)
        .post('/api/auth/resend-verification')
        .send({ email: EMAIL });
      expect(res.status).toBe(202);
      await settle(h);
      expect(h.mail.to(EMAIL, 'verification')).toHaveLength(1);
    });

    it('risposta identica (e nessuna email) per indirizzo inesistente e per account gia verificato', async () => {
      await register(h, EMAIL);
      await verifyEmail(h, h.mail.lastToken(EMAIL, 'verification'));
      h.mail.clear();

      const unknown = await http(h)
        .post('/api/auth/resend-verification')
        .send({ email: 'ghost@example.com' });
      const verified = await http(h)
        .post('/api/auth/resend-verification')
        .send({ email: EMAIL });

      await settle(h);
      expect(unknown.status).toBe(202);
      expect(verified.status).toBe(202);
      expect(body(unknown)).toBe(body(verified));
      expect(h.mail.sent).toHaveLength(0);
    });
  });
});
