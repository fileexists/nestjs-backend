/**
 * D1 - Enumerazione degli account (PostgreSQL vero): stesse risposte e stessi tempi
 * per "utente inesistente", "password errata" e "account solo Google"; registrazione
 * uniforme sia per email nuova sia per email gia registrata.
 */
// Costo bcrypt "reale" abbastanza alto da rendere misurabile la differenza di tempi;
// blocco per account disattivato (qui si fanno molti tentativi falliti di proposito).
process.env.BCRYPT_ROUNDS = '10';
process.env.LOGIN_MAX_FAILED_ATTEMPTS = '100000';

import { createHarness, Harness } from './support/harness';
import {
  PASSWORD,
  createVerifiedUser,
  http,
  login,
  median,
  register,
  sql,
  timed,
} from './support/api';
import { googleLogin } from './support/google';

const SAMPLES = 9;

describe('D1 - enumerazione degli account (e2e, PostgreSQL vero)', () => {
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

  describe('login', () => {
    it('utente inesistente, password errata e account solo-Google: stesso status e stesso messaggio', async () => {
      await createVerifiedUser(h, 'known@example.com');
      await googleLogin(h.app, h.google, {
        sub: 'g1',
        email: 'google-only@example.com',
        email_verified: true,
      });

      const unknown = await login(h, 'nobody@example.com', 'Wrong-Passw0rd!');
      const wrong = await login(h, 'known@example.com', 'Wrong-Passw0rd!');
      const googleOnly = await login(
        h,
        'google-only@example.com',
        'Wrong-Passw0rd!',
      );

      for (const res of [unknown, wrong, googleOnly]) {
        expect(res.status).toBe(401);
      }
      const message = (r: { body: unknown }) =>
        (r.body as { message: string }).message;
      expect(message(unknown)).toBe(message(wrong));
      expect(message(googleOnly)).toBe(message(wrong));
      expect(message(wrong)).toBe('Invalid email or password');
    });

    it('non suggerisce mai di usare Google ("Please login via google.")', async () => {
      await googleLogin(h.app, h.google, {
        sub: 'g1',
        email: 'google-only@example.com',
        email_verified: true,
      });
      const res = await login(h, 'google-only@example.com', PASSWORD);
      expect(JSON.stringify(res.body)).not.toMatch(/google/i);
    });

    it('login senza password: stessa risposta generica', async () => {
      await createVerifiedUser(h, 'known@example.com');
      const res = await http(h)
        .post('/api/auth/login')
        .send({ email: 'known@example.com' });
      expect(res.status).toBe(401);
      expect((res.body as { message: string }).message).toBe(
        'Invalid email or password',
      );
    });

    it('i tempi di risposta sono simili: un utente inesistente costa quanto una password errata', async () => {
      await createVerifiedUser(h, 'known@example.com');
      await login(h, 'known@example.com', 'warm-up-Passw0rd!'); // riscalda connessioni e JIT

      const unknown: number[] = [];
      const wrong: number[] = [];
      for (let i = 0; i < SAMPLES; i++) {
        unknown.push(
          await timed(() =>
            login(h, `ghost-${i}@example.com`, 'Wrong-Passw0rd!'),
          ),
        );
        wrong.push(
          await timed(() => login(h, 'known@example.com', 'Wrong-Passw0rd!')),
        );
      }

      const ratio = median(unknown) / median(wrong);
      // Senza bcrypt fittizio l'utente inesistente risponde in ~2 ms contro ~60 ms (rapporto ~0.03).
      expect(ratio).toBeGreaterThan(0.6);
      expect(ratio).toBeLessThan(1.6);
    });
  });

  describe('registrazione', () => {
    const body = (r: { body: unknown }) => JSON.stringify(r.body);

    it('risposta identica (202, senza userId) per email nuova e per email gia registrata', async () => {
      const fresh = await register(h, 'fresh@example.com');
      await createVerifiedUser(h, 'taken@example.com');
      const taken = await register(h, 'taken@example.com');

      expect(fresh.status).toBe(202);
      expect(taken.status).toBe(202);
      expect(body(fresh)).toBe(body(taken));
      expect(body(fresh)).not.toMatch(
        /userId|already|registered successfully/i,
      );
    });

    it('anche per un account solo-Google la risposta e identica', async () => {
      await googleLogin(h.app, h.google, {
        sub: 'g1',
        email: 'google-only@example.com',
        email_verified: true,
      });
      const taken = await register(h, 'google-only@example.com');
      const fresh = await register(h, 'fresh@example.com');
      expect(taken.status).toBe(202);
      expect(body(taken)).toBe(body(fresh));
    });

    it("l'email nuova riceve la verifica; quella gia registrata riceve un avviso e NON un token", async () => {
      await register(h, 'fresh@example.com');
      await createVerifiedUser(h, 'taken@example.com');
      h.mail.clear();
      await register(h, 'taken@example.com');

      expect(
        h.mail.to('taken@example.com', 'registration-notice'),
      ).toHaveLength(1);
      expect(h.mail.to('taken@example.com', 'verification')).toHaveLength(0);
      expect(h.mail.to('fresh@example.com', 'verification')).toHaveLength(0); // mail.clear() sopra
    });

    it("un tentativo su un'email esistente non crea ne modifica account (nemmeno la password)", async () => {
      await createVerifiedUser(h, 'taken@example.com');
      const before = await sql<{ password: string }>(
        h,
        `SELECT password FROM users WHERE email = 'taken@example.com'`,
      );

      await register(h, 'taken@example.com', 'Attacker-Passw0rd!');

      const after = await sql<{ password: string }>(
        h,
        `SELECT password FROM users WHERE email = 'taken@example.com'`,
      );
      expect(after).toEqual(before);
      expect(
        (await login(h, 'taken@example.com', 'Attacker-Passw0rd!')).status,
      ).toBe(401);
      expect(
        (await sql<{ n: number }>(h, 'SELECT count(*)::int AS n FROM users'))[0]
          .n,
      ).toBe(1);
    });

    it('gli avvisi non permettono di inondare una casella: al massimo uno ogni periodo di attesa', async () => {
      await createVerifiedUser(h, 'taken@example.com');
      h.mail.clear();
      for (let i = 0; i < 5; i++) await register(h, 'taken@example.com');
      expect(
        h.mail.to('taken@example.com', 'registration-notice'),
      ).toHaveLength(1);
    });

    it('i tempi di risposta sono simili tra email nuova ed email gia registrata', async () => {
      await createVerifiedUser(h, 'taken@example.com');
      await register(h, 'warmup@example.com');

      const fresh: number[] = [];
      const taken: number[] = [];
      for (let i = 0; i < SAMPLES; i++) {
        fresh.push(await timed(() => register(h, `fresh-${i}@example.com`)));
        taken.push(await timed(() => register(h, 'taken@example.com')));
      }

      const ratio = median(taken) / median(fresh);
      expect(ratio).toBeGreaterThan(0.6);
      expect(ratio).toBeLessThan(1.6);
    });
  });
});
