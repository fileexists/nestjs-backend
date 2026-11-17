/**
 * D2 - Blocco per account dopo tentativi falliti (PostgreSQL vero), oltre al limite per IP.
 * Blocco temporaneo e progressivo, senza poter bloccare un account altrui all'infinito.
 */
import { createHarness, Harness } from './support/harness';
import {
  PASSWORD,
  cookieNames,
  cookieValue,
  createVerifiedUser,
  http,
  login,
  sql,
} from './support/api';

const EMAIL = 'mario@example.com';
const WRONG = 'Wrong-Passw0rd!';

interface AttemptRow {
  identifier: string;
  failedCount: number;
  lockLevel: number;
  lockedUntil: Date | null;
}

describe('D2 - blocco per account (e2e, PostgreSQL vero)', () => {
  let h: Harness;

  beforeAll(async () => {
    h = await createHarness();
  });
  afterAll(async () => {
    await h?.close();
  });
  beforeEach(async () => {
    await h.reset();
    await createVerifiedUser(h, EMAIL);
  });

  const failN = async (n: number, email = EMAIL) => {
    for (let i = 0; i < n; i++) await login(h, email, WRONG);
  };
  const attempts = () => sql<AttemptRow>(h, 'SELECT * FROM login_attempts');
  const secondsLeft = (row: AttemptRow) =>
    (new Date(row.lockedUntil!).getTime() - Date.now()) / 1000;

  it('i primi 4 tentativi falliti non bloccano; il 5 si (anche con la password giusta)', async () => {
    await failN(4);
    expect((await login(h, EMAIL)).status).toBe(200);

    await failN(5);
    const locked = await login(h, EMAIL);
    expect(locked.status).toBe(429);
    expect(cookieNames(locked)).toEqual([]);
  });

  it("il blocco e uguale per un'email inesistente: non rivela se l'account esiste", async () => {
    await failN(5, 'ghost@example.com');
    const res = await login(h, 'ghost@example.com', WRONG);
    expect(res.status).toBe(429);
    const real = await (async () => {
      await failN(5);
      return login(h, EMAIL, WRONG);
    })();
    expect((res.body as { message: string }).message).toBe(
      (real.body as { message: string }).message,
    );
  });

  it('il primo blocco dura circa 1 minuto e i tentativi durante il blocco NON lo prolungano', async () => {
    await failN(5);
    const [first] = await attempts();
    expect(secondsLeft(first)).toBeGreaterThan(50);
    expect(secondsLeft(first)).toBeLessThanOrEqual(61);

    for (let i = 0; i < 5; i++)
      expect((await login(h, EMAIL, WRONG)).status).toBe(429);
    const [after] = await attempts();
    expect(new Date(after.lockedUntil!).getTime()).toBe(
      new Date(first.lockedUntil!).getTime(),
    );
    expect(after.lockLevel).toBe(1);
  });

  it('e progressivo: ogni blocco successivo raddoppia, fino a un massimo', async () => {
    const expire = () =>
      h.db.query(
        `UPDATE login_attempts SET "lockedUntil" = now() - interval '1 second'`,
      );
    const expected = [60, 120, 240, 480, 900, 900];

    for (const seconds of expected) {
      await failN(5);
      const [row] = await attempts();
      expect(secondsLeft(row)).toBeGreaterThan(seconds - 12);
      expect(secondsLeft(row)).toBeLessThanOrEqual(seconds + 1);
      await expire();
    }
  });

  it('dopo la scadenza servono di nuovo 5 errori per un nuovo blocco (non basta 1)', async () => {
    await failN(5);
    await h.db.query(
      `UPDATE login_attempts SET "lockedUntil" = now() - interval '1 second'`,
    );

    await failN(4);
    expect((await login(h, EMAIL, WRONG)).status).toBe(401);
    expect((await login(h, EMAIL, WRONG)).status).toBe(429);
  });

  it('un login riuscito azzera il contatore', async () => {
    await failN(4);
    expect((await login(h, EMAIL)).status).toBe(200);
    expect(await attempts()).toHaveLength(0);

    await failN(4);
    expect((await login(h, EMAIL)).status).toBe(200);
  });

  it('i fallimenti vecchi escono dalla finestra: il contatore riparte da zero', async () => {
    await failN(4);
    await h.db.query(
      `UPDATE login_attempts SET "lastFailedAt" = now() - interval '2 hours'`,
    );

    await failN(1);
    const [row] = await attempts();
    expect(row.failedCount).toBe(1);
    expect(row.lockedUntil).toBeNull();
  });

  it('gli account sono indipendenti', async () => {
    await createVerifiedUser(h, 'other@example.com');
    await failN(5);
    expect((await login(h, EMAIL)).status).toBe(429);
    expect((await login(h, 'other@example.com')).status).toBe(200);
  });

  it('email in maiuscolo o con spazi contano come lo stesso account', async () => {
    await failN(3);
    await login(h, ' MARIO@Example.COM ', WRONG);
    await login(h, 'Mario@example.com', WRONG);
    expect((await login(h, EMAIL)).status).toBe(429);
  });

  it("nel database c'e' solo l'hash dell'identificatore, non l'email", async () => {
    await failN(1);
    const [row] = await attempts();
    expect(row.identifier).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(row)).not.toContain('mario');
  });

  describe("chi attacca non puo tenere fuori il proprietario all'infinito", () => {
    it('il proprietario con un dispositivo gia riconosciuto entra anche durante il blocco; chi non ha il cookie no', async () => {
      const owner = await login(h, EMAIL);
      const trusted = cookieValue(owner, 'trusted_device');
      expect(trusted).toBeDefined();

      await failN(5); // l'attaccante blocca l'account
      expect((await login(h, EMAIL)).status).toBe(429); // anche con la password giusta, ma senza cookie

      const ownerAgain = await http(h)
        .post('/api/auth/login')
        .set('Cookie', `trusted_device=${trusted}`)
        .send({ email: EMAIL, password: PASSWORD });
      expect(ownerAgain.status).toBe(200);
    });

    it("il cookie e legato all'account: non sblocca un altro account", async () => {
      await createVerifiedUser(h, 'other@example.com');
      const trusted = cookieValue(
        await login(h, 'other@example.com'),
        'trusted_device',
      )!;

      await failN(5);
      const res = await http(h)
        .post('/api/auth/login')
        .set('Cookie', `trusted_device=${trusted}`)
        .send({ email: EMAIL, password: PASSWORD });
      expect(res.status).toBe(429);
    });

    it('un cookie forgiato o alterato non sblocca nulla', async () => {
      const trusted = cookieValue(await login(h, EMAIL), 'trusted_device')!;
      await failN(5);

      for (const forged of [
        `${trusted}x`,
        trusted.replace(/.$/, 'A'),
        'garbage',
        `${trusted.split('.')[0]}.9999999999999.AAAA`,
      ]) {
        const res = await http(h)
          .post('/api/auth/login')
          .set('Cookie', `trusted_device=${forged}`)
          .send({ email: EMAIL, password: PASSWORD });
        expect(res.status).toBe(429);
      }
    });

    it('il cookie non salta il controllo della password: con la password sbagliata resta 401', async () => {
      const trusted = cookieValue(await login(h, EMAIL), 'trusted_device')!;
      await failN(5);

      const res = await http(h)
        .post('/api/auth/login')
        .set('Cookie', `trusted_device=${trusted}`)
        .send({ email: EMAIL, password: WRONG });
      expect(res.status).toBe(401);
    });

    it('il cookie e httpOnly, SameSite=Lax e limitato a /api/auth', async () => {
      const res = await login(h, EMAIL);
      const cookie = (res.headers['set-cookie'] as unknown as string[]).find(
        (c) => c.startsWith('trusted_device='),
      )!;
      expect(cookie).toMatch(/HttpOnly/i);
      expect(cookie).toMatch(/SameSite=Lax/i);
      expect(cookie).toMatch(/Path=\/api\/auth/);
    });
  });

  it('richieste parallele di password errate non fanno saltare nulla e il blocco scatta', async () => {
    const results = await Promise.all(
      Array.from({ length: 10 }, () => login(h, EMAIL, WRONG)),
    );
    expect(results.every((r) => [401, 429].includes(r.status))).toBe(true);

    const [row] = await attempts();
    expect(row.lockLevel).toBeGreaterThanOrEqual(1);
    expect((await login(h, EMAIL)).status).toBe(429);
  });
});
