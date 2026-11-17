/**
 * B1 - Rotazione reale dei refresh token (PostgreSQL vero).
 * Prima: lo stesso refresh token funzionava all'infinito e dopo il logout valeva ancora.
 */
import { AuthCleanupService } from '../../src/modules/auth/auth-cleanup.service';
import { createHarness, Harness } from './support/harness';
import {
  PASSWORD,
  cookieHeader,
  cookieNames,
  cookieValue,
  createVerifiedUser,
  http,
  loginSession,
  refresh,
  sql,
  userRow,
} from './support/api';

const EMAIL = 'mario@example.com';

interface RefreshRow {
  id: string;
  userId: string;
  familyId: string;
  jtiHash: string;
  usedAt: Date | null;
  revokedAt: Date | null;
  expiresAt: Date;
}

const refreshRows = (h: Harness) =>
  sql<RefreshRow>(h, 'SELECT * FROM refresh_tokens ORDER BY "createdAt", id');

describe('B1 - rotazione refresh token (e2e, PostgreSQL vero)', () => {
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

  it('il login crea una famiglia con un refresh token registrato (solo hash) e non usato', async () => {
    const session = await loginSession(h, EMAIL);

    const rows = await refreshRows(h);
    expect(rows).toHaveLength(1);
    expect(rows[0].usedAt).toBeNull();
    expect(rows[0].revokedAt).toBeNull();
    expect(rows[0].jtiHash).toMatch(/^[0-9a-f]{64}$/);
    expect(session.refresh).not.toContain(rows[0].jtiHash);
    expect(rows[0].expiresAt.getTime()).toBeGreaterThan(Date.now());
  });

  it('POST /auth/refresh ruota: vecchio token usato, nuovo token nella stessa famiglia', async () => {
    const first = await loginSession(h, EMAIL);

    const res = await refresh(h, first.refresh);
    expect(res.status).toBe(200);
    const second = cookieValue(res, 'refresh_token');
    expect(second).toBeDefined();
    expect(second).not.toBe(first.refresh);
    expect(cookieNames(res)).toContain('access_token');

    const [oldRow, newRow] = await refreshRows(h);
    expect(oldRow.usedAt).not.toBeNull();
    expect(newRow.usedAt).toBeNull();
    expect(newRow.familyId).toBe(oldRow.familyId);
  });

  it('un refresh token gia usato viene rifiutato (401)', async () => {
    const first = await loginSession(h, EMAIL);
    expect((await refresh(h, first.refresh)).status).toBe(200);
    expect((await refresh(h, first.refresh)).status).toBe(401);
  });

  describe('reuse detection', () => {
    it("al riuso revoca l'intera famiglia: anche il token piu recente smette di funzionare", async () => {
      const first = await loginSession(h, EMAIL);
      const rotated = await refresh(h, first.refresh);
      const second = cookieValue(rotated, 'refresh_token')!;
      const third = cookieValue(await refresh(h, second), 'refresh_token')!;

      // L'attaccante ripresenta il PRIMO token (rubato).
      expect((await refresh(h, first.refresh)).status).toBe(401);

      expect((await refresh(h, third)).status).toBe(401);
      const rows = await refreshRows(h);
      expect(rows.every((r) => r.revokedAt !== null)).toBe(true);
    });

    it('al riuso invalida le sessioni: tokenVersion incrementato e access token precedenti rifiutati', async () => {
      const first = await loginSession(h, EMAIL);
      const before = await userRow(h, EMAIL);
      const accessBefore = cookieValue(
        await refresh(h, first.refresh),
        'access_token',
      )!;
      expect(
        (
          await http(h)
            .get('/api/user/me')
            .set('Cookie', cookieHeader({ access: accessBefore }))
        ).status,
      ).toBe(200);

      await refresh(h, first.refresh); // riuso

      expect((await userRow(h, EMAIL))?.tokenVersion).toBe(
        (before?.tokenVersion ?? 0) + 1,
      );
      expect(
        (
          await http(h)
            .get('/api/user/me')
            .set('Cookie', cookieHeader({ access: accessBefore }))
        ).status,
      ).toBe(401);
    });

    it('il riuso in una famiglia non tocca le altre famiglie dello stesso utente ma ne invalida le sessioni (tokenVersion)', async () => {
      const laptop = await loginSession(h, EMAIL);
      const phone = await loginSession(h, EMAIL);
      await refresh(h, laptop.refresh);
      await refresh(h, laptop.refresh); // riuso sul laptop

      const families = new Set((await refreshRows(h)).map((r) => r.familyId));
      expect(families.size).toBe(2);
      // il telefono ha un refresh token con tokenVersion vecchio: rifiutato
      expect((await refresh(h, phone.refresh)).status).toBe(401);
    });
  });

  describe('rifiuti', () => {
    it('senza cookie -> 401', async () => {
      expect((await refresh(h, undefined)).status).toBe(401);
    });

    it('token con firma non valida -> 401', async () => {
      const { refresh: token } = await loginSession(h, EMAIL);
      const tampered = `${token.slice(0, -3)}abc`;
      expect((await refresh(h, tampered)).status).toBe(401);
    });

    it('token scaduto nel database -> 401', async () => {
      const { refresh: token } = await loginSession(h, EMAIL);
      await h.db.query(
        `UPDATE refresh_tokens SET "expiresAt" = now() - interval '1 minute'`,
      );
      expect((await refresh(h, token)).status).toBe(401);
    });

    it('token firmato correttamente ma non presente in tabella (es. emesso prima della rotazione) -> 401', async () => {
      const { refresh: token } = await loginSession(h, EMAIL);
      await h.db.query('DELETE FROM refresh_tokens');
      expect((await refresh(h, token)).status).toBe(401);
    });
  });

  it('due refresh concorrenti con lo stesso token: ne riesce uno solo', async () => {
    const { refresh: token } = await loginSession(h, EMAIL);
    const results = await Promise.all([
      refresh(h, token),
      refresh(h, token),
      refresh(h, token),
    ]);
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
    expect(results.filter((r) => r.status === 401)).toHaveLength(2);
  });

  describe('logout', () => {
    it('revoca il refresh token corrente: dopo il logout non si puo piu rinnovare', async () => {
      const session = await loginSession(h, EMAIL);

      const res = await http(h)
        .post('/api/auth/logout')
        .set('Cookie', cookieHeader(session));
      expect(res.status).toBe(200);

      const rows = await refreshRows(h);
      expect(rows.every((r) => r.revokedAt !== null)).toBe(true);
      expect((await refresh(h, session.refresh)).status).toBe(401);
    });

    it('revoca anche i token gia ruotati della stessa famiglia', async () => {
      const first = await loginSession(h, EMAIL);
      const second = cookieValue(
        await refresh(h, first.refresh),
        'refresh_token',
      )!;

      await http(h)
        .post('/api/auth/logout')
        .set('Cookie', cookieHeader({ refresh: second }));

      expect((await refresh(h, second)).status).toBe(401);
    });

    it('non tocca le altre sessioni dello stesso utente', async () => {
      const laptop = await loginSession(h, EMAIL);
      const phone = await loginSession(h, EMAIL);

      await http(h)
        .post('/api/auth/logout')
        .set('Cookie', cookieHeader(laptop));

      expect((await refresh(h, phone.refresh)).status).toBe(200);
    });

    it('senza cookie risponde comunque 200 (idempotente) e cancella i cookie', async () => {
      const res = await http(h).post('/api/auth/logout');
      expect(res.status).toBe(200);
      expect(cookieNames(res)).toEqual(
        expect.arrayContaining(['access_token', 'refresh_token']),
      );
    });

    it('con un cookie spazzatura risponde 200 senza errori', async () => {
      const res = await http(h)
        .post('/api/auth/logout')
        .set('Cookie', cookieHeader({ refresh: 'not-a-jwt' }));
      expect(res.status).toBe(200);
    });
  });

  describe('logout-all', () => {
    it('revoca tutte le famiglie e invalida subito gli access token', async () => {
      const laptop = await loginSession(h, EMAIL);
      const phone = await loginSession(h, EMAIL);

      const res = await http(h)
        .post('/api/auth/logout-all')
        .set('Cookie', cookieHeader(laptop));
      expect(res.status).toBe(200);

      expect((await refresh(h, laptop.refresh)).status).toBe(401);
      expect((await refresh(h, phone.refresh)).status).toBe(401);
      expect(
        (
          await http(h)
            .get('/api/user/me')
            .set('Cookie', cookieHeader({ access: laptop.access }))
        ).status,
      ).toBe(401);
      expect(
        (
          await http(h)
            .get('/api/user/me')
            .set('Cookie', cookieHeader({ access: phone.access }))
        ).status,
      ).toBe(401);
    });
  });

  it('GET /auth/validate rinnova con il refresh token e ruota (il vecchio non vale piu)', async () => {
    const { refresh: token } = await loginSession(h, EMAIL);

    const res = await http(h)
      .get('/api/auth/validate')
      .set('Cookie', cookieHeader({ refresh: token }));
    expect(res.status).toBe(200);
    expect(cookieValue(res, 'refresh_token')).toBeDefined();
    expect((await refresh(h, token)).status).toBe(401);
  });

  describe('pulizia periodica', () => {
    it('elimina i refresh token scaduti e i token monouso scaduti, lasciando intatti gli altri', async () => {
      await loginSession(h, EMAIL);
      await loginSession(h, EMAIL);
      await h.db.query(
        `UPDATE refresh_tokens SET "expiresAt" = now() - interval '1 day'
          WHERE id = (SELECT id FROM refresh_tokens ORDER BY "createdAt" LIMIT 1)`,
      );
      await h.db.query(
        `UPDATE auth_tokens SET "expiresAt" = now() - interval '1 day'`,
      );
      await http(h)
        .post('/api/auth/resend-verification')
        .send({ email: 'ghost@example.com' });

      const result = await h.app.get(AuthCleanupService).run();

      expect(result.refreshTokens).toBe(1);
      expect(await refreshRows(h)).toHaveLength(1);
      const [{ tokens }] = await sql<{ tokens: number }>(
        h,
        'SELECT count(*)::int AS tokens FROM auth_tokens',
      );
      expect(tokens).toBe(0);
    });
  });

  it('(sanity) la password resta quella attesa dopo tutte queste operazioni', async () => {
    await loginSession(h, EMAIL, PASSWORD);
  });
});
