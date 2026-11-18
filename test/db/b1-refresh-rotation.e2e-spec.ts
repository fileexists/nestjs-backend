/**
 * B1 - Real refresh token rotation (real PostgreSQL).
 * Before: the same refresh token worked forever and was still valid after logout.
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

describe('B1 - refresh token rotation (e2e, real PostgreSQL)', () => {
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

  it('login creates a family with a registered refresh token (hash only) that is unused', async () => {
    const session = await loginSession(h, EMAIL);

    const rows = await refreshRows(h);
    expect(rows).toHaveLength(1);
    expect(rows[0].usedAt).toBeNull();
    expect(rows[0].revokedAt).toBeNull();
    expect(rows[0].jtiHash).toMatch(/^[0-9a-f]{64}$/);
    expect(session.refresh).not.toContain(rows[0].jtiHash);
    expect(rows[0].expiresAt.getTime()).toBeGreaterThan(Date.now());
  });

  it('POST /auth/refresh rotates: old token used, new token in the same family', async () => {
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

  it('an already used refresh token is rejected (401)', async () => {
    const first = await loginSession(h, EMAIL);
    expect((await refresh(h, first.refresh)).status).toBe(200);
    expect((await refresh(h, first.refresh)).status).toBe(401);
  });

  describe('reuse detection', () => {
    it('on reuse it revokes the whole family: even the most recent token stops working', async () => {
      const first = await loginSession(h, EMAIL);
      const rotated = await refresh(h, first.refresh);
      const second = cookieValue(rotated, 'refresh_token')!;
      const third = cookieValue(await refresh(h, second), 'refresh_token')!;

      // The attacker presents the FIRST (stolen) token again.
      expect((await refresh(h, first.refresh)).status).toBe(401);

      expect((await refresh(h, third)).status).toBe(401);
      const rows = await refreshRows(h);
      expect(rows.every((r) => r.revokedAt !== null)).toBe(true);
    });

    it('on reuse it invalidates the sessions: tokenVersion incremented and earlier access tokens rejected', async () => {
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

      await refresh(h, first.refresh); // reuse

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

    it("reuse in one family does not touch the user's other families but invalidates their sessions (tokenVersion)", async () => {
      const laptop = await loginSession(h, EMAIL);
      const phone = await loginSession(h, EMAIL);
      await refresh(h, laptop.refresh);
      await refresh(h, laptop.refresh); // reuse on the laptop

      const families = new Set((await refreshRows(h)).map((r) => r.familyId));
      expect(families.size).toBe(2);
      // the phone has a refresh token with an old tokenVersion: rejected
      expect((await refresh(h, phone.refresh)).status).toBe(401);
    });
  });

  describe('rejections', () => {
    it('no cookie -> 401', async () => {
      expect((await refresh(h, undefined)).status).toBe(401);
    });

    it('token with an invalid signature -> 401', async () => {
      const { refresh: token } = await loginSession(h, EMAIL);
      const tampered = `${token.slice(0, -3)}abc`;
      expect((await refresh(h, tampered)).status).toBe(401);
    });

    it('token expired in the database -> 401', async () => {
      const { refresh: token } = await loginSession(h, EMAIL);
      await h.db.query(
        `UPDATE refresh_tokens SET "expiresAt" = now() - interval '1 minute'`,
      );
      expect((await refresh(h, token)).status).toBe(401);
    });

    it('correctly signed token that is not in the table (e.g. issued before the rotation) -> 401', async () => {
      const { refresh: token } = await loginSession(h, EMAIL);
      await h.db.query('DELETE FROM refresh_tokens');
      expect((await refresh(h, token)).status).toBe(401);
    });
  });

  it('two concurrent refreshes with the same token: only one succeeds', async () => {
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
    it('revokes the current refresh token: after logout it can no longer be renewed', async () => {
      const session = await loginSession(h, EMAIL);

      const res = await http(h)
        .post('/api/auth/logout')
        .set('Cookie', cookieHeader(session));
      expect(res.status).toBe(200);

      const rows = await refreshRows(h);
      expect(rows.every((r) => r.revokedAt !== null)).toBe(true);
      expect((await refresh(h, session.refresh)).status).toBe(401);
    });

    it('also revokes the already rotated tokens of the same family', async () => {
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

    it("does not touch the user's other sessions", async () => {
      const laptop = await loginSession(h, EMAIL);
      const phone = await loginSession(h, EMAIL);

      await http(h)
        .post('/api/auth/logout')
        .set('Cookie', cookieHeader(laptop));

      expect((await refresh(h, phone.refresh)).status).toBe(200);
    });

    it('without a cookie still answers 200 (idempotent) and clears the cookies', async () => {
      const res = await http(h).post('/api/auth/logout');
      expect(res.status).toBe(200);
      expect(cookieNames(res)).toEqual(
        expect.arrayContaining(['access_token', 'refresh_token']),
      );
    });

    it('with a garbage cookie answers 200 without errors', async () => {
      const res = await http(h)
        .post('/api/auth/logout')
        .set('Cookie', cookieHeader({ refresh: 'not-a-jwt' }));
      expect(res.status).toBe(200);
    });
  });

  describe('logout-all', () => {
    it('revokes all the families and immediately invalidates the access tokens', async () => {
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

  it('GET /auth/validate renews with the refresh token and rotates (the old one is no longer valid)', async () => {
    const { refresh: token } = await loginSession(h, EMAIL);

    const res = await http(h)
      .get('/api/auth/validate')
      .set('Cookie', cookieHeader({ refresh: token }));
    expect(res.status).toBe(200);
    expect(cookieValue(res, 'refresh_token')).toBeDefined();
    expect((await refresh(h, token)).status).toBe(401);
  });

  describe('periodic cleanup', () => {
    it('deletes the expired refresh tokens and expired one-time tokens, leaving the others untouched', async () => {
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

  it('(sanity) the password stays the expected one after all these operations', async () => {
    await loginSession(h, EMAIL, PASSWORD);
  });
});
