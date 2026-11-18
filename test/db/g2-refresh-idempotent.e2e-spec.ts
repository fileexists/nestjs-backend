/**
 * Idempotent refresh (real PostgreSQL).
 * Before: with N parallel requests made with the same refresh cookie (access token expired),
 * one rotated it and the others got 401 (reused inside REFRESH_REUSE_GRACE_SECONDS). Now, inside
 * the grace period, a second use of the same refresh token gets the SAME pair of tokens; after
 * it, reuse detection is unchanged (family revoked + tokenVersion + 1).
 */
// Before importing AppModule: ConfigModule reads the environment when the module loads.
process.env.REFRESH_REUSE_GRACE_SECONDS = '2';

import { createHarness, Harness } from './support/harness';
import {
  Session,
  cookieHeader,
  cookieValue,
  createVerifiedUser,
  http,
  loginSession,
  refresh,
  sql,
  userRow,
} from './support/api';

const EMAIL = 'mario@example.com';
const PARALLEL = 8;
const GRACE_MS = 2000;
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe('Idempotent refresh (e2e, real PostgreSQL)', () => {
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

  const burst = <T>(call: () => PromiseLike<T>) =>
    Promise.all(Array.from({ length: PARALLEL }, call));

  const rows = () =>
    sql<{ usedAt: Date | null; revokedAt: Date | null }>(
      h,
      'SELECT "usedAt", "revokedAt" FROM refresh_tokens',
    );

  const meWith = async (access: string): Promise<number> =>
    (await http(h).get('/api/user/me').set('Authorization', `Bearer ${access}`))
      .status;

  it('parallel refreshes with the same cookie all succeed and get the same tokens', async () => {
    const session = await loginSession(h, EMAIL);

    const responses = await burst(() => refresh(h, session.refresh));

    expect(responses.map((r) => r.status)).toEqual(Array(PARALLEL).fill(200));
    const refreshTokens = new Set(
      responses.map((r) => cookieValue(r, 'refresh_token')),
    );
    const accessTokens = new Set(
      responses.map((r) => cookieValue(r, 'access_token')),
    );
    expect(refreshTokens.size).toBe(1);
    expect(accessTokens.size).toBe(1);
    expect(await meWith([...accessTokens][0]!)).toBe(200);
  });

  it('the rotation happens only once: one used token and one new one in the family', async () => {
    const session = await loginSession(h, EMAIL);

    await burst(() => refresh(h, session.refresh));

    const all = await rows();
    expect(all).toHaveLength(2);
    expect(all.filter((r) => r.usedAt)).toHaveLength(1);
    expect(all.every((r) => r.revokedAt === null)).toBe(true);
  });

  it('the same cookie used again, sequentially, inside the window gets the same pair', async () => {
    const session = await loginSession(h, EMAIL);

    const first = await refresh(h, session.refresh);
    const second = await refresh(h, session.refresh);

    expect(second.status).toBe(200);
    expect(cookieValue(second, 'refresh_token')).toBe(
      cookieValue(first, 'refresh_token'),
    );
    expect(cookieValue(second, 'access_token')).toBe(
      cookieValue(first, 'access_token'),
    );
  });

  it('the issued refresh token keeps rotating normally', async () => {
    const session = await loginSession(h, EMAIL);
    const first = await refresh(h, session.refresh);
    const next = cookieValue(first, 'refresh_token')!;

    const second = await refresh(h, next);

    expect(second.status).toBe(200);
    expect(cookieValue(second, 'refresh_token')).not.toBe(next);
  });

  it('parallel API calls with an expired access token (only the refresh cookie) all succeed', async () => {
    const session = await loginSession(h, EMAIL);

    const responses = await burst(() =>
      http(h)
        .get('/api/user/me')
        .set('Cookie', cookieHeader({ refresh: session.refresh })),
    );

    expect(responses.map((r) => r.status)).toEqual(Array(PARALLEL).fill(200));
    expect(
      new Set(responses.map((r) => cookieValue(r, 'refresh_token'))).size,
    ).toBe(1);
    expect((await rows()).filter((r) => r.usedAt)).toHaveLength(1);
  });

  describe('after the window', () => {
    it('reusing the token is a 401: the family is revoked and tokenVersion goes up', async () => {
      const session = await loginSession(h, EMAIL);
      const rotated = await refresh(h, session.refresh);
      const latest = cookieValue(rotated, 'refresh_token')!;
      const before = (await userRow(h, EMAIL))!.tokenVersion;

      await sleep(GRACE_MS + 400);
      expect((await refresh(h, session.refresh)).status).toBe(401);

      expect((await rows()).every((r) => r.revokedAt !== null)).toBe(true);
      expect((await userRow(h, EMAIL))!.tokenVersion).toBe(before + 1);
      expect((await refresh(h, latest)).status).toBe(401);
    });
  });

  describe('a revoked session never gets the cached pair', () => {
    const open = async (): Promise<{ session: Session; latest: string }> => {
      const session = await loginSession(h, EMAIL);
      const rotated = await refresh(h, session.refresh);
      return { session, latest: cookieValue(rotated, 'refresh_token')! };
    };

    it('after logout', async () => {
      const { session, latest } = await open();

      await http(h)
        .post('/api/auth/logout')
        .set('Cookie', cookieHeader({ refresh: latest }));

      expect((await refresh(h, session.refresh)).status).toBe(401);
    });

    it('after logout-all', async () => {
      const { session } = await open();
      const fresh = await loginSession(h, EMAIL);

      const res = await http(h)
        .post('/api/auth/logout-all')
        .set('Authorization', `Bearer ${fresh.access}`);
      expect(res.status).toBe(200);

      expect((await refresh(h, session.refresh)).status).toBe(401);
    });
  });

  it('failures are not cached: an invalid token keeps being a 401', async () => {
    const session = await loginSession(h, EMAIL);
    await sql(h, 'DELETE FROM refresh_tokens');

    expect((await refresh(h, session.refresh)).status).toBe(401);
    expect((await refresh(h, session.refresh)).status).toBe(401);
  });
});
