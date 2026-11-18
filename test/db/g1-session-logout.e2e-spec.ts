/**
 * Immediate logout (real PostgreSQL).
 * Before: logout only revoked the refresh token; the access token copied beforehand stayed valid
 * until it expired. Now it carries the session's family (fid) and on every request it is checked
 * that the family is still active.
 */
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
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
import { googleLogin } from './support/google';

const EMAIL = 'mario@example.com';

function payloadOf(token: string): Record<string, unknown> {
  return JSON.parse(
    Buffer.from(token.split('.')[1], 'base64url').toString('utf8'),
  ) as Record<string, unknown>;
}

describe('Immediate logout: the access token dies with the session (e2e, real PostgreSQL)', () => {
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

  /** Authenticated call with only the access token in the header, as whoever copied it would do. */
  const meWith = async (access: string): Promise<number> =>
    (await http(h).get('/api/user/me').set('Authorization', `Bearer ${access}`))
      .status;

  const logout = (session: Session) =>
    http(h)
      .post('/api/auth/logout')
      .set('Cookie', cookieHeader({ refresh: session.refresh }));

  const families = () =>
    sql<{ familyId: string }>(
      h,
      'SELECT DISTINCT "familyId" FROM refresh_tokens ORDER BY "familyId"',
    );

  describe('the family in the access token', () => {
    it('login puts in the access token the same family as the recorded refresh token', async () => {
      const session = await loginSession(h, EMAIL);

      const [family] = await families();
      expect(payloadOf(session.access).fid).toBe(family.familyId);
      expect(payloadOf(session.refresh).fid).toBe(family.familyId);
    });

    it('refresh issues a new access token of the same family', async () => {
      const first = await loginSession(h, EMAIL);

      const rotated = await refresh(h, first.refresh);
      const access = cookieValue(rotated, 'access_token')!;

      expect(payloadOf(access).fid).toBe(payloadOf(first.access).fid);
      expect(await families()).toHaveLength(1);
    });

    it('Google login also issues an access token carrying the session family', async () => {
      const { callback } = await googleLogin(h.app, h.google, {
        sub: 'g-1',
        email: 'giulia@example.com',
        email_verified: true,
      });
      const access = cookieValue(callback, 'access_token')!;

      const [family] = await families();
      expect(payloadOf(access).fid).toBe(family.familyId);
      expect(await meWith(access)).toBe(200);
    });
  });

  describe('logout on one device', () => {
    it('the access token copied before logout gets 401 immediately; the other device keeps working', async () => {
      const laptop = await loginSession(h, EMAIL);
      const phone = await loginSession(h, EMAIL);
      expect(await meWith(laptop.access)).toBe(200);
      expect(await meWith(phone.access)).toBe(200);

      expect((await logout(laptop)).status).toBe(200);

      expect(await meWith(laptop.access)).toBe(401);
      expect(await meWith(phone.access)).toBe(200);
      // the phone can still rotate its refresh token
      expect((await refresh(h, phone.refresh)).status).toBe(200);
      expect((await refresh(h, laptop.refresh)).status).toBe(401);
    });

    it('a repeated logout, or one without a cookie, breaks nothing and leaves the other sessions alone', async () => {
      const laptop = await loginSession(h, EMAIL);
      const phone = await loginSession(h, EMAIL);

      expect((await logout(laptop)).status).toBe(200);
      expect((await logout(laptop)).status).toBe(200);
      expect((await http(h).post('/api/auth/logout')).status).toBe(200);

      expect(await meWith(phone.access)).toBe(200);
    });
  });

  describe('logout-all', () => {
    it('immediately invalidates the access tokens of every device', async () => {
      const laptop = await loginSession(h, EMAIL);
      const phone = await loginSession(h, EMAIL);

      const res = await http(h)
        .post('/api/auth/logout-all')
        .set('Authorization', `Bearer ${laptop.access}`);
      expect(res.status).toBe(200);

      expect(await meWith(laptop.access)).toBe(401);
      expect(await meWith(phone.access)).toBe(401);
      expect((await refresh(h, phone.refresh)).status).toBe(401);
    });
  });

  describe('rotation does not make the session invalid', () => {
    it('after a refresh the old refresh tokens are "used" but not revoked: the family\'s access tokens stay valid', async () => {
      const first = await loginSession(h, EMAIL);
      const rotated = await refresh(h, first.refresh);
      const second = cookieValue(rotated, 'refresh_token')!;
      const secondAccess = cookieValue(rotated, 'access_token')!;
      await refresh(h, second);

      const rows = await sql<{ usedAt: Date | null; revokedAt: Date | null }>(
        h,
        'SELECT "usedAt", "revokedAt" FROM refresh_tokens',
      );
      expect(rows.filter((r) => r.usedAt)).toHaveLength(2);
      expect(rows.every((r) => r.revokedAt === null)).toBe(true);

      expect(await meWith(first.access)).toBe(200);
      expect(await meWith(secondAccess)).toBe(200);
    });
  });

  describe('reuse detection as before', () => {
    it("reusing an already used refresh token invalidates all the user's sessions", async () => {
      const laptop = await loginSession(h, EMAIL);
      const phone = await loginSession(h, EMAIL);
      await refresh(h, laptop.refresh);

      expect((await refresh(h, laptop.refresh)).status).toBe(401); // reuse

      expect(await meWith(laptop.access)).toBe(401);
      expect(await meWith(phone.access)).toBe(401);
      expect((await userRow(h, EMAIL))?.tokenVersion).toBe(1);
    });
  });

  describe('session no longer valid', () => {
    it('expired family: 401 even though the JWT has not expired yet', async () => {
      const session = await loginSession(h, EMAIL);
      expect(await meWith(session.access)).toBe(200);

      await sql(
        h,
        `UPDATE refresh_tokens SET "expiresAt" = now() - interval '1 minute'`,
      );

      expect(await meWith(session.access)).toBe(401);
    });

    it('family revoked by hand in the database: 401', async () => {
      const session = await loginSession(h, EMAIL);

      await sql(h, 'UPDATE refresh_tokens SET "revokedAt" = now()');

      expect(await meWith(session.access)).toBe(401);
    });

    it('family deleted (expired-token cleanup): 401', async () => {
      const session = await loginSession(h, EMAIL);

      await sql(h, 'DELETE FROM refresh_tokens');

      expect(await meWith(session.access)).toBe(401);
    });

    it('access token without fid (issued before this change): 401, but a refresh gives a valid one', async () => {
      const session = await loginSession(h, EMAIL);
      const user = (await userRow(h, EMAIL))!;
      const legacy = await h.app.get(JwtService).signAsync(
        { id: user.id, email: user.email, tokenVersion: user.tokenVersion },
        {
          secret: h.app.get(ConfigService).get<string>('JWT_SECRET'),
          expiresIn: '15m',
        },
      );
      expect(await meWith(legacy)).toBe(401);

      const rotated = await refresh(h, session.refresh);
      expect(await meWith(cookieValue(rotated, 'access_token')!)).toBe(200);
    });

    it("another user's family does not count: 401", async () => {
      await createVerifiedUser(h, 'luigi@example.com');
      await loginSession(h, EMAIL);
      await loginSession(h, 'luigi@example.com');
      const mario = (await userRow(h, EMAIL))!;
      const luigiFamily = (
        await sql<{ familyId: string }>(
          h,
          'SELECT "familyId" FROM refresh_tokens WHERE "userId" = (SELECT id FROM users WHERE email = $1)',
          ['luigi@example.com'],
        )
      )[0].familyId;

      const forged = await h.app.get(JwtService).signAsync(
        {
          id: mario.id,
          email: mario.email,
          tokenVersion: mario.tokenVersion,
          fid: luigiFamily,
        },
        {
          secret: h.app.get(ConfigService).get<string>('JWT_SECRET'),
          expiresIn: '15m',
        },
      );

      expect(await meWith(forged)).toBe(401);
    });
  });
});
