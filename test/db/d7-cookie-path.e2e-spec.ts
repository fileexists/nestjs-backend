/**
 * D7 - Il cookie del refresh token e limitato a /api/auth (PostgreSQL vero).
 */
import { CookieAccessInfo } from 'cookiejar';
import { createHarness, Harness } from './support/harness';
import {
  browser,
  createVerifiedUser,
  findSetCookie,
  login,
} from './support/api';

describe('D7 - path del cookie di refresh (e2e, PostgreSQL vero)', () => {
  let h: Harness;

  beforeAll(async () => {
    h = await createHarness();
  });
  afterAll(async () => {
    await h?.close();
  });
  beforeEach(async () => {
    await h.reset();
    await createVerifiedUser(h, 'mario@example.com');
  });

  it("il refresh token ha Path=/api/auth, l'access token resta su /", async () => {
    const res = await login(h, 'mario@example.com');

    expect(findSetCookie(res, 'refresh_token')).toMatch(
      /Path=\/api\/auth(;|$)/,
    );
    expect(findSetCookie(res, 'access_token')).toMatch(/Path=\/(;|$)/);
    expect(findSetCookie(res, 'refresh_token')).toMatch(/HttpOnly/i);
  });

  it('un browser invia il refresh token solo alle rotte /api/auth, non al resto delle API', async () => {
    const client = browser(h);
    await login(h, 'mario@example.com', undefined, client);
    const jar = (
      client as unknown as {
        jar: { getCookies(info: CookieAccessInfo): { name: string }[] };
      }
    ).jar;
    const names = (path: string) =>
      jar
        .getCookies(new CookieAccessInfo('127.0.0.1', path, false, false))
        .map((c) => c.name);

    expect(names('/api/auth/refresh')).toContain('refresh_token');
    expect(names('/api/auth/logout')).toContain('refresh_token');
    expect(names('/api/user/me')).not.toContain('refresh_token');
    expect(names('/api/permission')).not.toContain('refresh_token');
    expect(names('/api/user/me')).toContain('access_token');
  });

  it('il refresh continua a funzionare con il cookie del browser su /api/auth/refresh', async () => {
    const client = browser(h);
    await login(h, 'mario@example.com', undefined, client);
    expect((await client.post('/api/auth/refresh')).status).toBe(200);
  });

  it('il logout cancella il cookie sul path nuovo E su quello vecchio "/" (cookie emessi prima della modifica)', async () => {
    const res = await browser(h).post('/api/auth/logout');
    const cleared = (res.headers['set-cookie'] as unknown as string[]).filter(
      (c) => c.startsWith('refresh_token='),
    );

    expect(cleared.some((c) => /Path=\/api\/auth(;|$)/.test(c))).toBe(true);
    expect(cleared.some((c) => /Path=\/(;|$)/.test(c))).toBe(true);
    expect(cleared.every((c) => /Expires=Thu, 01 Jan 1970/.test(c))).toBe(true);
  });
});
