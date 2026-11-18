/**
 * D7 - The refresh token cookie is limited to /api/auth (real PostgreSQL).
 */
import { CookieAccessInfo } from 'cookiejar';
import { createHarness, Harness } from './support/harness';
import {
  browser,
  createVerifiedUser,
  findSetCookie,
  login,
} from './support/api';

describe('D7 - refresh cookie path (e2e, real PostgreSQL)', () => {
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

  it('the refresh token has Path=/api/auth, the access token stays on /', async () => {
    const res = await login(h, 'mario@example.com');

    expect(findSetCookie(res, 'refresh_token')).toMatch(
      /Path=\/api\/auth(;|$)/,
    );
    expect(findSetCookie(res, 'access_token')).toMatch(/Path=\/(;|$)/);
    expect(findSetCookie(res, 'refresh_token')).toMatch(/HttpOnly/i);
  });

  it('a browser sends the refresh token only to the /api/auth routes, not to the rest of the APIs', async () => {
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

  it('refresh keeps working with the browser cookie on /api/auth/refresh', async () => {
    const client = browser(h);
    await login(h, 'mario@example.com', undefined, client);
    expect((await client.post('/api/auth/refresh')).status).toBe(200);
  });

  it('logout clears the cookie on the new path AND on the old "/" one (cookies issued before the change)', async () => {
    const res = await browser(h).post('/api/auth/logout');
    const cleared = (res.headers['set-cookie'] as unknown as string[]).filter(
      (c) => c.startsWith('refresh_token='),
    );

    expect(cleared.some((c) => /Path=\/api\/auth(;|$)/.test(c))).toBe(true);
    expect(cleared.some((c) => /Path=\/(;|$)/.test(c))).toBe(true);
    expect(cleared.every((c) => /Expires=Thu, 01 Jan 1970/.test(c))).toBe(true);
  });
});
