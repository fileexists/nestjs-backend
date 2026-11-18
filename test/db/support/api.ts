import request from 'supertest';
import { AccountService } from '../../../src/modules/auth/account.service';
import type { Harness } from './harness';

export const PASSWORD = 'Correct-Passw0rd!';

export type Agent = ReturnType<typeof request.agent>;

/** Client without cookies: every request is independent. */
export function http(h: Harness): ReturnType<typeof request> {
  return request(h.app.getHttpServer());
}

/** Client with a cookie jar (like a browser: it respects Path/SameSite/Secure). */
export function browser(h: Harness): Agent {
  return request.agent(h.app.getHttpServer());
}

export function register(h: Harness, email: string, password = PASSWORD) {
  return http(h).post('/api/auth/register').send({ email, password });
}

export function login(
  h: Harness,
  email: string,
  password = PASSWORD,
  client: Pick<Agent, 'post'> = http(h),
) {
  return client.post('/api/auth/login').send({ email, password });
}

/** Median of a series of durations (ms): robust to occasional spikes. */
export function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

/** Duration (ms) of an async call. */
export async function timed(fn: () => PromiseLike<unknown>): Promise<number> {
  const start = process.hrtime.bigint();
  await fn();
  return Number(process.hrtime.bigint() - start) / 1e6;
}

/**
 * Waits for the app's background jobs (sending resend/reset emails: the HTTP response
 * does not wait for them, so as not to reveal through timings whether an address exists).
 */
export async function settle(h: Harness): Promise<void> {
  await h.app.get(AccountService).drain();
}

export function forgotPassword(h: Harness, email: string) {
  return http(h).post('/api/auth/forgot-password').send({ email });
}

export function resetPassword(h: Harness, token: string, password: string) {
  return http(h).post('/api/auth/reset-password').send({ token, password });
}

/** Confirms the email while choosing (or re-confirming) the account's password. */
export function verifyEmail(h: Harness, token: string, password = PASSWORD) {
  return http(h).post('/api/auth/verify-email').send({ token, password });
}

/** Registers and confirms the email through the token "received" in the outbox. */
export async function createVerifiedUser(
  h: Harness,
  email: string,
  password = PASSWORD,
): Promise<void> {
  const res = await register(h, email, password);
  if (res.status >= 300) {
    throw new Error(
      `register ${email} -> ${res.status} ${JSON.stringify(res.body)}`,
    );
  }
  const verified = await verifyEmail(
    h,
    h.mail.lastToken(email, 'verification'),
    password,
  );
  if (verified.status !== 200) {
    throw new Error(
      `verify ${email} -> ${verified.status} ${JSON.stringify(verified.body)}`,
    );
  }
}

export function cookieNames(res: request.Response): string[] {
  const raw = res.headers['set-cookie'] as unknown as
    string[] | string | undefined;
  const list = Array.isArray(raw) ? raw : raw ? [raw] : [];
  return list.map((c) => c.split('=')[0]);
}

export function findSetCookie(
  res: request.Response,
  name: string,
): string | undefined {
  const raw = res.headers['set-cookie'] as unknown as
    string[] | string | undefined;
  const list = Array.isArray(raw) ? raw : raw ? [raw] : [];
  return list.find((c) => c.startsWith(`${name}=`));
}

/** Direct SQL query on the test database, with a typed result. */
export async function sql<T>(
  h: Harness,
  query: string,
  params: unknown[] = [],
): Promise<T[]> {
  return h.db.query<T[]>(query, params);
}

/** Value of a cookie set by the response (undefined if absent or if deleted). */
export function cookieValue(
  res: request.Response,
  name: string,
): string | undefined {
  const cookie = findSetCookie(res, name);
  if (!cookie) return undefined;
  const value = cookie.split(';')[0].slice(name.length + 1);
  return value === '' ? undefined : value;
}

/** Cookie header "as a browser would send it" with the tokens chosen by the test. */
export function cookieHeader(tokens: {
  access?: string;
  refresh?: string;
}): string {
  return [
    tokens.access ? `access_token=${tokens.access}` : '',
    tokens.refresh ? `refresh_token=${tokens.refresh}` : '',
  ]
    .filter(Boolean)
    .join('; ');
}

export function refresh(h: Harness, refreshToken: string | undefined) {
  const req = http(h).post('/api/auth/refresh');
  return refreshToken
    ? req.set('Cookie', cookieHeader({ refresh: refreshToken }))
    : req;
}

export interface Session {
  access: string;
  refresh: string;
}

/** Login with valid credentials; returns the two tokens from the cookies. */
export async function loginSession(
  h: Harness,
  email: string,
  password = PASSWORD,
): Promise<Session> {
  const res = await login(h, email, password);
  const access = cookieValue(res, 'access_token');
  const refreshToken = cookieValue(res, 'refresh_token');
  if (res.status !== 200 || !access || !refreshToken) {
    throw new Error(
      `login ${email} -> ${res.status} ${JSON.stringify(res.body)}`,
    );
  }
  return { access, refresh: refreshToken };
}

export interface UserRow {
  id: string;
  email: string;
  password: string | null;
  googleId: string | null;
  provider: string | null;
  tokenVersion: number;
  emailVerifiedAt: Date | null;
}

export async function userRow(
  h: Harness,
  email: string,
): Promise<UserRow | undefined> {
  const rows: UserRow[] = await h.db.query(
    'SELECT id, email, password, "googleId", provider, "tokenVersion", "emailVerifiedAt" FROM users WHERE email = $1',
    [email],
  );
  return rows[0];
}
