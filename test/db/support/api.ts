import request from 'supertest';
import type { Harness } from './harness';

export const PASSWORD = 'Correct-Passw0rd!';

export type Agent = ReturnType<typeof request.agent>;

/** Client senza cookie: ogni richiesta e' indipendente. */
export function http(h: Harness): ReturnType<typeof request> {
  return request(h.app.getHttpServer());
}

/** Client con cookie jar (come un browser: rispetta Path/SameSite/Secure). */
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

/** Mediana di una serie di durate (ms): robusta ai picchi occasionali. */
export function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

/** Durata (ms) di una chiamata asincrona. */
export async function timed(fn: () => PromiseLike<unknown>): Promise<number> {
  const start = process.hrtime.bigint();
  await fn();
  return Number(process.hrtime.bigint() - start) / 1e6;
}

export function verifyEmail(h: Harness, token: string) {
  return http(h).post('/api/auth/verify-email').send({ token });
}

/** Registra e conferma l'email tramite il token "ricevuto" nell'outbox. */
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

/** Query SQL diretta sul database di test, con risultato tipizzato. */
export async function sql<T>(
  h: Harness,
  query: string,
  params: unknown[] = [],
): Promise<T[]> {
  return h.db.query<T[]>(query, params);
}

/** Valore di un cookie impostato dalla risposta (undefined se assente o se cancellato). */
export function cookieValue(
  res: request.Response,
  name: string,
): string | undefined {
  const cookie = findSetCookie(res, name);
  if (!cookie) return undefined;
  const value = cookie.split(';')[0].slice(name.length + 1);
  return value === '' ? undefined : value;
}

/** Cookie header "come li manderebbe un browser" con i token scelti dal test. */
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

/** Login con credenziali valide; ritorna i due token dai cookie. */
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
