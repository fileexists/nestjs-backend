import { createHmac, randomBytes, timingSafeEqual } from 'crypto';
import type { CookieOptions } from 'express';

export const OAUTH_STATE_COOKIE = 'oauth_state';
/** Il cookie viaggia solo verso gli endpoint Google (include /callback per prefisso). */
export const OAUTH_STATE_COOKIE_PATH = '/api/auth/google';
export const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace -- required syntax for augmenting Express's global namespace
  namespace Express {
    interface Request {
      /** Nonce `state` generato dal guard di avvio e passato a Passport. */
      oauthState?: string;
      /** Indice (nella whitelist FRONTEND_URL) dell'origine verso cui tornare dopo il login. */
      oauthRedirectIndex?: number;
    }
  }
}

const sign = (secret: string, payload: string): string =>
  createHmac('sha256', secret)
    .update(`oauth-state:${payload}`)
    .digest('base64url');

const safeEqual = (a: string, b: string): boolean => {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
};

/**
 * Genera il `state` anti-CSRF: un nonce casuale che viaggia nell'URL verso Google e,
 * firmato con HMAC, in un cookie httpOnly del browser che ha avviato il flusso.
 * Al ritorno i due devono coincidere: un callback preparato da un altro browser
 * (o forgiato) non ha il cookie giusto. `redirectIndex` e' firmato insieme al nonce,
 * quindi non si puo' alterare per dirottare il redirect finale.
 */
export function createOAuthState(
  secret: string,
  redirectIndex = 0,
): { state: string; cookie: string } {
  const nonce = randomBytes(32).toString('base64url');
  const payload = `${nonce}.${redirectIndex}`;
  return { state: nonce, cookie: `${payload}.${sign(secret, payload)}` };
}

/** Verifica cookie + parametro `state` del callback. Ritorna null se non coincidono o la firma non e' valida. */
export function verifyOAuthState(
  secret: string,
  cookie: unknown,
  state: unknown,
): { redirectIndex: number } | null {
  if (typeof cookie !== 'string' || typeof state !== 'string' || !state) {
    return null;
  }
  const parts = cookie.split('.');
  if (parts.length !== 3) return null;
  const [nonce, index, signature] = parts;
  if (!/^\d{1,3}$/.test(index)) return null;
  if (!safeEqual(signature, sign(secret, `${nonce}.${index}`))) return null;
  if (!safeEqual(nonce, state)) return null;
  return { redirectIndex: Number(index) };
}

export function oauthStateCookieOptions(isProduction: boolean): CookieOptions {
  return {
    httpOnly: true,
    secure: isProduction,
    // Lax: il ritorno da Google e' una navigazione top-level GET, il cookie deve arrivare.
    sameSite: 'lax',
    path: OAUTH_STATE_COOKIE_PATH,
    maxAge: OAUTH_STATE_TTL_MS,
  };
}
