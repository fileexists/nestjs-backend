import { createHmac, timingSafeEqual } from 'crypto';
import type { CookieOptions } from 'express';

export const TRUSTED_DEVICE_COOKIE = 'trusted_device';
export const TRUSTED_DEVICE_TTL_MS = 30 * 24 * 60 * 60 * 1000;
/** Il cookie viaggia solo verso /api/auth (dove sta il login). */
export const TRUSTED_DEVICE_COOKIE_PATH = '/api/auth';

const sign = (secret: string, payload: string): string =>
  createHmac('sha256', secret)
    .update(`trusted-device:${payload}`)
    .digest('base64url');

const safeEqual = (a: string, b: string): boolean => {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
};

/**
 * "Dispositivo riconosciuto": dopo un login riuscito il browser riceve un cookie
 * firmato legato a QUELL'account (e al suo tokenVersion). Serve a una sola cosa:
 * durante un blocco per tentativi falliti, il proprietario che ha gia' fatto login da
 * questo browser puo' ancora entrare (con la password giusta). Cosi' chi attacca da
 * fuori non puo' tenere fuori il proprietario all'infinito. Non salta il controllo
 * della password e non vale per altri account.
 */
export function createTrustedDeviceCookie(
  secret: string,
  userId: string,
  tokenVersion: number,
  now = Date.now(),
): string {
  const payload = `${userId}.${tokenVersion}.${now + TRUSTED_DEVICE_TTL_MS}`;
  return `${payload}.${sign(secret, payload)}`;
}

export function verifyTrustedDevice(
  secret: string,
  cookie: unknown,
  userId: string,
  tokenVersion: number,
  now = Date.now(),
): boolean {
  if (typeof cookie !== 'string') return false;
  const parts = cookie.split('.');
  if (parts.length !== 4) return false;
  const [cookieUser, cookieVersion, expiresAt, signature] = parts;
  const payload = `${cookieUser}.${cookieVersion}.${expiresAt}`;
  return (
    safeEqual(signature, sign(secret, payload)) &&
    cookieUser === userId &&
    cookieVersion === String(tokenVersion) &&
    Number(expiresAt) > now
  );
}

export function trustedDeviceCookieOptions(
  isProduction: boolean,
): CookieOptions {
  return {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    path: TRUSTED_DEVICE_COOKIE_PATH,
    maxAge: TRUSTED_DEVICE_TTL_MS,
  };
}
