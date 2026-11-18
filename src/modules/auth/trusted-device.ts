import { createHmac, timingSafeEqual } from 'crypto';
import type { CookieOptions } from 'express';

export const TRUSTED_DEVICE_COOKIE = 'trusted_device';
export const TRUSTED_DEVICE_TTL_MS = 30 * 24 * 60 * 60 * 1000;
/** The cookie only travels to /api/auth (where the login is). */
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
 * "Recognized device": after a successful login the browser receives a signed cookie
 * tied to THAT account (and to its tokenVersion). It serves a single purpose:
 * during a lock from failed attempts, the owner who has already logged in from
 * this browser can still get in (with the right password). So whoever attacks from
 * outside cannot keep the owner out forever. It does not skip the password
 * check and does not apply to other accounts.
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
