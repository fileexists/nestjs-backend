import { BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { parseFrontendUrls } from '../../common/utils/frontend-url';

/** Frontend page that receives the outcome of the Google login (fixed path). */
export const FRONTEND_AUTH_CALLBACK_PATH = '/auth/callback';

/** Whitelist of the frontend origins (FRONTEND_URL, validated at startup). */
export function frontendOrigins(configService: ConfigService): string[] {
  return parseFrontendUrls(
    configService.get<string>('FRONTEND_URL') ?? 'http://localhost:3000',
  );
}

/**
 * Picks the return origin requested with `?redirect_to=`: it must match EXACTLY
 * an origin in the whitelist (`URL.origin` is compared, so
 * `http://app.example.com@evil.com` or `http://app.example.com.evil.com` do not pass).
 * Returns the index in the whitelist: that is what gets signed in the cookie, never the URL.
 */
export function resolveRedirectIndex(
  origins: string[],
  value: unknown,
): number {
  const invalid = () =>
    new BadRequestException('redirect_to is not an allowed frontend origin');
  if (typeof value !== 'string') throw invalid();
  let origin: string;
  try {
    origin = new URL(value).origin;
  } catch {
    throw invalid();
  }
  const index = origins.indexOf(origin);
  if (index < 0) throw invalid();
  return index;
}

/**
 * Return URL to the frontend. It ALWAYS starts from an origin in the whitelist and a
 * fixed path: no part comes from the request (no open redirect).
 */
export function buildFrontendRedirect(
  origins: string[],
  index: number,
  params: { status: 'success' | 'error'; reason?: string },
): string {
  const base = origins[index] ?? origins[0];
  const url = new URL(FRONTEND_AUTH_CALLBACK_PATH, base);
  url.searchParams.set('status', params.status);
  if (params.reason) url.searchParams.set('reason', params.reason);
  return url.toString();
}
