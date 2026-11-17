import { BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { parseFrontendUrls } from '../../common/utils/frontend-url';

/** Pagina del frontend che riceve l'esito del login con Google (percorso fisso). */
export const FRONTEND_AUTH_CALLBACK_PATH = '/auth/callback';

/** Whitelist delle origini del frontend (FRONTEND_URL, validata all'avvio). */
export function frontendOrigins(configService: ConfigService): string[] {
  return parseFrontendUrls(
    configService.get<string>('FRONTEND_URL') ?? 'http://localhost:3000',
  );
}

/**
 * Sceglie l'origine di ritorno richiesta con `?redirect_to=`: deve coincidere
 * ESATTAMENTE con una origine della whitelist (si confronta `URL.origin`, quindi
 * `http://app.example.com@evil.com` o `http://app.example.com.evil.com` non passano).
 * Ritorna l'indice nella whitelist: e' quello che si firma nel cookie, mai l'URL.
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
 * URL di ritorno al frontend. Parte SEMPRE da un'origine della whitelist e da un
 * percorso fisso: nessuna parte arriva dalla richiesta (niente open redirect).
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
