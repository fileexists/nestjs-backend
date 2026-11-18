import { parseOrigins } from '../common/utils/frontend-url';

/**
 * Origins allowed by CORS (CORS_ORIGIN, comma-separated).
 * In production they are validated at startup (see env.validation.ts): https only, never `*`,
 * and they come back in canonical form (`https://app.example.com`, no trailing slash) so they
 * match the browser's `Origin` header. In development the value is used as written (default `*`).
 */
export function resolveCorsOrigins(
  value: string | undefined,
  production: boolean,
): string | string[] {
  const origins = production
    ? parseOrigins(value ?? '', { name: 'CORS_ORIGIN', requireHttps: true })
    : (value ?? '*')
        .split(',')
        .map((origin) => origin.trim())
        .filter(Boolean);
  return origins.length === 1 ? origins[0] : origins;
}
