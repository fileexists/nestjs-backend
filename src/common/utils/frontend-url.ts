export interface OriginListOptions {
  /** Name of the variable, used in the error messages. */
  name?: string;
  requireHttps?: boolean;
}

/**
 * Parses a list (comma-separated) of bare origins into their canonical form
 * (`scheme://host[:port]`, no trailing slash). Used for FRONTEND_URL and CORS_ORIGIN.
 * An origin with a path, query, fragment or credentials is rejected.
 */
export function parseOrigins(
  value: string,
  { name = 'FRONTEND_URL', requireHttps }: OriginListOptions = {},
): string[] {
  const parts = value
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean);
  if (parts.length === 0) {
    throw new Error(`${name} must contain at least one URL`);
  }

  const origins = parts.map((part) => {
    let url: URL;
    try {
      url = new URL(part);
    } catch {
      throw new Error(`${name} contains an invalid URL: "${part}"`);
    }
    if (url.protocol !== 'https:' && url.protocol !== 'http:') {
      throw new Error(`${name} must use http(s): "${part}"`);
    }
    if (requireHttps && url.protocol !== 'https:') {
      throw new Error(`${name} must use https in production: "${part}"`);
    }
    if (url.username || url.password) {
      throw new Error(`${name} must not contain credentials: "${part}"`);
    }
    if (url.pathname !== '/' || url.search || url.hash) {
      throw new Error(
        `${name} must be a bare origin (no path, query or fragment): "${part}"`,
      );
    }
    return url.origin;
  });

  return [...new Set(origins)];
}

/**
 * FRONTEND_URL: list (comma-separated) of the allowed frontend origins.
 * It is a whitelist: redirect URLs and the links in emails are built
 * ONLY from these values, never from user input (no open redirect).
 * The first origin is the default one.
 */
export function parseFrontendUrls(
  value: string,
  options: Pick<OriginListOptions, 'requireHttps'> = {},
): string[] {
  return parseOrigins(value, { ...options, name: 'FRONTEND_URL' });
}
