/**
 * FRONTEND_URL: elenco (separato da virgole) delle origini del frontend ammesse.
 * E' una whitelist: gli URL di redirect e i link nelle email si costruiscono
 * SOLO a partire da questi valori, mai da input dell'utente (nessun open redirect).
 * La prima origine e' quella predefinita.
 */
export function parseFrontendUrls(
  value: string,
  options: { requireHttps?: boolean } = {},
): string[] {
  const parts = value
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean);
  if (parts.length === 0) {
    throw new Error('FRONTEND_URL must contain at least one URL');
  }

  const origins = parts.map((part) => {
    let url: URL;
    try {
      url = new URL(part);
    } catch {
      throw new Error(`FRONTEND_URL contains an invalid URL: "${part}"`);
    }
    if (url.protocol !== 'https:' && url.protocol !== 'http:') {
      throw new Error(`FRONTEND_URL must use http(s): "${part}"`);
    }
    if (options.requireHttps && url.protocol !== 'https:') {
      throw new Error(`FRONTEND_URL must use https in production: "${part}"`);
    }
    if (url.username || url.password) {
      throw new Error(`FRONTEND_URL must not contain credentials: "${part}"`);
    }
    if (url.pathname !== '/' || url.search || url.hash) {
      throw new Error(
        `FRONTEND_URL must be a bare origin (no path, query or fragment): "${part}"`,
      );
    }
    return url.origin;
  });

  return [...new Set(origins)];
}
