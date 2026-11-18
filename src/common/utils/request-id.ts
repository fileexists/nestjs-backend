import { randomUUID } from 'crypto';
import type { Request, Response } from 'express';

/** What a client-supplied request id may look like: short, and nothing that could forge a log line. */
export const REQUEST_ID_PATTERN = /^[A-Za-z0-9-]{1,64}$/;

/**
 * Makes sure the request carries a usable `x-request-id` and echoes it in the response.
 * A client-supplied id is kept only if it matches REQUEST_ID_PATTERN (it ends up in the logs and in
 * a response header, so a newline or an 8 KB string must not get through); anything else, or a
 * repeated header, is replaced by a fresh UUID. Safe to call more than once.
 */
export function ensureRequestId(request: Request, response: Response): string {
  const supplied = request.headers['x-request-id'];
  const requestId =
    typeof supplied === 'string' && REQUEST_ID_PATTERN.test(supplied)
      ? supplied
      : randomUUID();
  request.headers['x-request-id'] = requestId;
  response.setHeader('X-Request-Id', requestId);
  return requestId;
}
