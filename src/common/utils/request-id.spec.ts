import type { Request, Response } from 'express';
import { RequestIdInterceptor } from '../interceptors/request-id.interceptor';
import { ensureRequestId, REQUEST_ID_PATTERN } from './request-id';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function call(headers: Record<string, unknown>) {
  const request = { headers: { ...headers } } as unknown as Request;
  const setHeader = jest.fn();
  const response = { setHeader } as unknown as Response;
  const id = ensureRequestId(request, response);
  return { id, request, setHeader };
}

describe('ensureRequestId', () => {
  it.each([
    'a',
    'abc-123',
    '550e8400-e29b-41d4-a716-446655440000',
    'A'.repeat(64),
  ])('keeps a well formed client id: %s', (supplied) => {
    const { id, request, setHeader } = call({ 'x-request-id': supplied });

    expect(id).toBe(supplied);
    expect(request.headers['x-request-id']).toBe(supplied);
    expect(setHeader).toHaveBeenCalledWith('X-Request-Id', supplied);
  });

  it.each([
    ['too long', 'a'.repeat(65)],
    ['empty', ''],
    ['a space', 'abc 123'],
    ['a new line (log forging)', 'abc\nERROR forged'],
    ['a carriage return', 'abc\rdef'],
    ['an underscore', 'abc_123'],
    ['a dot', 'abc.123'],
    ['non-ASCII', 'abc-é'],
    ['markup', '<script>'],
  ])('replaces an id with %s by a UUID', (_label, supplied) => {
    const { id, request, setHeader } = call({ 'x-request-id': supplied });

    expect(id).toMatch(UUID);
    expect(request.headers['x-request-id']).toBe(id);
    expect(setHeader).toHaveBeenCalledWith('X-Request-Id', id);
  });

  it('generates a UUID when there is no header', () => {
    expect(call({}).id).toMatch(UUID);
  });

  it('does not trust a repeated header (an array)', () => {
    expect(call({ 'x-request-id': ['a', 'b'] }).id).toMatch(UUID);
  });

  it('is stable when called again on the same request', () => {
    const request = { headers: {} } as unknown as Request;
    const response = { setHeader: jest.fn() } as unknown as Response;

    const first = ensureRequestId(request, response);

    expect(ensureRequestId(request, response)).toBe(first);
  });

  it('the pattern is exactly letters, digits and hyphens, 1 to 64 characters', () => {
    expect(REQUEST_ID_PATTERN.source).toBe('^[A-Za-z0-9-]{1,64}$');
  });
});

describe('RequestIdInterceptor', () => {
  it('applies the same rule before the handler runs', () => {
    const request = {
      headers: { 'x-request-id': 'bad id\nwith newline' },
    } as unknown as Request;
    const setHeader = jest.fn();
    const next = { handle: jest.fn().mockReturnValue('stream') };
    const context = {
      switchToHttp: () => ({
        getRequest: () => request,
        getResponse: () => ({ setHeader }),
      }),
    };

    const result = new RequestIdInterceptor().intercept(
      context as never,
      next as never,
    );

    expect(result).toBe('stream');
    expect(request.headers['x-request-id']).toMatch(UUID);
    expect(setHeader).toHaveBeenCalledWith(
      'X-Request-Id',
      request.headers['x-request-id'],
    );
  });
});
