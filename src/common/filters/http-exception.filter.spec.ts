import { ArgumentsHost, HttpException, Logger } from '@nestjs/common';
import { HttpExceptionFilter } from './http-exception.filter';

describe('HttpExceptionFilter', () => {
  const json = jest.fn();
  const status = jest.fn().mockReturnValue({ json });
  const setHeader = jest.fn();
  const host = (request: object) =>
    ({
      switchToHttp: () => ({
        getResponse: () => ({ status, setHeader }),
        getRequest: () => ({ headers: {}, ...request }),
      }),
    }) as unknown as ArgumentsHost;

  afterEach(() => jest.restoreAllMocks());

  it('does not write the query string to the log (it may contain one-time codes)', () => {
    const error = jest.spyOn(Logger.prototype, 'error').mockImplementation();

    new HttpExceptionFilter().catch(
      new HttpException('nope', 401),
      host({
        method: 'GET',
        url: '/api/auth/google/callback?code=SECRET&state=abc',
        path: '/api/auth/google/callback',
      }),
    );

    expect(error).toHaveBeenCalledWith(
      expect.stringMatching(
        /^GET \/api\/auth\/google\/callback → 401 \[request [A-Za-z0-9-]+\]$/,
      ),
    );
    expect(JSON.stringify(error.mock.calls)).not.toContain('SECRET');
  });

  it('responds with status, message and path', () => {
    jest.spyOn(Logger.prototype, 'error').mockImplementation();

    new HttpExceptionFilter().catch(
      new HttpException('nope', 403),
      host({ method: 'GET', url: '/x', path: '/x' }),
    );

    expect(status).toHaveBeenCalledWith(403);
    expect(json).toHaveBeenCalledWith(
      expect.objectContaining({ statusCode: 403, message: 'nope', path: '/x' }),
    );
  });

  describe('request id in the error log', () => {
    const run = (headers: Record<string, unknown>) => {
      const error = jest.spyOn(Logger.prototype, 'error').mockImplementation();
      new HttpExceptionFilter().catch(
        new HttpException('nope', 401),
        host({ method: 'GET', url: '/x', path: '/x', headers }),
      );
      return error.mock.calls[0][0] as string;
    };

    it('logs the id the client sent when it is well formed, and echoes it in the response', () => {
      expect(run({ 'x-request-id': 'abc-123' })).toBe(
        'GET /x → 401 [request abc-123]',
      );
      expect(setHeader).toHaveBeenCalledWith('X-Request-Id', 'abc-123');
    });

    it('a guard rejection happens before the interceptor: the filter still gives the request an id', () => {
      const line = run({});

      const id = /\[request (.+)\]$/.exec(line)?.[1];
      expect(id).toMatch(/^[0-9a-f-]{36}$/);
      expect(setHeader).toHaveBeenCalledWith('X-Request-Id', id);
    });

    it('never writes a forged id (new line, spaces, too long) into the log', () => {
      for (const forged of [
        'abc\nERROR fake line',
        'has space',
        'a'.repeat(65),
        '',
      ]) {
        setHeader.mockClear();
        const line = run({ 'x-request-id': forged });

        expect(line.split('\n')).toHaveLength(1);
        expect(line).not.toContain(forged || 'never-empty-match');
        expect(line).toMatch(/\[request [0-9a-f-]{36}\]$/);
      }
    });
  });
});
