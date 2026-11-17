import { ArgumentsHost, HttpException, Logger } from '@nestjs/common';
import { HttpExceptionFilter } from './http-exception.filter';

describe('HttpExceptionFilter', () => {
  const json = jest.fn();
  const status = jest.fn().mockReturnValue({ json });
  const host = (request: object) =>
    ({
      switchToHttp: () => ({
        getResponse: () => ({ status }),
        getRequest: () => request,
      }),
    }) as unknown as ArgumentsHost;

  afterEach(() => jest.restoreAllMocks());

  it('non scrive nel log la query string (puo contenere codici monouso)', () => {
    const error = jest.spyOn(Logger.prototype, 'error').mockImplementation();

    new HttpExceptionFilter().catch(
      new HttpException('nope', 401),
      host({
        method: 'GET',
        url: '/api/auth/google/callback?code=SECRET&state=abc',
        path: '/api/auth/google/callback',
      }),
    );

    expect(error).toHaveBeenCalledWith('GET /api/auth/google/callback → 401');
    expect(JSON.stringify(error.mock.calls)).not.toContain('SECRET');
  });

  it('risponde con stato, messaggio e percorso', () => {
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
});
