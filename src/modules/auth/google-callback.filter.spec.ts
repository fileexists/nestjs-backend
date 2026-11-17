import {
  ArgumentsHost,
  BadRequestException,
  InternalServerErrorException,
  NotImplementedException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { GoogleCallbackExceptionFilter } from './google-callback.filter';
import { GoogleAuthException } from './google-auth.exception';

describe('GoogleCallbackExceptionFilter (C1)', () => {
  const config = {
    get: () => 'https://app.example.com,https://admin.example.com',
  } as unknown as ConfigService;
  const filter = new GoogleCallbackExceptionFilter(config);

  function host(request: Record<string, unknown> = {}) {
    const response = {
      redirect: jest.fn(),
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
    const argumentsHost = {
      switchToHttp: () => ({
        getRequest: () => ({ method: 'GET', url: '/x', ...request }),
        getResponse: () => response,
      }),
    } as unknown as ArgumentsHost;
    return { argumentsHost, response };
  }

  it.each([
    'state_invalid',
    'email_unverified',
    'email_missing',
    'account_conflict',
  ] as const)(
    'GoogleAuthException(%s) -> redirect 302 al frontend con reason=%s',
    (code) => {
      const { argumentsHost, response } = host();
      filter.catch(new GoogleAuthException(code, 'msg'), argumentsHost);

      expect(response.redirect).toHaveBeenCalledWith(
        302,
        `https://app.example.com/auth/callback?status=error&reason=${code}`,
      );
    },
  );

  it('un 401 generico (es. consenso negato) -> reason=failed', () => {
    const { argumentsHost, response } = host();
    filter.catch(new UnauthorizedException(), argumentsHost);
    expect(response.redirect).toHaveBeenCalledWith(
      302,
      'https://app.example.com/auth/callback?status=error&reason=failed',
    );
  });

  it('usa l origine scelta all avvio (indice firmato) anche per gli errori', () => {
    const { argumentsHost, response } = host({ oauthRedirectIndex: 1 });
    filter.catch(new GoogleAuthException('failed', 'x'), argumentsHost);
    expect(response.redirect).toHaveBeenCalledWith(
      302,
      'https://admin.example.com/auth/callback?status=error&reason=failed',
    );
  });

  it('un errore inatteso (non HTTP) riporta comunque al frontend con reason=server_error', () => {
    const { argumentsHost, response } = host();
    filter.catch(new Error('db exploded'), argumentsHost);
    expect(response.redirect).toHaveBeenCalledWith(
      302,
      'https://app.example.com/auth/callback?status=error&reason=server_error',
    );
  });

  it.each([
    ['501 provider non configurato', new NotImplementedException('x'), 501],
    ['400', new BadRequestException('x'), 400],
    ['500 HTTP esplicito', new InternalServerErrorException('x'), 500],
  ])('%s resta una risposta JSON, non un redirect', (_label, error, status) => {
    const { argumentsHost, response } = host();
    filter.catch(error, argumentsHost);
    expect(response.redirect).not.toHaveBeenCalled();
    expect(response.status).toHaveBeenCalledWith(status);
  });
});
