import { ExecutionContext, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AuthGuard } from '@nestjs/passport';
import type { Request, Response } from 'express';
import type { Observable } from 'rxjs';
import {
  createOAuthState,
  OAUTH_STATE_COOKIE,
  oauthStateCookieOptions,
  verifyOAuthState,
} from '../../modules/auth/oauth-state';
import { GoogleAuthException } from '../../modules/auth/google-auth.exception';

type CanActivateResult = boolean | Promise<boolean> | Observable<boolean>;

/**
 * Avvio del flusso (GET /auth/google): genera il `state`, lo mette in un cookie
 * firmato e lo passa a Passport, che lo inoltra a Google.
 * Non si chiede `accessType: offline` ne `prompt: consent`: i token di Google non si usano.
 */
@Injectable()
export class GoogleOAuthGuard extends AuthGuard('google') {
  constructor(protected readonly configService: ConfigService) {
    super();
  }

  canActivate(context: ExecutionContext): CanActivateResult {
    const http = context.switchToHttp();
    const request = http.getRequest<Request>();
    const response = http.getResponse<Response>();

    const { state, cookie } = createOAuthState(
      this.configService.getOrThrow<string>('JWT_SECRET'),
    );
    response.cookie(
      OAUTH_STATE_COOKIE,
      cookie,
      oauthStateCookieOptions(
        this.configService.get<string>('NODE_ENV') === 'production',
      ),
    );
    request.oauthState = state;
    return super.canActivate(context);
  }

  getAuthenticateOptions(context: ExecutionContext): { state?: string } {
    return { state: context.switchToHttp().getRequest<Request>().oauthState };
  }
}

/**
 * Callback (GET /auth/google/callback): PRIMA di parlare con Google verifica che il
 * `state` coincida con il cookie firmato del browser. Il cookie e' monouso: viene
 * cancellato sempre, anche se la verifica fallisce.
 */
@Injectable()
export class GoogleCallbackGuard extends AuthGuard('google') {
  constructor(protected readonly configService: ConfigService) {
    super();
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const http = context.switchToHttp();
    const request = http.getRequest<Request>();
    const response = http.getResponse<Response>();

    const verified = verifyOAuthState(
      this.configService.getOrThrow<string>('JWT_SECRET'),
      (request.cookies as Record<string, unknown> | undefined)?.[
        OAUTH_STATE_COOKIE
      ],
      request.query.state,
    );
    response.clearCookie(OAUTH_STATE_COOKIE, {
      ...oauthStateCookieOptions(
        this.configService.get<string>('NODE_ENV') === 'production',
      ),
      maxAge: undefined,
    });
    if (!verified) {
      throw new GoogleAuthException(
        'state_invalid',
        'Invalid or missing OAuth state. Please start the Google login again.',
      );
    }
    request.oauthRedirectIndex = verified.redirectIndex;

    return (await super.canActivate(context)) as boolean;
  }
}
