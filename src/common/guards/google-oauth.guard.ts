import {
  ExecutionContext,
  Injectable,
  NotImplementedException,
} from '@nestjs/common';
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
import {
  frontendOrigins,
  resolveRedirectIndex,
} from '../../modules/auth/frontend-redirect';
import { isGoogleConfigured } from '../../modules/auth/strategies/google.strategy';

type CanActivateResult = boolean | Promise<boolean> | Observable<boolean>;

/** Without GOOGLE_* the provider is disabled: 501 instead of a strategy with fake credentials. */
function assertGoogleConfigured(configService: ConfigService): void {
  if (!isGoogleConfigured(configService)) {
    throw new NotImplementedException(
      'Google login is not configured on this server.',
    );
  }
}

/**
 * Start of the flow (GET /auth/google): generates the `state`, puts it in a signed
 * cookie and hands it to Passport, which forwards it to Google.
 * `accessType: offline` and `prompt: consent` are not requested: Google's tokens are not used.
 */
@Injectable()
export class GoogleOAuthGuard extends AuthGuard('google') {
  constructor(protected readonly configService: ConfigService) {
    super();
  }

  canActivate(context: ExecutionContext): CanActivateResult {
    assertGoogleConfigured(this.configService);
    const http = context.switchToHttp();
    const request = http.getRequest<Request>();
    const response = http.getResponse<Response>();

    // Return origin: only among those in the FRONTEND_URL whitelist; the index is signed.
    const redirectIndex =
      request.query.redirect_to === undefined
        ? 0
        : resolveRedirectIndex(
            frontendOrigins(this.configService),
            request.query.redirect_to,
          );
    const { state, cookie } = createOAuthState(
      this.configService.getOrThrow<string>('JWT_SECRET'),
      redirectIndex,
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
 * Callback (GET /auth/google/callback): BEFORE talking to Google it checks that the
 * `state` matches the browser's signed cookie. The cookie is single-use: it is
 * always deleted, even if the check fails.
 */
@Injectable()
export class GoogleCallbackGuard extends AuthGuard('google') {
  constructor(protected readonly configService: ConfigService) {
    super();
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    assertGoogleConfigured(this.configService);
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
