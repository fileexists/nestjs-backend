import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Request, Response } from 'express';
import { HttpExceptionFilter } from '../../common/filters/http-exception.filter';
import { buildFrontendRedirect, frontendOrigins } from './frontend-redirect';
import { GoogleAuthException } from './google-auth.exception';

/**
 * The Google callback is a browser navigation, not an API call: an
 * error must not leave the user on a JSON page, but take them back to the frontend
 * with `?status=error&reason=...`. Cases that are not a login outcome
 * (501 provider not configured, 429, ...) stay normal HTTP responses.
 */
@Catch()
@Injectable()
export class GoogleCallbackExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(GoogleCallbackExceptionFilter.name);
  private readonly fallback = new HttpExceptionFilter();

  constructor(private readonly configService: ConfigService) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    if (
      exception instanceof HttpException &&
      !(exception instanceof UnauthorizedException)
    ) {
      this.fallback.catch(exception, host);
      return;
    }

    const http = host.switchToHttp();
    const request = http.getRequest<Request>();
    const response = http.getResponse<Response>();

    let reason = 'server_error';
    if (exception instanceof GoogleAuthException) {
      reason = exception.code;
    } else if (exception instanceof UnauthorizedException) {
      reason = 'failed'; // e.g. consent denied on Google, invalid code
    } else {
      this.logger.error(
        `Unexpected error in the Google callback: ${exception instanceof Error ? exception.message : String(exception)}`,
      );
    }

    response.redirect(
      HttpStatus.FOUND,
      buildFrontendRedirect(
        frontendOrigins(this.configService),
        request.oauthRedirectIndex ?? 0,
        { status: 'error', reason },
      ),
    );
  }
}
