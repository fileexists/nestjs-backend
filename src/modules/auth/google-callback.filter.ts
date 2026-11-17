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
 * Il callback di Google e' una navigazione del browser, non una chiamata API: un
 * errore non deve lasciare l'utente su una pagina JSON, ma riportarlo al frontend
 * con `?status=error&reason=...`. Restano risposte HTTP normali i casi che non sono
 * un esito di login (501 provider non configurato, 429, ...).
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
      reason = 'failed'; // es. consenso negato su Google, code non valido
    } else {
      this.logger.error(
        `Errore inatteso nel callback Google: ${exception instanceof Error ? exception.message : String(exception)}`,
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
