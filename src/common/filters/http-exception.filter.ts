import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { ensureRequestId } from '../utils/request-id';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(HttpExceptionFilter.name);

  catch(exception: HttpException, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    const status = exception.getStatus();
    const exceptionResponse = exception.getResponse();

    const message =
      typeof exceptionResponse === 'string'
        ? exceptionResponse
        : (exceptionResponse as Record<string, unknown>).message;

    // Guards run before interceptors, so a 401/403 from a guard has no request id yet: make sure
    // there is one (validated), so the log line and the response header always carry it.
    const requestId = ensureRequestId(request, response);

    // Path only: the query string may contain single-use codes (e.g. Google's `code`).
    this.logger.error(
      `${request.method} ${request.path} → ${status} [request ${requestId}]`,
    );

    response.status(status).json({
      statusCode: status,
      message,
      path: request.url,
      timestamp: new Date().toISOString(),
    });
  }
}
