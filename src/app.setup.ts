import { ClassSerializerInterceptor, ValidationPipe } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import cookieParser from 'cookie-parser';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';
import { RequestIdInterceptor } from './common/interceptors/request-id.interceptor';

export const GLOBAL_PREFIX = 'api';

/**
 * Configurazione HTTP condivisa tra `main.ts` e i test e2e su database vero:
 * così i test girano con prefisso, cookie parser, pipe, filtri e interceptor
 * identici a quelli di produzione.
 */
export function configureApp(app: NestExpressApplication): void {
  // Trust the first proxy hop (nginx/Caddy) so req.ip and the ThrottlerGuard
  // see the real client IP instead of bucketing every request under the proxy's IP.
  app.set('trust proxy', 1);

  app.setGlobalPrefix(GLOBAL_PREFIX, { exclude: ['health'] });
  app.use(cookieParser());

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );
  app.useGlobalFilters(new HttpExceptionFilter());
  app.useGlobalInterceptors(
    new RequestIdInterceptor(),
    new ClassSerializerInterceptor(app.get(Reflector)),
  );
}
