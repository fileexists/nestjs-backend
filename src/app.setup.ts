import { ClassSerializerInterceptor, ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import cookieParser from 'cookie-parser';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';
import { RequestIdInterceptor } from './common/interceptors/request-id.interceptor';

export const GLOBAL_PREFIX = 'api';

/** Value for Express's `trust proxy` setting: the hop count, or `false` for none. */
export function trustProxyHops(app: NestExpressApplication): number | false {
  const hops = Number(app.get(ConfigService).get('TRUST_PROXY') ?? 1);
  return hops > 0 ? hops : false;
}

/**
 * HTTP configuration shared between `main.ts` and the e2e tests on a real database:
 * so the tests run with the same prefix, cookie parser, pipes, filters and interceptors
 * as production.
 */
export function configureApp(app: NestExpressApplication): void {
  // TRUST_PROXY = number of proxy hops (nginx/Caddy...) whose X-Forwarded-For is trusted, so req.ip
  // and the ThrottlerGuard see the real client IP instead of bucketing every request under the
  // proxy's IP. 0 = no proxy in front: the header is ignored (anyone could otherwise spoof their IP).
  app.set('trust proxy', trustProxyHops(app));

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
