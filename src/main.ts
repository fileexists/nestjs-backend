import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import { Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import compression from 'compression';
import helmet from 'helmet';
import { AppModule } from './app.module';
import { configureApp } from './app.setup';
import { resolveCorsOrigins } from './config/cors';
import { isSwaggerEnabled, setupSwagger } from './config/swagger';

async function bootstrap(): Promise<void> {
  const logger = new Logger('Bootstrap');
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  app.enableShutdownHooks();
  configureApp(app);

  const configService = app.get(ConfigService);
  const port = configService.get<number>('PORT') ?? 3000;
  const nodeEnv = configService.get<string>('NODE_ENV');
  const production = nodeEnv === 'production';

  app.use(compression());
  app.use(helmet({ contentSecurityPolicy: production }));
  app.enableCors({
    origin: resolveCorsOrigins(
      configService.get<string>('CORS_ORIGIN'),
      production,
    ),
    credentials: true,
  });

  const swagger = isSwaggerEnabled(
    nodeEnv,
    configService.get<boolean>('SWAGGER_ENABLED'),
  );
  if (swagger) setupSwagger(app);

  await app.listen(port, '0.0.0.0');
  logger.log(`Application running on http://localhost:${port}`);
  if (swagger) {
    logger.log(`Swagger docs available at http://localhost:${port}/docs`);
  }
}

void bootstrap();
