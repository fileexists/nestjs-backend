import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import { Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import compression from 'compression';
import helmet from 'helmet';
import { AppModule } from './app.module';
import { configureApp } from './app.setup';

async function bootstrap(): Promise<void> {
  const logger = new Logger('Bootstrap');
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  app.enableShutdownHooks();
  configureApp(app);

  const configService = app.get(ConfigService);
  const port = configService.get<number>('PORT') ?? 3000;
  const corsOrigins = (configService.get<string>('CORS_ORIGIN') ?? '*')
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean);

  app.use(compression());
  app.use(
    helmet({
      contentSecurityPolicy:
        configService.get<string>('NODE_ENV') === 'production',
    }),
  );
  app.enableCors({
    origin: corsOrigins.length === 1 ? corsOrigins[0] : corsOrigins,
    credentials: true,
  });

  const swaggerConfig = new DocumentBuilder()
    .setTitle('NestJS Auth & Roles')
    .setDescription(
      'Authentication backend with JWT, refresh token rotation, RBAC, and Google OAuth2.',
    )
    .setVersion('1.0')
    .addBearerAuth(
      { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
      'Bearer token',
    )
    .addCookieAuth('access_token')
    .build();

  SwaggerModule.setup('docs', app, () =>
    SwaggerModule.createDocument(app, swaggerConfig),
  );

  await app.listen(port, '0.0.0.0');
  logger.log(`Application running on http://localhost:${port}`);
  logger.log(`Swagger docs available at http://localhost:${port}/docs`);
}

void bootstrap();
