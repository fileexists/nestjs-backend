import { INestApplication } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

/**
 * The API documentation (`/docs`) is on everywhere except production, where it has to be asked
 * for explicitly with SWAGGER_ENABLED=true.
 */
export function isSwaggerEnabled(
  nodeEnv: string | undefined,
  swaggerEnabled: unknown,
): boolean {
  return (
    nodeEnv !== 'production' ||
    swaggerEnabled === true ||
    swaggerEnabled === 'true'
  );
}

export function setupSwagger(app: INestApplication): void {
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
}
