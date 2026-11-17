import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { ScheduleModule } from '@nestjs/schedule';
import * as Joi from 'joi';
import { join } from 'path';
import { DURATION_PATTERN } from './common/utils/duration';
import { parseFrontendUrls } from './common/utils/frontend-url';
import { ENTITIES } from './common/entities';
import { AuthModule } from './modules/auth/auth.module';
import { UserModule } from './modules/user/user.module';
import { PermissionModule } from './modules/permission/permission.module';
import { AuthGuard } from './common/guards/auth.guard';
import { PermissionsGuard } from './common/guards/permissions.guard';
import { AppController } from './app.controller';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      // I test non devono dipendere dal .env di sviluppo (DB e segreti veri).
      ignoreEnvFile: process.env.NODE_ENV === 'test',
      validationSchema: Joi.object({
        NODE_ENV: Joi.string()
          .valid('development', 'production', 'test')
          .default('development'),
        PORT: Joi.number().default(3000),
        JWT_SECRET: Joi.string().min(16).required(),
        REFRESH_TOKEN_SECRET: Joi.string().min(16).required(),
        JWT_EXPIRATION: Joi.string().default('15m'),
        REFRESH_TOKEN_EXPIRATION: Joi.string().default('7d'),
        // Tolleranza (secondi) per il riuso di un refresh token appena ruotato (richieste
        // parallele del browser). 0 = ogni riuso e' trattato come furto.
        REFRESH_REUSE_GRACE_SECONDS: Joi.number()
          .integer()
          .min(0)
          .max(60)
          .default(0),
        DATABASE_URL: Joi.string().required(),
        // Applica le migrazioni all'avvio (default: no, si lanciano con `yarn migration:run`).
        DB_MIGRATIONS_RUN: Joi.boolean().default(false),
        CORS_ORIGIN: Joi.string().default('*'),
        // Email (SMTP). In sviluppo: Mailpit (localhost:1025, oppure mailpit:1025 dentro compose).
        SMTP_HOST: Joi.string().when('NODE_ENV', {
          is: 'production',
          then: Joi.required(),
          otherwise: Joi.string().default('localhost'),
        }),
        SMTP_PORT: Joi.number().port().default(1025),
        SMTP_SECURE: Joi.boolean().default(false),
        SMTP_USER: Joi.string().optional().allow(''),
        SMTP_PASS: Joi.string().optional().allow(''),
        MAIL_FROM: Joi.string().default('Auth <no-reply@localhost>'),
        EMAIL_VERIFICATION_TTL: Joi.string()
          .pattern(DURATION_PATTERN)
          .default('24h'),
        // Whitelist (separata da virgole) delle origini del frontend: link nelle
        // email e redirect si costruiscono SOLO da qui. La prima e' quella predefinita.
        FRONTEND_URL: Joi.string()
          .custom((value: string) => {
            parseFrontendUrls(value);
            return value;
          })
          .default('http://localhost:3000'),
        GOOGLE_CLIENT_ID: Joi.string().optional().allow(''),
        GOOGLE_CLIENT_SECRET: Joi.string().optional().allow(''),
        GOOGLE_CALLBACK_URL: Joi.string().optional().allow(''),
      }).custom((env: { NODE_ENV?: string; FRONTEND_URL?: string }) => {
        // In produzione il frontend e' sempre esplicito e solo https.
        if (env.NODE_ENV === 'production') {
          parseFrontendUrls(env.FRONTEND_URL ?? '', { requireHttps: true });
        }
        return env;
      }),
      validationOptions: {
        libraryOptions: { allowUnknown: true, abortEarly: true },
      },
    }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        url: configService.get<string>('DATABASE_URL'),
        entities: ENTITIES,
        migrations: [
          join(__dirname, '..', 'database', 'migrations', '*.{js,ts}'),
        ],
        migrationsRun: configService.get<boolean>('DB_MIGRATIONS_RUN') ?? false,
        // Lo schema si evolve SOLO con le migrazioni (database/migrations/).
        synchronize: false,
        logging: configService.get<string>('NODE_ENV') === 'development',
      }),
    }),
    ScheduleModule.forRoot(),
    AuthModule,
    UserModule,
    PermissionModule,
    ThrottlerModule.forRoot({
      throttlers: [{ ttl: 60_000, limit: 100 }],
    }),
  ],
  controllers: [AppController],
  providers: [
    AuthGuard,
    PermissionsGuard,
    ThrottlerGuard,
    { provide: APP_GUARD, useExisting: AuthGuard },
    { provide: APP_GUARD, useExisting: PermissionsGuard },
    { provide: APP_GUARD, useExisting: ThrottlerGuard },
  ],
})
export class AppModule {}
