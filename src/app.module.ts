import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { ScheduleModule } from '@nestjs/schedule';
import { join } from 'path';
import { envValidationSchema } from './config/env.validation';
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
      // Tests must not depend on the development .env (real DB and secrets).
      ignoreEnvFile: process.env.NODE_ENV === 'test',
      validationSchema: envValidationSchema,
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
        // The schema evolves ONLY through migrations (database/migrations/).
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
    // Order matters: global guards run in the order they are registered here. The rate limit goes
    // FIRST so that requests the other guards reject (no/invalid token: 401, no permission: 403)
    // still count; with it last, anonymous traffic on protected routes was never limited.
    { provide: APP_GUARD, useExisting: ThrottlerGuard },
    { provide: APP_GUARD, useExisting: AuthGuard },
    { provide: APP_GUARD, useExisting: PermissionsGuard },
  ],
})
export class AppModule {}
