import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthToken } from '../../common/entities/auth-token.entity';
import { RefreshToken } from '../../common/entities/refresh-token.entity';
import { AuthCleanupService } from './auth-cleanup.service';
import { RefreshTokenService } from './refresh-token.service';
import { AccountService } from './account.service';
import { AuthTokenService } from './auth-token.service';
import { MailModule } from '../mail/mail.module';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import {
  GoogleStrategy,
  isGoogleConfigured,
} from './strategies/google.strategy';
import { GoogleCallbackExceptionFilter } from './google-callback.filter';
import { UserModule } from '../user/user.module';
import { PermissionModule } from '../permission/permission.module';
import type { StringValue } from 'ms';

@Module({
  imports: [
    ConfigModule,
    PassportModule,
    JwtModule.registerAsync({
      global: true,
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: {
          expiresIn: (configService.get<string>('JWT_EXPIRATION') ??
            '15m') as StringValue,
        },
      }),
    }),
    TypeOrmModule.forFeature([AuthToken, RefreshToken]),
    MailModule,
    UserModule,
    PermissionModule,
  ],
  providers: [
    AuthService,
    AccountService,
    AuthTokenService,
    RefreshTokenService,
    AuthCleanupService,
    GoogleCallbackExceptionFilter,
    // Provider opzionale: senza GOOGLE_* non si registra nessuna strategia e gli
    // endpoint Google rispondono 501 (vedi i guard).
    {
      provide: GoogleStrategy,
      useFactory: (configService: ConfigService) =>
        isGoogleConfigured(configService)
          ? new GoogleStrategy(configService)
          : null,
      inject: [ConfigService],
    },
  ],
  controllers: [AuthController],
  exports: [AuthService],
})
export class AuthModule {}
