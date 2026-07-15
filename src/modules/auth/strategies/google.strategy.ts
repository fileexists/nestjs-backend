import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(configService: ConfigService) {
    super({
      clientID:
        configService.get<string>('GOOGLE_CLIENT_ID') ??
        'placeholder-client-id',
      clientSecret:
        configService.get<string>('GOOGLE_CLIENT_SECRET') ??
        'placeholder-client-secret',
      callbackURL: configService.get<string>('GOOGLE_CALLBACK_URL'),
      scope: ['email', 'profile'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: { id: string; emails: { value: string }[]; displayName: string },
    done: VerifyCallback,
  ): Promise<void> {
    const { id, emails, displayName } = profile;
    done(null, {
      googleId: id,
      email: emails?.[0]?.value,
      name: displayName,
      accessToken,
      refreshToken,
    });
  }
}
