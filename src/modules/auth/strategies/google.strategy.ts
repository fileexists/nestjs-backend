import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-google-oauth20';
import { GoogleProfilePayload } from '../../../common/interfaces/jwt-payload.interface';
import { GoogleProfileLike, mapGoogleProfile } from './google-profile';

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

  // Ritorna il payload (Nest chiama `done` per noi); lancia 401 se l'email manca o non e' verificata.
  validate(
    accessToken: string,
    refreshToken: string,
    profile: GoogleProfileLike,
  ): GoogleProfilePayload {
    return { ...mapGoogleProfile(profile), accessToken, refreshToken };
  }
}
