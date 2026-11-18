import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-google-oauth20';
import { GoogleProfilePayload } from '../../../common/interfaces/jwt-payload.interface';
import { GoogleProfileLike, mapGoogleProfile } from './google-profile';

/** Google login is only active if ALL THREE GOOGLE_* variables are set. */
export function isGoogleConfigured(configService: ConfigService): boolean {
  return [
    'GOOGLE_CLIENT_ID',
    'GOOGLE_CLIENT_SECRET',
    'GOOGLE_CALLBACK_URL',
  ].every((key) => !!configService.get<string>(key)?.trim());
}

/**
 * Registered by AuthModule only if Google is configured (see `isGoogleConfigured`):
 * no fake values like "placeholder-client-id".
 */
@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(configService: ConfigService) {
    super({
      clientID: configService.getOrThrow<string>('GOOGLE_CLIENT_ID'),
      clientSecret: configService.getOrThrow<string>('GOOGLE_CLIENT_SECRET'),
      callbackURL: configService.getOrThrow<string>('GOOGLE_CALLBACK_URL'),
      scope: ['email', 'profile'],
    });
  }

  // Returns the payload (Nest calls `done` for us). Google's tokens are not needed
  // and are not propagated; throws 401 if the email is missing or not verified.
  validate(
    _accessToken: string,
    _refreshToken: string,
    profile: GoogleProfileLike,
  ): GoogleProfilePayload {
    return mapGoogleProfile(profile);
  }
}
