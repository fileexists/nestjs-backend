import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-google-oauth20';
import { GoogleProfilePayload } from '../../../common/interfaces/jwt-payload.interface';
import { GoogleProfileLike, mapGoogleProfile } from './google-profile';

/** Il login con Google e' attivo solo se TUTTE e tre le variabili GOOGLE_* sono valorizzate. */
export function isGoogleConfigured(configService: ConfigService): boolean {
  return [
    'GOOGLE_CLIENT_ID',
    'GOOGLE_CLIENT_SECRET',
    'GOOGLE_CALLBACK_URL',
  ].every((key) => !!configService.get<string>(key)?.trim());
}

/**
 * Registrata da AuthModule solo se Google e' configurato (vedi `isGoogleConfigured`):
 * nessun valore finto tipo "placeholder-client-id".
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

  // Ritorna il payload (Nest chiama `done` per noi). I token di Google non servono
  // e non vengono propagati; lancia 401 se l'email manca o non e' verificata.
  validate(
    _accessToken: string,
    _refreshToken: string,
    profile: GoogleProfileLike,
  ): GoogleProfilePayload {
    return mapGoogleProfile(profile);
  }
}
