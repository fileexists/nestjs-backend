import { UnauthorizedException } from '@nestjs/common';

/** Parte del profilo Passport (passport-google-oauth20, formato OpenID) che ci serve. */
export interface GoogleProfileLike {
  id?: string;
  displayName?: string;
  emails?: { value?: string; verified?: boolean | string }[];
  _json?: { email_verified?: boolean | string };
}

export interface MappedGoogleProfile {
  googleId: string;
  email: string;
  name?: string;
}

const isTrue = (value: unknown): boolean => value === true || value === 'true';

/**
 * Accetta solo profili con email PRESENTE e VERIFICATA da Google
 * (`email_verified === true`): un'email non verificata non prova nulla sul
 * proprietario e non deve mai essere collegata a un account esistente.
 */
export function mapGoogleProfile(
  profile: GoogleProfileLike,
): MappedGoogleProfile {
  if (!profile.id) {
    throw new UnauthorizedException('Google profile has no account id.');
  }
  const entry = profile.emails?.find((e) => !!e.value);
  if (!entry?.value) {
    throw new UnauthorizedException('Google account has no email address.');
  }
  const verified = entry.verified ?? profile._json?.email_verified;
  if (!isTrue(verified)) {
    throw new UnauthorizedException(
      'The email address of this Google account is not verified.',
    );
  }
  return {
    googleId: profile.id,
    email: entry.value,
    name: profile.displayName,
  };
}
