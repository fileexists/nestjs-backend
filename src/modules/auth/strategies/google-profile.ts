import { GoogleAuthException } from '../google-auth.exception';
import { normalizeEmail } from '../../../common/utils/email';

/** The part of the Passport profile (passport-google-oauth20, OpenID format) that we need. */
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
 * Only accepts profiles with an email that is PRESENT and VERIFIED by Google
 * (`email_verified === true`): an unverified email proves nothing about the
 * owner and must never be linked to an existing account.
 */
export function mapGoogleProfile(
  profile: GoogleProfileLike,
): MappedGoogleProfile {
  if (!profile.id) {
    throw new GoogleAuthException(
      'failed',
      'Google profile has no account id.',
    );
  }
  const entry = profile.emails?.find((e) => !!e.value);
  if (!entry?.value) {
    throw new GoogleAuthException(
      'email_missing',
      'Google account has no email address.',
    );
  }
  const verified = entry.verified ?? profile._json?.email_verified;
  if (!isTrue(verified)) {
    throw new GoogleAuthException(
      'email_unverified',
      'The email address of this Google account is not verified.',
    );
  }
  return {
    googleId: profile.id,
    email: normalizeEmail(entry.value),
    name: profile.displayName,
  };
}
