import { UnauthorizedException } from '@nestjs/common';
import { mapGoogleProfile } from './google-profile';

describe('mapGoogleProfile (A1: only emails verified by Google)', () => {
  const base = { id: 'g-1', displayName: 'Mario' };

  it('accepts a profile with a verified email', () => {
    expect(
      mapGoogleProfile({
        ...base,
        emails: [{ value: 'mario@example.com', verified: true }],
      }),
    ).toEqual({ googleId: 'g-1', email: 'mario@example.com', name: 'Mario' });
  });

  it('normalizes the email (lowercase, no spaces): Google may return it in uppercase', () => {
    expect(
      mapGoogleProfile({
        ...base,
        emails: [{ value: ' Mario.ROSSI@Example.com ', verified: true }],
      }).email,
    ).toBe('mario.rossi@example.com');
  });

  it('accepts email_verified expressed as the string "true" (legacy formats)', () => {
    expect(
      mapGoogleProfile({
        ...base,
        emails: [{ value: 'a@example.com', verified: 'true' }],
      }).email,
    ).toBe('a@example.com');
  });

  it('uses _json.email_verified when the flag is not in the emails list', () => {
    expect(
      mapGoogleProfile({
        ...base,
        emails: [{ value: 'a@example.com' }],
        _json: { email_verified: true },
      }).email,
    ).toBe('a@example.com');
  });

  it('rejects with 401 a profile without an email, with a clear message', () => {
    expect.assertions(3);
    for (const profile of [
      { ...base },
      { ...base, emails: [] },
      { ...base, emails: [{ value: '' }] },
    ]) {
      try {
        mapGoogleProfile(profile);
      } catch (error) {
        expect((error as UnauthorizedException).message).toMatch(/no email/i);
      }
    }
  });

  it.each([
    [
      'verified=false',
      [{ value: 'a@example.com', verified: false }],
      undefined,
    ],
    ['missing flag', [{ value: 'a@example.com' }], undefined],
    [
      '"false" as a string',
      [{ value: 'a@example.com', verified: 'false' }],
      undefined,
    ],
    [
      'explicit false wins over _json true',
      [{ value: 'a@example.com', verified: false }],
      { email_verified: true },
    ],
  ])('rejects with 401 an unverified email (%s)', (_label, emails, _json) => {
    let error: unknown;
    try {
      mapGoogleProfile({ ...base, emails, _json });
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(UnauthorizedException);
    expect((error as UnauthorizedException).getStatus()).toBe(401);
    expect((error as UnauthorizedException).message).toMatch(/not verified/i);
  });

  it('rejects a profile without a Google id', () => {
    expect(() =>
      mapGoogleProfile({
        emails: [{ value: 'a@example.com', verified: true }],
      }),
    ).toThrow(UnauthorizedException);
  });
});
