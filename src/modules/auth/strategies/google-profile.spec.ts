import { UnauthorizedException } from '@nestjs/common';
import { mapGoogleProfile } from './google-profile';

describe('mapGoogleProfile (A1: solo email verificate da Google)', () => {
  const base = { id: 'g-1', displayName: 'Mario' };

  it('accetta un profilo con email verificata', () => {
    expect(
      mapGoogleProfile({
        ...base,
        emails: [{ value: 'mario@example.com', verified: true }],
      }),
    ).toEqual({ googleId: 'g-1', email: 'mario@example.com', name: 'Mario' });
  });

  it('accetta email_verified espresso come stringa "true" (formati legacy)', () => {
    expect(
      mapGoogleProfile({
        ...base,
        emails: [{ value: 'a@example.com', verified: 'true' }],
      }).email,
    ).toBe('a@example.com');
  });

  it('usa _json.email_verified quando il flag non e nell elenco emails', () => {
    expect(
      mapGoogleProfile({
        ...base,
        emails: [{ value: 'a@example.com' }],
        _json: { email_verified: true },
      }).email,
    ).toBe('a@example.com');
  });

  it('rifiuta con 401 un profilo senza email, con messaggio chiaro', () => {
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
    ['flag assente', [{ value: 'a@example.com' }], undefined],
    [
      '"false" come stringa',
      [{ value: 'a@example.com', verified: 'false' }],
      undefined,
    ],
    [
      'esplicito false vince su _json true',
      [{ value: 'a@example.com', verified: false }],
      { email_verified: true },
    ],
  ])(
    "rifiuta con 401 un'email non verificata (%s)",
    (_label, emails, _json) => {
      let error: unknown;
      try {
        mapGoogleProfile({ ...base, emails, _json });
      } catch (e) {
        error = e;
      }
      expect(error).toBeInstanceOf(UnauthorizedException);
      expect((error as UnauthorizedException).getStatus()).toBe(401);
      expect((error as UnauthorizedException).message).toMatch(/not verified/i);
    },
  );

  it('rifiuta un profilo senza id Google', () => {
    expect(() =>
      mapGoogleProfile({
        emails: [{ value: 'a@example.com', verified: true }],
      }),
    ).toThrow(UnauthorizedException);
  });
});
