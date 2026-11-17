import { ConfigService } from '@nestjs/config';
import passport from 'passport';
import { GoogleAuthException } from '../google-auth.exception';
import { GoogleStrategy, isGoogleConfigured } from './google.strategy';

const config = (values: Record<string, string | undefined>) =>
  ({
    get: (key: string) => values[key],
    getOrThrow: (key: string) => {
      if (!values[key]) throw new Error(`missing ${key}`);
      return values[key];
    },
  }) as unknown as ConfigService;

const FULL = {
  GOOGLE_CLIENT_ID: 'client-id',
  GOOGLE_CLIENT_SECRET: 'client-secret',
  GOOGLE_CALLBACK_URL: 'http://localhost:5000/api/auth/google/callback',
};

describe('isGoogleConfigured (C2)', () => {
  it('true solo con tutte e tre le variabili valorizzate', () => {
    expect(isGoogleConfigured(config(FULL))).toBe(true);
  });

  it.each(['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'GOOGLE_CALLBACK_URL'])(
    'false se manca %s',
    (key) => {
      expect(isGoogleConfigured(config({ ...FULL, [key]: undefined }))).toBe(
        false,
      );
    },
  );

  it.each(['', '   '])(
    'false per valori vuoti o di soli spazi (%j)',
    (blank) => {
      expect(
        isGoogleConfigured(config({ ...FULL, GOOGLE_CLIENT_ID: blank })),
      ).toBe(false);
    },
  );
});

describe('GoogleStrategy (C2)', () => {
  it('non accetta credenziali mancanti: niente placeholder-client-id', () => {
    expect(() => new GoogleStrategy(config({}))).toThrow(
      /missing GOOGLE_CLIENT_ID/,
    );
  });

  describe('con credenziali', () => {
    let strategy: GoogleStrategy;
    beforeAll(() => {
      strategy = new GoogleStrategy(config(FULL));
    });
    afterAll(() => {
      (passport as unknown as { unuse(name: string): void }).unuse('google');
    });

    it('chiede solo scope email e profile', () => {
      const scope = (strategy as unknown as { _scope: string[] })._scope;
      expect([...scope].sort()).toEqual(['email', 'profile']);
    });

    it('validate ritorna googleId, email e nome SENZA i token di Google', () => {
      const result = strategy.validate(
        'google-access-token',
        'google-refresh-token',
        {
          id: 'g-1',
          displayName: 'Mario',
          emails: [{ value: 'Mario@Example.com', verified: true }],
        },
      );

      expect(result).toEqual({
        googleId: 'g-1',
        email: 'mario@example.com',
        name: 'Mario',
      });
      expect(JSON.stringify(result)).not.toContain('google-access-token');
      expect(JSON.stringify(result)).not.toContain('google-refresh-token');
      expect(Object.keys(result)).not.toEqual(
        expect.arrayContaining(['accessToken', 'refreshToken']),
      );
    });

    it("validate rifiuta con 401 un'email non verificata", () => {
      expect(() =>
        strategy.validate('a', 'r', {
          id: 'g-1',
          emails: [{ value: 'x@example.com', verified: false }],
        }),
      ).toThrow(GoogleAuthException);
    });
  });
});
