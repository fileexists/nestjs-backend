import { resolveCorsOrigins } from './cors';

describe('resolveCorsOrigins', () => {
  describe('development', () => {
    it('keeps the permissive default', () => {
      expect(resolveCorsOrigins(undefined, false)).toBe('*');
      expect(resolveCorsOrigins('*', false)).toBe('*');
    });

    it('returns a single origin as a string and several as a list, as written', () => {
      expect(resolveCorsOrigins('http://localhost:3000', false)).toBe(
        'http://localhost:3000',
      );
      expect(
        resolveCorsOrigins(
          'http://localhost:3000, http://localhost:4000',
          false,
        ),
      ).toEqual(['http://localhost:3000', 'http://localhost:4000']);
    });
  });

  describe('production', () => {
    it('returns the canonical origin, so it matches the browser Origin header', () => {
      expect(resolveCorsOrigins('https://app.example.com/', true)).toBe(
        'https://app.example.com',
      );
    });

    it('returns several origins as a list', () => {
      expect(
        resolveCorsOrigins(
          'https://a.example.com, https://b.example.com',
          true,
        ),
      ).toEqual(['https://a.example.com', 'https://b.example.com']);
    });

    it.each([undefined, '', '*', 'http://app.example.com'])(
      'refuses %j',
      (value) => {
        expect(() => resolveCorsOrigins(value, true)).toThrow(/CORS_ORIGIN/);
      },
    );
  });
});
