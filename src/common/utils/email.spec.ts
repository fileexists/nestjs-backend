import { normalizeEmail } from './email';

describe('normalizeEmail', () => {
  it.each([
    ['Mario.Rossi@Example.com', 'mario.rossi@example.com'],
    ['  mario@example.com  ', 'mario@example.com'],
    ['\tMARIO@EXAMPLE.COM\n', 'mario@example.com'],
    ['user+Tag@Example.Org', 'user+tag@example.org'],
    ['élan@Example.COM', 'élan@example.com'],
  ])('%j -> %j', (input, expected) => {
    expect(normalizeEmail(input)).toBe(expected);
  });

  it('is idempotent', () => {
    const once = normalizeEmail('  A@B.com ');
    expect(normalizeEmail(once)).toBe(once);
  });

  it('does not touch the inside of the address (no aliases, no dots removed)', () => {
    expect(normalizeEmail('first.last+news@gmail.com')).toBe(
      'first.last+news@gmail.com',
    );
  });
});
