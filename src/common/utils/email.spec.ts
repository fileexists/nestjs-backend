import { normalizeEmail } from './email';

describe('normalizeEmail', () => {
  it.each([
    ['Mario.Rossi@Example.com', 'mario.rossi@example.com'],
    ['  mario@example.com  ', 'mario@example.com'],
    ['\tMARIO@EXAMPLE.COM\n', 'mario@example.com'],
    ['user+Tag@Example.Org', 'user+tag@example.org'],
    ['già@Esempio.IT', 'già@esempio.it'],
  ])('%j -> %j', (input, expected) => {
    expect(normalizeEmail(input)).toBe(expected);
  });

  it('e idempotente', () => {
    const once = normalizeEmail('  A@B.com ');
    expect(normalizeEmail(once)).toBe(once);
  });

  it('non tocca l interno dell indirizzo (nessun alias, niente punti rimossi)', () => {
    expect(normalizeEmail('first.last+news@gmail.com')).toBe(
      'first.last+news@gmail.com',
    );
  });
});
