import { parseDurationMs } from './duration';

describe('parseDurationMs', () => {
  it.each([
    ['500ms', 500],
    ['30s', 30_000],
    ['15m', 900_000],
    ['24h', 86_400_000],
    ['7d', 604_800_000],
    ['2w', 1_209_600_000],
  ])('converte %s in %i ms', (input, expected) => {
    expect(parseDurationMs(input)).toBe(expected);
  });

  it.each(['', 'abc', '15', 'm15', '1.5h', '-5m', '10 m'])(
    'ritorna 0 per il formato non valido "%s"',
    (input) => {
      expect(parseDurationMs(input)).toBe(0);
    },
  );
});
