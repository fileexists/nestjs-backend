import { isUniqueViolation } from './db-errors';

describe('isUniqueViolation (D4)', () => {
  it('recognizes code 23505 on the error (TypeORM QueryFailedError)', () => {
    expect(isUniqueViolation({ code: '23505' })).toBe(true);
  });

  it('recognizes the code in driverError', () => {
    expect(isUniqueViolation({ driverError: { code: '23505' } })).toBe(true);
  });

  it.each([
    { code: '23503' },
    { code: '42P01' },
    {},
    null,
    undefined,
    'error',
    new Error('x'),
  ])('ignores %j', (error) => {
    expect(isUniqueViolation(error)).toBe(false);
  });
});
