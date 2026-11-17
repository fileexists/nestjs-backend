import { isUniqueViolation } from './db-errors';

describe('isUniqueViolation (D4)', () => {
  it("riconosce il codice 23505 sull'errore (TypeORM QueryFailedError)", () => {
    expect(isUniqueViolation({ code: '23505' })).toBe(true);
  });

  it('riconosce il codice nel driverError', () => {
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
  ])('ignora %j', (error) => {
    expect(isUniqueViolation(error)).toBe(false);
  });
});
