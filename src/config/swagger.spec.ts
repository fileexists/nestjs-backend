import { isSwaggerEnabled } from './swagger';

describe('isSwaggerEnabled', () => {
  it.each(['development', 'test', undefined])(
    'is on outside production (%s), whatever SWAGGER_ENABLED says',
    (env) => {
      expect(isSwaggerEnabled(env, undefined)).toBe(true);
      expect(isSwaggerEnabled(env, false)).toBe(true);
    },
  );

  it('is off in production by default', () => {
    expect(isSwaggerEnabled('production', undefined)).toBe(false);
    expect(isSwaggerEnabled('production', false)).toBe(false);
    expect(isSwaggerEnabled('production', 'false')).toBe(false);
  });

  it('is on in production only with SWAGGER_ENABLED=true', () => {
    expect(isSwaggerEnabled('production', true)).toBe(true);
    expect(isSwaggerEnabled('production', 'true')).toBe(true);
  });
});
