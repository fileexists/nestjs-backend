import { envValidationSchema } from './env.validation';

const BASE = {
  JWT_SECRET: 'x'.repeat(32),
  REFRESH_TOKEN_SECRET: 'y'.repeat(32),
  DATABASE_URL: 'postgresql://u:p@localhost:5432/db',
};

const validate = (
  env: Record<string, unknown>,
): { value: Record<string, unknown>; error?: Error } =>
  envValidationSchema.validate({ ...BASE, ...env }, { allowUnknown: true });

describe('environment validation', () => {
  it('in production rejects the placeholder secrets from .env.sample', () => {
    const production = {
      NODE_ENV: 'production',
      SMTP_HOST: 'smtp.example.com',
      FRONTEND_URL: 'https://app.example.com',
      CORS_ORIGIN: 'https://app.example.com',
    };
    expect(
      validate({
        ...production,
        JWT_SECRET: 'change-me-to-a-long-random-string',
      }).error?.message,
    ).toMatch(/placeholder/);
    expect(validate(production).error).toBeUndefined();
  });

  it('rejects the same secret for access and refresh tokens', () => {
    const { error } = validate({ REFRESH_TOKEN_SECRET: BASE.JWT_SECRET });
    expect(error?.message).toMatch(/must be different/);
  });

  it('applies the safe defaults', () => {
    const { value, error } = validate({});
    expect(error).toBeUndefined();
    expect(value).toMatchObject({
      BCRYPT_ROUNDS: 12,
      FRONTEND_URL: 'http://localhost:3000',
      SMTP_HOST: 'localhost',
      SMTP_PORT: 1025,
      EMAIL_VERIFICATION_TTL: '24h',
      PASSWORD_RESET_TTL: '1h',
      REFRESH_REUSE_GRACE_SECONDS: 10,
      LOGIN_MAX_FAILED_ATTEMPTS: 5,
      LOGIN_LOCK_BASE_SECONDS: 60,
      LOGIN_LOCK_MAX_SECONDS: 900,
      DB_MIGRATIONS_RUN: false,
    });
  });

  describe('BCRYPT_ROUNDS (D6)', () => {
    it.each([4, 10, 12, 15])('accepts %i', (rounds) => {
      expect(validate({ BCRYPT_ROUNDS: rounds }).error).toBeUndefined();
    });
    it.each([3, 16, 'abc', 1.5])('rejects %j', (rounds) => {
      expect(validate({ BCRYPT_ROUNDS: rounds }).error).toBeDefined();
    });
    it('in production does not go below 10', () => {
      const prod = {
        NODE_ENV: 'production',
        SMTP_HOST: 'smtp.example.com',
        FRONTEND_URL: 'https://app.example.com',
        CORS_ORIGIN: 'https://app.example.com',
      };
      expect(validate({ ...prod, BCRYPT_ROUNDS: 8 }).error?.message).toMatch(
        /at least 10/,
      );
      expect(validate({ ...prod, BCRYPT_ROUNDS: 10 }).error).toBeUndefined();
    });
  });

  describe('FRONTEND_URL (C1)', () => {
    it('accepts a whitelist of origins', () => {
      expect(
        validate({
          FRONTEND_URL: 'https://a.example.com,https://b.example.com',
        }).error,
      ).toBeUndefined();
    });
    it.each([
      'javascript:alert(1)',
      'https://a.example.com/path',
      'not a url',
      'https://u:p@a.example.com',
    ])('rejects %j', (url) => {
      expect(validate({ FRONTEND_URL: url }).error).toBeDefined();
    });
    it('in production requires https', () => {
      const prod = {
        NODE_ENV: 'production',
        SMTP_HOST: 'smtp.example.com',
        CORS_ORIGIN: 'https://app.example.com',
      };
      expect(
        validate({ ...prod, FRONTEND_URL: 'http://app.example.com' }).error
          ?.message,
      ).toMatch(/https/);
      expect(
        validate({ ...prod, FRONTEND_URL: 'https://app.example.com' }).error,
      ).toBeUndefined();
    });
    it('in production the default (localhost over http) cannot be used', () => {
      expect(
        validate({
          NODE_ENV: 'production',
          SMTP_HOST: 'smtp.example.com',
          CORS_ORIGIN: 'https://app.example.com',
        }).error?.message,
      ).toMatch(/FRONTEND_URL must use https/);
    });
  });

  describe('CORS_ORIGIN', () => {
    const prod = {
      NODE_ENV: 'production',
      SMTP_HOST: 'smtp.example.com',
      FRONTEND_URL: 'https://app.example.com',
    };

    it('keeps the permissive default (*) outside production', () => {
      const { value, error } = validate({});
      expect(error).toBeUndefined();
      expect(value.CORS_ORIGIN).toBe('*');
    });

    it('is required in production', () => {
      expect(validate(prod).error?.message).toMatch(/CORS_ORIGIN/);
    });

    it.each(['*', 'https://app.example.com,*', ' * '])(
      'is never %j in production',
      (value) => {
        expect(
          validate({ ...prod, CORS_ORIGIN: value }).error?.message,
        ).toMatch(/CORS_ORIGIN must list the https origin/);
      },
    );

    it.each([
      'http://app.example.com',
      'https://app.example.com,http://admin.example.com',
    ])('only accepts https origins in production: rejects %j', (value) => {
      expect(validate({ ...prod, CORS_ORIGIN: value }).error?.message).toMatch(
        /CORS_ORIGIN must use https/,
      );
    });

    it.each([
      'https://app.example.com/path',
      'https://u:p@app.example.com',
      'not a url',
    ])('rejects a malformed origin in production: %j', (value) => {
      expect(validate({ ...prod, CORS_ORIGIN: value }).error?.message).toMatch(
        /CORS_ORIGIN/,
      );
    });

    it('accepts one or more https origins in production', () => {
      expect(
        validate({ ...prod, CORS_ORIGIN: 'https://app.example.com' }).error,
      ).toBeUndefined();
      expect(
        validate({
          ...prod,
          CORS_ORIGIN: 'https://app.example.com, https://admin.example.com',
        }).error,
      ).toBeUndefined();
    });

    it('is not checked outside production (any value, including http)', () => {
      expect(
        validate({ CORS_ORIGIN: 'http://localhost:3000,http://localhost:4000' })
          .error,
      ).toBeUndefined();
    });
  });

  describe('SWAGGER_ENABLED', () => {
    it('is off by default', () => {
      expect(validate({}).value.SWAGGER_ENABLED).toBe(false);
    });
    it.each([
      ['true', true],
      ['false', false],
    ])('reads %j', (raw, expected) => {
      expect(validate({ SWAGGER_ENABLED: raw }).value.SWAGGER_ENABLED).toBe(
        expected,
      );
    });
    it('rejects anything that is not a boolean', () => {
      expect(validate({ SWAGGER_ENABLED: 'maybe' }).error).toBeDefined();
    });
  });

  describe('TRUST_PROXY', () => {
    it('defaults to 1 hop', () => {
      expect(validate({}).value.TRUST_PROXY).toBe(1);
    });
    it.each([0, 1, 2, '3'])('accepts %j hops (0 = no proxy)', (hops) => {
      expect(validate({ TRUST_PROXY: hops }).error).toBeUndefined();
    });
    it.each([-1, 1.5, 'yes', 'true'])('rejects %j', (hops) => {
      expect(validate({ TRUST_PROXY: hops }).error).toBeDefined();
    });
  });

  describe('SMTP', () => {
    it('SMTP_HOST is required in production', () => {
      const prod = {
        NODE_ENV: 'production',
        FRONTEND_URL: 'https://app.example.com',
        CORS_ORIGIN: 'https://app.example.com',
      };
      expect(validate(prod).error).toBeDefined();
      expect(
        validate({ ...prod, SMTP_HOST: 'smtp.example.com' }).error,
      ).toBeUndefined();
    });
    it('the port must be valid', () => {
      expect(validate({ SMTP_PORT: 70000 }).error).toBeDefined();
      expect(validate({ SMTP_PORT: 587 }).error).toBeUndefined();
    });
    it('the password reset link duration has a valid format', () => {
      expect(validate({ PASSWORD_RESET_TTL: '30m' }).error).toBeUndefined();
      expect(validate({ PASSWORD_RESET_TTL: 'presto' }).error).toBeDefined();
    });
    it('the verification link duration has a valid format', () => {
      expect(validate({ EMAIL_VERIFICATION_TTL: '2d' }).error).toBeUndefined();
      expect(
        validate({ EMAIL_VERIFICATION_TTL: 'forever' }).error,
      ).toBeDefined();
    });
  });

  it('secrets stay required and at least 16 characters long', () => {
    expect(
      envValidationSchema.validate(
        { ...BASE, JWT_SECRET: 'short' },
        { allowUnknown: true },
      ).error,
    ).toBeDefined();
    expect(
      envValidationSchema.validate(
        { ...BASE, DATABASE_URL: undefined },
        { allowUnknown: true },
      ).error,
    ).toBeDefined();
  });

  it('Google is optional (empty = disabled)', () => {
    expect(
      validate({
        GOOGLE_CLIENT_ID: '',
        GOOGLE_CLIENT_SECRET: '',
        GOOGLE_CALLBACK_URL: '',
      }).error,
    ).toBeUndefined();
  });
});
