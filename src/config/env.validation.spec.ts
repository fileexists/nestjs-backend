import { envValidationSchema } from './env.validation';

const BASE = {
  JWT_SECRET: 'x'.repeat(32),
  REFRESH_TOKEN_SECRET: 'y'.repeat(32),
  DATABASE_URL: 'postgresql://u:p@localhost:5432/db',
};

const validate = (env: Record<string, unknown>) =>
  envValidationSchema.validate({ ...BASE, ...env }, { allowUnknown: true });

describe('validazione ambiente', () => {
  it('applica i default sicuri', () => {
    const { value, error } = validate({});
    expect(error).toBeUndefined();
    expect(value).toMatchObject({
      BCRYPT_ROUNDS: 12,
      FRONTEND_URL: 'http://localhost:3000',
      SMTP_HOST: 'localhost',
      SMTP_PORT: 1025,
      EMAIL_VERIFICATION_TTL: '24h',
      REFRESH_REUSE_GRACE_SECONDS: 0,
      LOGIN_MAX_FAILED_ATTEMPTS: 5,
      LOGIN_LOCK_BASE_SECONDS: 60,
      LOGIN_LOCK_MAX_SECONDS: 900,
      DB_MIGRATIONS_RUN: false,
    });
  });

  describe('BCRYPT_ROUNDS (D6)', () => {
    it.each([4, 10, 12, 15])('accetta %i', (rounds) => {
      expect(validate({ BCRYPT_ROUNDS: rounds }).error).toBeUndefined();
    });
    it.each([3, 16, 'abc', 1.5])('rifiuta %j', (rounds) => {
      expect(validate({ BCRYPT_ROUNDS: rounds }).error).toBeDefined();
    });
    it('in produzione non scende sotto 10', () => {
      const prod = {
        NODE_ENV: 'production',
        SMTP_HOST: 'smtp.example.com',
        FRONTEND_URL: 'https://app.example.com',
      };
      expect(validate({ ...prod, BCRYPT_ROUNDS: 8 }).error?.message).toMatch(
        /at least 10/,
      );
      expect(validate({ ...prod, BCRYPT_ROUNDS: 10 }).error).toBeUndefined();
    });
  });

  describe('FRONTEND_URL (C1)', () => {
    it('accetta una whitelist di origini', () => {
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
    ])('rifiuta %j', (url) => {
      expect(validate({ FRONTEND_URL: url }).error).toBeDefined();
    });
    it('in produzione richiede https', () => {
      const prod = { NODE_ENV: 'production', SMTP_HOST: 'smtp.example.com' };
      expect(
        validate({ ...prod, FRONTEND_URL: 'http://app.example.com' }).error
          ?.message,
      ).toMatch(/https/);
      expect(
        validate({ ...prod, FRONTEND_URL: 'https://app.example.com' }).error,
      ).toBeUndefined();
    });
    it('in produzione non si puo usare il default (localhost in http)', () => {
      expect(
        validate({ NODE_ENV: 'production', SMTP_HOST: 'smtp.example.com' })
          .error,
      ).toBeDefined();
    });
  });

  describe('SMTP', () => {
    it('SMTP_HOST e obbligatorio in produzione', () => {
      const prod = {
        NODE_ENV: 'production',
        FRONTEND_URL: 'https://app.example.com',
      };
      expect(validate(prod).error).toBeDefined();
      expect(
        validate({ ...prod, SMTP_HOST: 'smtp.example.com' }).error,
      ).toBeUndefined();
    });
    it('la porta deve essere valida', () => {
      expect(validate({ SMTP_PORT: 70000 }).error).toBeDefined();
      expect(validate({ SMTP_PORT: 587 }).error).toBeUndefined();
    });
    it('la durata del link di verifica ha un formato valido', () => {
      expect(validate({ EMAIL_VERIFICATION_TTL: '2d' }).error).toBeUndefined();
      expect(validate({ EMAIL_VERIFICATION_TTL: 'tanto' }).error).toBeDefined();
    });
  });

  it('i segreti restano obbligatori e lunghi almeno 16 caratteri', () => {
    expect(
      envValidationSchema.validate(
        { ...BASE, JWT_SECRET: 'corto' },
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

  it('Google e opzionale (vuoto = disattivato)', () => {
    expect(
      validate({
        GOOGLE_CLIENT_ID: '',
        GOOGLE_CLIENT_SECRET: '',
        GOOGLE_CALLBACK_URL: '',
      }).error,
    ).toBeUndefined();
  });
});
