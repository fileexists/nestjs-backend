import * as Joi from 'joi';
import { DURATION_PATTERN } from '../common/utils/duration';
import { parseFrontendUrls, parseOrigins } from '../common/utils/frontend-url';

/**
 * Validation of the environment variables (used by ConfigModule in AppModule).
 * Kept apart from the module so it can be tested in isolation.
 */
export const envValidationSchema = Joi.object({
  NODE_ENV: Joi.string()
    .valid('development', 'production', 'test')
    .default('development'),
  PORT: Joi.number().default(3000),
  JWT_SECRET: Joi.string().min(16).required(),
  REFRESH_TOKEN_SECRET: Joi.string().min(16).required(),
  JWT_EXPIRATION: Joi.string().default('15m'),
  // bcrypt cost. At least 10 in production (see the check further down).
  BCRYPT_ROUNDS: Joi.number().integer().min(4).max(15).default(12),
  // Progressive per-account lock after failed login attempts.
  LOGIN_MAX_FAILED_ATTEMPTS: Joi.number().integer().min(1).default(5),
  LOGIN_LOCK_BASE_SECONDS: Joi.number().integer().min(1).default(60),
  LOGIN_LOCK_MAX_SECONDS: Joi.number().integer().min(1).default(900),
  LOGIN_ATTEMPT_WINDOW_SECONDS: Joi.number().integer().min(1).default(1800),
  REFRESH_TOKEN_EXPIRATION: Joi.string().default('7d'),
  // Within this many seconds of the rotation, a second use of the same refresh token (two
  // tabs, parallel requests) is only rejected; after that, it is treated as theft.
  REFRESH_REUSE_GRACE_SECONDS: Joi.number()
    .integer()
    .min(0)
    .max(60)
    .default(10),
  DATABASE_URL: Joi.string().required(),
  // Apply the migrations at startup (default: no, run them with `yarn migration:run`).
  DB_MIGRATIONS_RUN: Joi.boolean().default(false),
  // Origins allowed by CORS (comma-separated). Development: `*` by default. Production: required,
  // https origins only, never `*` (checked below).
  CORS_ORIGIN: Joi.string().when('NODE_ENV', {
    is: 'production',
    then: Joi.required(),
    otherwise: Joi.string().default('*'),
  }),
  // The API docs (/docs) are on outside production; in production only with SWAGGER_ENABLED=true.
  SWAGGER_ENABLED: Joi.boolean().default(false),
  // Proxies in front of the app whose X-Forwarded-For is trusted (number of hops). 0 = none.
  TRUST_PROXY: Joi.number().integer().min(0).default(1),
  // Email (SMTP). In development: Mailpit (localhost:1025, or mailpit:1025 inside compose).
  SMTP_HOST: Joi.string().when('NODE_ENV', {
    is: 'production',
    then: Joi.required(),
    otherwise: Joi.string().default('localhost'),
  }),
  SMTP_PORT: Joi.number().port().default(1025),
  SMTP_SECURE: Joi.boolean().default(false),
  SMTP_USER: Joi.string().optional().allow(''),
  SMTP_PASS: Joi.string().optional().allow(''),
  MAIL_FROM: Joi.string().default('Auth <no-reply@localhost>'),
  EMAIL_VERIFICATION_TTL: Joi.string().pattern(DURATION_PATTERN).default('24h'),
  // How long the password reset link lasts.
  PASSWORD_RESET_TTL: Joi.string().pattern(DURATION_PATTERN).default('1h'),
  // Whitelist (comma-separated) of the frontend origins: links in
  // emails and redirects are built ONLY from here. The first one is the default.
  FRONTEND_URL: Joi.string()
    .custom((value: string) => {
      parseFrontendUrls(value);
      return value;
    })
    .default('http://localhost:3000'),
  GOOGLE_CLIENT_ID: Joi.string().optional().allow(''),
  GOOGLE_CLIENT_SECRET: Joi.string().optional().allow(''),
  GOOGLE_CALLBACK_URL: Joi.string().optional().allow(''),
}).custom(
  (env: {
    NODE_ENV?: string;
    FRONTEND_URL?: string;
    CORS_ORIGIN?: string;
    BCRYPT_ROUNDS?: number;
    JWT_SECRET?: string;
    REFRESH_TOKEN_SECRET?: string;
  }) => {
    // With the same secret a refresh token (7 days) would work as an access token.
    if (env.JWT_SECRET === env.REFRESH_TOKEN_SECRET) {
      throw new Error('JWT_SECRET and REFRESH_TOKEN_SECRET must be different');
    }
    if (env.NODE_ENV === 'production') {
      // The placeholders in .env.sample are not secrets.
      for (const secret of [env.JWT_SECRET, env.REFRESH_TOKEN_SECRET]) {
        if (/change-me/i.test(secret ?? '')) {
          throw new Error('Replace the placeholder secrets from .env.sample');
        }
      }
      // In production the frontend is always explicit and https only...
      parseFrontendUrls(env.FRONTEND_URL ?? '', { requireHttps: true });
      // ...and so is CORS: explicit https origins, never `*` (cookies travel with the requests).
      const cors = env.CORS_ORIGIN ?? '';
      if (cors.split(',').some((origin) => origin.trim() === '*')) {
        throw new Error(
          "CORS_ORIGIN must list the https origin(s) of the frontend in production, not '*'",
        );
      }
      parseOrigins(cors, { name: 'CORS_ORIGIN', requireHttps: true });
      // ...and the bcrypt cost cannot be lowered below 10.
      if ((env.BCRYPT_ROUNDS ?? 12) < 10) {
        throw new Error('BCRYPT_ROUNDS must be at least 10 in production');
      }
    }
    return env;
  },
);
