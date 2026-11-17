import * as Joi from 'joi';
import { DURATION_PATTERN } from '../common/utils/duration';
import { parseFrontendUrls } from '../common/utils/frontend-url';

/**
 * Validazione delle variabili d'ambiente (usata da ConfigModule in AppModule).
 * Separata dal modulo per poterla testare in isolamento.
 */
export const envValidationSchema = Joi.object({
  NODE_ENV: Joi.string()
    .valid('development', 'production', 'test')
    .default('development'),
  PORT: Joi.number().default(3000),
  JWT_SECRET: Joi.string().min(16).required(),
  REFRESH_TOKEN_SECRET: Joi.string().min(16).required(),
  JWT_EXPIRATION: Joi.string().default('15m'),
  // Costo bcrypt. In produzione almeno 10 (vedi controllo piu' sotto).
  BCRYPT_ROUNDS: Joi.number().integer().min(4).max(15).default(12),
  // Blocco progressivo per account dopo tentativi di login falliti.
  LOGIN_MAX_FAILED_ATTEMPTS: Joi.number().integer().min(1).default(5),
  LOGIN_LOCK_BASE_SECONDS: Joi.number().integer().min(1).default(60),
  LOGIN_LOCK_MAX_SECONDS: Joi.number().integer().min(1).default(900),
  LOGIN_ATTEMPT_WINDOW_SECONDS: Joi.number().integer().min(1).default(1800),
  REFRESH_TOKEN_EXPIRATION: Joi.string().default('7d'),
  // Entro questi secondi dalla rotazione, un secondo uso dello stesso refresh token (due
  // schede, richieste parallele) viene solo rifiutato; dopo, e' trattato come furto.
  REFRESH_REUSE_GRACE_SECONDS: Joi.number()
    .integer()
    .min(0)
    .max(60)
    .default(10),
  DATABASE_URL: Joi.string().required(),
  // Applica le migrazioni all'avvio (default: no, si lanciano con `yarn migration:run`).
  DB_MIGRATIONS_RUN: Joi.boolean().default(false),
  CORS_ORIGIN: Joi.string().default('*'),
  // Email (SMTP). In sviluppo: Mailpit (localhost:1025, oppure mailpit:1025 dentro compose).
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
  // Durata del link di reset password.
  PASSWORD_RESET_TTL: Joi.string().pattern(DURATION_PATTERN).default('1h'),
  // Whitelist (separata da virgole) delle origini del frontend: link nelle
  // email e redirect si costruiscono SOLO da qui. La prima e' quella predefinita.
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
    BCRYPT_ROUNDS?: number;
    JWT_SECRET?: string;
    REFRESH_TOKEN_SECRET?: string;
  }) => {
    // Con lo stesso segreto un refresh token (7 giorni) varrebbe come access token.
    if (env.JWT_SECRET === env.REFRESH_TOKEN_SECRET) {
      throw new Error('JWT_SECRET and REFRESH_TOKEN_SECRET must be different');
    }
    if (env.NODE_ENV === 'production') {
      // I segnaposto di .env.sample non sono segreti.
      for (const secret of [env.JWT_SECRET, env.REFRESH_TOKEN_SECRET]) {
        if (/change-me/i.test(secret ?? '')) {
          throw new Error('Replace the placeholder secrets from .env.sample');
        }
      }
      // In produzione il frontend e' sempre esplicito e solo https...
      parseFrontendUrls(env.FRONTEND_URL ?? '', { requireHttps: true });
      // ...e il costo bcrypt non puo' essere abbassato sotto 10.
      if ((env.BCRYPT_ROUNDS ?? 12) < 10) {
        throw new Error('BCRYPT_ROUNDS must be at least 10 in production');
      }
    }
    return env;
  },
);
