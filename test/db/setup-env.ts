/**
 * Run by Jest before every e2e test file on a real database
 * (`setupFiles` in test/jest-e2e-db.json), i.e. BEFORE AppModule is imported.
 *
 * It sets up a fully isolated environment: the development .env is not read
 * (AppModule uses `ignoreEnvFile` when NODE_ENV=test) and the database is the test one
 * (default: the `postgres-test` container of docker-compose, port 5433).
 */
process.env.NODE_ENV = 'test';
process.env.DATABASE_URL =
  process.env.E2E_DATABASE_URL ??
  'postgresql://nestjs:nestjs_secret@localhost:5433/nestjs_e2e';
process.env.JWT_SECRET = 'e2e-jwt-secret-minimum-length-32-chars!!';
process.env.REFRESH_TOKEN_SECRET = 'e2e-refresh-secret-minimum-length-32!!';
process.env.JWT_EXPIRATION = '15m';
process.env.REFRESH_TOKEN_EXPIRATION = '7d';
process.env.CORS_ORIGIN = 'http://localhost:3000';
process.env.FRONTEND_URL = 'http://localhost:3000';
process.env.BCRYPT_ROUNDS = '4';
// No tolerance: the refresh token reuse tests expect immediate revocation.
process.env.REFRESH_REUSE_GRACE_SECONDS = '0';
// Google: fake credentials. The network to Google is always stubbed (support/google.ts).
process.env.GOOGLE_CLIENT_ID = 'e2e-google-client-id';
process.env.GOOGLE_CLIENT_SECRET = 'e2e-google-client-secret';
process.env.GOOGLE_CALLBACK_URL =
  'http://localhost:5000/api/auth/google/callback';
// SMTP: in the e2e tests emails go to an in-memory outbox; only smtp.e2e-spec.ts uses a real SMTP (Mailpit).
process.env.SMTP_HOST = process.env.E2E_SMTP_HOST ?? 'localhost';
process.env.SMTP_PORT = process.env.E2E_SMTP_PORT ?? '1025';
process.env.MAIL_FROM = 'E2E <no-reply@e2e.local>';
