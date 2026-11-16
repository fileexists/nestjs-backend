/**
 * Eseguito da Jest prima di ogni file di test e2e su database vero
 * (`setupFiles` in test/jest-e2e-db.json), cioè PRIMA che AppModule venga importato.
 *
 * Imposta un ambiente completamente isolato: il .env di sviluppo non viene letto
 * (AppModule usa `ignoreEnvFile` quando NODE_ENV=test) e il database è quello
 * di test (default: container `postgres-test` del docker-compose, porta 5433).
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
