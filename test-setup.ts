if (!process.env.JWT_SECRET)
  process.env.JWT_SECRET = 'test-jwt-secret-minimum-length-32chars';
if (!process.env.REFRESH_TOKEN_SECRET)
  process.env.REFRESH_TOKEN_SECRET = 'test-refresh-secret-minimum-len-32!!';
if (!process.env.DATABASE_URL)
  process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test_db';
if (!process.env.CORS_ORIGIN) process.env.CORS_ORIGIN = 'http://localhost:3000';
// Google/FRONTEND_URL/SMTP: fake values for unit and mocked-repository e2e tests (no network to Google).
if (!process.env.GOOGLE_CLIENT_ID)
  process.env.GOOGLE_CLIENT_ID = 'test-google-client-id';
if (!process.env.GOOGLE_CLIENT_SECRET)
  process.env.GOOGLE_CLIENT_SECRET = 'test-google-client-secret';
if (!process.env.GOOGLE_CALLBACK_URL)
  process.env.GOOGLE_CALLBACK_URL =
    'http://localhost:5000/api/auth/google/callback';
if (!process.env.FRONTEND_URL)
  process.env.FRONTEND_URL = 'http://localhost:3000';
if (!process.env.BCRYPT_ROUNDS) process.env.BCRYPT_ROUNDS = '4';
