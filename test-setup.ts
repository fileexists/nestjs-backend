if (!process.env.JWT_SECRET) process.env.JWT_SECRET = 'test-jwt-secret-minimum-length-32chars';
if (!process.env.REFRESH_TOKEN_SECRET) process.env.REFRESH_TOKEN_SECRET = 'test-refresh-secret-minimum-len-32!!';
if (!process.env.DATABASE_URL) process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test_db';
if (!process.env.CORS_ORIGIN) process.env.CORS_ORIGIN = 'http://localhost:3000';
