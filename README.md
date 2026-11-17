# NestJS Auth Backend

A production-ready authentication backend built with **NestJS 12**, **TypeORM**, and **PostgreSQL**.

## Features

- JWT authentication with **real refresh-token rotation** (one-time tokens, reuse detection, revocation on logout)
- Email verification, password reset, and uniform responses that don't reveal whether an account exists
- Per-account progressive login lockout (on top of the per-IP rate limit)
- Google OAuth2 via Passport.js (anti-CSRF `state`, verified email only, redirect to the frontend)
- Role-based access control (RBAC) with a flexible `@Permissions()` decorator
- PostgreSQL + TypeORM with migration support
- Helmet security headers, rate limiting, global validation
- Swagger/OpenAPI documentation
- Full unit and e2e test suite (Jest + Supertest)

---

## Stack

| Layer | Technology |
|-------|-----------|
| Framework | NestJS 12 |
| ORM | TypeORM 1.x |
| Database | PostgreSQL 17 |
| Auth | JWT + Passport (local + Google OAuth2) |
| Hashing | bcrypt (`BCRYPT_ROUNDS`, default 12, transparent re-hash) |
| Email | nodemailer (SMTP; Mailpit in development) |
| Validation | class-validator + class-transformer |
| Docs | Swagger / OpenAPI |
| Testing | Jest + Supertest |

---

## Project Structure

```
├── database/
│   ├── migrations/          # TypeORM migrations
│   └── seeds/               # Database seeders
├── docs/
│   └── PROGETTO.md          # design: Bearer API keys for the public widget (not implemented)
├── scripts/
│   └── test-api.sh          # cURL integration tests
├── src/
│   ├── common/
│   │   ├── decorators/      # @Public(), @Permissions()
│   │   ├── dto/             # Shared DTOs
│   │   ├── entities/        # TypeORM entities (User, Permission)
│   │   ├── filters/         # Global HTTP exception filter
│   │   └── guards/          # AuthGuard, PermissionsGuard, GoogleOAuthGuard
│   ├── config/              # environment validation (Joi)
│   ├── modules/
│   │   ├── mail/            # SMTP email (verification, reset, notices)
│   │   ├── auth/            # JWT + Google OAuth, AuthService, AuthController
│   │   │   └── strategies/  # GoogleStrategy
│   │   ├── permission/      # Permission CRUD
│   │   └── user/            # User profile endpoint
│   ├── app.module.ts
│   └── main.ts
├── test/                    # e2e test suites
├── docker-compose.yml       # PostgreSQL via Docker
├── typeorm.config.ts        # Migration CLI config
└── .env.sample
```

---

## Quick Start

### 1. Start PostgreSQL (and Mailpit)

```bash
docker compose up -d
# Mailpit (development SMTP) UI: http://localhost:8025
```

### 2. Install dependencies

```bash
yarn install
```

### 3. Configure environment

```bash
cp .env.sample .env
# Edit .env — set JWT_SECRET, REFRESH_TOKEN_SECRET, and verify DATABASE_URL
```

### 4. Run migrations

```bash
# Apply (REQUIRED: `synchronize` is off in every environment):
yarn migration:run

# Generate (after modifying entities):
yarn migration:generate database/migrations/<MigrationName>
```

The schema changes **only** through `database/migrations/`. To apply them at startup instead, set `DB_MIGRATIONS_RUN=true`.

> **Existing databases:** `NormalizeEmails` renames duplicate accounts (same email apart from case) and archives them in `user_email_changes`; local accounts created before `AddEmailVerification` start **unverified** and must verify their email (or reset their password) to log in with a password. Accounts created by `yarn seed` are verified.

### 5. Seed the database

```bash
# Creates default permissions (ADMIN, USER, MODERATOR) + an admin user
yarn seed --email admin@example.com --password MySecurePass! --permission ADMIN

# Google-only user (no password):
yarn seed --email admin@example.com --permission ADMIN

# Multiple permissions:
yarn seed --email admin@example.com --password MyPass! --permission ADMIN,MODERATOR
```

> **Note:** If you rename the `USER` permission in the seeder, update `auth.controller.ts` accordingly.

### 6. Start the server

```bash
# Development (watch mode)
yarn start:dev

# Production
yarn build && yarn start:prod
```

Swagger UI is available at `http://localhost:5000/docs`.

---

## Google OAuth2 Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/).
2. Create a project → **APIs & Services → OAuth consent screen** → External.
3. **APIs & Services → Credentials → Create Credentials → OAuth client ID** (Web application).
4. Add `http://localhost:5000/api/auth/google/callback` to **Authorized redirect URIs**.
5. Copy the Client ID and Client Secret to your `.env`:

```env
GOOGLE_CLIENT_ID=your-client-id
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_CALLBACK_URL=http://localhost:5000/api/auth/google/callback
```

---

## API Endpoints

All routes below sit behind the global `/api` prefix (see [Project Structure](#project-structure)) — the only exception is `/health`.

### Auth (`/api/auth`)

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| POST | `/api/auth/register` | Register with email + password. Always `202` with the same body, whether or not the address exists | Public |
| POST | `/api/auth/verify-email` | Confirm the email with the emailed token | Public |
| POST | `/api/auth/resend-verification` | Resend the verification email (uniform `202`) | Public |
| POST | `/api/auth/login` | Login (requires a verified email; `429` when the account is temporarily locked) | Public |
| POST | `/api/auth/refresh` | Rotate the refresh token (cookie `refresh_token`) | Public |
| POST | `/api/auth/logout` | Revoke the current session and clear cookies | Public |
| POST | `/api/auth/logout-all` | Revoke all sessions (bumps `tokenVersion`, revokes refresh tokens) | JWT |
| POST | `/api/auth/forgot-password` | Request a reset link (uniform `202`) | Public |
| POST | `/api/auth/reset-password` | Set a new password with the emailed token; revokes all sessions | Public |
| GET | `/api/auth/validate` | Validate / refresh tokens | Public |
| GET | `/api/auth/google` | Initiate Google OAuth (`?redirect_to=<allowed origin>` optional). `501` if Google isn't configured | Public |
| GET | `/api/auth/google/callback` | Sets the cookies and redirects to `FRONTEND_URL/auth/callback?status=success\|error[&reason=…]` | Public |

### User (`/api/user`)

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/api/user/me` | Get current user profile | JWT |

### Permission (`/api/permission`)

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/api/permission` | List all permissions | ADMIN |
| POST | `/api/permission` | Create a permission | ADMIN |
| PUT | `/api/permission/:id` | Update a permission | ADMIN |
| DELETE | `/api/permission/:id` | Delete a permission | ADMIN |

### Health

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/health` | Health check | Public |

---

## Decorators

### `@Public()`

Marks a route or controller as publicly accessible (skips `AuthGuard`).

```typescript
@Controller('auth')
@Public()
export class AuthController {}
```

### `@Permissions(...)`

Restricts access based on user permissions. Supports AND/OR/wildcard logic.

```typescript
// OR — requires EDIT or DELETE
@Permissions('EDIT', 'DELETE')

// AND — requires both READ and WRITE
@Permissions(['READ', 'WRITE'])

// Combined — (READ AND WRITE) OR ADMIN
@Permissions(['READ', 'WRITE'], 'ADMIN')

// Wildcard — any permission matching MANAGE_*
@Permissions('MANAGE_*')
```

> Permissions are case-insensitive. Users with `ADMIN` bypass all permission checks.

---

## Guards

### `AuthGuard` (global)

- Checks `Authorization: Bearer <token>` header or `access_token` cookie.
- On `TokenExpiredError`, automatically refreshes via `refresh_token` cookie.
- Returns `401 Unauthorized` if both tokens are absent or invalid.

### `PermissionsGuard` (global)

- Reads required permissions from the `@Permissions()` decorator.
- Queries the user's permissions from the database.
- Returns `403 Forbidden` if the user lacks the required permissions.
- `ADMIN` permission bypasses all checks.

### `ThrottlerGuard` (global)

Rate limiting: 100 requests per 60 seconds per IP.

---

## Token Strategy

| Token | Storage | Expiry (default) | Cookie `Path` | httpOnly |
|-------|---------|-----------------|---------------|---------|
| Access token | `access_token` cookie | 15 minutes | `/` | Yes |
| Refresh token | `refresh_token` cookie | 7 days | `/api/auth` | Yes |
| Trusted device | `trusted_device` cookie | 30 days | `/api/auth` | Yes |

- **Rotation:** every refresh marks the old token as used and issues a new one in the same *family* (`refresh_tokens` table, only the hash of the `jti` is stored). Presenting an already-used token revokes the whole family and bumps `tokenVersion`.
- **Instant revocation:** the access token carries `tokenVersion`, checked on every request (one primary-key lookup): logout-all, reuse detection and password reset invalidate it immediately. A single-session `logout` revokes the refresh token; the access token of that session lives until it expires (≤ `JWT_EXPIRATION`).
- **Refresh cookie path:** because it is only sent to `/api/auth/*`, clients renew with `POST /api/auth/refresh` (or `GET /api/auth/validate`), not through other routes. If a proxy changes the public path, rewrite the cookie path (`proxy_cookie_path /api/auth <public path>/auth;`).
- `trusted_device` only lets the account owner log in (still with the right password) while the account is temporarily locked by someone else's failed attempts; it never skips the password check and is tied to the account and its `tokenVersion`.
- Cookies get the `secure` flag automatically when `NODE_ENV=production`. Expired tokens are cleaned up daily.

---

## Configuration

See [`.env.sample`](.env.sample) for every variable. The ones introduced with the security hardening:

| Variable | Default | Purpose |
|----------|---------|---------|
| `FRONTEND_URL` | `http://localhost:3000` | Whitelist (comma-separated origins) for email links and the Google redirect. Required, https-only in production |
| `SMTP_HOST` / `SMTP_PORT` | `localhost` / `1025` | Email delivery (`SMTP_HOST` required in production). `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`, `MAIL_FROM` optional |
| `EMAIL_VERIFICATION_TTL` / `PASSWORD_RESET_TTL` | `24h` / `1h` | Lifetime of the emailed links |
| `BCRYPT_ROUNDS` | `12` | bcrypt cost (≥ 10 in production) |
| `LOGIN_MAX_FAILED_ATTEMPTS`, `LOGIN_LOCK_BASE_SECONDS`, `LOGIN_LOCK_MAX_SECONDS`, `LOGIN_ATTEMPT_WINDOW_SECONDS` | `5`, `60`, `900`, `1800` | Progressive per-account lockout |
| `REFRESH_REUSE_GRACE_SECONDS` | `0` | Tolerance for parallel refreshes with the same token |
| `DB_MIGRATIONS_RUN` | `false` | Apply migrations at startup |

Without `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` and `GOOGLE_CALLBACK_URL` the Google provider is **disabled** and its endpoints answer `501`.

---

## Running Tests

```bash
# Unit tests
yarn test

# Unit tests with coverage
yarn test:cov

# e2e tests with mocked repositories (no database needed)
yarn test:e2e

# e2e tests against a REAL PostgreSQL (schema rebuilt from the migrations)
docker compose --profile test up -d postgres-test      # port 5433, data in tmpfs
docker compose up -d mailpit                            # optional: also runs the real-SMTP test
E2E_MAILPIT_API=http://localhost:8025 yarn test:e2e:db

# everything
yarn test:all
```

`yarn test:e2e:db` refuses to run on any database that isn't local and named `*e2e*`/`*test*` (it drops the schema). Override the URL with `E2E_DATABASE_URL`. The Google flow is exercised with the **real** Passport strategy, with only its two network calls stubbed. CI runs the same suite on a GitHub runner with PostgreSQL and Mailpit as service containers (`e2e-db` job).

### Manual cURL Tests

```bash
# Start the server first, then:
./scripts/test-api.sh

# Custom host:
./scripts/test-api.sh http://localhost:5000
```

---

## Migrations

```bash
# Generate a new migration after changing entities
yarn migration:generate database/migrations/CreateUsersTable

# Apply pending migrations
yarn migration:run

# Revert the last migration
yarn migration:revert

# Show migration status
yarn migration:show
```

---

## Reverse Proxy

The app is meant to run behind a reverse proxy (nginx, Caddy, Traefik...) that terminates TLS. It already trusts the first proxy hop (`app.set('trust proxy', 1)` in `main.ts`), so `req.ip` and the `ThrottlerGuard`'s per-IP rate limiting still work correctly instead of bucketing every client under the proxy's IP.

Both examples below forward the request path unchanged (no rewriting) — since the app already expects everything under `/api` (see [API Endpoints](#api-endpoints)), that's the config with the least room for surprises. This means on the dedicated subdomain the path still includes `/api`, e.g. `api.example.com/api/auth/login`, not `api.example.com/auth/login`. You can run either setup alone or both at once against the same backend.

<details>
<summary>Example nginx / Caddy config</summary>

**nginx**

```nginx
# Option 1: dedicated subdomain — api.example.com/api/auth/login
server {
    listen 443 ssl http2;
    server_name api.example.com;

    ssl_certificate     /etc/letsencrypt/live/api.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:5000; # no trailing path → forwards the URI as-is
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cookie_path / /;
    }
}

# Option 2: same domain as the frontend, under /api — example.com/api/auth/login
server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    location /api/ {
        proxy_pass http://127.0.0.1:5000; # same rule: no trailing path, /api/... passes through as-is
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cookie_path / /;
    }

    location /health {
        proxy_pass http://127.0.0.1:5000/health;
        proxy_set_header Host $host;
    }

    location /docs {
        proxy_pass http://127.0.0.1:5000/docs;
        proxy_set_header Host $host;
    }

    # ... rest of the site (frontend, etc.)
}
```

**Caddy**

```caddyfile
# Option 1: dedicated subdomain — api.example.com/api/auth/login
api.example.com {
    reverse_proxy 127.0.0.1:5000
}

# Option 2: same domain as the frontend, under /api — example.com/api/auth/login
example.com {
    handle /api/* {
        reverse_proxy 127.0.0.1:5000
    }

    handle /health {
        reverse_proxy 127.0.0.1:5000
    }

    handle /docs {
        reverse_proxy 127.0.0.1:5000
    }

    # ... rest of the site (frontend, etc.)
}
```

`/health` and `/docs` sit outside the `/api` prefix (see [API Endpoints](#api-endpoints)), so on the path-based setup they need their own `location`/`handle` block to be reachable from the main domain — otherwise they're only reachable through the dedicated subdomain.

Set `NODE_ENV=production` so the auth cookies get the `secure` flag, and set `CORS_ORIGIN` to the exact origin(s) serving the frontend — `credentials: true` cookies don't work with a wildcard origin.

</details>

---

## Contributing

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'feat: add my feature'`
4. Push: `git push origin feature/my-feature`
5. Open a pull request.

---

## Contact

Deyvid Manolov — [Telegram](https://t.me/FileExists) — [deyvid.dev](https://www.deyvid.dev)
