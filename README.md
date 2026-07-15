# NestJS Auth Backend

A production-ready authentication backend built with **NestJS 11**, **TypeORM**, and **PostgreSQL**.

## Features

- JWT authentication with automatic refresh-token rotation
- Google OAuth2 via Passport.js
- Role-based access control (RBAC) with a flexible `@Permissions()` decorator
- PostgreSQL + TypeORM with migration support
- Helmet security headers, rate limiting, global validation
- Swagger/OpenAPI documentation
- Full unit and e2e test suite (Jest + Supertest)

---

## Stack

| Layer | Technology |
|-------|-----------|
| Framework | NestJS 11 |
| ORM | TypeORM 0.3 |
| Database | PostgreSQL 17 |
| Auth | JWT + Passport (local + Google OAuth2) |
| Hashing | bcrypt (10 rounds) |
| Validation | class-validator + class-transformer |
| Docs | Swagger / OpenAPI |
| Testing | Jest + Supertest |

---

## Project Structure

```
├── database/
│   ├── migrations/          # TypeORM migrations
│   └── seeds/               # Database seeders
├── scripts/
│   └── test-api.sh          # cURL integration tests
├── src/
│   ├── common/
│   │   ├── decorators/      # @Public(), @Permissions()
│   │   ├── dto/             # Shared DTOs
│   │   ├── entities/        # TypeORM entities (User, Permission)
│   │   ├── filters/         # Global HTTP exception filter
│   │   └── guards/          # AuthGuard, PermissionsGuard, GoogleOAuthGuard
│   ├── modules/
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

### 1. Start PostgreSQL

```bash
docker-compose up -d
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
# Generate (after modifying entities):
yarn migration:generate src/database/migrations/<MigrationName>

# Apply:
yarn migration:run
```

In development, `synchronize: true` is active so the schema is auto-synced without migrations.

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
| POST | `/api/auth/register` | Register with email + password | Public |
| POST | `/api/auth/login` | Login with email + password | Public |
| POST | `/api/auth/logout` | Clear auth cookies | Public |
| POST | `/api/auth/logout-all` | Revoke all sessions (bumps `tokenVersion`) | JWT |
| GET | `/api/auth/validate` | Validate / refresh tokens | Public |
| GET | `/api/auth/google` | Initiate Google OAuth | Public |
| GET | `/api/auth/google/callback` | Google OAuth callback | Public |

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

| Token | Storage | Expiry (default) | httpOnly |
|-------|---------|-----------------|---------|
| Access token | `access_token` cookie | 15 minutes | Yes |
| Refresh token | `refresh_token` cookie | 7 days | Yes |

Tokens are automatically rotated on each refresh. Cookies get the `secure` flag automatically when `NODE_ENV=production`.

---

## Running Tests

```bash
# Unit tests
yarn test

# Unit tests with coverage
yarn test:cov

# e2e tests (no real database needed — mocked)
yarn test:e2e
```

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
yarn migration:generate src/database/migrations/CreateUsersTable

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

<details>
<summary>Example nginx / Caddy config</summary>

**nginx**

```nginx
server {
    listen 443 ssl http2;
    server_name api.example.com;

    ssl_certificate     /etc/letsencrypt/live/api.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cookie_path / /;
    }
}
```

**Caddy**

```caddyfile
api.example.com {
    reverse_proxy 127.0.0.1:5000
}
```

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
