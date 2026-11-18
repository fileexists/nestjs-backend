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
# Edit .env — set JWT_SECRET and REFRESH_TOKEN_SECRET (different from each other; in production
# the placeholders from .env.sample are rejected at startup), and verify DATABASE_URL
```

### 4. Run migrations

```bash
# Apply (REQUIRED: `synchronize` is off in every environment):
yarn migration:run

# Generate (after modifying entities):
yarn migration:generate database/migrations/<MigrationName>
```

The schema changes **only** through `database/migrations/`. To apply them at startup instead, set `DB_MIGRATIONS_RUN=true`.

> **Existing databases:** `NormalizeEmails` renames duplicate accounts (same email apart from case) and archives them in `user_email_changes` (see below); local accounts created before `AddEmailVerification` start **unverified** and must verify their email (or reset their password) to log in with a password. Accounts created by `yarn seed` are verified. An admin created before this change can log in again after "forgot password", or you can verify the account by hand:

```sql
UPDATE users SET "emailVerifiedAt" = now() WHERE email = 'admin@example.com';
```

**New installs can ignore this.** `NormalizeEmails` only has work to do on a database that already holds emails with capital letters or stray spaces. On an empty (or already tidy) database it just adds the unique index on `lower(email)`, and the table below is never created.

On an upgraded database that did need fixing, the migration creates **`user_email_changes`**: a one-off archive that the application never reads. Each row is an account whose email was touched, with the original value (`reason = 'normalized'`: only trimmed/lowercased; `reason = 'duplicate'`: same address as another account apart from case, so it was renamed to `name+dup-N-id@domain` and its password disabled). For duplicates it also keeps the old password hash and verification date, so nothing is lost if two people really did sign up with `Mario@x.com` and `mario@x.com`.

Check whether there is anything to review:

```sql
SELECT reason, count(*) FROM user_email_changes GROUP BY reason;
SELECT "originalEmail", "newEmail", "canonicalUserId" FROM user_email_changes WHERE reason = 'duplicate';
```

If there are no `duplicate` rows, or you have already sorted them out, drop the table by hand (`DROP TABLE user_email_changes;`): it holds old password hashes that no longer serve a purpose. The `down` of `NormalizeEmails` still works afterwards, it just has nothing to restore.

### 5. Seed the database

```bash
# Creates default permissions (ADMIN, USER, MODERATOR) + an admin user
yarn seed --email admin@example.com --password MySecurePass! --permission ADMIN

# Google-only user (no password):
yarn seed --email admin@example.com --permission ADMIN

# Multiple permissions:
yarn seed --email admin@example.com --password MyPass! --permission ADMIN,MODERATOR
```

> **Note:** The `USER` permission is the one every new account gets and the app refuses to register anyone without it (`AuthService.register` in `auth.service.ts` asks `PermissionService.getRequired('USER')`; `PermissionService` re-creates it at every startup if it is missing). If you rename it in the seeder, change it in `auth.service.ts` and in the list of essential permissions in `permission.service.ts` too.

### 6. Start the server

```bash
# Development (watch mode)
yarn start:dev

# Production
yarn build && yarn start:prod
```

Swagger UI is available at `http://localhost:5000/docs` everywhere except production, where it is **off** unless you set `SWAGGER_ENABLED=true`.

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
| POST | `/api/auth/verify-email` | Confirm the email with the emailed token **and choose the password** (`{ token, password }`; replaces the one given at registration) | Public |
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

Restricts access based on user permissions. Supports AND/OR/wildcard logic. It can go on a method or on a whole controller class: a method-level decorator **replaces** the class-level one for that route (it is not merged with it), and a route with neither is open to any authenticated user.

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

**Wildcard semantics.** `*` is special only in the permission written in `@Permissions()` (the *required* one), where it matches any run of characters, including none: `MANAGE_*` is satisfied by `MANAGE_USERS` and by `MANAGE_`. The whole name has to match (`MANAGE_*` does not match `NOT_MANAGE_USERS`) and every other character is literal (`REPORT.*` does not match `REPORTX1`; a dot is a dot). A permission a user *holds* is never a pattern: someone who holds `MANAGE_*` has exactly that name and does not satisfy `MANAGE_USERS`. A lone `*` means "any permission at all": it is satisfied by holding at least one.

---

## Guards

Global guards run in this order (the order of the `APP_GUARD` providers in `app.module.ts`): **`ThrottlerGuard` → `AuthGuard` → `PermissionsGuard`**. The rate limit is first so that requests the other two reject (no token, no permission) still count against it.

### `AuthGuard` (global)

- Checks `Authorization: Bearer <token>` header or `access_token` cookie.
- On `TokenExpiredError`, automatically refreshes via `refresh_token` cookie.
- Returns `401 Unauthorized` if both tokens are absent or invalid.

### `PermissionsGuard` (global)

- Reads required permissions from the `@Permissions()` decorator, on the method or the class (method wins).
- Queries the user's permissions from the database.
- Returns `403 Forbidden` if the user lacks the required permissions.
- `ADMIN` permission bypasses all checks.

### `ThrottlerGuard` (global)

Rate limiting: 100 requests per 60 seconds per IP. The counters live in the memory of each instance (see [Running more than one instance](#running-more-than-one-instance)).

---

## Token Strategy

| Token | Storage | Expiry (default) | Cookie `Path` | httpOnly |
|-------|---------|-----------------|---------------|---------|
| Access token | `access_token` cookie | 15 minutes | `/` | Yes |
| Refresh token | `refresh_token` cookie | 7 days | `/api/auth` | Yes |
| Trusted device | `trusted_device` cookie | 30 days | `/api/auth` | Yes |

- **Rotation:** every refresh marks the old token as used and issues a new one in the same *family* (`refresh_tokens` table, only the hash of the `jti` is stored). Presenting an already-used token **after the grace period** revokes the whole family and bumps `tokenVersion`.
- **Idempotent refresh:** when the access token expires, a page often fires several requests at once, all carrying the same refresh cookie. Inside the grace period (`REFRESH_REUSE_GRACE_SECONDS`) a second use of the same refresh token gets the **same pair of tokens** the first rotation issued (kept in memory, per `jti`, for the length of the grace period and then dropped), so all those requests succeed instead of all but one getting a 401. Whether a use is inside or outside the grace period is decided in SQL with the database clock, not the application's. Logout, logout-all, password reset and a detected replay drop the cached pairs of the sessions they revoke. Limits: the cache is per instance, so with several instances a request that lands on another one is only rejected (never treated as theft inside the grace period); and inside the grace period whoever holds the refresh token gets the pair, so keep the grace short (`0` turns the whole thing off: every second use is theft).
- **Instant revocation:** the access token carries `tokenVersion` and `fid`, the id of the session family it belongs to (the same `fid` as the refresh token of that device). On every request one indexed query checks that the family belongs to the user and is neither revoked nor expired, and that `tokenVersion` still matches. So `logout` (this device only), logout-all, reuse detection and password reset kill the access token immediately, even if someone copied it; the user's other devices keep working after a plain `logout`. After a refresh the old refresh tokens are only marked as used, not revoked, so the session (and the access tokens of that family) stay valid between rotations.
- **Cost:** one query per authenticated request, the same count as before (it replaced the lookup of the user by primary key). There is deliberately **no in-memory cache** of the session state: with more than one instance a logout could not be invalidated everywhere, and a revoked token would keep working for as long as the cache TTL.
- **Deploying this change:** access tokens issued before it have no `fid` and are rejected with 401. The browser keeps its `refresh_token` cookie, so `POST /api/auth/refresh` (or `GET /api/auth/validate`) hands out a new pair; clients that only hold a Bearer access token must refresh or log in again. Nobody is logged out for good: refresh tokens are unchanged.
- **Refresh cookie path:** because it is only sent to `/api/auth/*`, clients renew with `POST /api/auth/refresh` (or `GET /api/auth/validate`), not through other routes. If a proxy changes the public path, rewrite the cookie path (`proxy_cookie_path /api/auth <public path>/auth;`).
- `trusted_device` only lets the account owner log in (still with the right password) while the account is temporarily locked by someone else's failed attempts; it never skips the password check and is tied to the account and its `tokenVersion`.
- Known limit: whoever knows an email can keep that account locked for new devices (up to `LOGIN_LOCK_MAX_SECONDS`) by sending wrong passwords; known devices, the password reset and the per-IP limit on `/auth/login` (5 per minute) soften it. A CAPTCHA would be the next step.
- Cookies get the `secure` flag automatically when `NODE_ENV=production`. Expired tokens and stale login attempt counters are cleaned up **every hour** (the counters are written for any email, existing or not, so they must not pile up).

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
| `REFRESH_REUSE_GRACE_SECONDS` | `10` | A refresh token used twice within this many seconds gets the same pair of tokens as the first use (parallel requests; same instance only, see [Idempotent refresh](#token-strategy)); later, it counts as theft and revokes the session family. `0` = always theft |
| `CORS_ORIGIN` | `*` (development only) | Origins allowed by CORS, comma-separated. **Required in production**: https origins only, never `*` (the app refuses to start otherwise) |
| `SWAGGER_ENABLED` | `false` | Swagger UI at `/docs`. Always on outside production; in production only with `SWAGGER_ENABLED=true` |
| `TRUST_PROXY` | `1` | Number of reverse proxies in front of the app whose `X-Forwarded-For` is trusted. **Set `0` when nothing sits in front** (otherwise anyone can fake their IP and sidestep the rate limits) |
| `DB_MIGRATIONS_RUN` | `false` | Apply migrations at startup |

Without `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` and `GOOGLE_CALLBACK_URL` the Google provider is **disabled** and its endpoints answer `501`.

---

## Production notes

### Frontend and API on the same site

The auth cookies are `SameSite=Lax`: the browser only sends them with requests made from the **same site** as the API. Serve the frontend and the API from the same registrable domain (`app.example.com` + `api.example.com`, or one domain with `/api` behind the proxy). A frontend on a different site (`app.example.com` calling `api.other.net`) will not send the cookies and every call will look logged out; there is no setting that fixes that without weakening the cookies. Set `CORS_ORIGIN` to the frontend's origin and call the API with `credentials: 'include'`.

### Running the migrations (staging and production)

`synchronize` is off, so the schema only exists once the migrations have run. Two ways:

| | How | When |
|---|---|---|
| **Deploy step (recommended)** | `yarn migration:run` against the target database (`DATABASE_URL`), before starting the new version. It uses the TypeScript sources and the dev dependencies, so run it from the repository checkout or the CI job, not from a production-only image. `yarn migration:show` lists what is pending | Staging, production, and anything with more than one instance |
| **At startup** | `DB_MIGRATIONS_RUN=true`: the app applies the pending (compiled) migrations when it boots | A single instance, where one process boots at a time. With several instances booting together they would race to apply the same migration |

Back up the production database before the first run: `NormalizeEmails` renames duplicate accounts, and `migration:revert` is there for emergencies, not for routine use.

### Email delivery and shutdown

Verification, password reset and "address already registered" emails are sent **in the background**, after the HTTP response (so response times do not reveal whether an address has an account). A send is attempted up to 3 times (waiting 2 s, then 10 s) on network errors and SMTP 4xx answers. There is **no persistent queue**: an email that still fails after the retries, or that is in flight when the process is killed, is **lost**. The user can ask again (resend verification, forgot password), and a failed send is logged.

On `SIGTERM`/`SIGINT` the app waits up to 20 seconds for the emails already queued before exiting (`AccountService.onApplicationShutdown`); give your orchestrator a termination grace period longer than that (Kubernetes' default of 30 s is fine). If you need delivery guarantees across crashes and deploys, put a durable queue (a table, Redis, a managed service) behind `MailService`.

### Request ids in the logs

Every response carries an `X-Request-Id` header. A client may send its own, but it is accepted only if it matches `^[A-Za-z0-9-]{1,64}$` (it ends up in log lines and a response header, so no spaces, new lines or long strings); anything else is replaced by a fresh UUID. The id is part of every error log line (`GET /api/user/me → 401 [request <id>]`), including the 401/403 that a guard raises before the request reaches a controller.

### Running more than one instance

A few things live in the memory of each process and are **not shared** between instances:

- **Rate limiting** (`ThrottlerGuard`): every instance counts on its own, so the effective limit is up to *N* times higher with *N* instances. Per-account login lockout is stored in the database and is shared.
- **Scheduled cleanup** (hourly): every instance runs it. The deletes are idempotent, so this is harmless, just redundant.
- **Idempotent refresh**: the cached pair of tokens is per instance. A parallel request that lands on a different instance than the one that rotated is rejected (not treated as theft). Sticky routing by client avoids it.

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

The app is meant to run behind a reverse proxy (nginx, Caddy, Traefik...) that terminates TLS. It trusts the number of proxy hops given by `TRUST_PROXY` (default `1`), so `req.ip` and the `ThrottlerGuard`'s per-IP rate limiting still work correctly instead of bucketing every client under the proxy's IP. **If nothing sits in front of the app, set `TRUST_PROXY=0`**: with a trusted hop and no proxy, anyone can send their own `X-Forwarded-For` and get a fresh rate-limit bucket on every request. With two proxies in a row (e.g. a CDN and nginx) set `2`.

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

Set `NODE_ENV=production` so the auth cookies get the `secure` flag, and set `CORS_ORIGIN` to the exact https origin(s) serving the frontend — `credentials: true` cookies don't work with a wildcard origin, so in production the app refuses to start with `CORS_ORIGIN` missing, `*` or on http.

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
