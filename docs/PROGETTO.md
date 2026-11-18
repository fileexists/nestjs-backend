# Project: Bearer authentication for the public APIs (widget)

> **Status: design only.** Nothing described here is implemented. The cookie flow for staff (login, refresh,
> logout, Google) **does not change**; the only part already in production, mentioned as a reference, is the
> immediate revocation of staff sessions (see section 15).

## 1. Problem

The widget runs on the customers' websites, so on a **different domain** from the API. The widget's requests
are *cross-site*: the `sameSite=lax` cookies (the ones staff use today) **are not sent**.
So we need credentials that travel in a header, tied to the **store** and **separate from the user login**.

It is not solved with `SameSite=None; Secure`: browsers increasingly block third-party cookies
(Safari ITP, Chrome), it would expose us to CSRF and it would tie the widget to a user session that does not exist (the
visitor of the customer's site is not a staff user).

## 2. Goals and non-goals

| Goal | Non-goal |
| --- | --- |
| Identify **which store** is calling the public APIs | Authenticate the individual end visitor (out of scope) |
| Revocable, rotatable keys with minimal scopes | Replace or change the staff login |
| Work without cookies, from any authorized origin | Protect against whoever controls the customer's site |
| Limit abuse (per-key rate limit) | Guarantee that a public key stays secret (it cannot) |

## 3. Model: two kinds of key

| | **Publishable** (`pk_live_…`) | **Secret** (`sk_live_…`) |
| --- | --- | --- |
| Where it lives | Embedded in the widget, **visible to anyone** | Only on the customer's server |
| What it can do | Only the widget's read operations/actions | Server-to-server integrations, wider scopes |
| `Origin` check | **Yes**, list of allowed origins per key | No (it does not come from a browser) |
| Accepted exposure | High: assume it is public | Never in the browser, never in the logs |

A `pk_` key is **not a secret**: anyone who opens the browser tools can read it. Its protection is
(1) minimal privileges, (2) origin binding, (3) rate limit, (4) fast revocation. That is why it is not used for
anything sensitive: sensitive operations require an `sk_` on the server side.

### Format

```
pk_live_<8-char prefix>_<32-byte secret, base64url>
```

- the non-secret **prefix** is used to recognize the key in the dashboard and in the logs;
- only `SHA-256(full key)` is stored in the database: the key has 256 bits of entropy, so a fast hash
  is enough (bcrypt here would just be a cost on every request);
- the `sk_live_` prefix makes the key recognizable to *secret scanning* systems (e.g. GitHub).

## 4. Data

Today there is **no** store entity: it has to be defined (`stores`). New tables, with migrations in
`database/migrations/` (never `synchronize`):

```
stores            id uuid PK, name, createdAt, …
api_keys          id uuid PK
                  storeId uuid FK → stores ON DELETE CASCADE
                  name varchar            -- label chosen by staff
                  type  'publishable' | 'secret'
                  keyPrefix varchar(8)    -- not secret
                  keyHash   varchar(64) UNIQUE  -- sha256 of the full key
                  scopes text[]           -- e.g. widget:read, widget:write
                  allowedOrigins text[]   -- publishable only; exact origins (https://shop.example.com)
                  rateLimitPerMinute int
                  expiresAt timestamptz NULL
                  lastUsedAt timestamptz NULL
                  revokedAt  timestamptz NULL
                  createdBy uuid FK → users
                  createdAt timestamptz
api_key_events    audit: created / revoked / used from a new IP / request with a disallowed Origin
```

A key is valid if `revokedAt IS NULL` and `expiresAt` is in the future or null.

## 5. Transport and verification

```
Authorization: Bearer pk_live_ab12cd34_…
Origin: https://shop.example.com          (sent by the browser)
```

1. The guard extracts the Bearer token, computes `SHA-256`, looks up `keyHash` (unique index) with a
   constant-time comparison; a non-existent, revoked or expired key → **always the same 401**, without saying which case.
2. For `pk_` keys: the `Origin` header **must** be in the key's `allowedOrigins` (exact comparison, no
   wildcards on subdomains); otherwise 403 and an audit event. A request without `Origin` using a `pk_` → 403.
3. The **scopes** required by the route are checked.
4. The **per-key** rate limit is applied (not just per IP) and `lastUsedAt` is updated asynchronously.
5. `request.apiKey = { id, storeId, scopes }` is set: from here on the code reasons **per store**.

Keys **never** travel in the query string (they would end up in the logs and in the `Referer`) and cookies
are not accepted on these routes.

## 6. CORS

The *preflight* (`OPTIONS`) **does not carry the `Authorization` header**, so the key cannot be resolved to decide
the origin. Solution on two levels:

- CORS level: global list = **union of the `allowedOrigins` of the active keys** (cache with a 30–60 s TTL),
  only for the `/public/v1/*` routes; response with `Access-Control-Allow-Origin: <origin>` (never `*` with
  credentials), `Access-Control-Allow-Headers: Authorization, Content-Type`, `Vary: Origin`;
- key level: the precise check of point 5.2 on the real request.

**No `Access-Control-Allow-Credentials`** on these routes: there are no cookies. The staff CORS
(`CORS_ORIGIN`, with `credentials: true`) stays separate and unchanged.

## 7. Separation from the user login

- Distinct namespace: **`/api/public/v1/*`** for the widget, `/api/*` as today for staff.
- A **dedicated guard** (`ApiKeyGuard`, `@ApiKeyAuth('scope')` decorator) next to the existing `AuthGuard`.
  A route is *either* staff *or* public, never both; the global `AuthGuard` skips the `@ApiKeyAuth` routes.
- A staff JWT is **not** accepted on `/public/v1` and an API key does **not** authenticate staff routes
  (different claims/prefix: they cannot be mixed up).
- Key management is **a staff feature**, so it uses the existing cookie flow and the
  permissions (`@Permissions('ADMIN')` or a dedicated `STORE_ADMIN` permission).

## 8. Key management (staff)

| Endpoint | What it does |
| --- | --- |
| `POST /api/stores/:id/api-keys` | Creates the key. Shows it **only once** in plain text |
| `GET /api/stores/:id/api-keys` | List: prefix, type, scopes, origins, `lastUsedAt`. Never the key |
| `PATCH /api/stores/:id/api-keys/:keyId` | Changes name, scopes, origins, limit |
| `DELETE /api/stores/:id/api-keys/:keyId` | Revokes (`revokedAt`), takes effect within the cache TTL (≤ 60 s) |

**Rotation without downtime:** a store can have two active keys per type; create the new one, update the
widget, revoke the old one. Expiry (`expiresAt`) is optional, recommended for `sk_` keys.

## 9. Short-lived widget sessions (recommended, phase 2)

A fixed, public `pk_` is easy to copy and reuse. To reduce the exposure:

1. the widget calls `POST /api/public/v1/sessions` with the `pk_` (and a valid `Origin`);
2. it receives a **short-lived Bearer token** (5–15 min), signed, with `storeId`, scopes and key id;
3. the following calls use that token; when it expires it asks for a new one.

This way the `pk_` is used very rarely, revoking the key also stops the tokens already issued (the key id is
checked on every request, like `tokenVersion` and the session family today, see section 15) and an anti-bot
check (CAPTCHA/Turnstile) can be added on this endpoint alone without touching the rest.

## 10. Security: summary

- `SHA-256` hash of the key, constant-time comparison, no plain-text key in the logs or in the database;
- uniform responses (same 401) and no hint about existing keys;
- per-key + per-IP rate limit; quotas and alerts on abnormal spikes;
- `Cache-Control: no-store` on the responses that contain a newly created key;
- HTTPS only; `Referrer-Policy` and CSP already handled by Helmet;
- fast revocation (short cache) and audit of creation, revocation and suspicious uses;
- honest limit: the `Origin` check stops use from **other sites in the browser**, not from a server-side script
  (which can send whatever header it likes). That is why the `pk_` has minimal privileges and a rate limit, and sensitive
  actions sit behind `sk_`.

## 11. Implementation plan (phases)

1. **Data**: `stores`, `api_keys`, `api_key_events` + migrations + entities.
2. **Key service**: generation, hashing, creation/revocation/rotation, validation cache.
3. **Guard and decorator**: `ApiKeyGuard`, `@ApiKeyAuth()`, per-key rate limit (custom throttler tracker).
4. **Dynamic CORS** for `/public/v1/*` and per-key `Origin` verification.
5. **Management endpoints** for staff (+ Swagger).
6. **Short widget sessions** (+ anti-bot).
7. **Observability**: per-key metrics, alerts, audit retention.

## 12. Planned tests

- unit: key format/hash, comparison, scopes, exact `Origin` (no `evil.com`, no
  `shop.example.com.evil.com`), cache and revocation;
- e2e on a real PostgreSQL: valid/expired/revoked key (same 401), disallowed `Origin`, missing scope,
  per-key rate limit, CORS preflight, a staff JWT does **not** pass on `/public/v1` and vice versa, rotation with
  two active keys, key shown only once;
- security: no key in the logs, no cookie accepted on the public routes.

## 13. Discarded alternatives

| Alternative | Why not |
| --- | --- |
| `SameSite=None; Secure` cookie | Third-party cookies are increasingly blocked; exposes to CSRF; makes no sense for a visitor who is not a user |
| OAuth2 *client credentials* | Suited to server-to-server, but the widget runs in the browser: a public credential would still be needed |
| A single signed JWT per store | Not revocable without server-side state and slow to rotate |
| mTLS | Impossible to use from a widget in the browser |

## 14. Open questions

1. What are the widget's operations (real scopes)? Are only reads needed, or also writes (e.g. sending messages)?
2. Can a store have several domains (staging, production)? If so, multiple `allowedOrigins` per key.
3. Do we need to distinguish the **visitors** of the customer's site (e.g. conversations) or is the store enough?
4. Quotas/plans per store (different rate limits per tariff)?
5. Who can create keys: only `ADMIN` or also the store owner (dedicated permission)?

## 15. Reference: immediate revocation of staff sessions (already implemented)

It is not part of the key design, but it is the revocation model to follow:

- every login opens a **family** of refresh tokens (`fid`); the access token carries the same `fid` and `tokenVersion`;
- on every request a single query checks that the family belongs to the user, is not revoked and not expired, and that
  `tokenVersion` matches. So logging out of one device, logout-all, reuse of a refresh token and a password
  reset invalidate the access token **immediately** (even if it was copied), without touching the other devices
  when only one is logged out;
- after a rotation the old refresh tokens are only "used", not revoked: the family stays active;
- an access token without `fid` (issued before this change) is rejected with 401: on deploy a
  refresh (`POST /api/auth/refresh`) or a new login is enough;
- cost: one indexed query per request (the same one as before, not an extra one). **No in-memory cache**:
  with several instances it cannot be invalidated everywhere, and revocation would no longer be immediate. For the API keys (section 8)
  a short cache is instead an accepted trade-off from the start (revocation within the TTL).

### Refresh, configuration and per-instance state

- **Idempotent refresh:** inside `REFRESH_REUSE_GRACE_SECONDS`, a second use of the same refresh token gets
  the same pair of tokens as the first rotation (cached per `jti` in memory, dropped on logout, logout-all, password
  reset and a detected replay). The inside/outside decision is made in SQL with the database clock. After the
  window, reuse detection is unchanged (family revoked + `tokenVersion + 1`). Trade-off: inside the window whoever
  holds the refresh token gets the pair, hence the short default.
- **Per-instance state:** the throttler counters, the refresh cache above and the hourly cleanup cron live in each
  instance. With *N* instances the rate limits are up to *N* times higher, the refresh is idempotent only when the
  parallel requests reach the same instance, and the cleanup runs *N* times (idempotent deletes). Any shared
  behaviour (a global rate limit, a shared refresh cache) would need an external store such as Redis.
- **Production configuration:** `CORS_ORIGIN` is required, https only and never `*`; `/docs` is off unless
  `SWAGGER_ENABLED=true`; `TRUST_PROXY` is the number of trusted proxy hops (default 1, `0` when there is no proxy).
- **Guards:** the global guards run as `ThrottlerGuard` → `AuthGuard` → `PermissionsGuard`, so rejected requests
  still count towards the rate limit. `PermissionsGuard` reads `@Permissions()` from the method and then the class
  (the method wins); `*` is a wildcard only in the required permission and every other character is literal.
- **Email delivery:** emails are sent in the background with 3 attempts (2 s, 10 s). There is no persistent queue: an
  email that keeps failing, or is in flight when the process is killed, is lost. On shutdown the app waits up to 20 s
  for the queued ones (`AccountService.onApplicationShutdown`).
- **Request ids:** `X-Request-Id` from the client is kept only if it matches `^[A-Za-z0-9-]{1,64}$`, otherwise a UUID
  is generated; the id is in every error log line, guard rejections included.
