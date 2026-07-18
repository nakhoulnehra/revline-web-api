# User Auth — Backend

Session-based SPA auth using Laravel Sanctum's stateful cookie mode. No API tokens are issued anywhere.

## Endpoints

| Method | Path | Auth | Throttle | Purpose |
|---|---|---|---|---|
| GET | `/sanctum/csrf-cookie` | guest | — | Sets `XSRF-TOKEN` + session cookies before any POST |
| POST | `/api/register` | guest | 5/min per IP (`registration`) | Creates user, logs them in, returns user (201) |
| POST | `/api/login` | guest | 10/min per IP (`login`) + 5 failures/min per email+IP | Authenticates, regenerates session, returns user |
| GET | `/api/user` | `auth:sanctum` | — | Current user via `UserResource` |
| POST | `/api/logout` | `auth:sanctum` | — | Logs out, invalidates session, regenerates CSRF token (204) |

All request/response bodies are JSON; validation failures return 422, throttling 429, missing CSRF 419, unauthenticated 401.

## Flow expected from the SPA

1. `GET /sanctum/csrf-cookie` (once) → browser holds `XSRF-TOKEN` + session cookie.
2. POST requests send the `X-XSRF-TOKEN` header (value of the `XSRF-TOKEN` cookie) with `credentials: include`.
3. Register auto-logs the new user in (fresh session), so no follow-up login call is needed.

## Security decisions in place

- **Hashing**: `password => 'hashed'` cast on `User`, bcrypt with `BCRYPT_ROUNDS=12`.
- **Sessions**: database driver, session ID regenerated on login/register, invalidated + CSRF regenerated on logout. Logout only kills the current browser session.
- **Rate limiting**: named limiters in `AppServiceProvider` (`registration`, `login`) plus per-email+IP failed-login limiter inside `LoginRequest` (key is SHA-256 hashed; cleared on success).
- **Enumeration resistance**: wrong password and unknown email return the identical 422 message.
- **Input normalization**: email lowercased+trimmed on register and login; duplicate emails rejected case-insensitively.
- **Validation**: password min 8 (`Password::min(8)`), max 255, must be confirmed on register; email max 255, unique.
- **Output safety**: `UserResource` whitelists fields; `password`/`remember_token` are `#[Hidden]` on the model; no tokens/session IDs in responses.
- **CORS**: locked to `FRONTEND_URL` with `supports_credentials`; stateful domains via `SANCTUM_STATEFUL_DOMAINS=localhost:5173`.
- **Cookies**: `SameSite=Lax`. `SESSION_SECURE_COOKIE=false` is local-only — set it to `true` (HTTPS) in production, along with `APP_DEBUG=false`.

## Not implemented yet (deferred)

- Email verification (`User` already implements `MustVerifyEmail`; no `verified` middleware is applied anywhere yet).
- Password reset / forgot password (`password_reset_tokens` table already exists).
- "Remember me" logins.

## Tests

`tests/Feature/` covers registration, login, session lifecycle, logout, throttling, CSRF, and response-shape safety. Run `php artisan test` after any auth change.
