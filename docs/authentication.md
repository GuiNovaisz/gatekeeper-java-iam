# Authentication

1. GET `/api/auth/csrf`, retaining the `SESSION` cookie; read headerName/token.
2. POST `/api/auth/login` JSON login/password with that CSRF header and cookie.
3. 204 means complete authentication; 202 means MFA_REQUIRED. Password success alone
   creates no principal for MFA-enabled identities.
4. POST `/api/auth/mfa` JSON code/recovery (boolean), same CSRF/cookie. 204 completes
   authentication and rotates the session again.
5. POST `/api/auth/logout` with CSRF revokes all this identity's sessions/tokens.

No hosted login page/frontend is supplied; API/CLI harness establishes the browser
session before the standard authorization request. There is no Resource Owner
Password Credentials OAuth grant, implicit grant, Basic user login or custom JWT login.

Login failure always returns 401 with the same sanitized payload for unknown,
wrong password, inactive account and throttling. Unknown identities perform dummy
Argon2 verification. Invalid request shape returns generic 400. Source limit:
30 attempts/5 minutes; account limit: 8/5 minutes. They count all attempts, including
success; buckets are fixed windows, do not extend indefinitely on rejected attempts.
No Thread.sleep. Registration: 5/source/5 minutes. MFA verification: 5/account and
30/source/5 minutes. MFA management: 10/account/5 minutes. Password change: 5/5 minutes.
Production needs load/abuse tuning and limits before the app/DB as defense in depth.

See `IamSecurityIT`: real HTTP login, known/unknown, locked/disabled, temporary block,
time advancement, session fixation, CSRF and MFA boundary. Clock injection controls
application expiry checks; framework OAuth expiry uses its own system clock and
tests expire database code records without sleeping.
