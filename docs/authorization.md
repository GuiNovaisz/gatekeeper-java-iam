# Authorization and endpoint matrix

Roles group permissions in DB; USER → identity:read; ADMIN → identity:read,
identity:manage, audit:read, metrics:read. Authorities are loaded server-side.
Permission policies use route checks and method security for identity/admin/audit.
There is no user-controlled role field or public role-management endpoint.

| Endpoints | Classification | Policy |
|---|---|---|
| GET /api/auth/csrf | public | returns synchronizer token, cookie |
| POST /api/auth/login, /api/auth/mfa | public | CSRF; incomplete auth cannot reach protected routes |
| POST /api/registration | public | CSRF; generic 202 for accepted duplicate/new request |
| POST /api/recovery/request, /api/recovery/reset | public | CSRF + per-source/account limits |
| GET /actuator/health, /actuator/health/** | public | status only; readiness includes DB |
| GET /.well-known/openid-configuration, /.well-known/oauth-authorization-server, /oauth2/jwks | protocol endpoint | framework public discovery and public keys |
| GET /oauth2/authorize | protocol endpoint | active, complete browser principal; exact URI; S256 |
| POST /oauth2/token | protocol endpoint | registered public PKCE / confidential client auth; 60/source/minute |
| POST /oauth2/revoke, /oauth2/introspect | protocol endpoint | framework client authentication |
| /userinfo, /connect/logout | protocol endpoint | framework OIDC semantics; no custom claims of cookie/token revocation |
| GET /resource/me | authenticated | bearer-only; resource.read + signature/issuer/audience/time + live authorization |
| GET /api/identities/{id} | authenticated | identity:read AND exact own opaque subject; foreign/missing → 404 |
| POST /api/password | authenticated | CSRF + current password; revokes all credentials |
| POST /api/mfa/enrollment, /api/mfa/activation, /api/mfa/recovery-codes; DELETE /api/mfa | authenticated | CSRF + reauthentication/proof, rate limit |
| GET /api/sessions; DELETE /api/sessions/{id}; DELETE /api/sessions | authenticated | own management handles only; DELETE collection revokes others |
| POST /api/auth/logout | authenticated | CSRF; revoke all identity credentials |
| PATCH /api/admin/identities/{id}/state | privileged | identity:manage + CSRF |
| GET /api/audit | privileged | audit:read; latest 100 entries |
| GET /actuator/prometheus | privileged | metrics:read |
| all other requests | denied | denyAll fallback, including env/configprops/heapdump |

Only servlet ERROR dispatch is permitted to the sanitized error handler; direct
`/error` is not public. Unsupported Spring protocol capabilities are not granted
to seeded clients. Dynamic client registration is not enabled. OIDC RP logout is
framework functionality; the explicitly audited all-credentials logout is
`POST /api/auth/logout`. Do not assume an RP logout invalidates self-contained JWTs.

Foreign ownership returns 404 to avoid a resource-existence oracle. Even ADMIN does
not bypass the own-identity route; privileged state changes have their own endpoint.
