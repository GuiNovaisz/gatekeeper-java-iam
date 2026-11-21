# Threat model — before authentication implementation

Gatekeeper is a single-deployment IAM foundation, not an identity proofing service.
Assets: password hashes, encrypted MFA seeds, access/refresh tokens, authorization
codes, browser sessions, signing keys, reset/recovery credentials, opaque identity
IDs, roles/permissions and persistent security audit records.

Actors: legitimate user; privileged administrator; registered OAuth client;
unauthenticated attacker; compromised browser/client; malicious authenticated user.

Trust boundaries:

1. Browser/client ↔ Gatekeeper: TLS required outside loopback; cookie and bearer
   authentication use separate filter chains. User-controlled IDs never grant ownership.
2. Gatekeeper ↔ PostgreSQL: parameterized JDBC, constrained schema, transactions;
   production needs transport encryption and separate migration/runtime roles.
3. OAuth client ↔ authorization server: exact redirect registration, S256 PKCE,
   hashed confidential secret, no dynamic registration.
4. Resource server ↔ authorization server: issuer, audience, signature and expiry
   validation; public JWKS only. JWT revocation is bounded by short expiry at external consumers.

| Threat | Control | Residual risk | Planned evidence |
|---|---|---|---|
| Credential stuffing | source/account throttle, MFA | distributed stolen credentials | AuthenticationIT |
| Brute force | DB fixed windows, temporary blocking | intentional temporary denial | AuthenticationIT |
| Password spraying | per-source windows, MFA | distributed low-rate attacks | AuthenticationIT |
| Username enumeration | generic login/reset/registration responses, dummy password hash | timing/network differences | AuthenticationIT |
| Session fixation | rotate session on complete authentication | compromised runtime | AuthenticationIT |
| Session theft | HttpOnly, Secure production, SameSite=Lax, revocation | browser/host compromise | AuthenticationIT |
| CSRF | synchronizer token on cookie mutations | XSS can act in origin | AuthenticationIT |
| XSS credential impact | restrictive headers, no external frontend, no localStorage | compromised browser | header tests |
| Authorization-code interception | mandatory S256 PKCE | client compromise | ProtocolIT |
| Token theft | 5-minute JWT, audience, revocation at local consumer | external JWT valid until expiry | ProtocolIT |
| Refresh theft/replay | rotation, row lock, spent-token hashes, family revocation | bearer stolen before legitimate use | ProtocolIT |
| Privilege escalation | permission policies, deny-all fallback | privileged operator compromise | AuthorizationIT |
| Horizontal bypass | authenticated opaque subject + ownership lookup | privileged DB access | AuthorizationIT |
| Vertical bypass | method + route permission checks | malicious administrator | AuthorizationIT |
| Open redirect | exact registered URI, no arbitrary success URL | registered client compromise | ProtocolIT |
| Malicious redirect URI | fixed seeded loopback clients | production registration operator | ProtocolIT |
| Client impersonation | Argon2 client secret / public PKCE | leaked client secret | ProtocolIT |
| Weak client secrets | minimum entropy/length configuration | operator chooses predictable secret | configuration tests |
| MFA bypass | incomplete authentication never gets SecurityContext | recovery/host compromise | MfaIT |
| MFA replay | monotonic accepted timestep under row lock | real-time phishing | MfaIT |
| Recovery abuse | hashed 256-bit reset, 128-bit recovery, expiry, atomic consume | compromised delivery channel | RecoveryIT |
| Audit tampering | trigger denies UPDATE/DELETE/TRUNCATE | owner/superuser can disable trigger | PersistenceIT |
| Signing-key compromise | external PKCS12, no committed key, kid | local file/operator compromise | key tests / runbook |
| Secret logging | no request-body/header logging, allowlisted audit fields | infrastructure outside app | artifact scan |

Brute force guesses many passwords for one identity; spraying tests a few common
passwords across many identities; stuffing reuses credentials leaked elsewhere.
No single rate limiter eliminates these attacks. Limits use direct peer addresses;
forwarded headers are not trusted. Production proxy design must preserve this boundary.

Concurrency design: unique normalized login; atomic throttle upsert; identity row
locks serialize enrollment/TOTP/recovery/reset; atomic reset claim; OAuth refresh/code
exchange transaction locks serialize token-family changes. Revocation deletes JDBC
sessions and OAuth authorizations; in-flight requests retain a bounded race addressed
by live credential-version checks before protected use.
