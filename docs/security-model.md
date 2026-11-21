# Security model and boundaries

Protects local identity credentials, browser session integrity, permission/ownership
decisions and registered OAuth/OIDC exchanges. Does not verify a person's legal
identity, secure a compromised browser/host, provide phishing-resistant MFA, or
replace production TLS, backups, database privileges, key custody and incident response.

Identity IDs are random UUIDs. Login is trimmed, lowercased with Locale.ROOT,
ASCII-only `[a-z0-9@._+-]` (3–254 chars), unique in PostgreSQL. It may be email-shaped
but no email ownership is asserted. Login changes are not exposed in this milestone.
Public identity responses expose ID, state and MFA flag, not login/email/hash.
States ACTIVE / LOCKED / DISABLED are administrator-controlled; LOCKED is not an
automatic permanent lockout. Temporary abuse blocking is separate and expires.

Passwords: Argon2id, 19 MiB, 2 iterations, parallelism 1, 16-byte random salt,
32-byte output; `{argon2id}` format enables migration. Passphrases 15–128 Unicode
code points, no composition requirement/truncation, small explicit common list.
The list is not a breached-password database. Tune work factors on deployment
hardware; no claim of a measured one-second verification cost is made.

Browser security: Spring Session JDBC, idle timeout 20 minutes, HttpOnly,
SameSite=Lax; Secure defaults true. Compose explicitly permits insecure cookies
only on local HTTP loopback. Complete login rotates the session ID. Pending MFA
is not an authenticated SecurityContext; challenge expires in 3 minutes and is
bound to credential version. CSRF synchronizer token required on browser POST,
PATCH and DELETE, including login and public recovery. CORS is closed. Resource
routes use a separate stateless bearer-only chain and ignore browser contexts.

Every protected cookie request rechecks active identity and credential version.
Reset, password change, MFA enable/disable and account state changes increment
version, delete all sessions and delete OAuth authorizations. Logout revokes all
credentials for that identity (deliberately stronger than ending one session).
Single/other-session revocation removes only selected JDBC sessions. In-flight
operations that passed a check can complete; there is no claim of instantaneous
cancellation of already-executing work.

JWT: RS256, kid derived from public key, opaque subject, issuer configuration,
audience `gatekeeper-resource`, scopes, iat/exp/jti and credential version `cv` as
a decimal string. No unnecessary PII. 5-minute TTL, Spring default 60-second
validation clock skew. Local `/resource/me` additionally requires a live active
stored authorization and matching credential version; external resource servers
doing offline JWT validation retain their configured expiry/skew revocation delay.

Refresh tokens: only confidential code client; 30-minute rolling TTL; no public
refresh tokens. Reuse disabled. Token-hash advisory locks plus identity and
authorization row locks serialize exchange. Old refresh-token SHA-256 fingerprints
are retained; replay deletes that authorization family, including descendants.
Concurrent old-token requests yield one success and one denial; denial revokes
the winner's family. Clients must serialize refresh and reauthenticate after a
network-ambiguous refresh. No sender-constrained tokens in v0.1.0.

Secret handling: environment supplies AES-256-GCM MFA key and PKCS12 password;
PKCS12 private key is outside Git. TOTP seeds use random 96-bit IV and authenticated
encryption. Recovery/reset high-entropy values use SHA-256 fingerprints. Passwords
and confidential secrets use Argon2id. Spring's JDBC OAuth authorization store
retains bearer token values and security context to support protocol lookups;
production database/storage/backups must be encrypted and tightly access-controlled.
This local foundation does not supply KMS/encrypted PostgreSQL volumes. Application
DB compromise remains a token/identity compromise even with password hashing.

Audit trigger prohibits application UPDATE/DELETE/TRUNCATE, not a privileged DBA
disabling the trigger. No externally anchored tamper-evident ledger. Runtime and
migration use the same local DB owner; production must split roles and revoke DDL.
Audit retention/deletion is an operator policy, not GDPR automation. Disabling an
identity preserves audit history; no general identity deletion endpoint exists.

Public error contracts avoid account existence; no perfect timing equivalence is
claimed. DB-account/source rate limits reduce single-source abuse, not botnets.
Peer addresses only; forwarded headers are not trusted. A production reverse proxy
requires a reviewed source-address policy, TLS and corresponding issuer/cookie settings.

Key rotation overlap, production delivery, external KMS, distributed abuse detection,
WebAuthn and GDPR workflows are explicit limitations/roadmap items, not implemented claims.
