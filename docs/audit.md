# Audit and observability

security_audit is persistent and append-only via PostgreSQL trigger covering UPDATE,
DELETE and TRUNCATE. Entries: random ID, injected-clock timestamp, actor/target opaque
UUID, fixed action/outcome, generated correlation UUID. No arbitrary metadata/request
payload fields. No passwords, credential hashes, seeds, recovery/reset credentials,
tokens, Authorization header, client secret or session ID.

Events include registration; login success/failure/throttling; password change/reset;
MFA challenge/failure/enrollment start/activation/verification/disable; recovery use/regeneration; session
revocation; all-credential revocation; account-state admin action; client seed; token
issuance/refresh/replay/revocation; logout. Transactional success events roll back with
failed mutations. Failed login and throttle events commit outside rejected auth work.
General HTTP denials are enforced/tested but not all are separate persistent audit events.
Correlation IDs identify each security event, not a distributed tracing implementation.

Metrics `gatekeeper.security.events` use fixed action/outcome labels only. No login,
identity ID, token, session ID or IP labels. `/actuator/prometheus` is privileged;
health status is public, readiness includes PostgreSQL, no dependency details.

Investigate through privileged GET /api/audit (last 100) or read-only SQL by incident
operators. App logs contain fixed structured key/value security context, not request
bodies/headers. Do not enable Spring Security/web TRACE or attach raw HTTP traffic to
public artifacts. Tests capture logs and check known generated credentials; artifact
scanner also checks JWT/private-key/bearer/GitHub-token/TOTP URI patterns.

Database owner/superuser can defeat append-only triggers. Production needs least-
privilege runtime DB role and protected external audit retention. Local Compose uses
one DB owner for bootstrap simplicity; this is not an immutable external ledger.
