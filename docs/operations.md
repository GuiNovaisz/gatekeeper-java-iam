# Operations — local foundation

Prerequisites: Git, Docker Engine/Compose v2, JDK 21 (`JAVA_HOME`), PowerShell 7 on
Windows or POSIX shell + OpenSSL on Linux. No Maven installation required.

```powershell
git clone https://github.com/GuiNovaisz/gatekeeper-java-iam.git
cd gatekeeper-java-iam
git switch feature/iam-foundation
# Set JAVA_HOME to your installed JDK 21 for this shell only.
./scripts/configure.ps1
docker compose up --build --wait --wait-timeout 180
Invoke-RestMethod http://127.0.0.1:8080/actuator/health/readiness
./mvnw.cmd -B -ntp clean verify
docker compose down
```

Linux: `sh scripts/configure.sh`, `docker compose up --build --wait`,
`sh mvnw -B -ntp clean verify`, `docker compose down`. Testcontainers requires a
reachable Docker engine; tests fail instead of skipping if absent. With recent
Docker Engine, set `DOCKER_API_VERSION=1.44` if the local default client negotiation
is incompatible. CI already sets it.

Configuration creates ignored `.env` and `secrets/signing.p12`, refusing overwrite.
No default password. .env has DATABASE_PASSWORD, MFA_ENCRYPTION_KEY (32-byte Base64),
SIGNING_KEYSTORE_PASSWORD, DEMO_CLIENT_SECRET (256-bit generated), BOOTSTRAP_LOGIN,
BOOTSTRAP_PASSWORD. Windows script restricts ACLs; Linux uses umask 077 and grants
container read access to the bind-mounted store. Protect this directory and backups.
Do not print .env or `docker compose config` to public logs: rendered configuration
contains secrets. CI masks generated credentials **before** writing them to .env.

Local bootstrap creates ADMIN only if the configured login is absent. It never
promotes an existing user or resets a password on restart. Read credentials privately
from .env for local use. Authenticate via CSRF/login APIs, change password with current
password, then remove BOOTSTRAP_LOGIN/BOOTSTRAP_PASSWORD from .env and recreate app
container. Scripts refuse to overwrite persistent encryption/signing material.

Docker clean-start: unique Compose project with a new volume; migrations run from
empty PostgreSQL. App runs UID/GID 10001, read-only root, limited tmpfs/capabilities,
loopback port, no DB port exposed. `docker compose down` preserves data. Only use
`docker compose down -v` to discard the selected local demo project's data intentionally.
Never run cleanup against another user's Compose project.

OAuth demo is the integration harness described in oauth-oidc.md. No redirect listener
or frontend is required: harness captures the registered redirect without following it.
The discovery issuer remains http://127.0.0.1:8080. `GATEKEEPER_PORT` changes the host
binding for isolated smoke tests; use the standard 8080 mapping for a real local issuer.

Password change/reset/MFA change/account lock: atomic revocation of relevant sessions
and authorizations. GET /api/sessions lists management handles; DELETE collection
revokes others. POST /api/auth/logout revokes all. Admin PATCH identity state supports
ACTIVE/LOCKED/DISABLED. Never re-enable accounts without investigating the event.

Audit inspection: privileged GET /api/audit or read-only SQL:
`SELECT occurred_at,actor,action,outcome,target,correlation_id FROM security_audit ORDER BY occurred_at DESC LIMIT 100;`
Do not select token/seed/credential columns for reports. Metrics are permission-protected.
Public readiness includes DB connectivity; app fails startup if DB/migrations/key config
are unavailable. No secrets in health details. No automatic retry loop hides startup failure.

Key operations: PKCS12 alias signing, RSA >=3072. Retain original store across restarts.
Do not rotate by rerunning configure scripts. See token-lifecycle.md for planned
controlled public-key overlap; current implementation loads a single signing key.
AES key rotation requires an explicit authenticated seed re-encryption migration.
Do not replace MFA_ENCRYPTION_KEY before re-encryption. Production requires proper key
custody, TLS, Secure cookies, production issuer, separate DB roles, encrypted storage
and a real RecoveryDelivery provider (only local/test fake is bundled).

Backup DB together with the encryption/signing key versions in separately protected
custody; treat DB dumps as sensitive because the official OAuth JDBC store contains
bearer values. Restore may resurrect reset/recovery credentials or sessions consumed
after the snapshot. Before serving a restore, revoke all browser/OAuth sessions and
reset credentials, rotate recovery codes through a verified process, and review audit
continuity. MFA keys lost without backup cannot be reconstructed.

Retention: local buckets, reset rows, authorizations, spent-refresh fingerprints and
audit records currently need operator retention. Do not delete spent fingerprints
while their authorization family can still be active. Production bounded retention
and external audit export are roadmap work. Identity disabling preserves audit history.
