# Reproducible security evidence

Local verification: JDK 21.0.13.1+2, Spring Boot 4.2.0 / Security 7.2.0,
PostgreSQL 18.7 Testcontainer, Spring application
on an actual random HTTP port. `mvnw.cmd -B -ntp clean verify`: **19 tests**, consisting
of 3 unit and 16 integration/security/protocol/concurrency tests; 0 failures, 0 errors,
0 skips. No security test disables itself without Docker. See testing.md for the
method-to-control matrix. Tests print only fixed redacted proof markers.

| Proof | Observed result |
|---|---|
| G1 | passwordHash=argon2id; plaintext inequality and matches checked |
| G2 | actual pre-auth cookie differs after complete login |
| G3 | mutating cookie request without CSRF → 403 |
| G4 | A accessing B identity/session management handle → 404 |
| G5 | USER admin mutation → 403; permission-bearing ADMIN → 204 |
| G6 | account attempts block temporarily; injected Clock expiry permits login |
| G7 | seed pending until valid possession proof; MFA password-only access denied |
| G8 | recovery reuse denied; concurrent attempts=2, success=1 |
| G9 | reset replay/expiry denied; only digest persisted |
| G10 | concurrent reset attempts=2, success=1, rejected=1 |
| G11 | real public code+S256 exchange=200; OIDC ID token and resource access succeed |
| G12 | missing/wrong verifier rejected; plain/missing challenge cannot issue code |
| G13 | code replay/expiry rejected; concurrent attempts=2, success=1 |
| G14 | unregistered host and loopback port rejected; attacker redirect never followed |
| G15 | malformed/expired/signature/audience/issuer decoder checks reject; positive control succeeds |
| G16 | refresh rotates, old token denied, descendants revoked; concurrent success=1, validFamilies=0 |
| G17 | standard refresh revocation, password/reset/session/logout consequences verified |
| G18 | persistent security event; UPDATE/DELETE/TRUNCATE denied; no secret payload fields |
| G19 | generated credential comparisons in captured logs pass; pattern source/report/Compose scan findings=0 |
| G20 | normalized unique login, permission foreign key and security schema constraints enforced |

Representative emitted lines:

```text
G2_G5_SESSION_AUTHZ_PROOF rotated=true csrf=denied horizontal=denied vertical=denied defaultDeny=true
G7_G8_MFA_PROOF activationRequiresProof=true passwordOnly=denied totpReplay=denied recoverySingleUse=true encryptedSeed=true
G9_G10_G17_RESET_PROOF replay=rejected concurrentAttempts=2 success=1 rejected=1 expired=rejected oldSession=revoked
G11_G13_OIDC_PROOF discovery=true publicJWKS=true authorizationCodeS256=accepted codeReplay=rejected idToken=true
G12_G14_PKCE_REDIRECT_PROOF missingVerifier=rejected wrongVerifier=rejected plain=rejected invalidRedirect=rejected exactPort=true
G16_REFRESH_REPLAY_PROOF rotated=true old=rejected family=revoked concurrentAttempts=2 success=1 validFamilies=0
G18_AUDIT_PROOF persistent=true update=denied delete=denied truncate=denied secretFields=absent
```

Docker: multi-stage build passed; a task-owned Compose project started from an empty
PostgreSQL volume; readiness=200, discovery=200, anonymous audit=401. Runtime reports
Temurin 21.0.13.1+2, UID/GID=10001. Local host port was selected dynamically because
8080/18081 were already occupied; no existing service was interrupted. API stayed
loopback-only. CI uses its isolated runner's standard port 8080.

[PR #1](https://github.com/GuiNovaisz/gatekeeper-java-iam/pull/1) tracks hosted CI and
dependency review. Branch protections require both security-verification and
dependency-review, PR and resolved conversations, forbid force pushes/deletion and
apply to admins; approving review count is zero so solo maintenance remains possible.
GitHub secret scanning/push protection are enabled. PR #1 was integrated into `dev`
with merge commit `083204123307560f267d2351886f708efea8bf40`; its file tree matches
the approved feature SHA `0f5c92c0e5434796b212fff3693fecb6a5e9075d`. The feature
branch is preserved. `main` remains at `ece60096a5b6ba1e2be38ac142473b0254418b9a`;
version remains `0.1.0-dev`. No promotion to main, tag or Release is authorized
by the integration mission; release preparation requires a separate audit.

Resolved-dependency audit: `scripts/audit-dependencies.py` queried OSV for **144**
Maven coordinates (including test transitives), returning **0 advisories** after
upgrading the framework/dependency base. There are no advisory suppressions. CI
repeats that audit and fails closed on API error or any finding, alongside GitHub's
PR dependency-review action with high threshold and all dependency scopes.

Artifact pattern scanning complements generated-value checks; it cannot prove absence
of every possible secret. Tests do not establish production certification, distributed
abuse resistance, external key custody or completed overlapping key rotation.
