# ADR 003 — Official authorization server, constrained first-party clients

Status: accepted. Use maintained Spring Authorization Server 1.5.8 with Boot 3.5.16;
do not write grant/token/PKCE protocols. New Spring Security 7 integrates the server,
but this supported compatible line avoids an unnecessary major migration.

Enable OIDC, discovery, public JWKS, Authorization Code and S256 for both public and
confidential seeded clients. Exact redirect registration including port, preapproved
first-party demo scopes only. No public refresh, password grant, implicit grant,
dynamic registration or third-party consent UI. API harness proves actual exchanges.
The absence of a hosted login UI is deliberate for this backend-only milestone.
