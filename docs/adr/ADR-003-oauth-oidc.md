# ADR 003 — Official authorization server, constrained first-party clients

Status: accepted. Use Spring Authorization Server integrated in Spring Security 7.2.0
with Boot 4.2.0; do not write grant/token/PKCE protocols. Dependency audit rejected the
initial Boot 3.5 line because its BOM resolved known vulnerable transitives. The current
stable base supplies patched Framework/Jackson/Tomcat/JDBC dependencies. Bouncy Castle
1.85 and the audited Commons Compress parser are explicit pins. All functional and
protocol proofs must be rerun after a security dependency upgrade.

Enable OIDC, discovery, public JWKS, Authorization Code and S256 for both public and
confidential seeded clients. Exact redirect registration including port, preapproved
first-party demo scopes only. No public refresh, password grant, implicit grant,
dynamic registration or third-party consent UI. API harness proves actual exchanges.
The absence of a hosted login UI is deliberate for this backend-only milestone.
