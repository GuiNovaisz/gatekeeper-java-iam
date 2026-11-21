# ADR 002 — Separate browser sessions and OAuth bearer access

Status: accepted. Browser interactions require server-side revocation and CSRF;
OAuth consumers need standards-based bearer tokens. Use Spring Session JDBC and
separate security chains. Cookie APIs never accept a bearer token as an implicit
replacement, resource APIs never inherit the browser session. Deny other routes.

Five-minute JWTs allow offline external validation; local resource endpoint additionally
checks active persisted authorization and identity version. External offline consumers
retain expiry/skew revocation delay. Logout intentionally revokes all identity sessions
and authorizations. No credential is stored in localStorage. In-flight requests are
not cancelled by deletion; production design must account for that bounded race.
