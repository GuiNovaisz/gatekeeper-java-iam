# ADR 005 — Serialized refresh rotation with family replay reaction

Status: accepted. Framework reuse=false rotates but does not alone prove family
revocation on old-token reuse. Decorate official code/refresh authentication providers
with a transaction, advisory token-fingerprint lock and identity/authorization row locks.
Persist old SHA-256 refresh fingerprint and authorization family ID after successful
rotation. Replay removes the family and commits that removal before throwing invalid_grant.

Two concurrent refreshes of the same value: one issuance, one denial, winner's family
then revoked. This favors theft response over retry convenience. Clients serialize
refresh, reauthenticate on ambiguous failures. No public-client refresh. Thirty-minute
rolling TTL; no separate absolute-family TTL in this milestone. Fingerprints must be
retained as long as descendants can be valid; retention is an operator limitation.
