# Token lifecycle

Access JWT: RS256, opaque `sub`, configured `iss`, `aud=gatekeeper-resource`,
scope, iat/exp/jti, kid and decimal credential-version `cv`. Five-minute TTL plus
consumer validation skew (Spring default 60 seconds). ID token is for the client
audience and nonce, not an API access credential. Resource server validates signature,
time, issuer and audience before doing an additional live authorization/version lookup.

Confidential code client gets a 30-minute rotating refresh token; public client
gets no refresh token. `reuseRefreshTokens=false` is necessary but alone does not
provide family replay response. Gatekeeper's provider decorator remembers spent
refresh digests and commits family deletion before reporting invalid_grant.

Serialization: SHA-256 fingerprint → PostgreSQL advisory transaction lock → identity
row lock → authorization row lock → re-read token → official provider → save spent
fingerprint/audit → commit. Reset/state-change use identity → authorization order.
No two exchanges of one code/refresh may create independently valid token families.
Parallel refresh can revoke the winning family; clients must serialize their requests.

Spent fingerprints are not automatically deleted; retain while a family can be active.
The schema expiration timestamp is informational, not a promise of automatic purge.
Before production, add reviewed retention jobs for expired authorizations/fingerprints,
reset rows and throttle buckets. Storage growth remains a local foundation limit.

RFC 7009 `/oauth2/revoke` uses Spring client authentication. Revoking refresh also
invalidates related tokens according to Spring semantics. Browser logout deletes all
authorizations. Password reset/change, MFA enable/disable, account lock/disable do the
same. Local resource checks reflect revocation; external offline JWT consumers see
expiry-bound revocation. Key removal cannot selectively revoke one user's JWT.

Signing store uses external PKCS12 alias `signing`, RSA >=3072, stable public-key-derived
kid; no private material in source. No live overlapping key rotation implementation.
Runbook: provision new signing key, retain old **public** key for max access/ID token
TTL + skew, switch signer kid, publish union JWKS during overlap, remove old public
key after overlap. Current single-key loader needs an extension for that union;
replacing the store and restarting immediately breaks verification of old tokens.
Treat emergency compromise separately: revoke authorizations, expire sessions,
rotate key and require consumers to refresh JWKS; no instant external revocation claim.
