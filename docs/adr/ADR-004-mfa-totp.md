# ADR 004 — TOTP with possession proof and monotonic replay prevention

Status: accepted. RFC 6238 SHA1 / six digits / 30-second steps supports common
authenticator apps. Use JCA HMAC, RFC dynamic truncation and RFC test vectors, not
a new cryptographic construction. Accept one step either side, reject already accepted
and older steps under identity row lock. Enrollment expires and requires possession
before activation. Current password gates enrollment; activation revokes credentials.

Seeds need reversible protection for verification: AES-256-GCM external 32-byte key,
fresh 96-bit nonce, authenticated context. Recovery codes are high-entropy hashed,
single-use, shown once. No KMS, phishing resistance or automatic encryption-key rotation
claim; local environment/backup compromise remains significant.
