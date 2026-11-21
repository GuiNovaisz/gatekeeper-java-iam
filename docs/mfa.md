# TOTP and recovery codes

RFC 6238 interoperable SHA1 profile: 160-bit CSPRNG seed, Base32, 6 digits, 30-second
step, +/-1 step window. Uses JCA HMAC and dynamic truncation specified by the RFC;
RFC vectors verify the six-digit profile. No custom cryptographic primitive.

Authenticated POST enrollment requires current password. Seed/otpauth URI returned
once; encrypted pending seed expires after 5 minutes. No active seed until POST
activation validates a current code. Activation invalidates sessions/tokens and
returns ten recovery codes once. Store them outside the browser. Reauthenticate.

Under an identity row lock, the last accepted timestep monotonically increases.
An already-accepted or older step cannot authenticate again across any context
for this identity, including enrollment proof. Accepting a future step means the
user must wait beyond that step; keep clocks synchronized. Real-time phishing is
still possible. This guarantee is stronger than context-only replay prevention.

Recovery codes have 128 bits of CSPRNG entropy, stored as SHA-256 digests, consumed
by atomic DELETE under the same row lock. Two concurrent uses have exactly one
winner. A recovery code completes a pending password+MFA login; it is not a standalone
password reset. Codes can be regenerated (invalidates old codes) using current
password + fresh TOTP. Disabling MFA also requires both proofs and revokes all
sessions/tokens. Account password reset never disables MFA.

AES-256-GCM seed encryption authenticates ciphertext; key is external environment,
not a database field. Key/DB snapshots together expose seeds; local .env custody
is not KMS. Rotating this key requires decrypt/re-encrypt under controlled migration;
losing it makes enrolled TOTP unusable. See operations.md before recovery.
