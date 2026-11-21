# ADR 006 — External persistent signing material

Status: accepted. Load RSA >=3072 PKCS12 alias signing; password from environment.
Local configure generates a fresh store once and refuses overwrite. RS256 JWT kid is
derived from public key; JWKS emits public parameters only. Reuse across restarts
avoids accidental token invalidation caused by ephemeral boot keys.

Production should use managed key custody and controlled dual-public-key overlap.
Current implementation loads one key; overlap/live rotation is not implemented.
Replacing/restarting breaks old verification unless consumers retain cached public
keys. Token-lifecycle runbook describes the extension and emergency revocation needs.
No private signing material belongs in Git, reports, image build context or CI artifacts.
