# ADR 008 — Hashed single-use reset, local fake delivery boundary

Status: accepted. Generate 256-bit reset credential, retain SHA-256 digest only,
ten-minute expiry, generic request response. Under identity row lock atomically claim
unconsumed/unexpired token, hash replacement password, revoke sessions/authorizations,
increment version and audit in one transaction. New reset request invalidates old token.
MFA remains enabled. Tests prove replay, expiry, enumeration contract and one race winner.

No external mail dependency. Local/test-only bounded in-memory provider permits a
deterministic take-once test harness without exposing a public mailbox or logging
credentials. Other profiles need an actual provider bean and protected outbox/verified
delivery channel. Complete factor loss is an operator verification process, not a
public MFA bypass endpoint. Restarting fake delivery loses pending messages safely.
