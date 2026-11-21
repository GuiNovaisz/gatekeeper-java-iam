# Account recovery

Public request returns empty 202 for known/unknown active account. Input validation
and rate limits are independent of existence: 10/source/5 minutes, 3/account/5 minutes.
Reset submission: 10/source/5 minutes. No perfect timing-equality claim.

256-bit CSPRNG reset token, 10-minute expiry, SHA-256 digest only in password_reset.
New request invalidates previous reset credentials. Reset locks identity then atomically
marks one unconsumed, unexpired digest. Password validation/hash, consumption, version
increment, session/token deletion and audit commit together. Invalid/expired/replayed
values get generic 400. Concurrent attempts produce exactly one winner.

`RecoveryDelivery` is a boundary. `LocalRecoveryDelivery` exists only under local/test
profiles: bounded 100-message in-memory mailbox with TTL, take-once Java test API;
there is no HTTP mailbox or logging of reset credentials. It is deterministic for
the integration harness, not an email provider. Restart loses local mailbox contents;
request a new token. Nonlocal startup requires an actual provider bean and deliberately
fails without one. Production provider must prove channel ownership, protect an outbox
and avoid timing/data oracles. No external email integration in this milestone.

Reset never disables MFA or regenerates recovery codes. A user who loses all factors
needs an external, documented operator identity-verification process. No insecure
public bypass/admin recovery endpoint is provided.
