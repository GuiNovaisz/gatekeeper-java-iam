# Sessions

Spring Session JDBC schema comes from the official PostgreSQL schema, versioned
with Flyway. `SESSION` holds a browser bearer secret; its raw value is never listed.
The `primary_id` management handle is separate from `session_id`. List only the
current principal's handles/timestamps. Revoke one by management handle; revoke
other sessions by DELETE collection. Ownership is checked in the DELETE predicate.

Rotation after login is verified against actual HTTP cookies, not mocked authentication.
Session attributes contain only pending identity/expiry/version or the Spring
principal/authorities and credential version, never the submitted password.

20-minute inactivity expiry; application live checks reject stale/disabled accounts.
Logout, password reset/change and security-sensitive MFA changes revoke all sessions
and authorizations. No active-session secret appears in API responses, logs or evidence.
Concurrent already-running requests may complete; cancellation is not guaranteed.
