# ADR 007 — Persistent append-only security events

Status: accepted. Write fixed action/outcome and opaque IDs to PostgreSQL. Trigger
denies UPDATE/DELETE/TRUNCATE for normal SQL operations. Transactional success events
commit with mutations; failed-login events are written independently of rejected auth.
No arbitrary metadata means no accidental credential payload sink. Metrics label only
bounded actions/outcomes; correlation UUID is a log/audit field, never a metric label.

Local application DB owner can disable the trigger; this is append-only application
behavior, not cryptographic immutability or protection from DB administrators.
Separate production roles/external retention remain necessary. Retention/deletion
is documented operator work; no claim of complete GDPR workflow.
