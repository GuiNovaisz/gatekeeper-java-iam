# ADR 001 — Argon2id password and confidential client hashing

Status: accepted. Spring Security recommends adaptive one-way password functions
and deployment-specific cost tuning. Choose Argon2id through Spring's encoder,
19,456 KiB memory, 2 iterations, parallelism 1, 16-byte salt, 32-byte hash. Bouncy
Castle supplies its implementation. bcrypt was evaluated; its input byte-length
limitations complicate long Unicode passphrases, so it is not the default.

Cost: each hash consumes about 19 MiB working memory plus implementation overhead;
latency depends on hardware and is not asserted as a measured value here. Source
and account throttles limit repeated online work; production needs edge limits and
capacity measurements. Delegating `{argon2id}` format permits new encoder IDs and
an explicit migration/re-hash after verified login; automatic migration is not yet
implemented. Never downgrade existing hashes silently. No reversible password encryption.

Sources: [Spring password storage](https://docs.spring.io/spring-security/reference/features/authentication/password-storage.html),
[OWASP password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
