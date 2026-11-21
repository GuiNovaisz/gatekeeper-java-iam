# Architecture

Modular monolith; Java 21; Spring Boot; Spring Security and its maintained Spring
Authorization Server integrated in Security 7.2; JDBC/PostgreSQL; Flyway. HTTP adapters delegate to
transactional application services; domain policies have no HTTP dependency.

```mermaid
flowchart TD
  B[Browser / CLI] --> S[Spring Security filter chains]
  C[Registered OAuth client] --> O[Spring Authorization Server / OIDC]
  S --> I[Identity and credentials]
  S --> M[TOTP and recovery]
  S --> A[Permissions and ownership]
  S --> R[Sessions and recovery]
  O --> T[Serialized token lifecycle]
  I & M & A & R & T --> D[(PostgreSQL / Flyway)]
  I & M & A & R & T --> L[Append-only audit]
  L --> D
  K[External PKCS12 / AES key] --> O
  K --> M
```

Security chains separate protocol endpoints, bearer-only `/resource/**`, and
browser APIs. Cookie mutation endpoints keep CSRF. No CORS allowlist is enabled.
Unclassified routes are denied. Protocol logic is delegated to the Spring provider;
extensions enforce S256 and serialized refresh/code consumption, not a custom OAuth protocol.

Database is the consistency boundary; there is no Redis/message broker. Browser
sessions use Spring Session JDBC. API responses never return session bearer secrets.
