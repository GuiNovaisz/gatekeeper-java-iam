# Verified stack — 2026-11-20

Selected supported maintenance lines deliberately; newest major releases are not
automatically a reason to migrate. Resolved versions are recorded from Maven, not
inferred from search snippets.

| Component | Selected | Official evidence / rationale |
|---|---|---|
| Java target/runtime | 21 LTS | [Adoptium API](https://api.adoptium.net/v3/assets/latest/21/hotspot?architecture=x64&image_type=jdk&os=windows&vendor=eclipse); local verification 21.0.13.1+2, SHA256 bbebea1469996b276683c9299c227b294f85c847039c82633218186a4ad4fbf2 |
| Spring Boot | 3.5.16 | [official managed coordinates](https://docs.spring.io/spring-boot/3.5/appendix/dependency-versions/coordinates.html); stable compatible maintenance line |
| Spring Security | 6.5.11 | Boot 3.5.16 BOM |
| Spring Authorization Server | 1.5.8 | [official getting started](https://docs.spring.io/spring-authorization-server/reference/getting-started.html); maintained official 1.5 line; newer Security 7 integrates authorization-server code |
| Spring Session | 3.5.7 | Boot BOM |
| PostgreSQL server | 18.7 Alpine | [release notes](https://www.postgresql.org/docs/release/); supported maintenance version, not day-one PostgreSQL 19 |
| PostgreSQL JDBC | 42.7.11 | Boot BOM |
| Flyway | 11.7.2 | Boot BOM; explicit PostgreSQL module |
| Bouncy Castle | 1.84 | [official provider](https://www.bouncycastle.org/download/bouncy-castle-java/), Maven Central artifact resolved |
| Testcontainers | 1.21.4 | Boot BOM; real PostgreSQL, no disabledWithoutDocker |
| Maven Wrapper distribution | 3.9.16 | [Maven downloads](https://maven.apache.org/download.cgi); stable 3.9 line; official wrapper only-script distribution |
| JUnit / Surefire / Failsafe | BOM / 3.5.6 / 3.5.6 | resolved by Boot parent; see dependency tree for transitive versions |

GitHub Actions latest stable releases queried from official GitHub release API:

| Action | Version | Pinned commit |
|---|---|---|
| actions/checkout | v7.0.1 | 3d3c42e5aac5ba805825da76410c181273ba90b1 |
| actions/setup-java | v6.3.0 | d1374f8ac74474200d16ef8ecee22c7ae7a51880 |
| actions/upload-artifact | v7.0.2 | cf430e030ddbb5b0abf93d22962f4752f3646cd9 |
| actions/dependency-review-action | v5.0.1 | bbc44d14a204704ccc493733616cd1e93a0321ec |

Sources: [checkout releases](https://github.com/actions/checkout/releases),
[setup-java releases](https://github.com/actions/setup-java/releases),
[upload-artifact releases](https://github.com/actions/upload-artifact/releases),
[dependency-review releases](https://github.com/actions/dependency-review-action/releases).
Dockerfile pins resolved multi-platform image digests. Updating a digest requires
rebuilding, tests and Compose clean-start. Version pins do not replace vulnerability review.

Standards: [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238),
[RFC 7636](https://www.rfc-editor.org/rfc/rfc7636),
[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700),
[OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html).
