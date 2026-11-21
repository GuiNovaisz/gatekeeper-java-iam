# Verified stack — 2026-11-20

Resolved versions are recorded from Maven, not inferred from search snippets. The
initial Boot 3.5 BOM failed a resolved-transitive OSV audit; it was replaced by the
current stable Boot 4.2 line. No advisory is waived just to make the scanner green.

| Component | Selected | Official evidence / rationale |
|---|---|---|
| Java target/runtime | 21 LTS | [Adoptium API](https://api.adoptium.net/v3/assets/latest/21/hotspot?architecture=x64&image_type=jdk&os=windows&vendor=eclipse); local verification 21.0.13.1+2, SHA256 bbebea1469996b276683c9299c227b294f85c847039c82633218186a4ad4fbf2 |
| Spring Boot | 4.2.0 | [official managed coordinates](https://docs.spring.io/spring-boot/appendix/dependency-versions/coordinates.html); current stable |
| Spring Framework | 7.1.0 | Boot 4.2.0 BOM |
| Spring Security | 7.2.0 | Boot 4.2.0 BOM |
| Spring Authorization Server | 7.2.0 (integrated) | [official getting started](https://docs.spring.io/spring-security/reference/servlet/oauth2/authorization-server/getting-started.html); integrated official implementation |
| Spring Session | 4.2.0 | Boot BOM; modular session JDBC starter |
| PostgreSQL server | 18.7 Alpine | [release notes](https://www.postgresql.org/docs/release/); supported maintenance version, not day-one PostgreSQL 19 |
| PostgreSQL JDBC | 42.7.14 | Boot BOM |
| Flyway | 12.11.0 | Boot BOM; modular Flyway starter + PostgreSQL module |
| Bouncy Castle | 1.85 | [official provider](https://www.bouncycastle.org/download/bouncy-castle-java/), fixes [GHSA-9pwp-9qqc-pr26](https://github.com/advisories/GHSA-9pwp-9qqc-pr26) / [GHSA-qp49-qgx5-5m26](https://github.com/advisories/GHSA-qp49-qgx5-5m26) |
| Commons Compress (test transitive pin) | 1.28.0 | [Apache security notices](https://commons.apache.org/proper/commons-compress/security.html); audited archive parser |
| Testcontainers | 2.0.5 | Boot BOM; real PostgreSQL, no disabledWithoutDocker |
| Maven Wrapper distribution | 3.9.16 | [Maven downloads](https://maven.apache.org/download.cgi); stable 3.9 line; official wrapper only-script distribution |
| JUnit / Surefire / Failsafe | 6.1.3 / 3.6.1 / 3.6.1 | resolved by Boot parent |
| Jackson application / harness compatibility | 3.1.8 / 2.21.8 | Boot BOM; Jackson 2 is test-only HTTP harness |
| Tomcat / Micrometer | 11.0.27 / 1.18.0 | Boot BOM |

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
