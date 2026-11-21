FROM maven:3.9.16-eclipse-temurin-21-alpine@sha256:308cba8b638ed7e4658cea3f8399066219466211c805f6d5728c3c9c7614661b AS build
WORKDIR /build
COPY pom.xml .
RUN mvn -B -ntp dependency:go-offline
COPY src ./src
RUN mvn -B -ntp -DskipTests package

FROM eclipse-temurin:24-jre-alpine@sha256:4044b6c87cb088885bcd0220f7dc7a8a4aab76577605fa471945d2e98270741f
RUN addgroup -S -g 10001 gatekeeper && adduser -S -u 10001 -G gatekeeper gatekeeper
WORKDIR /app
COPY --from=build --chown=10001:10001 /build/target/gatekeeper-java-iam-0.1.0.jar app.jar
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["java","-XX:MaxRAMPercentage=65","-jar","/app/app.jar"]
