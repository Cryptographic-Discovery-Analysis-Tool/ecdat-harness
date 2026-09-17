# harness §6/§8.1: JDK build should be pinned here once the harness commits
# to one (Lock §6.1 / ecdat/docs/open-issues.md OI-002: no pin exists yet).
# Using Amazon Corretto 25 for now -- this is the JDK actually used for the
# CFG-R1 validation runs in harness/eval/experiments.md, recorded exactly
# rather than left ambiguous, but it is NOT a frozen harness pin.
FROM maven:3.9.16-amazoncorretto-25-alpine AS build
WORKDIR /src
COPY pom.xml .
COPY src ./src
COPY keystore ./keystore
RUN --mount=type=cache,target=/root/.m2 mvn -q -DskipTests package

FROM amazoncorretto:25-alpine
WORKDIR /app
COPY --from=build /src/target/payment-gateway-*.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]
