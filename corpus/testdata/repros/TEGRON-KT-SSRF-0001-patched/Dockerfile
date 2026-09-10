# Builds the Kotlin corpus repro server and runs it on 127.0.0.1:8080. Kotlin is a
# JVM/bytecode lane, so the build stage compiles the committed .kt source with
# kotlinc (the analogue of the Java repro's in-container javac) — no compiled
# artifact is checked in. The runtime base carries a JRE plus a POSIX shell + wget
# so the proof engine's trigger argv (sh -c "/server & sleep 1; wget ...
# /fetch?target=internal") can be exec'd into the container. /server is a launcher
# that execs `java -cp /app/app.jar com.example.web.MainKt`. The seed is planted at
# /tmp/tegron_canary; the server beacons it to $TEGRON_OOB_URL only when the
# vulnerable SSRF path fires (see UrlFetcher.kt SOUNDNESS notes).
FROM eclipse-temurin:21-jdk AS build
ARG KOTLIN_VERSION=2.0.21
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl unzip \
    && rm -rf /var/lib/apt/lists/* \
    && curl -sSL -o /tmp/kotlin.zip \
        "https://github.com/JetBrains/kotlin/releases/download/v${KOTLIN_VERSION}/kotlin-compiler-${KOTLIN_VERSION}.zip" \
    && unzip -q /tmp/kotlin.zip -d /opt \
    && rm /tmp/kotlin.zip
ENV PATH="/opt/kotlinc/bin:${PATH}"
WORKDIR /src
COPY src ./src
RUN kotlinc $(find src -name '*.kt') -include-runtime -d /out/app.jar

FROM eclipse-temurin:21-jre
RUN if ! command -v wget >/dev/null 2>&1; then \
        (apt-get update && apt-get install -y --no-install-recommends wget && rm -rf /var/lib/apt/lists/*) || true; \
    fi
COPY --from=build /out /app
# /server is the launcher the trigger argv runs: it execs the JVM entry point.
RUN printf '#!/bin/sh\nexec java -cp /app/app.jar com.example.web.MainKt "$@"\n' > /server && chmod +x /server
EXPOSE 8080
# CMD (not ENTRYPOINT) so Provision's long-lived override cleanly REPLACES the start command;
# the trigger argv is the sole thing that drives the ingress.
CMD ["/server"]
