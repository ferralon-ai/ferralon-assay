# build/jvm-toolchain/Dockerfile — one reusable JVM toolchain image (JDK 21 + Maven + Gradle).
#
# Purpose: a fixture-GENERATION and test environment ONLY. It is invoked on a
# maintainer machine (or a one-off CI toolchain job) to mint COLD ground-truth
# fixtures for the JVM dependency-inventory resolver BEFORE that resolver is
# written — the native tool captures (mvn dependency:tree / gradle dependencies,
# the oracle) plus the resolved .m2 / modules-2 cache slice the resolver reads.
# The resolver code itself stays build-tool-free and NEVER runs this image at
# analysis time (mirrors the scipjava.go TEGRON_JAVA_ANALYZER_IMAGE gate: the
# container is a Prove/fixture seam, never the Assess path).
#
# One image, two consumers (the reuse seam): (1) this cycle's benchmark captures
# under internal/plugin/javaanalysis/testdata/, and (2) BASALT's corpus harness
# (its honest-absent-for-lack-of-JVM gap). It takes a project dir at /work and
# emits captures + a cache slice; it is corpus-agnostic.
#
# Base is pinned by digest for reproducibility; Maven ships in the base
# (Apache Maven 3.9.x, Temurin JDK 21), Gradle is added pinned by version+SHA-256.
# The exact JDK/Maven/Gradle triple is stamped into every fixture's
# tool-version.txt at capture time so provenance is auditable and regenerable.

FROM maven:3.9-eclipse-temurin-21@sha256:8f6ac126f7810bb5549c4cd122d2bf0e9cda5bdeb0838aa928f09e779fd8bef8

# Gradle — pinned by version and distribution SHA-256 (verify-before-install).
ARG GRADLE_VERSION=8.10.2
ARG GRADLE_SHA256=31c55713e40233a8303827ceb42ca48a47267a0ad4bab9177123121e71524c26
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends unzip; \
    rm -rf /var/lib/apt/lists/*; \
    curl -fsSL -o /tmp/gradle.zip "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip"; \
    echo "${GRADLE_SHA256}  /tmp/gradle.zip" | sha256sum -c -; \
    unzip -q /tmp/gradle.zip -d /opt; \
    ln -s "/opt/gradle-${GRADLE_VERSION}/bin/gradle" /usr/local/bin/gradle; \
    rm /tmp/gradle.zip; \
    gradle --version

# Gradle needs a writable, deterministic home; keep it inside the image so a
# container-local cache warm doesn't leak onto the host mount.
ENV GRADLE_USER_HOME=/root/.gradle

# The capture driver. It takes the case dir (relative to /work) as $1, runs the
# native tool, and snapshots the cache slice the resolver reads.
COPY generate-captures.sh /opt/capture/run.sh
RUN chmod +x /opt/capture/run.sh

WORKDIR /work
ENTRYPOINT ["/opt/capture/run.sh"]
