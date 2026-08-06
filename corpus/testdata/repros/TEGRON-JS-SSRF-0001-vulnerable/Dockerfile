# Builds the JS corpus repro server and runs it on 127.0.0.1:8080. The runtime base
# carries Node plus a POSIX shell + wget so the proof engine's trigger argv
# (sh -c "/server & sleep 1; wget ... /fetch?target=internal") can be exec'd into the
# container. /server is a launcher that execs `node /app/app.js`. The seed is planted
# at /tmp/tegron_canary by the canary engine; the server beacons it to $TEGRON_OOB_URL
# only when the vulnerable SSRF path fires (see src/fetcher.js SOUNDNESS notes).
#
# The repro is dependency-free (no `npm install`): src/app.js hand-rolls an
# Express-shaped app.get(path, handler) router over the Node http module, so the
# source analyzer recognizes the route idiom while the image needs no node_modules.
FROM node:20-slim
RUN if ! command -v wget >/dev/null 2>&1; then \
        (apt-get update && apt-get install -y --no-install-recommends wget && rm -rf /var/lib/apt/lists/*) || true; \
    fi
WORKDIR /app
COPY src ./
# /server is the launcher the trigger argv runs: it execs the Node entry point.
RUN printf '#!/bin/sh\nexec node /app/app.js "$@"\n' > /server && chmod +x /server
EXPOSE 8080
# CMD (not ENTRYPOINT) so Provision's long-lived override cleanly REPLACES the start command;
# the trigger argv is the sole thing that drives the ingress.
CMD ["/server"]
