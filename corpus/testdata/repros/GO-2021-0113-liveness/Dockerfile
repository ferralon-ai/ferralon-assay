# Builds the GO-2021-0113 LIVENESS-AUGMENTED repro server (vulnerable x/text v0.3.6) and
# runs it on 127.0.0.1:8080. Same handler/route/port as -trivial, but the success path
# also emits a marker-gated benign liveness beacon (see main.go LIVENESS SOUNDNESS). The
# runtime is busybox so the canary engine's trigger argv (sh -c "/server & sleep 1; wget
# ...") can be exec'd into the container. The seed is planted at /tmp/tegron_canary; the
# panic-recovery path beacons the EXPLOIT signal when language.Parse faults on a malformed
# tag, and the success path beacons the LIVENESS signal only when X-Tegron-Liveness is set.
FROM golang:1.26.3 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -mod=vendor -o /out/server .

FROM busybox:1.36
COPY --from=build /out/server /server
EXPOSE 8080
# CMD (not ENTRYPOINT) so Provision's `sleep 300` override cleanly REPLACES the start
# command — the container becomes a quiet long-lived shell, and the canary engine's
# trigger argv (which starts /server in the background and sends the malformed
# Accept-Language request) is the sole thing that drives the ingress (T4 Decision 2).
CMD ["/server"]
