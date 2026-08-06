# Builds the corpus repro server and runs it on 127.0.0.1:8080. The runtime is busybox so
# the proof engine's trigger argv (sh -c "/server & ...; wget ...") can be exec'd into the
# container. The seed is planted at /tmp/tegron_canary; the server beacons it to
# $TEGRON_OOB_URL only when the vulnerable path fires (see main.go SOUNDNESS notes).
FROM golang:1.26.3 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/server .

FROM busybox:1.36
COPY --from=build /out/server /server
EXPOSE 8080
# CMD (not ENTRYPOINT) so Provision's long-lived override cleanly REPLACES the start command;
# the trigger argv is the sole thing that drives the ingress.
CMD ["/server"]
