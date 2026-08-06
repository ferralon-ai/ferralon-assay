# Builds the GO-2021-0113 trivial repro server (vulnerable x/text v0.3.6) and runs it
# on 127.0.0.1:8080. The runtime is busybox so the canary engine's trigger argv
# (sh -c "wget ... Accept-Language: <malformed>") can be exec'd into the container.
# The seed is planted at /tmp/tegron_canary; the server's panic-recovery path beacons
# it to $TEGRON_OOB_URL only when language.Parse faults on the malformed tag.
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
