# Corpus repro: real Gogs v0.13.0 (pre-fix predecessor) for the CVE-2024-55947
# symlink arbitrary-file-write two-trace. Builds gogs from source, bakes in
# python3 + git + the intrinsic-beacon driver. NO ENTRYPOINT: the platform sandbox
# provisions the image with `sleep 300` overriding any entrypoint (docker.go:78) and
# drives the workload via the trigger argv (a single `sh -c` that starts `gogs web`,
# provisions via /install, commits the symlink, PUTs the payload, confirms the
# out-of-repo write, and beacons $TEGRON_OOB_URL). Predecessor / patched share this
# Dockerfile and differ only by the GOGS_COMMIT build-arg.
FROM golang:1.20-bullseye AS build
ARG GOGS_COMMIT=v0.13.0
ENV CGO_ENABLED=1
RUN apt-get update && apt-get install -y --no-install-recommends git build-essential \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone https://github.com/gogs/gogs . && git checkout "${GOGS_COMMIT}"
# -mod=mod (network on) because 0.13.x is not expected to ship a vendor/ dir.
RUN go build -tags "sqlite sqlite_unlock_notify" -mod=mod -o /out/gogs .

FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y --no-install-recommends git openssh-client ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -d /home/git -s /bin/bash git
# Out-of-repo sentinel: a benign canary landing here proves the symlink escape.
RUN mkdir -p /srv/sentinel && chown git:git /srv/sentinel
COPY --from=build /out/gogs /usr/local/bin/gogs
COPY poe_driver_beacon.py /opt/poe_driver_beacon.py
USER git
WORKDIR /home/git
# gogs derives its work dir (log/, data/, custom/) from the executable's directory
# unless GOGS_WORK_DIR is set. The binary lives in root-owned /usr/local/bin, so as
# the non-root `git` user gogs FATAL-exits at boot trying `mkdir /usr/local/bin/log`
# (before it ever serves /install). Pin the work dir to git-writable /home/git so
# boot-time InitLogging succeeds and `gogs web` actually comes up on :3000.
ENV GOGS_WORK_DIR=/home/git
EXPOSE 3000
