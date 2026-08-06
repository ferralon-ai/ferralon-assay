# Builds the GO-2021-0264 reachable repro on a VULNERABLE Go toolchain (1.17.1, in the
# affected 1.17.0-1.17.2 range) and runs the ZIP-upload service on 127.0.0.1:8080.
# Pinning the vulnerable toolchain is what makes the (*zip.Reader).Open panic latent;
# however there is no canary-engine strategy that crafts the pathological archive, so
# the case stops at stopped_capability rather than minting a proof. Busybox runtime so
# the trigger argv can be exec'd into the container if a future engine is registered.
FROM golang:1.17.1 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/server .

FROM busybox:1.36
COPY --from=build /out/server /server
EXPOSE 8080
ENTRYPOINT ["/server"]
