# Builds the GO-2021-0113 PATCHED repro server (fixed x/text v0.3.7) and runs it on
# 127.0.0.1:8080. Same image shape as the trivial repro, but on v0.3.7 language.Parse
# returns an error instead of panicking, so the recover block is never entered and the
# seed is never beaconed — the build is silent even if the canary engine runs.
FROM golang:1.26.3 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -mod=vendor -o /out/server .

FROM busybox:1.36
COPY --from=build /out/server /server
EXPOSE 8080
ENTRYPOINT ["/server"]
