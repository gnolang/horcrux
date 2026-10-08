# Pinned by the multi-arch index digest so a rebuild of the same source always
# compiles with the same Go toolchain. The C toolchain and musl, which is linked
# statically into the binary, come from Alpine's package index at build time
# (apk add below), so they can differ between two builds of the same source.
# To move the pin: read the new digest with
# `docker buildx imagetools inspect golang:<tag>` and update the tag and digest
# together, here and in docker/horcrux/native.Dockerfile — and keep it in step
# with the GOTOOLCHAIN pin in .github/workflows/govulncheck.yml, which must scan
# the same Go toolchain this image builds with, and with the toolchain lines in
# go.work and go.mod. .github/workflows/image.yml fails when any of them differ.
FROM golang:1.27-alpine@sha256:738d1cf061836894ff6bb8c33881080ac66de8cf0586615012a0c8f592649cfa AS build-env

RUN apk add --update --no-cache make git libc-dev bash gcc linux-headers eudev-dev

ARG TARGETARCH

WORKDIR /horcrux

ADD . .

# Build for the target platform with Alpine's native toolchain. buildx runs this
# stage under QEMU for non-native architectures, so the binary is compiled
# natively (CGO uses the in-image gcc) with no external cross toolchain fetched,
# which would be both a reliability and a supply-chain risk.
RUN GOOS=linux GOARCH=$TARGETARCH CGO_ENABLED=1 LDFLAGS='-linkmode external -extldflags "-static"' make install

RUN if [ -d "/go/bin/linux_${TARGETARCH}" ]; then mv /go/bin/linux_${TARGETARCH}/* /go/bin/; fi

# Build-only donor stage: creates the horcrux user, its passwd entry and its
# home directory. Only files are copied out of it — never its binary, so the
# final image carries no shell and no busybox applets.
FROM busybox:1.34.1-musl@sha256:8d80daaf06e357574a3891b89e4f81d031768a918c4e72e5fbb99fa9d6813eac AS busybox-min
RUN addgroup --gid 2345 -S horcrux && adduser --uid 2345 -S horcrux -G horcrux

# Final image, assembled by COPY alone: the statically linked horcrux binary,
# the CA bundle, and the horcrux user. No shell, no utilities, no RUN — code in
# the container has nothing to execute but horcrux itself.
FROM scratch

LABEL org.opencontainers.image.source="https://github.com/gnolang/horcrux"

# Install chain binaries
COPY --from=build-env /go/bin/horcrux /bin/horcrux

# Install trusted CA certificates
COPY --from=build-env /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem

# Install horcrux user. The passwd file is load-bearing twice: it resolves
# USER horcrux, and the container runtime takes $HOME from its home field.
# Without an entry for the uid, Docker sets HOME=/ and horcrux looks for its
# config under /.horcrux. Do not replace the passwd file with a bare numeric
# USER. Independently of this file, if HOME reaches horcrux unset, its default
# config-dir lookup execs getent, which this image does not have, and fails;
# --home skips that lookup.
COPY --from=busybox-min /etc/passwd /etc/passwd
COPY --from=busybox-min --chown=2345:2345 /home/horcrux /home/horcrux

WORKDIR /home/horcrux
USER horcrux
