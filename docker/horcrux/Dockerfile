# Pinned by the multi-arch index digest so a rebuild of the same source always
# compiles with the same toolchain image. To move the pin: read the new digest
# with `docker buildx imagetools inspect golang:<tag>` and update the tag and
# digest together — and keep it in step with the GOTOOLCHAIN pin in
# .github/workflows/govulncheck.yml, which must scan the same toolchain this
# image builds with.
FROM golang:1.25-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59 AS build-env

RUN apk add --update --no-cache make git libc-dev bash gcc linux-headers eudev-dev

ARG TARGETARCH

WORKDIR /horcrux

ADD . .

# Build for the target platform with Alpine's native toolchain. buildx runs this
# stage under QEMU for non-native architectures, so the binary is compiled
# natively (CGO uses the in-image gcc) with no external cross toolchain fetched —
# the previous musl.cc download was both a reliability and a supply-chain risk.
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
# USER horcrux, and the container runtime takes $HOME from its home field —
# without it, config-dir resolution falls back to exec'ing getent/sh, which do
# not exist in this image. Do not replace it with a bare numeric USER.
COPY --from=busybox-min /etc/passwd /etc/passwd
COPY --from=busybox-min --chown=2345:2345 /home/horcrux /home/horcrux

WORKDIR /home/horcrux
USER horcrux
