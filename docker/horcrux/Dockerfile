FROM golang:1.25-alpine AS build-env

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

# Static busybox for the final scratch image: one multi-call binary that the
# hard links below point at. Pinned by digest because it ships in the image.
FROM busybox:1.34.1-musl@sha256:8d80daaf06e357574a3891b89e4f81d031768a918c4e72e5fbb99fa9d6813eac AS busybox-min
RUN addgroup --gid 2345 -S horcrux && adduser --uid 2345 -S horcrux -G horcrux

# Use ln and rm from full featured busybox for assembling final image
FROM busybox:1.34.1-musl@sha256:8d80daaf06e357574a3891b89e4f81d031768a918c4e72e5fbb99fa9d6813eac AS busybox-full

# Build final image from scratch
FROM scratch

LABEL org.opencontainers.image.source="https://github.com/gnolang/horcrux"

WORKDIR /bin

# Install ln (for making hard links) and rm (for cleanup) from full busybox image (will be deleted, only needed for image assembly)
COPY --from=busybox-full /bin/ln /bin/rm ./

# Install busybox as the shell binary. The hard links below are the only applet
# names on PATH; the multi-call binary still runs any applet when invoked with a
# spoofed argv[0], so the container is hardened at the runtime, not by this image.
COPY --from=busybox-min /bin/busybox /bin/sh

# Add hard links for read-only utils, then remove ln and rm
# Will then only have one copy of the busybox minimal binary file with all utils pointing to the same underlying inode
RUN ln sh pwd && \
    ln sh ls && \
    ln sh cat && \
    ln sh less && \
    ln sh grep && \
    ln sh sleep && \
    ln sh env && \
    ln sh tar && \
    ln sh tee && \
    ln sh du && \
    rm ln rm

# Install chain binaries
COPY --from=build-env /go/bin/horcrux /bin

# Install trusted CA certificates
COPY --from=build-env /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem

# Install horcrux user
COPY --from=busybox-min /etc/passwd /etc/passwd
COPY --from=busybox-min --chown=2345:2345 /home/horcrux /home/horcrux

WORKDIR /home/horcrux
USER horcrux
