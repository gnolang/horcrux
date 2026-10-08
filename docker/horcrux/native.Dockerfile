# Same golang image as docker/horcrux/Dockerfile, pinned by the same multi-arch
# index digest; move the pins together as docker/horcrux/Dockerfile describes.
FROM golang:1.27-alpine@sha256:738d1cf061836894ff6bb8c33881080ac66de8cf0586615012a0c8f592649cfa AS build-env

RUN apk add --update --no-cache curl make git libc-dev bash gcc linux-headers eudev-dev

WORKDIR /horcrux

ADD go.mod go.sum ./

RUN go mod download

ADD . .

RUN CGO_ENABLED=1 LDFLAGS='-linkmode external -extldflags "-static"' make install

# Build-only donor stage: creates the horcrux user, its passwd entry and its
# home directory. Only files are copied out of it — never its binary.
FROM busybox:1.34.1-musl@sha256:8d80daaf06e357574a3891b89e4f81d031768a918c4e72e5fbb99fa9d6813eac AS busybox-min
RUN addgroup --gid 2345 -S horcrux && adduser --uid 2345 -S horcrux -G horcrux

# Final image, assembled by COPY alone in the same shape as the release image
# (docker/horcrux/Dockerfile), so the e2e tests run an image of the same shape
# as the one that ships: no shell, no utilities, no RUN.
FROM scratch

LABEL org.opencontainers.image.source="https://github.com/gnolang/horcrux"

# Install chain binaries
COPY --from=build-env /go/bin/horcrux /bin/horcrux

# Install trusted CA certificates
COPY --from=build-env /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem

# Install horcrux user; docker/horcrux/Dockerfile explains why the passwd file
# is required.
COPY --from=busybox-min /etc/passwd /etc/passwd
COPY --from=busybox-min --chown=2345:2345 /home/horcrux /home/horcrux

WORKDIR /home/horcrux
USER horcrux
