# syntax=docker/dockerfile:1@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183

FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS builder

WORKDIR /src
RUN apk add --no-cache make

COPY go.mod go.sum ./
RUN go mod download

COPY Makefile ./
COPY cmd ./cmd
COPY internal ./internal

ARG TARGETOS=linux
ARG TARGETARCH

RUN GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" make build BIN_DIR=/out

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/kube-vpn /kube-vpn

EXPOSE 9999

ARG VERSION=dev
COPY <<EOF /version
${VERSION}
EOF

# Container runs as root by default to manage network interfaces, policy routes, and nftables inside the pod netns.
# nosemgrep: dockerfile.security.missing-user-entrypoint.missing-user-entrypoint
ENTRYPOINT ["/kube-vpn"]
