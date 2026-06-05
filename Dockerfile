FROM golang:1.25-alpine AS builder
ARG VERSION=unknown
WORKDIR /src
COPY go.mod go.sum ./
COPY replace/ replace/
RUN go mod download
COPY . .
RUN apk add --no-cache git build-base && make build VERSION="${VERSION}" TAGS="with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,with_cloudflared,badlinkname,tfogo_checklinkname0,with_grpc,with_awg,with_xdp"

FROM alpine
RUN apk add --no-cache bash tzdata ca-certificates nftables
COPY --from=builder /src/sing-box /usr/local/bin/sing-box
ENTRYPOINT ["sing-box"]
