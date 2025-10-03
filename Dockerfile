# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS builder

WORKDIR /src

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/glyphctl ./cmd/glyphctl

FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /home/nonroot

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder --chown=nonroot:nonroot --chmod=0555 /out/glyphctl /usr/local/bin/glyphctl

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/glyphctl"]
CMD ["--help"]
