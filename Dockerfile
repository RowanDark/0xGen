# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS builder

WORKDIR /src

RUN apk add --no-cache git ca-certificates

# Pre-create the directories that are bind mounted in the runtime image so they can
# be copied with the desired ownership/permissions without running commands in the
# distroless stage.
RUN install -d -m 0755 /out \
    && install -d -m 0700 /home/nonroot \
    && install -d -m 0700 /home/nonroot/.oxg \
    && install -d -m 0700 /home/nonroot/.cache

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/0xgenctl ./cmd/0xgenctl

FROM gcr.io/distroless/static-debian12:nonroot

ENV HOME=/home/nonroot \
    XDG_CONFIG_HOME=/home/nonroot/.oxg \
    XDG_CACHE_HOME=/home/nonroot/.cache

WORKDIR /home/nonroot

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder --chown=nonroot:nonroot --chmod=0555 /out/0xgenctl /usr/local/0xgen/bin/0xgenctl
COPY --from=builder --chown=nonroot:nonroot --chmod=0700 /home/nonroot/.oxg /home/nonroot/.oxg
COPY --from=builder --chown=nonroot:nonroot --chmod=0700 /home/nonroot/.cache /home/nonroot/.cache
COPY --from=builder --chown=nonroot:nonroot --chmod=0755 /out /out

VOLUME ["/home/nonroot/.oxg", "/home/nonroot/.cache", "/out"]

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/0xgen/bin/0xgenctl"]
CMD ["--help"]
