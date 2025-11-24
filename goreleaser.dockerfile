# syntax=docker/dockerfile:1.7
# Dockerfile for GoReleaser - uses pre-built binaries

FROM gcr.io/distroless/static-debian12:nonroot

ENV HOME=/home/nonroot \
    XDG_CONFIG_HOME=/home/nonroot/.oxg \
    XDG_CACHE_HOME=/home/nonroot/.cache

WORKDIR /home/nonroot

# Copy the pre-built binary from GoReleaser's build context
# GoReleaser places the binary in the root of the build context
COPY 0xgenctl /usr/local/0xgen/bin/0xgenctl

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/0xgen/bin/0xgenctl"]
CMD ["--help"]
