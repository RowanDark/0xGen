# Container Hardening

Glyph publishes a container image intended for CI pipelines and tightly scoped
runtime environments. The image is built on the distroless `static-debian12`
flavour, runs as an unprivileged user, and exposes no package manager or shell.
This document captures the default hardening and recommended runtime profile.

## Image build

* Multi-stage build with a minimal Alpine toolchain stage and a distroless
  runtime image.
* `glyphctl` binary compiled with CGO disabled and Go build trimming enabled.
* `nonroot` user enforced as the entrypoint user; no `root` binaries are
  present.
* `/home/nonroot/.glyph`, `/home/nonroot/.cache`, and `/out` are declared as
  volumes to allow a read-only root filesystem.
* Release pipelines sign the image with Cosign and scan for vulnerabilities
  using both Trivy and Grype.

## Recommended runtime profile

Run the container with a read-only root filesystem, no extra capabilities, and
explicit resource limits. A typical invocation looks like:

```bash
docker run \
  --rm \
  --read-only \
  --cap-drop=ALL \
  --security-opt no-new-privileges \
  --pids-limit=256 \
  --memory=512m \
  --cpus="1.0" \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  --tmpfs /home/nonroot/.cache:rw,noexec,nosuid,nodev,size=64m \
  --mount type=volume,source=glyph-data,dst=/home/nonroot/.glyph \
  --mount type=volume,source=glyph-output,dst=/out \
  ghcr.io/rowandark/glyphctl:latest --help
```

### CI usage

For CI jobs, bind the repository into the container and keep the filesystem
read-only:

```bash
docker run \
  --rm \
  --read-only \
  --cap-drop=ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  --tmpfs /home/nonroot/.cache:rw,noexec,nosuid,nodev,size=64m \
  --mount type=bind,src="$PWD",dst=/workspace,ro \
  --workdir /workspace \
  ghcr.io/rowandark/glyphctl:latest demo
```

Mount any plugin directories that need to be executed into `/plugins` with a
read-only bind mount. Plugin execution continues to take place inside the
sandbox provided by `glyphctl` and does not require elevated container
privileges.

## Vulnerability scanning

Pull request builds invoke both Trivy and Grype against the locally built image.
Release builds repeat the scans against the multi-architecture manifest before
publishing to GitHub Container Registry. Scans fail the pipeline on high or
critical severities, ensuring new dependencies do not introduce regressions.
