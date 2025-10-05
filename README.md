# Glyph

[![Docs](https://img.shields.io/badge/docs-material-blue)](https://rowandark.github.io/Glyph/)

Glyph is an automation toolkit for orchestrating red-team and detection workflows.
It coordinates plugins such as Galdr (HTTP rewriting proxy), Excavator (Playwright
crawler), Seer (secret/PII detector), Ranker, and Scribe to turn raw telemetry into
ranked findings and human-readable reports.

## Installation

### macOS (Homebrew)

macOS users can install the prebuilt `glyphctl` binary via Homebrew using the
[RowanDark/homebrew-glyph tap](https://github.com/RowanDark/homebrew-glyph):

```bash
brew install rowandark/glyph/glyph
```

### Linux (Debian/Ubuntu)

Download the `.deb` package from the
[GitHub Releases page](https://github.com/RowanDark/Glyph/releases) and install
it with `dpkg`:

```bash
sudo dpkg -i glyphctl_<version>_linux_amd64.deb
```

Replace `<version>` with the release you want to install. The package installs
`glyphctl` into `/usr/local/bin`.

### Linux (Fedora/RHEL/OpenSUSE)

RPM packages are published alongside each release. Install them with `rpm`:

```bash
sudo rpm -i glyphctl_<version>_linux_amd64.rpm
```

### Windows (Scoop)

Add this repository as a Scoop bucket and install the manifest:

```powershell
scoop bucket add glyph https://github.com/RowanDark/Glyph
scoop install glyphctl
```

### Container image

A hardened container image is pushed to GitHub Container Registry with every
release. The image runs as an unprivileged user and expects a read-only root
filesystem. Pull it and run `glyphctl` with the recommended least-privilege
profile:

```bash
docker pull ghcr.io/rowandark/glyphctl:latest
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
  ghcr.io/rowandark/glyphctl:latest --version
```

See the [container hardening guide](docs/security/container.md) for additional
context, CI integration notes, and plugin execution tips.

## Quickstart

Clone the repository and run the zero-touch demo pipeline:

```bash
glyphctl demo
```

The command spins up a local demo target, runs the Seer detector against it, ranks
the generated findings, and emits an interactive HTML report under `out/demo/`.
`make demo` remains available as a thin wrapper if you prefer a Make-based entry
point. See the [Quickstart walkthrough](https://rowandark.github.io/Glyph/quickstart/)
for a full tour and troubleshooting notes.

## Documentation

Browse the full documentation site at [rowandark.github.io/Glyph](https://rowandark.github.io/Glyph/).
Highlights include:

* [Quickstart demo](https://rowandark.github.io/Glyph/quickstart/)
* [Plugin author guide](https://rowandark.github.io/Glyph/plugins/)
* [CLI reference](https://rowandark.github.io/Glyph/cli/)
* [Developer guide](https://rowandark.github.io/Glyph/dev-guide/)
* [Security overview](https://rowandark.github.io/Glyph/security/)
* [Build provenance](https://rowandark.github.io/Glyph/security/provenance/)
* [Supply chain security](https://rowandark.github.io/Glyph/security/supply-chain/)
* [Threat model](https://rowandark.github.io/Glyph/security/threat-model/)
* [Plugin security guide](PLUGIN_GUIDE.md)

## Security

Please review our [security policy](SECURITY.md) for instructions on reporting
vulnerabilities, supported versions, and the disclosure timeline. The
[Glyph threat model](THREAT_MODEL.md) outlines major attack vectors and
assumptions, while the [plugin security guide](PLUGIN_GUIDE.md) captures safe
patterns for new integrations.
