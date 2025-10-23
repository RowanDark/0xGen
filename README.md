# 0xgen

<!-- version-badge -->[![Release](https://img.shields.io/badge/release-v0.0.0--dev-blue)](https://github.com/RowanDark/0xgen/releases/latest)<!-- /version-badge --> [![Build status](https://github.com/RowanDark/0xgen/actions/workflows/ci.yml/badge.svg)](https://github.com/RowanDark/0xgen/actions/workflows/ci.yml) [![Docs](https://img.shields.io/badge/docs-material-blue)](https://rowandark.github.io/0xgen/) [![Plugin count](https://img.shields.io/endpoint?url=https://rowandark.github.io/0xgen/api/plugin-stats.json&cacheSeconds=3600)](https://rowandark.github.io/0xgen/plugins/catalog/)

0xgen — Generation Zero: AI-driven offensive security.

The badges above highlight the most recent 0xgen release, continuous-integration
status, documentation portal, and the live plugin catalog size published from the
docs build pipeline.

> Read this page in [Spanish](README.es.md).

## Installation

### macOS (Homebrew)

macOS users can install the prebuilt `0xgenctl` binary via Homebrew using the
[RowanDark/homebrew-0xgen tap](https://github.com/RowanDark/homebrew-0xgen):

```bash
brew install rowandark/0xgen/0xgen
```

### Linux (Debian/Ubuntu)

Download the `.deb` package from the
[GitHub Releases page](https://github.com/RowanDark/0xgen/releases) and install
it with `dpkg`:

```bash
sudo dpkg -i 0xgenctl_<version>_linux_amd64.deb
```

Replace `<version>` with the release you want to install. The package installs
`0xgenctl` into `/usr/local/0xgen/bin`. Add that directory to your `PATH` or
create a symlink if you want to invoke the CLI without a fully qualified path.

### Linux (Fedora/RHEL/OpenSUSE)

RPM packages are published alongside each release. Install them with `rpm`:

```bash
sudo rpm -i 0xgenctl_<version>_linux_amd64.rpm
```

### Windows

There are three supported installation paths on Windows:

#### Installer (MSI)

Download the `0xgenctl_v<version>_windows_amd64.msi` (or `arm64`) asset from the
[Releases page](https://github.com/RowanDark/0xgen/releases). Launch it with a
double-click or from PowerShell:

```powershell
msiexec /i .\0xgenctl_v<version>_windows_amd64.msi /qn
```

The installer places `0xgenctl.exe` under `C:\Program Files\0xgen` and updates
`PATH` for future shells. Verify the installation:

```powershell
"C:\Program Files\0xgen\0xgenctl.exe" --version
```

#### Portable ZIP

Every release also ships a portable archive named
`0xgenctl_v<version>_windows_<arch>.zip`. Extract it anywhere you prefer and run
the bundled binary:

```powershell
Expand-Archive -Path .\0xgenctl_v<version>_windows_amd64.zip -DestinationPath C:\Tools\0xgen
C:\Tools\0xgen\0xgenctl.exe --version
```

#### Scoop

Add this repository as a Scoop bucket and install the published manifest:

```powershell
scoop bucket add 0xgen https://github.com/RowanDark/0xgen
scoop install 0xgenctl
0xgenctl --version
```

### Container image

A hardened container image is pushed to GitHub Container Registry with every
release. The image runs as an unprivileged user and expects a read-only root
filesystem. Pull it and run `0xgenctl` with the recommended least-privilege
profile:

```bash
docker pull ghcr.io/rowandark/0xgenctl:latest
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
  ghcr.io/rowandark/0xgenctl:latest --version
```

See the [container hardening guide](docs/en/security/container.md) for additional
context, CI integration notes, and plugin execution tips.

## Quickstart

Clone the repository and run the zero-touch demo pipeline:

```bash
0xgenctl demo
```

The command spins up a local demo target, runs the Seer detector against it, ranks
the generated findings, and emits an interactive HTML report under `out/demo/`.
`make demo` remains available as a thin wrapper if you prefer a Make-based entry
point. See the [Quickstart walkthrough](https://rowandark.github.io/0xgen/quickstart/)
for a full tour and troubleshooting notes.

To inspect the generated Cases, launch the embedded UI server and open the
provided address in your browser:

```bash
0xgenctl serve ui --input out/demo/findings.jsonl
```

The UI lists correlated Cases, risk metadata, and evidence, and offers SARIF and
JSON exports for downstream tooling.

As the pipeline completes, the CLI streams status updates for each stage and
prints a Case preview summarising the top finding, including its proof of
concept command and embedded thumbnail metadata.

## Documentation

Browse the full documentation site at [rowandark.github.io/0xgen](https://rowandark.github.io/0xgen/).
Highlights include:

* [Quickstart demo](https://rowandark.github.io/0xgen/quickstart/)
* [Plugin author guide](https://rowandark.github.io/0xgen/plugins/)
* [CLI reference](https://rowandark.github.io/0xgen/cli/)
* [Developer guide](https://rowandark.github.io/0xgen/dev-guide/)
* [Security overview](https://rowandark.github.io/0xgen/security/)
* [Build provenance](https://rowandark.github.io/0xgen/security/provenance/)
* [Supply chain security](https://rowandark.github.io/0xgen/security/supply-chain/)
* [Threat model](https://rowandark.github.io/0xgen/security/threat-model/)
* [Plugin security guide](PLUGIN_GUIDE.md)

Need documentation for a specific release? Use the version selector in the site
header or jump directly to [archived snapshots](https://rowandark.github.io/0xgen/versions/).

## Security

Please review our [security policy](SECURITY.md) for instructions on reporting
vulnerabilities, supported versions, and the disclosure timeline. The
[0xgen threat model](THREAT_MODEL.md) outlines major attack vectors and
assumptions, while the [plugin security guide](PLUGIN_GUIDE.md) captures safe
patterns for new integrations.

## Desktop Shell

A cross-platform Tauri shell lives under [`apps/desktop-shell`](apps/desktop-shell). It ships a React + Vite + Tailwind front-end with TanStack Router and a hardened IPC boundary that proxies 0xgen API calls.
