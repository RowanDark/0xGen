# 0xgen

<!-- version-badge -->[![Release](https://img.shields.io/badge/release-v0.0.0--dev-blue)](https://github.com/RowanDark/0xgen/releases/latest)<!-- /version-badge --> [![Build status](https://github.com/RowanDark/0xgen/actions/workflows/ci.yml/badge.svg)](https://github.com/RowanDark/0xgen/actions/workflows/ci.yml) [![Docs status](https://github.com/RowanDark/0xgen/actions/workflows/docs.yml/badge.svg?branch=main)](https://rowandark.github.io/0xgen/) [![Plugin count](https://img.shields.io/endpoint?url=https://rowandark.github.io/0xgen/api/plugin-stats.json&cacheSeconds=3600)](https://rowandark.github.io/0xgen/plugins/catalog/)

0xgen — Generation Zero: AI-driven offensive security.

The badges above highlight the most recent 0xgen release, continuous-integration
status, documentation portal, and the live plugin catalog size published from the
docs build pipeline.

> Read this page in [Spanish](README.es.md).

## Installation

### 🚀 Easy Install Wizard (Recommended)

The fastest way to get started is with our automated install wizard:

**macOS & Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/RowanDark/0xGen/main/install.sh | bash
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/RowanDark/0xGen/main/install.ps1 | iex
```

The wizard automatically detects your system, installs dependencies, and configures 0xGen. See [INSTALL.md](INSTALL.md) for more details and options.

---

### Manual Installation Methods

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
  --mount type=volume,source=oxg-data,dst=/home/nonroot/.oxg \
  --mount type=volume,source=oxg-output,dst=/out \
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

## Plugins

0xgen's modular architecture is powered by 14 production plugins that handle everything from passive reconnaissance to active vulnerability detection. Each plugin runs in an isolated sandbox with explicit capability grants, ensuring safe execution even with untrusted code.

### Core Detection Plugins

| Plugin | Description | Use Case |
|--------|-------------|----------|
| **[Hydra](plugins/hydra/)** | AI-powered vulnerability detection with 5 specialized analyzers (XSS, SQLi, SSRF, Command Injection, Open Redirect) and consensus evaluation | Automated vulnerability discovery with <5% false positive rate. Ideal for continuous security testing and bug bounty hunting. |
| **[Seer](plugins/seer/)** | Passive telemetry analyzer for secrets and PII detection using entropy heuristics and pattern matching | Identify leaked credentials (AWS keys, Slack tokens, JWTs) and sensitive data in HTTP traffic without active probing. |
| **[Keys](plugins/keys/)** | Cryptographic key and token detection with high-entropy analysis | Extract API keys, access tokens, and cryptographic material from responses for security audits. |

### Discovery & Mapping

| Plugin | Description | Use Case |
|--------|-------------|----------|
| **[Cartographer](plugins/cartographer/)** | Application surface mapping and asset discovery from crawlers and passive sensors | Build comprehensive attack surface maps to prioritize testing targets and identify hidden endpoints. |
| **[Excavator](plugins/excavator/)** | Data extraction and structured information harvesting | Extract structured data from responses for correlation analysis and evidence collection. |
| **[Grapher](plugins/grapher/)** | Relationship graphing and dependency visualization | Visualize application architecture, API dependencies, and data flows for threat modeling. |

### Analysis & Intelligence

| Plugin | Description | Use Case |
|--------|-------------|----------|
| **[Entropy](plugins/entropy/)** | Shannon entropy analysis for detecting randomness and obfuscation | Identify compressed data, encrypted payloads, or obfuscated code that may hide malicious behavior. |
| **[Ranker](plugins/ranker/)** | Finding prioritization and risk scoring using CVSS and context | Triage large finding sets by automatically ranking vulnerabilities based on exploitability and impact. |
| **[Cryptographer](plugins/cryptographer/)** | Cryptographic analysis and cipher identification | Detect weak encryption, identify cipher usage, and analyze cryptographic implementations. |

### Active Testing

| Plugin | Description | Use Case |
|--------|-------------|----------|
| **[Raider](plugins/raider/)** | Offensive testing campaign orchestration with attack playbooks | Execute coordinated exploitation attempts once high-value targets are identified by discovery plugins. |

### OSINT & External Data

| Plugin | Description | Use Case |
|--------|-------------|----------|
| **[OSINT Well](plugins/osint-well/)** | Open-source intelligence aggregation from public sources | Enrich findings with external threat intelligence, leaked credential databases, and public exploit data. |

### Infrastructure

| Plugin | Description | Use Case |
|--------|-------------|----------|
| **[Galdr Proxy](plugins/galdr-proxy/)** | HTTP/HTTPS proxy engine with full MITM interception | Intercept and analyze application traffic for both passive monitoring and active manipulation testing. |
| **[Scribe](plugins/scribe/)** | Report generation with SARIF, JSON, HTML, and PDF export | Generate professional security reports with findings, evidence, and remediation guidance for stakeholders. |

### Development & Examples

| Plugin | Description | Use Case |
|--------|-------------|----------|
| **[Example Hello](plugins/example-hello/)** | Minimal SDK example demonstrating plugin development patterns | Learn plugin development with a simple reference implementation showing core SDK concepts. |

### Plugin Capabilities

Plugins request explicit capabilities that determine their permissions:

- **`CAP_EMIT_FINDINGS`** - Emit security findings to 0xgen core
- **`CAP_HTTP_PASSIVE`** - Observe HTTP traffic without modification
- **`CAP_HTTP_ACTIVE`** - Modify and inject HTTP traffic
- **`CAP_FLOW_INSPECT`** - Access complete request/response pairs
- **`CAP_AI_ANALYSIS`** - Use AI evaluation services
- **`CAP_SPIDER`** - Crawl and discover web application structure
- **`CAP_NETWORK`** - Make arbitrary network requests
- **`CAP_FILE_READ`** - Read files from disk
- **`CAP_EXEC`** - Execute external processes

### Plugin Security

All plugins (except those marked `trusted: true` for development) run in a 5-layer security sandbox:

1. **cgroups** - Resource limits (CPU, memory, PIDs)
2. **chroot** - Isolated filesystem (read-only root)
3. **Network restrictions** - Localhost and allowlisted IPs only
4. **seccomp-bpf** - Syscall filtering (safe operations only)
5. **Capability dropping** - No Linux capabilities except analysis APIs

See the [Plugin Security Guide](PLUGIN_GUIDE.md) for threat model details and safe development patterns.

### Creating Custom Plugins

Develop your own plugins using the [Plugin SDK](sdk/plugin-sdk):

```go
import pluginsdk "github.com/RowanDark/0xgen/sdk/plugin-sdk"

hooks := pluginsdk.Hooks{
    OnHTTPResponse: func(ctx *pluginsdk.Context, event pluginsdk.HTTPPassiveEvent) error {
        // Your detection logic
        return ctx.EmitFinding(pluginsdk.Finding{
            Type:     "custom.vulnerability",
            Severity: pluginsdk.SeverityHigh,
            Message:  "Detected custom vulnerability",
        })
    },
}
```

See the [Plugin Author Guide](https://rowandark.github.io/0xgen/plugins/) for complete SDK documentation, capability matrix, and submission guidelines.

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
