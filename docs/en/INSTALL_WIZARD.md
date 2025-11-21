# 0xGen Easy Install Wizard

The 0xGen Easy Install Wizard is a centralized, automated installation tool that simplifies the installation process across all supported platforms.

## Overview

The wizard provides:

- **Automatic system detection** - Identifies your OS, architecture, and available package managers
- **Dependency management** - Installs missing dependencies (Go, Rust, Node.js, Python)
- **Component selection** - Choose which parts of 0xGen to install
- **Smart installation** - Uses the best installation method for your platform
- **Post-install configuration** - Sets up CA certificates and configuration directories

## Quick Start

### macOS & Linux

```bash
# One-line install
curl -fsSL https://raw.githubusercontent.com/RowanDark/0xGen/main/install.sh | bash

# Or download first
wget https://raw.githubusercontent.com/RowanDark/0xGen/main/install.sh
chmod +x install.sh
./install.sh
```

### Windows (PowerShell)

```powershell
# One-line install
irm https://raw.githubusercontent.com/RowanDark/0xGen/main/install.ps1 | iex

# Or download first
Invoke-WebRequest -Uri https://raw.githubusercontent.com/RowanDark/0xGen/main/install.ps1 -OutFile install.ps1
.\install.ps1
```

## Installation Modes

### Quick Mode

Installs with recommended defaults (CLI tools + plugins):

```bash
./install.sh --quick
# or
./install.sh -q
```

### Custom Mode

Interactive mode where you choose components:

```bash
./install.sh
# Then select components when prompted
```

### CLI Only

Install only command-line tools:

```bash
./install.sh --cli-only
```

### With GUI

Include the desktop GUI application:

```bash
./install.sh --gui
```

### Build from Source

Build all components from source code:

```bash
./install.sh --source
```

## Command-Line Options

### Bash Script (macOS/Linux)

```
Usage: ./install.sh [OPTIONS]

Options:
  --quick, -q        Quick install with defaults
  --cli-only         Install only CLI tools
  --gui              Include Desktop GUI
  --source           Build from source
  --install-dir DIR  Installation directory (default: /usr/local/bin)
  --help, -h         Show help message
```

### PowerShell Script (Windows)

```
Usage: .\install.ps1 [OPTIONS]

Options:
  -Quick             Quick install with defaults
  -CliOnly           Install only CLI tools
  -Gui               Include Desktop GUI
  -InstallDir PATH   Installation directory (default: %LOCALAPPDATA%\0xGen\bin)
  -Help              Show help message
```

## Components

The wizard can install the following components:

### 1. CLI Tools (Recommended)

- `0xgenctl` - Command-line interface for running scans and managing 0xGen
- `0xgend` - Proxy daemon for intercepting and analyzing HTTP/HTTPS traffic

**Default**: Installed in quick mode

### 2. Desktop GUI (Optional)

- Tauri-based graphical interface
- Requires Node.js 18+, pnpm, and Rust

**Default**: Not installed in quick mode

### 3. Plugins (Recommended)

Security testing plugins including:
- **cartographer** - Application surface mapping
- **hydra** - AI-powered vulnerability detection
- **raider** - Offensive testing
- **seer** - Secrets and PII detection
- **cryptographer** - Cryptographic analysis
- And more...

**Default**: Installed in quick mode

### 4. Documentation (Optional)

Local documentation server built with MkDocs

**Default**: Not installed in quick mode

## Installation Methods

The wizard automatically selects the best installation method for your platform:

### macOS

| Method | When Used | Requires |
|--------|-----------|----------|
| **Homebrew** | If `brew` is installed | Homebrew |
| **Pre-built binary** | Fallback | curl, tar |
| **Build from source** | With `--source` flag | Go 1.21+, Make, Git |

### Linux

| Method | When Used | Requires |
|--------|-----------|----------|
| **APT** | On Debian/Ubuntu | apt-get |
| **DNF/YUM** | On Fedora/RHEL/CentOS | dnf or yum |
| **Homebrew** | If `brew` is installed | Homebrew on Linux |
| **Pre-built binary** | Fallback | curl, tar |
| **Build from source** | With `--source` flag | Go 1.21+, Make, Git |

### Windows

| Method | When Used | Requires |
|--------|-----------|----------|
| **Scoop** | If `scoop` is installed | Scoop |
| **Pre-built binary** | Fallback | PowerShell 5.1+ |
| **Build from source** | With `--source` flag | Go 1.21+, Make, Git |

## Dependencies

The wizard can automatically install missing dependencies:

### For CLI Tools

- **Go 1.21+** (if building from source)
- **Git** (if building from source)
- **Make** (if building from source)

### For Desktop GUI

- **Node.js 18+**
- **pnpm 8+**
- **Rust** (latest stable)

### For Documentation

- **Python 3.8+**
- **pip**
- **mkdocs** and dependencies

## Post-Installation Setup

After installation, the wizard automatically:

1. **Creates configuration directory** (`~/.0xgen/`)
2. **Sets up plugin directory** (`~/.0xgen/plugins/`)
3. **Offers to install CA certificate** (for proxy functionality)
4. **Updates PATH** (if needed)

### Manual CA Certificate Setup

If you skipped CA certificate setup during installation:

```bash
# Generate and trust CA certificate
0xgenctl ca generate
0xgenctl ca install
```

### Verify Installation

```bash
# Check version
0xgenctl --version
0xgend --version

# Run demo
0xgenctl demo
```

## Installation Flow

The wizard follows this workflow:

```
1. Display welcome header
2. Detect OS and architecture
3. Select installation mode (Quick or Custom)
   └─> If Custom: Select components
4. Check for required dependencies
   └─> If missing: Offer to install
5. Select best installation method
6. Confirm installation plan
7. Download/install components
8. Post-installation setup
   ├─> Create config directories
   ├─> Set up CA certificate (optional)
   └─> Update PATH (if needed)
9. Display installation summary
```

## Troubleshooting

### "Permission denied" when running install.sh

**Solution**: Make the script executable

```bash
chmod +x install.sh
./install.sh
```

### "command not found: 0xgenctl" after installation

**Solution**: Restart your terminal or add to PATH

```bash
# Check installation location
which 0xgenctl

# Add to PATH (if needed)
export PATH=$PATH:/usr/local/bin

# Or add to shell config
echo 'export PATH=$PATH:/usr/local/bin' >> ~/.bashrc
source ~/.bashrc
```

### Windows: "Script execution is disabled"

**Solution**: Enable script execution

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Homebrew/Scoop bucket not found

The wizard attempts to add the official 0xGen tap/bucket. If this fails:

**macOS/Linux**:
```bash
brew tap RowanDark/0xgen
```

**Windows**:
```powershell
scoop bucket add 0xgen https://github.com/RowanDark/scoop-0xgen
```

### Failed to download binary

If GitHub releases are unavailable:

1. Check your internet connection
2. Try a different installation method: `./install.sh --source`
3. Manually download from [GitHub Releases](https://github.com/RowanDark/0xGen/releases)

### Missing dependencies on Linux

The wizard attempts to install dependencies using your package manager. If this fails:

**Debian/Ubuntu**:
```bash
sudo apt-get update
sudo apt-get install -y golang git build-essential
```

**Fedora/RHEL**:
```bash
sudo dnf install -y golang git make
```

**Arch Linux**:
```bash
sudo pacman -S go git make
```

### GUI build fails

Desktop GUI requires additional system dependencies:

**macOS**:
```bash
xcode-select --install
```

**Ubuntu/Debian**:
```bash
sudo apt-get install libwebkit2gtk-4.1-dev \
  build-essential \
  curl \
  wget \
  file \
  libxdo-dev \
  libssl-dev \
  libayatana-appindicator3-dev \
  librsvg2-dev
```

**Windows**:
- Install [WebView2](https://developer.microsoft.com/en-us/microsoft-edge/webview2/)
- Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/)

## Advanced Usage

### Custom Installation Directory

```bash
# Install to custom directory
./install.sh --install-dir /opt/0xgen

# Update PATH
export PATH=$PATH:/opt/0xgen
```

### Installing Specific Components Only

```bash
# CLI only (no GUI, no docs)
./install.sh --cli-only --quick

# CLI + GUI
./install.sh --gui --quick
```

### Offline Installation

1. Download the install script and binary on a connected machine:
```bash
wget https://raw.githubusercontent.com/RowanDark/0xGen/main/install.sh
wget https://github.com/RowanDark/0xGen/releases/latest/download/0xgen_linux_amd64.tar.gz
```

2. Transfer both files to the offline machine

3. Run the installer in binary mode (it will detect the local tarball)

### Automated/Unattended Installation

Use `--quick` mode for CI/CD or automated deployments:

```bash
# Non-interactive installation
./install.sh --quick --cli-only

# With custom directory for containerized environments
./install.sh --quick --install-dir /app/bin
```

## Environment Variables

The wizard respects these environment variables:

- `INSTALL_DIR` - Override default installation directory
- `SKIP_DEPENDENCIES` - Skip dependency installation (advanced)
- `FORCE_METHOD` - Force specific installation method (homebrew, apt, binary, source)

Example:
```bash
export INSTALL_DIR=/opt/0xgen
export FORCE_METHOD=binary
./install.sh
```

## Security Considerations

### Verify the Install Script

Before running, verify the script hasn't been tampered with:

```bash
# Download script
curl -fsSL https://raw.githubusercontent.com/RowanDark/0xGen/main/install.sh -o install.sh

# Review the script
less install.sh

# Run only if you trust the code
chmod +x install.sh
./install.sh
```

### SLSA Provenance Verification

When installing via binary, verify build provenance:

```bash
# Download binary and provenance
curl -LO https://github.com/RowanDark/0xGen/releases/latest/download/0xgen_linux_amd64.tar.gz
curl -LO https://github.com/RowanDark/0xGen/releases/latest/download/0xgen-provenance.intoto.jsonl

# Verify (after installing 0xgenctl)
0xgenctl verify-build --provenance 0xgen-provenance.intoto.jsonl 0xgen_linux_amd64.tar.gz
```

### Building from Source

For maximum security and supply chain verification:

```bash
# Build from audited source
./install.sh --source

# Review source before building
cd ~/0xGen
git log --oneline | head -10
git diff main
```

## Uninstallation

The wizard doesn't provide an uninstall option yet. To uninstall:

### Homebrew

```bash
brew uninstall 0xgen
brew untap RowanDark/0xgen
```

### Scoop

```powershell
scoop uninstall 0xgen
```

### Manual/Binary Installation

```bash
# Remove binaries
sudo rm /usr/local/bin/0xgenctl /usr/local/bin/0xgend

# Remove configuration
rm -rf ~/.0xgen
rm -rf ~/.config/0xgen
```

## Contributing

The install wizard is open source. Contributions welcome!

- **Bash script**: `/install.sh`
- **PowerShell script**: `/install.ps1`
- **Documentation**: `/docs/en/INSTALL_WIZARD.md`

### Testing

Test the wizard in a clean environment:

```bash
# macOS/Linux
docker run -it ubuntu:22.04 bash
# Inside container:
apt-get update && apt-get install -y curl
curl -fsSL https://raw.githubusercontent.com/RowanDark/0xGen/main/install.sh | bash
```

### Reporting Issues

If the wizard doesn't work for your system:

1. Run with verbose output: `bash -x install.sh`
2. Report the issue: https://github.com/RowanDark/0xGen/issues
3. Include:
   - OS and version (`uname -a`)
   - Architecture (`uname -m`)
   - Error messages
   - Output of `bash -x install.sh`

## FAQ

### Q: Does the wizard require sudo/admin privileges?

A: Not for installation to `$HOME/.local/bin` or `%LOCALAPPDATA%`. It only requires elevated privileges for:
- Installing to `/usr/local/bin` (default)
- Installing CA certificate to system trust store
- Installing system dependencies via package managers

### Q: Can I run the wizard without internet access?

A: Partially. You can use the wizard with pre-downloaded binaries, but dependency installation requires internet access.

### Q: Does the wizard support proxy environments?

A: Yes, it respects `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` environment variables.

### Q: Can I customize the installation?

A: Yes, use custom mode (don't pass `--quick`) to interactively select components.

### Q: What if I already have Go/Rust/Node.js installed?

A: The wizard detects existing installations and skips dependency installation.

### Q: Can I install multiple versions of 0xGen?

A: Yes, use different `--install-dir` values for each version.

### Q: Is the wizard itself secure?

A: Yes. The wizard:
- Uses HTTPS for all downloads
- Verifies checksums where available
- Never executes arbitrary code from untrusted sources
- Is fully auditable (open source)

## Additional Resources

- **Installation Guide**: [INSTALL.md](../../../INSTALL.md)
- **Quick Start**: [quickstart.md](./quickstart.md)
- **Troubleshooting**: [troubleshooting.md](./troubleshooting.md)
- **GitHub Repository**: https://github.com/RowanDark/0xGen
- **Release Notes**: https://github.com/RowanDark/0xGen/releases

---

**Last Updated**: 2025-11-21
**Wizard Version**: 1.0.0
