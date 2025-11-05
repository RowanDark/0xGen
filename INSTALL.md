# Installation Guide

This guide covers all methods for installing 0xGen v2.0.0-alpha on Linux, macOS, and Windows.

---

## Quick Install

### Homebrew (macOS/Linux) - Recommended
```bash
brew tap RowanDark/0xgen
brew install 0xgen
0xgenctl --version
```

### Scoop (Windows) - Recommended
```powershell
scoop bucket add 0xgen https://github.com/RowanDark/scoop-0xgen
scoop install 0xgen
0xgenctl --version
```

---

## Platform-Specific Instructions

### macOS

#### Option 1: Homebrew (Recommended)
```bash
# Add tap
brew tap RowanDark/0xgen

# Install
brew install 0xgen

# Verify
0xgenctl --version
0xgend --version
```

#### Option 2: Pre-built Binary
```bash
# Intel Mac (amd64)
curl -LO https://github.com/RowanDark/0xGen/releases/download/v2.0.0-alpha/0xgen-v2.0.0-alpha-darwin-amd64.tar.gz
tar -xzf 0xgen-v2.0.0-alpha-darwin-amd64.tar.gz
sudo mv 0xgenctl 0xgend /usr/local/bin/
chmod +x /usr/local/bin/0xgenctl /usr/local/bin/0xgend

# Apple Silicon (arm64)
curl -LO https://github.com/RowanDark/0xGen/releases/download/v2.0.0-alpha/0xgen-v2.0.0-alpha-darwin-arm64.tar.gz
tar -xzf 0xgen-v2.0.0-alpha-darwin-arm64.tar.gz
sudo mv 0xgenctl 0xgend /usr/local/bin/
chmod +x /usr/local/bin/0xgenctl /usr/local/bin/0xgend

# Verify
0xgenctl --version
```

---

### Linux

#### Option 1: Debian/Ubuntu (.deb package)
```bash
# Download package
curl -LO https://github.com/RowanDark/0xGen/releases/download/v2.0.0-alpha/0xgen_2.0.0-alpha_amd64.deb

# Install
sudo dpkg -i 0xgen_2.0.0-alpha_amd64.deb

# Fix dependencies if needed
sudo apt-get install -f

# Verify
0xgenctl --version
```

#### Option 2: Red Hat/CentOS/Fedora (.rpm package)
```bash
# Download package
curl -LO https://github.com/RowanDark/0xGen/releases/download/v2.0.0-alpha/0xgen-2.0.0-alpha.x86_64.rpm

# Install
sudo rpm -i 0xgen-2.0.0-alpha.x86_64.rpm

# Or use yum/dnf
sudo yum localinstall 0xgen-2.0.0-alpha.x86_64.rpm

# Verify
0xgenctl --version
```

#### Option 3: Pre-built Binary (any Linux)
```bash
# AMD64 (x86_64)
curl -LO https://github.com/RowanDark/0xGen/releases/download/v2.0.0-alpha/0xgen-v2.0.0-alpha-linux-amd64.tar.gz
tar -xzf 0xgen-v2.0.0-alpha-linux-amd64.tar.gz
sudo mv 0xgenctl 0xgend /usr/local/bin/
chmod +x /usr/local/bin/0xgenctl /usr/local/bin/0xgend

# ARM64 (aarch64)
curl -LO https://github.com/RowanDark/0xGen/releases/download/v2.0.0-alpha/0xgen-v2.0.0-alpha-linux-arm64.tar.gz
tar -xzf 0xgen-v2.0.0-alpha-linux-arm64.tar.gz
sudo mv 0xgenctl 0xgend /usr/local/bin/
chmod +x /usr/local/bin/0xgenctl /usr/local/bin/0xgend

# Verify
0xgenctl --version
```

#### Option 4: Homebrew on Linux
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Add tap and install
brew tap RowanDark/0xgen
brew install 0xgen
0xgenctl --version
```

---

### Windows

#### Option 1: Scoop (Recommended)
```powershell
# Install Scoop if not already installed
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
irm get.scoop.sh | iex

# Add bucket and install
scoop bucket add 0xgen https://github.com/RowanDark/scoop-0xgen
scoop install 0xgen

# Verify
0xgenctl --version
```

#### Option 2: MSI Installer
```powershell
# Download installer
curl -LO https://github.com/RowanDark/0xGen/releases/download/v2.0.0-alpha/0xgen-2.0.0-alpha-amd64.msi

# Run installer (double-click or use msiexec)
msiexec /i 0xgen-2.0.0-alpha-amd64.msi

# Verify (restart terminal)
0xgenctl --version
```

#### Option 3: Pre-built Binary (ZIP)
```powershell
# AMD64 (x86_64)
curl -LO https://github.com/RowanDark/0xGen/releases/download/v2.0.0-alpha/0xgen-v2.0.0-alpha-windows-amd64.zip

# Extract
Expand-Archive -Path 0xgen-v2.0.0-alpha-windows-amd64.zip -DestinationPath C:\0xgen

# Add to PATH manually or use:
$env:Path += ";C:\0xgen"
[System.Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\0xgen", [System.EnvironmentVariableTarget]::User)

# Verify
0xgenctl --version
```

#### Option 4: Windows Subsystem for Linux (WSL2) - Recommended for Maximum Security
```bash
# Inside WSL2 Ubuntu
curl -LO https://github.com/RowanDark/0xGen/releases/download/v2.0.0-alpha/0xgen_2.0.0-alpha_amd64.deb
sudo dpkg -i 0xgen_2.0.0-alpha_amd64.deb
0xgenctl --version
```

**Why WSL2?** Provides full plugin sandboxing with chroot (not available in native Windows).

---

## Docker

### Pull Official Image
```bash
docker pull ghcr.io/rowandark/0xgen:v2.0.0-alpha
```

### Run Commands
```bash
# CLI
docker run --rm ghcr.io/rowandark/0xgen:v2.0.0-alpha 0xgenctl --help

# Proxy server (expose port 8080)
docker run -p 8080:8080 ghcr.io/rowandark/0xgen:v2.0.0-alpha 0xgend start --port 8080

# Mount volume for output
docker run -v $(pwd)/out:/out ghcr.io/rowandark/0xgen:v2.0.0-alpha 0xgenctl demo
```

### Docker Compose
```yaml
version: '3.8'
services:
  0xgen:
    image: ghcr.io/rowandark/0xgen:v2.0.0-alpha
    ports:
      - "8080:8080"
    volumes:
      - ./out:/out
    command: 0xgend start --port 8080
```

---

## Build from Source

### Prerequisites
- **Go**: 1.21 or later
- **Git**: Any recent version
- **Make**: GNU Make

### Clone Repository
```bash
git clone https://github.com/RowanDark/0xGen.git
cd 0xGen
git checkout v2.0.0-alpha
```

### Build
```bash
# Build all binaries
make build

# Binaries output to ./bin/
ls -lh bin/
```

### Install
```bash
# Install to /usr/local/bin (Unix/Linux/macOS)
sudo make install

# Or copy manually
sudo cp bin/0xgenctl bin/0xgend /usr/local/bin/
sudo chmod +x /usr/local/bin/0xgenctl /usr/local/bin/0xgend

# Verify
0xgenctl --version
```

---

## Desktop Shell (GUI)

The desktop shell requires additional setup.

### Prerequisites
- **Node.js**: 18 or later
- **pnpm**: 8 or later (`npm install -g pnpm`)
- **Rust**: Latest stable (for Tauri)

### Install Dependencies
```bash
cd apps/desktop-shell
pnpm install
```

### Development Mode
```bash
pnpm tauri:dev
```

### Production Build
```bash
# Build for current platform
pnpm tauri build

# Outputs to src-tauri/target/release/bundle/
```

### Platform-Specific Notes

**macOS**:
```bash
# Install Xcode Command Line Tools if not already installed
xcode-select --install

# Build
cd apps/desktop-shell
pnpm tauri build

# Install DMG from src-tauri/target/release/bundle/dmg/
```

**Linux**:
```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt-get install libwebkit2gtk-4.1-dev \
  build-essential \
  curl \
  wget \
  file \
  libxdo-dev \
  libssl-dev \
  libayatana-appindicator3-dev \
  librsvg2-dev

# Build
cd apps/desktop-shell
pnpm tauri build

# Install .deb or .AppImage from src-tauri/target/release/bundle/
```

**Windows**:
```powershell
# Install WebView2 (usually pre-installed on Windows 10+)
# Download from https://developer.microsoft.com/en-us/microsoft-edge/webview2/ if needed

# Build
cd apps/desktop-shell
pnpm tauri build

# Install .msi from src-tauri/target/release/bundle/msi/
```

---

## Verification

### Verify Installation
```bash
# Check version
0xgenctl --version
0xgend --version

# Run demo
0xgenctl demo

# Check output
ls -lh out/demo/
```

### Verify SLSA Provenance
```bash
# Download provenance
curl -LO https://github.com/RowanDark/0xGen/releases/download/v2.0.0-alpha/0xgen-v2.0.0-alpha-provenance.intoto.jsonl

# Verify with 0xgenctl
0xgenctl verify-build --provenance 0xgen-v2.0.0-alpha-provenance.intoto.jsonl /usr/local/bin/0xgenctl
```

### Verify Checksum
```bash
# Download checksums
curl -LO https://github.com/RowanDark/0xGen/releases/download/v2.0.0-alpha/SHA256SUMS.txt

# Verify
sha256sum -c SHA256SUMS.txt 2>&1 | grep OK
```

---

## Post-Installation Setup

### 1. Trust CA Certificate (One-Time Setup)
```bash
# Generate and trust CA certificate
0xgenctl proxy trust

# This installs the CA certificate to your system trust store
```

### 2. Configure Browser Proxy
**Firefox**:
1. Settings → Network Settings → Manual proxy configuration
2. HTTP Proxy: `localhost`, Port: `8080`
3. Enable "Use this proxy server for all protocols"

**Chrome/Brave**:
```bash
# macOS/Linux
google-chrome --proxy-server="localhost:8080"

# Windows
chrome.exe --proxy-server="localhost:8080"
```

### 3. Start Proxy Server
```bash
# Start in foreground
0xgend start

# Or start in background
0xgend start --daemon
```

---

## Troubleshooting

### "command not found: 0xgenctl"
**Solution**: Add to PATH or use full path
```bash
# Check installation location
which 0xgenctl

# If not found, add to PATH:
export PATH=$PATH:/usr/local/bin

# Or add to ~/.bashrc or ~/.zshrc:
echo 'export PATH=$PATH:/usr/local/bin' >> ~/.bashrc
source ~/.bashrc
```

### "Permission denied"
**Solution**: Make binaries executable
```bash
sudo chmod +x /usr/local/bin/0xgenctl /usr/local/bin/0xgend
```

### Desktop Shell Won't Start
**Solution 1**: Install dependencies
```bash
cd apps/desktop-shell
pnpm install
```

**Solution 2**: Check Node.js version
```bash
node --version
# Should be v18.0.0 or later
```

### SLSA Verification Fails
**Solution**: Ensure you downloaded both artifact and provenance from same release
```bash
# Re-download both files
curl -LO https://github.com/RowanDark/0xGen/releases/download/v2.0.0-alpha/0xgen-linux-amd64.tar.gz
curl -LO https://github.com/RowanDark/0xGen/releases/download/v2.0.0-alpha/0xgen-v2.0.0-alpha-provenance.intoto.jsonl

# Verify
0xgenctl verify-build --provenance 0xgen-v2.0.0-alpha-provenance.intoto.jsonl 0xgen-linux-amd64.tar.gz
```

### Windows: "0xgenctl is not digitally signed"
**Solution**: This is expected for alpha builds. Bypass with:
```powershell
# Right-click exe → Properties → Unblock
# Or:
Unblock-File -Path C:\path\to\0xgenctl.exe
```

For production releases, binaries will be signed with Authenticode.

---

## Uninstallation

### Homebrew
```bash
brew uninstall 0xgen
brew untap RowanDark/0xgen
```

### Scoop
```powershell
scoop uninstall 0xgen
scoop bucket rm 0xgen
```

### Debian/Ubuntu
```bash
sudo apt-get remove 0xgen
```

### Red Hat/CentOS/Fedora
```bash
sudo rpm -e 0xgen
```

### Manual Installation
```bash
sudo rm /usr/local/bin/0xgenctl /usr/local/bin/0xgend
```

### Remove Configuration & Data
```bash
rm -rf ~/.0xgen
rm -rf ~/.config/0xgen
```

---

## Next Steps

After installation:
1. **Quick Start**: Run `0xgenctl demo` to see 0xGen in action
2. **Documentation**: Read [ROADMAP.md](ROADMAP.md) for features and roadmap
3. **Tutorial**: Follow [docs/en/quickstart.md](docs/en/quickstart.md)
4. **Desktop GUI**: Launch with `cd apps/desktop-shell && pnpm tauri:dev`

---

## Support

- **Issues**: https://github.com/RowanDark/0xGen/issues
- **Discussions**: https://github.com/RowanDark/0xGen/discussions
- **Documentation**: [ROADMAP.md](ROADMAP.md)

---

**Version**: v2.0.0-alpha
**Last Updated**: 2025-11-04
