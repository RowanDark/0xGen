#!/usr/bin/env bash
# 0xGen Easy Install Wizard
# Centralized installation script for all platforms and components
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/RowanDark/0xGen/main/install.sh | bash
#   or
#   ./install.sh

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Version
WIZARD_VERSION="1.0.0"

# Global variables
OS=""
ARCH=""
INSTALL_METHOD=""
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
INSTALL_CLI=true
INSTALL_GUI=false
INSTALL_PLUGINS=true
INSTALL_DOCS=false
BUILD_FROM_SOURCE=false
QUICK_MODE=false

#############################################
# Utility Functions
#############################################

print_header() {
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
   ___        ____
  / _ \ __  _/ ___| ___ _ __
 | | | |\ \/ / |  _/ _ \ '_ \
 | |_| | >  <| |_| |  __/ | | |
  \___/ /_/\_\\____|\___|_| |_|

    Easy Install Wizard v%s
EOF
    printf "$WIZARD_VERSION\n"
    echo -e "${NC}"
    echo -e "${BOLD}Welcome to the 0xGen installation wizard!${NC}\n"
}

print_step() {
    echo -e "\n${BLUE}${BOLD}==>${NC} ${BOLD}$1${NC}"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_info() {
    echo -e "${CYAN}ℹ${NC} $1"
}

ask_yes_no() {
    local prompt="$1"
    local default="${2:-n}"
    local response

    if [[ "$default" == "y" ]]; then
        prompt="$prompt [Y/n] "
    else
        prompt="$prompt [y/N] "
    fi

    read -p "$(echo -e ${CYAN}?${NC} $prompt)" response
    response=${response:-$default}

    [[ "$response" =~ ^[Yy]$ ]]
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

#############################################
# System Detection
#############################################

detect_os() {
    print_step "Detecting your system..."

    case "$(uname -s)" in
        Darwin*)
            OS="macos"
            print_success "Detected: macOS"
            ;;
        Linux*)
            OS="linux"
            if [[ -f /etc/os-release ]]; then
                . /etc/os-release
                print_success "Detected: $PRETTY_NAME"
            else
                print_success "Detected: Linux"
            fi
            ;;
        MINGW*|MSYS*|CYGWIN*)
            OS="windows"
            print_success "Detected: Windows"
            ;;
        *)
            print_error "Unsupported operating system: $(uname -s)"
            exit 1
            ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        armv7l)
            ARCH="armv7"
            ;;
        *)
            print_error "Unsupported architecture: $(uname -m)"
            exit 1
            ;;
    esac
    print_success "Architecture: $ARCH"
}

#############################################
# Dependency Checking
#############################################

check_dependencies() {
    print_step "Checking dependencies..."

    local missing_deps=()

    # Check for CLI dependencies
    if [[ "$INSTALL_CLI" == true ]] && [[ "$BUILD_FROM_SOURCE" == true ]]; then
        if ! command_exists go; then
            missing_deps+=("go")
            print_warning "Go is not installed (required for building from source)"
        else
            local go_version=$(go version | awk '{print $3}' | sed 's/go//')
            print_success "Go $go_version is installed"
        fi

        if ! command_exists git; then
            missing_deps+=("git")
            print_warning "Git is not installed"
        else
            print_success "Git is installed"
        fi

        if ! command_exists make; then
            missing_deps+=("make")
            print_warning "Make is not installed"
        else
            print_success "Make is installed"
        fi
    fi

    # Check for GUI dependencies
    if [[ "$INSTALL_GUI" == true ]]; then
        if ! command_exists node; then
            missing_deps+=("node")
            print_warning "Node.js is not installed (required for GUI)"
        else
            local node_version=$(node --version)
            print_success "Node.js $node_version is installed"
        fi

        if ! command_exists pnpm; then
            missing_deps+=("pnpm")
            print_warning "pnpm is not installed (required for GUI)"
        else
            local pnpm_version=$(pnpm --version)
            print_success "pnpm $pnpm_version is installed"
        fi

        if ! command_exists cargo; then
            missing_deps+=("rust")
            print_warning "Rust is not installed (required for GUI)"
        else
            local rust_version=$(rustc --version | awk '{print $2}')
            print_success "Rust $rust_version is installed"
        fi
    fi

    # Check for documentation dependencies
    if [[ "$INSTALL_DOCS" == true ]]; then
        if ! command_exists python3; then
            missing_deps+=("python3")
            print_warning "Python 3 is not installed (required for docs)"
        else
            local python_version=$(python3 --version | awk '{print $2}')
            print_success "Python $python_version is installed"
        fi
    fi

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        echo ""
        print_warning "Missing dependencies: ${missing_deps[*]}"

        if ! $QUICK_MODE; then
            if ask_yes_no "Would you like to install missing dependencies?" "y"; then
                install_dependencies "${missing_deps[@]}"
            else
                print_error "Cannot proceed without required dependencies"
                exit 1
            fi
        fi
    else
        print_success "All required dependencies are installed!"
    fi
}

install_dependencies() {
    local deps=("$@")
    print_step "Installing dependencies..."

    case "$OS" in
        macos)
            if ! command_exists brew; then
                print_info "Installing Homebrew..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi

            for dep in "${deps[@]}"; do
                case "$dep" in
                    go)
                        brew install go
                        ;;
                    node)
                        brew install node@18
                        ;;
                    pnpm)
                        brew install pnpm
                        ;;
                    rust)
                        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
                        source "$HOME/.cargo/env"
                        ;;
                    python3)
                        brew install python@3.11
                        ;;
                    git|make)
                        xcode-select --install 2>/dev/null || true
                        ;;
                esac
            done
            ;;

        linux)
            local pkg_manager=""
            if command_exists apt-get; then
                pkg_manager="apt"
                sudo apt-get update
            elif command_exists dnf; then
                pkg_manager="dnf"
            elif command_exists yum; then
                pkg_manager="yum"
            elif command_exists pacman; then
                pkg_manager="pacman"
            fi

            for dep in "${deps[@]}"; do
                case "$dep" in
                    go)
                        print_info "Installing Go..."
                        if [[ "$pkg_manager" == "apt" ]]; then
                            sudo apt-get install -y golang-go
                        elif [[ "$pkg_manager" == "dnf" ]]; then
                            sudo dnf install -y golang
                        elif [[ "$pkg_manager" == "yum" ]]; then
                            sudo yum install -y golang
                        elif [[ "$pkg_manager" == "pacman" ]]; then
                            sudo pacman -S --noconfirm go
                        fi
                        ;;
                    node)
                        print_info "Installing Node.js..."
                        if [[ "$pkg_manager" == "apt" ]]; then
                            curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
                            sudo apt-get install -y nodejs
                        elif [[ "$pkg_manager" == "dnf" ]] || [[ "$pkg_manager" == "yum" ]]; then
                            curl -fsSL https://rpm.nodesource.com/setup_18.x | sudo bash -
                            sudo $pkg_manager install -y nodejs
                        fi
                        ;;
                    pnpm)
                        curl -fsSL https://get.pnpm.io/install.sh | sh -
                        ;;
                    rust)
                        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
                        source "$HOME/.cargo/env"
                        ;;
                    python3)
                        if [[ "$pkg_manager" == "apt" ]]; then
                            sudo apt-get install -y python3 python3-pip
                        elif [[ "$pkg_manager" == "dnf" ]] || [[ "$pkg_manager" == "yum" ]]; then
                            sudo $pkg_manager install -y python3 python3-pip
                        fi
                        ;;
                    git)
                        if [[ "$pkg_manager" == "apt" ]]; then
                            sudo apt-get install -y git
                        elif [[ "$pkg_manager" == "dnf" ]] || [[ "$pkg_manager" == "yum" ]]; then
                            sudo $pkg_manager install -y git
                        fi
                        ;;
                    make)
                        if [[ "$pkg_manager" == "apt" ]]; then
                            sudo apt-get install -y build-essential
                        elif [[ "$pkg_manager" == "dnf" ]] || [[ "$pkg_manager" == "yum" ]]; then
                            sudo $pkg_manager groupinstall -y "Development Tools"
                        fi
                        ;;
                esac
            done
            ;;

        windows)
            print_info "Please install the following manually or use Scoop/Chocolatey:"
            for dep in "${deps[@]}"; do
                echo "  - $dep"
            done
            print_info "Visit: https://scoop.sh or https://chocolatey.org"
            ;;
    esac
}

#############################################
# Installation Method Selection
#############################################

select_install_method() {
    print_step "Selecting installation method..."

    case "$OS" in
        macos)
            if command_exists brew; then
                INSTALL_METHOD="homebrew"
                print_success "Using Homebrew (recommended for macOS)"
            else
                print_info "Homebrew not found. Available options:"
                echo "  1) Install via Homebrew (recommended)"
                echo "  2) Download pre-built binary"
                echo "  3) Build from source"

                if ! $QUICK_MODE; then
                    read -p "$(echo -e ${CYAN}?${NC} Select installation method [1]: )" choice
                    choice=${choice:-1}

                    case "$choice" in
                        1)
                            install_dependencies "homebrew"
                            INSTALL_METHOD="homebrew"
                            ;;
                        2)
                            INSTALL_METHOD="binary"
                            ;;
                        3)
                            INSTALL_METHOD="source"
                            BUILD_FROM_SOURCE=true
                            ;;
                    esac
                else
                    INSTALL_METHOD="binary"
                fi
            fi
            ;;

        linux)
            if [[ -f /etc/os-release ]]; then
                . /etc/os-release
                case "$ID" in
                    ubuntu|debian)
                        if command_exists apt-get; then
                            INSTALL_METHOD="apt"
                            print_success "Using APT package manager"
                        fi
                        ;;
                    fedora|rhel|centos)
                        if command_exists dnf; then
                            INSTALL_METHOD="dnf"
                            print_success "Using DNF package manager"
                        elif command_exists yum; then
                            INSTALL_METHOD="yum"
                            print_success "Using YUM package manager"
                        fi
                        ;;
                    arch|manjaro)
                        INSTALL_METHOD="binary"
                        print_info "Using pre-built binary (AUR package coming soon)"
                        ;;
                esac
            fi

            if [[ -z "$INSTALL_METHOD" ]]; then
                if command_exists brew; then
                    INSTALL_METHOD="homebrew"
                    print_success "Using Homebrew on Linux"
                else
                    INSTALL_METHOD="binary"
                    print_success "Using pre-built binary"
                fi
            fi
            ;;

        windows)
            if command_exists scoop; then
                INSTALL_METHOD="scoop"
                print_success "Using Scoop (recommended for Windows)"
            else
                print_info "Scoop not found. Recommended: install Scoop first"
                print_info "Visit: https://scoop.sh"
                INSTALL_METHOD="binary"
            fi
            ;;
    esac
}

#############################################
# Component Selection
#############################################

select_components() {
    if $QUICK_MODE; then
        print_step "Quick mode: Installing CLI tools and plugins"
        INSTALL_CLI=true
        INSTALL_GUI=false
        INSTALL_PLUGINS=true
        INSTALL_DOCS=false
        return
    fi

    print_step "Select components to install..."

    echo ""
    echo "Available components:"
    echo "  1) CLI Tools (0xgenctl, 0xgend) - Core command-line interface [recommended]"
    echo "  2) Desktop GUI - Tauri-based graphical interface"
    echo "  3) Plugins - Security testing plugins (cartographer, hydra, raider, etc.)"
    echo "  4) Documentation - Local documentation server"
    echo ""

    if ask_yes_no "Install CLI tools?" "y"; then
        INSTALL_CLI=true
    else
        INSTALL_CLI=false
    fi

    if ask_yes_no "Install Desktop GUI?" "n"; then
        INSTALL_GUI=true
    else
        INSTALL_GUI=false
    fi

    if ask_yes_no "Install plugins?" "y"; then
        INSTALL_PLUGINS=true
    else
        INSTALL_PLUGINS=false
    fi

    if ask_yes_no "Install documentation?" "n"; then
        INSTALL_DOCS=true
    else
        INSTALL_DOCS=false
    fi
}

#############################################
# Installation Functions
#############################################

install_via_homebrew() {
    print_step "Installing via Homebrew..."

    # Add tap if not already added
    if ! brew tap | grep -q "rowandark/0xgen"; then
        print_info "Adding 0xGen tap..."
        brew tap rowandark/0xgen
    fi

    if [[ "$INSTALL_CLI" == true ]]; then
        print_info "Installing 0xGen CLI..."
        brew install 0xgen
        print_success "0xGen CLI installed!"
    fi

    if [[ "$INSTALL_GUI" == true ]]; then
        print_warning "Desktop GUI installation via Homebrew coming soon"
        print_info "Please build from source for now"
    fi
}

install_via_apt() {
    print_step "Installing via APT..."

    # Add repository
    print_info "Adding 0xGen repository..."
    curl -fsSL https://packages.0xgen.dev/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/0xgen-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/0xgen-archive-keyring.gpg] https://packages.0xgen.dev/deb stable main" | \
        sudo tee /etc/apt/sources.list.d/0xgen.list

    sudo apt-get update

    if [[ "$INSTALL_CLI" == true ]]; then
        print_info "Installing 0xGen CLI..."
        sudo apt-get install -y 0xgen
        print_success "0xGen CLI installed!"
    fi
}

install_via_dnf() {
    print_step "Installing via DNF..."

    # Add repository
    print_info "Adding 0xGen repository..."
    sudo tee /etc/yum.repos.d/0xgen.repo > /dev/null << EOF
[0xgen]
name=0xGen Repository
baseurl=https://packages.0xgen.dev/rpm
enabled=1
gpgcheck=1
gpgkey=https://packages.0xgen.dev/gpg.key
EOF

    if [[ "$INSTALL_CLI" == true ]]; then
        print_info "Installing 0xGen CLI..."
        sudo dnf install -y 0xgen
        print_success "0xGen CLI installed!"
    fi
}

install_via_scoop() {
    print_step "Installing via Scoop..."

    # Add bucket if not already added
    if ! scoop bucket list | grep -q "0xgen"; then
        print_info "Adding 0xGen bucket..."
        scoop bucket add 0xgen https://github.com/RowanDark/scoop-0xgen
    fi

    if [[ "$INSTALL_CLI" == true ]]; then
        print_info "Installing 0xGen CLI..."
        scoop install 0xgen
        print_success "0xGen CLI installed!"
    fi
}

install_via_binary() {
    print_step "Installing from pre-built binary..."

    # Get the latest version tag from GitHub API
    local version=$(curl -fsSL https://api.github.com/repos/RowanDark/0xGen/releases/latest | grep '"tag_name":' | sed -E 's/.*"tag_name": "([^"]+)".*/\1/')
    if [[ -z "$version" ]]; then
        print_error "Failed to fetch latest version from GitHub"
        return 1
    fi

    local base_url="https://github.com/RowanDark/0xGen/releases/latest/download"

    # Determine binary name (GoReleaser format: 0xgenctl_${version}_${os}_${arch})
    local binary_name="0xgenctl_${version}_${OS}_${ARCH}"
    if [[ "$OS" == "windows" ]]; then
        binary_name="${binary_name}.zip"
    else
        binary_name="${binary_name}.tar.gz"
    fi

    print_info "Downloading $binary_name..."
    local temp_dir=$(mktemp -d)

    if curl -fsSL -o "$temp_dir/$binary_name" "$base_url/$binary_name"; then
        print_success "Downloaded successfully"

        # Extract
        print_info "Extracting..."
        cd "$temp_dir"
        if [[ "$OS" == "windows" ]]; then
            unzip -q "$binary_name"
        else
            tar -xzf "$binary_name"
        fi

        # Install binaries
        print_info "Installing to $INSTALL_DIR..."
        sudo mkdir -p "$INSTALL_DIR"

        if [[ "$INSTALL_CLI" == true ]]; then
            sudo cp 0xgenctl "$INSTALL_DIR/"
            sudo cp 0xgend "$INSTALL_DIR/"
            sudo chmod +x "$INSTALL_DIR/0xgenctl" "$INSTALL_DIR/0xgend"
            print_success "Installed 0xgenctl and 0xgend"
        fi

        # Cleanup
        cd -
        rm -rf "$temp_dir"

        print_success "Binary installation complete!"
    else
        print_error "Failed to download binary"
        print_info "Please visit: https://github.com/RowanDark/0xGen/releases"
        return 1
    fi
}

install_via_source() {
    print_step "Building from source..."

    local repo_dir="${HOME}/0xGen"

    # Clone repository if needed
    if [[ ! -d "$repo_dir" ]]; then
        print_info "Cloning repository..."
        git clone https://github.com/RowanDark/0xGen.git "$repo_dir"
    else
        print_info "Using existing repository at $repo_dir"
        cd "$repo_dir"
        git pull origin main
    fi

    cd "$repo_dir"

    # Build CLI
    if [[ "$INSTALL_CLI" == true ]]; then
        print_info "Building CLI tools..."
        make build

        print_info "Installing to $INSTALL_DIR..."
        sudo mkdir -p "$INSTALL_DIR"
        sudo cp bin/0xgenctl "$INSTALL_DIR/"
        sudo cp bin/0xgend "$INSTALL_DIR/"
        sudo chmod +x "$INSTALL_DIR/0xgenctl" "$INSTALL_DIR/0xgend"

        print_success "CLI tools built and installed!"
    fi

    # Build GUI
    if [[ "$INSTALL_GUI" == true ]]; then
        print_info "Building Desktop GUI..."
        cd apps/desktop-shell

        print_info "Installing Node.js dependencies..."
        pnpm install

        print_info "Building Tauri application..."
        pnpm tauri build

        # Installation location varies by OS
        case "$OS" in
            macos)
                print_info "Installing to /Applications..."
                sudo cp -r src-tauri/target/release/bundle/macos/0xGen.app /Applications/
                ;;
            linux)
                print_info "Installing desktop entry..."
                sudo cp src-tauri/target/release/bundle/deb/0xgen*.deb /tmp/
                sudo dpkg -i /tmp/0xgen*.deb || sudo apt-get install -f -y
                ;;
            windows)
                print_info "MSI installer created at: src-tauri/target/release/bundle/msi/"
                ;;
        esac

        cd "$repo_dir"
        print_success "Desktop GUI built and installed!"
    fi

    # Install plugins
    if [[ "$INSTALL_PLUGINS" == true ]]; then
        print_info "Installing plugins..."
        # Plugins are bundled with the CLI, just validate them
        make validate-manifests
        print_success "Plugins validated!"
    fi

    # Build documentation
    if [[ "$INSTALL_DOCS" == true ]]; then
        print_info "Building documentation..."
        cd docs
        pip3 install -r requirements.txt
        mkdocs build
        print_success "Documentation built!"
        print_info "To serve docs: cd $repo_dir/docs && mkdocs serve"
    fi
}

#############################################
# Post-Installation Setup
#############################################

post_install_setup() {
    print_step "Post-installation setup..."

    # Verify installation
    if command_exists 0xgenctl; then
        local version=$(0xgenctl version 2>/dev/null || echo "unknown")
        print_success "0xgenctl is installed: $version"
    else
        print_warning "0xgenctl not found in PATH"
        print_info "You may need to add $INSTALL_DIR to your PATH"
    fi

    # CA Certificate setup
    if [[ "$INSTALL_CLI" == true ]] && ! $QUICK_MODE; then
        echo ""
        print_info "For proxy functionality, you'll need to trust the 0xGen CA certificate"

        if ask_yes_no "Would you like to set up the CA certificate now?" "y"; then
            setup_ca_certificate
        else
            print_info "You can set up the CA certificate later with: 0xgenctl ca install"
        fi
    fi

    # Create config directory
    local config_dir="${HOME}/.0xgen"
    if [[ ! -d "$config_dir" ]]; then
        mkdir -p "$config_dir"
        print_success "Created config directory: $config_dir"
    fi

    # Plugin directory
    if [[ "$INSTALL_PLUGINS" == true ]]; then
        local plugin_dir="$config_dir/plugins"
        mkdir -p "$plugin_dir"
        print_success "Created plugin directory: $plugin_dir"
    fi

    print_success "Post-installation setup complete!"
}

setup_ca_certificate() {
    print_info "Setting up CA certificate..."

    # Generate CA if it doesn't exist
    if ! 0xgenctl ca export >/dev/null 2>&1; then
        print_info "Generating CA certificate..."
        0xgenctl ca generate
    fi

    # Trust the CA
    case "$OS" in
        macos)
            print_info "Trusting CA in macOS keychain..."
            0xgenctl ca install
            print_success "CA certificate trusted!"
            ;;
        linux)
            print_info "Trusting CA in system certificate store..."
            0xgenctl ca install
            print_success "CA certificate trusted!"
            ;;
        windows)
            print_info "Trusting CA in Windows certificate store..."
            0xgenctl ca install
            print_success "CA certificate trusted!"
            ;;
    esac
}

#############################################
# Summary
#############################################

print_summary() {
    echo ""
    print_step "Installation Summary"
    echo ""

    echo -e "${BOLD}Installed Components:${NC}"
    [[ "$INSTALL_CLI" == true ]] && echo -e "  ${GREEN}✓${NC} CLI Tools (0xgenctl, 0xgend)"
    [[ "$INSTALL_GUI" == true ]] && echo -e "  ${GREEN}✓${NC} Desktop GUI"
    [[ "$INSTALL_PLUGINS" == true ]] && echo -e "  ${GREEN}✓${NC} Plugins"
    [[ "$INSTALL_DOCS" == true ]] && echo -e "  ${GREEN}✓${NC} Documentation"

    echo ""
    echo -e "${BOLD}Next Steps:${NC}"
    echo ""
    echo "  1. Verify installation:"
    echo "     $ 0xgenctl version"
    echo ""
    echo "  2. Start the proxy daemon:"
    echo "     $ 0xgend start"
    echo ""
    echo "  3. Configure your browser to use the proxy:"
    echo "     HTTP Proxy: localhost:8080"
    echo ""
    echo "  4. Run a quick test:"
    echo "     $ 0xgenctl scan https://example.com"
    echo ""

    if [[ "$INSTALL_GUI" == true ]]; then
        echo "  5. Launch the Desktop GUI:"
        case "$OS" in
            macos)
                echo "     Open from Applications folder"
                ;;
            linux)
                echo "     $ 0xgen-gui"
                ;;
            windows)
                echo "     Search for '0xGen' in Start Menu"
                ;;
        esac
        echo ""
    fi

    echo -e "${BOLD}Documentation:${NC}"
    echo "  - Quick Start: https://docs.0xgen.dev/quickstart"
    echo "  - User Guide: https://docs.0xgen.dev/guide"
    echo "  - Plugin Development: https://docs.0xgen.dev/plugins"
    echo ""

    echo -e "${BOLD}Community:${NC}"
    echo "  - GitHub: https://github.com/RowanDark/0xGen"
    echo "  - Issues: https://github.com/RowanDark/0xGen/issues"
    echo ""

    echo -e "${GREEN}${BOLD}Thank you for installing 0xGen!${NC}"
    echo ""
}

#############################################
# Main Installation Flow
#############################################

main() {
    # Parse command-line arguments first (to handle --help before checks)
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --quick|-q)
                QUICK_MODE=true
                shift
                ;;
            --cli-only)
                INSTALL_CLI=true
                INSTALL_GUI=false
                INSTALL_PLUGINS=true
                INSTALL_DOCS=false
                shift
                ;;
            --gui)
                INSTALL_GUI=true
                shift
                ;;
            --source)
                BUILD_FROM_SOURCE=true
                shift
                ;;
            --install-dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --quick, -q        Quick install with defaults"
                echo "  --cli-only         Install only CLI tools"
                echo "  --gui              Include Desktop GUI"
                echo "  --source           Build from source"
                echo "  --install-dir DIR  Installation directory (default: /usr/local/bin)"
                echo "  --help, -h         Show this help message"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done

    # Check if running as root (not recommended)
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root is not recommended"
        if ! ask_yes_no "Continue anyway?" "n"; then
            exit 1
        fi
    fi

    print_header

    # Show quick mode or custom mode
    if ! $QUICK_MODE; then
        echo "Installation Modes:"
        echo "  1) Quick Install - Recommended defaults (CLI + plugins)"
        echo "  2) Custom Install - Choose components"
        echo ""
        read -p "$(echo -e ${CYAN}?${NC} Select mode [1]: )" mode_choice
        mode_choice=${mode_choice:-1}

        if [[ "$mode_choice" == "1" ]]; then
            QUICK_MODE=true
        fi
    fi

    # Detection
    detect_os
    detect_arch

    # Component selection
    select_components

    # Check dependencies
    check_dependencies

    # Select installation method
    select_install_method

    # Confirm installation
    if ! $QUICK_MODE; then
        echo ""
        print_step "Installation Plan"
        echo "  OS: $OS ($ARCH)"
        echo "  Method: $INSTALL_METHOD"
        echo "  Install CLI: $INSTALL_CLI"
        echo "  Install GUI: $INSTALL_GUI"
        echo "  Install Plugins: $INSTALL_PLUGINS"
        echo "  Install Docs: $INSTALL_DOCS"
        echo ""

        if ! ask_yes_no "Proceed with installation?" "y"; then
            print_info "Installation cancelled"
            exit 0
        fi
    fi

    # Perform installation
    case "$INSTALL_METHOD" in
        homebrew)
            install_via_homebrew
            ;;
        apt)
            install_via_apt
            ;;
        dnf|yum)
            install_via_dnf
            ;;
        scoop)
            install_via_scoop
            ;;
        binary)
            install_via_binary
            ;;
        source)
            install_via_source
            ;;
        *)
            print_error "No installation method selected"
            exit 1
            ;;
    esac

    # Post-installation
    post_install_setup

    # Show summary
    print_summary
}

# Run main installation
main "$@"
