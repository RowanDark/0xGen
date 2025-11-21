# 0xGen Easy Install Wizard - PowerShell Version
# Centralized installation script for Windows
#
# Usage:
#   irm https://raw.githubusercontent.com/RowanDark/0xGen/main/install.ps1 | iex
#   or
#   .\install.ps1

#Requires -Version 5.1

param(
    [switch]$Quick,
    [switch]$CliOnly,
    [switch]$Gui,
    [switch]$Help,
    [string]$InstallDir = "$env:LOCALAPPDATA\0xGen\bin"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Version
$WizardVersion = "1.0.0"

# Global variables
$InstallCLI = $true
$InstallGUI = $false
$InstallPlugins = $true
$InstallDocs = $false
$QuickMode = $Quick.IsPresent

#############################################
# Utility Functions
#############################################

function Write-Header {
    Write-Host ""
    Write-Host "   ___        ____" -ForegroundColor Cyan
    Write-Host "  / _ \ __  _/ ___| ___ _ __" -ForegroundColor Cyan
    Write-Host " | | | |\ \/ / |  _/ _ \ '_ \" -ForegroundColor Cyan
    Write-Host " | |_| | >  <| |_| |  __/ | | |" -ForegroundColor Cyan
    Write-Host "  \___/ /_/\_\\____|\___|_| |_|" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    Easy Install Wizard v$WizardVersion" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Welcome to the 0xGen installation wizard!" -ForegroundColor White
    Write-Host ""
}

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "=> $Message" -ForegroundColor Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "✓ $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "✗ $Message" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠ $Message" -ForegroundColor Yellow
}

function Write-Info {
    param([string]$Message)
    Write-Host "ℹ $Message" -ForegroundColor Cyan
}

function Ask-YesNo {
    param(
        [string]$Prompt,
        [bool]$Default = $false
    )

    if ($QuickMode) {
        return $Default
    }

    $defaultText = if ($Default) { "[Y/n]" } else { "[y/N]" }
    $response = Read-Host "? $Prompt $defaultText"

    if ([string]::IsNullOrWhiteSpace($response)) {
        return $Default
    }

    return $response -match '^[Yy]'
}

function Test-CommandExists {
    param([string]$Command)
    $null -ne (Get-Command $Command -ErrorAction SilentlyContinue)
}

function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

#############################################
# System Detection
#############################################

function Get-SystemInfo {
    Write-Step "Detecting your system..."

    $os = "windows"
    $arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }

    $osInfo = Get-CimInstance Win32_OperatingSystem
    Write-Success "Detected: $($osInfo.Caption) ($arch)"

    return @{
        OS = $os
        Arch = $arch
        OSInfo = $osInfo
    }
}

#############################################
# Dependency Checking
#############################################

function Test-Dependencies {
    Write-Step "Checking dependencies..."

    $missingDeps = @()

    # Check for Scoop
    if (Test-CommandExists "scoop") {
        Write-Success "Scoop package manager is installed"
    } else {
        Write-Warning "Scoop is not installed (recommended for Windows)"
        $missingDeps += "scoop"
    }

    # Check for Git
    if (Test-CommandExists "git") {
        $gitVersion = (git --version) -replace 'git version ', ''
        Write-Success "Git $gitVersion is installed"
    } else {
        Write-Warning "Git is not installed"
        $missingDeps += "git"
    }

    # Check for GUI dependencies
    if ($InstallGUI) {
        if (Test-CommandExists "node") {
            $nodeVersion = node --version
            Write-Success "Node.js $nodeVersion is installed"
        } else {
            Write-Warning "Node.js is not installed (required for GUI)"
            $missingDeps += "node"
        }

        if (Test-CommandExists "pnpm") {
            $pnpmVersion = pnpm --version
            Write-Success "pnpm $pnpmVersion is installed"
        } else {
            Write-Warning "pnpm is not installed (required for GUI)"
            $missingDeps += "pnpm"
        }

        if (Test-CommandExists "cargo") {
            $rustVersion = (rustc --version) -replace 'rustc ', '' -replace ' \(.*\)', ''
            Write-Success "Rust $rustVersion is installed"
        } else {
            Write-Warning "Rust is not installed (required for GUI)"
            $missingDeps += "rust"
        }
    }

    if ($missingDeps.Count -gt 0) {
        Write-Host ""
        Write-Warning "Missing dependencies: $($missingDeps -join ', ')"

        if (-not $QuickMode) {
            if (Ask-YesNo "Would you like to install missing dependencies?" $true) {
                Install-Dependencies $missingDeps
            } else {
                Write-Error "Cannot proceed without required dependencies"
                exit 1
            }
        }
    } else {
        Write-Success "All required dependencies are installed!"
    }
}

function Install-Dependencies {
    param([string[]]$Dependencies)

    Write-Step "Installing dependencies..."

    foreach ($dep in $Dependencies) {
        switch ($dep) {
            "scoop" {
                Write-Info "Installing Scoop..."
                Invoke-Expression "& {$(Invoke-RestMethod get.scoop.sh)} -RunAsAdmin"
            }
            "git" {
                if (Test-CommandExists "scoop") {
                    scoop install git
                } else {
                    Write-Info "Installing Git..."
                    $gitInstaller = "$env:TEMP\Git-Setup.exe"
                    Invoke-WebRequest -Uri "https://github.com/git-for-windows/git/releases/latest/download/Git-2.43.0-64-bit.exe" -OutFile $gitInstaller
                    Start-Process $gitInstaller -ArgumentList "/VERYSILENT" -Wait
                    Remove-Item $gitInstaller
                }
            }
            "node" {
                if (Test-CommandExists "scoop") {
                    scoop install nodejs-lts
                } else {
                    Write-Info "Installing Node.js..."
                    $nodeInstaller = "$env:TEMP\node-setup.msi"
                    Invoke-WebRequest -Uri "https://nodejs.org/dist/v18.19.0/node-v18.19.0-x64.msi" -OutFile $nodeInstaller
                    Start-Process msiexec.exe -ArgumentList "/i `"$nodeInstaller`" /quiet" -Wait
                    Remove-Item $nodeInstaller
                }
            }
            "pnpm" {
                if (Test-CommandExists "npm") {
                    npm install -g pnpm
                } else {
                    Write-Warning "Please install Node.js first"
                }
            }
            "rust" {
                Write-Info "Installing Rust..."
                $rustupInit = "$env:TEMP\rustup-init.exe"
                Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $rustupInit
                Start-Process $rustupInit -ArgumentList "-y" -Wait
                Remove-Item $rustupInit
            }
        }
    }
}

#############################################
# Component Selection
#############################################

function Select-Components {
    if ($QuickMode -or $CliOnly) {
        Write-Step "Quick mode: Installing CLI tools and plugins"
        $script:InstallCLI = $true
        $script:InstallGUI = $false
        $script:InstallPlugins = $true
        $script:InstallDocs = $false
        return
    }

    Write-Step "Select components to install..."

    Write-Host ""
    Write-Host "Available components:"
    Write-Host "  1) CLI Tools (0xgenctl, 0xgend) - Core command-line interface [recommended]"
    Write-Host "  2) Desktop GUI - Tauri-based graphical interface"
    Write-Host "  3) Plugins - Security testing plugins"
    Write-Host "  4) Documentation - Local documentation"
    Write-Host ""

    $script:InstallCLI = Ask-YesNo "Install CLI tools?" $true
    $script:InstallGUI = Ask-YesNo "Install Desktop GUI?" $false
    $script:InstallPlugins = Ask-YesNo "Install plugins?" $true
    $script:InstallDocs = Ask-YesNo "Install documentation?" $false
}

#############################################
# Installation Functions
#############################################

function Install-ViaScoop {
    Write-Step "Installing via Scoop..."

    # Add bucket if not already added
    $buckets = scoop bucket list
    if ($buckets -notcontains "0xgen") {
        Write-Info "Adding 0xGen bucket..."
        scoop bucket add 0xgen https://github.com/RowanDark/scoop-0xgen
    }

    if ($InstallCLI) {
        Write-Info "Installing 0xGen CLI..."
        scoop install 0xgen
        Write-Success "0xGen CLI installed!"
    }

    if ($InstallGUI) {
        Write-Warning "Desktop GUI installation via Scoop coming soon"
        Write-Info "Please build from source for now"
    }
}

function Install-ViaBinary {
    Write-Step "Installing from pre-built binary..."

    $baseUrl = "https://github.com/RowanDark/0xGen/releases/latest/download"
    $binaryName = "0xgen_windows_amd64.zip"

    Write-Info "Downloading $binaryName..."
    $tempFile = "$env:TEMP\$binaryName"
    $tempDir = "$env:TEMP\0xgen-install"

    try {
        Invoke-WebRequest -Uri "$baseUrl/$binaryName" -OutFile $tempFile
        Write-Success "Downloaded successfully"

        # Extract
        Write-Info "Extracting..."
        if (Test-Path $tempDir) {
            Remove-Item -Path $tempDir -Recurse -Force
        }
        Expand-Archive -Path $tempFile -DestinationPath $tempDir

        # Install binaries
        Write-Info "Installing to $InstallDir..."
        if (-not (Test-Path $InstallDir)) {
            New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        }

        if ($InstallCLI) {
            Copy-Item "$tempDir\0xgenctl.exe" -Destination $InstallDir -Force
            Copy-Item "$tempDir\0xgend.exe" -Destination $InstallDir -Force
            Write-Success "Installed 0xgenctl.exe and 0xgend.exe"
        }

        # Add to PATH if not already
        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        if ($userPath -notlike "*$InstallDir*") {
            Write-Info "Adding $InstallDir to PATH..."
            [Environment]::SetEnvironmentVariable("Path", "$userPath;$InstallDir", "User")
            Write-Success "Added to PATH (restart terminal to apply)"
        }

        # Cleanup
        Remove-Item $tempFile -Force
        Remove-Item $tempDir -Recurse -Force

        Write-Success "Binary installation complete!"
    } catch {
        Write-Error "Failed to download or install binary: $_"
        Write-Info "Please visit: https://github.com/RowanDark/0xGen/releases"
        return
    }
}

function Install-ViaSource {
    Write-Step "Building from source..."

    $repoDir = "$env:USERPROFILE\0xGen"

    # Clone repository if needed
    if (-not (Test-Path $repoDir)) {
        Write-Info "Cloning repository..."
        git clone https://github.com/RowanDark/0xGen.git $repoDir
    } else {
        Write-Info "Using existing repository at $repoDir"
        Push-Location $repoDir
        git pull origin main
        Pop-Location
    }

    Push-Location $repoDir

    try {
        # Build CLI
        if ($InstallCLI) {
            Write-Info "Building CLI tools..."
            & make build

            Write-Info "Installing to $InstallDir..."
            if (-not (Test-Path $InstallDir)) {
                New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
            }

            Copy-Item "bin\0xgenctl.exe" -Destination $InstallDir -Force
            Copy-Item "bin\0xgend.exe" -Destination $InstallDir -Force

            Write-Success "CLI tools built and installed!"
        }

        # Build GUI
        if ($InstallGUI) {
            Write-Info "Building Desktop GUI..."
            Push-Location apps\desktop-shell

            Write-Info "Installing Node.js dependencies..."
            pnpm install

            Write-Info "Building Tauri application..."
            pnpm tauri build

            Write-Info "MSI installer created at: src-tauri\target\release\bundle\msi\"

            Pop-Location
            Write-Success "Desktop GUI built!"
        }

        # Install plugins
        if ($InstallPlugins) {
            Write-Info "Installing plugins..."
            & make validate-manifests
            Write-Success "Plugins validated!"
        }

        # Build documentation
        if ($InstallDocs) {
            Write-Info "Building documentation..."
            Push-Location docs
            pip install -r requirements.txt
            mkdocs build
            Write-Success "Documentation built!"
            Write-Info "To serve docs: cd $repoDir\docs && mkdocs serve"
            Pop-Location
        }
    } finally {
        Pop-Location
    }
}

#############################################
# Post-Installation Setup
#############################################

function Invoke-PostInstallSetup {
    Write-Step "Post-installation setup..."

    # Refresh environment variables
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "User") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "Machine")

    # Verify installation
    if (Test-CommandExists "0xgenctl") {
        $version = & 0xgenctl version 2>$null
        if ($version) {
            Write-Success "0xgenctl is installed: $version"
        } else {
            Write-Success "0xgenctl is installed"
        }
    } else {
        Write-Warning "0xgenctl not found in PATH"
        Write-Info "You may need to restart your terminal or add $InstallDir to PATH"
    }

    # CA Certificate setup
    if ($InstallCLI -and -not $QuickMode) {
        Write-Host ""
        Write-Info "For proxy functionality, you'll need to trust the 0xGen CA certificate"

        if (Ask-YesNo "Would you like to set up the CA certificate now?" $true) {
            Set-CACertificate
        } else {
            Write-Info "You can set up the CA certificate later with: 0xgenctl ca install"
        }
    }

    # Create config directory
    $configDir = "$env:USERPROFILE\.0xgen"
    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
        Write-Success "Created config directory: $configDir"
    }

    # Plugin directory
    if ($InstallPlugins) {
        $pluginDir = "$configDir\plugins"
        if (-not (Test-Path $pluginDir)) {
            New-Item -ItemType Directory -Path $pluginDir -Force | Out-Null
        }
        Write-Success "Created plugin directory: $pluginDir"
    }

    Write-Success "Post-installation setup complete!"
}

function Set-CACertificate {
    Write-Info "Setting up CA certificate..."

    # Generate CA if it doesn't exist
    try {
        & 0xgenctl ca export | Out-Null
    } catch {
        Write-Info "Generating CA certificate..."
        & 0xgenctl ca generate
    }

    # Trust the CA
    Write-Info "Trusting CA in Windows certificate store..."
    if (Test-IsAdmin) {
        & 0xgenctl ca install
        Write-Success "CA certificate trusted!"
    } else {
        Write-Warning "Administrator privileges required to install CA certificate"
        Write-Info "Please run: 0xgenctl ca install (as Administrator)"
    }
}

#############################################
# Summary
#############################################

function Write-Summary {
    Write-Host ""
    Write-Step "Installation Summary"
    Write-Host ""

    Write-Host "Installed Components:" -ForegroundColor White
    if ($InstallCLI) { Write-Success "CLI Tools (0xgenctl, 0xgend)" }
    if ($InstallGUI) { Write-Success "Desktop GUI" }
    if ($InstallPlugins) { Write-Success "Plugins" }
    if ($InstallDocs) { Write-Success "Documentation" }

    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor White
    Write-Host ""
    Write-Host "  1. Verify installation:"
    Write-Host "     > 0xgenctl version"
    Write-Host ""
    Write-Host "  2. Start the proxy daemon:"
    Write-Host "     > 0xgend start"
    Write-Host ""
    Write-Host "  3. Configure your browser to use the proxy:"
    Write-Host "     HTTP Proxy: localhost:8080"
    Write-Host ""
    Write-Host "  4. Run a quick test:"
    Write-Host "     > 0xgenctl scan https://example.com"
    Write-Host ""

    if ($InstallGUI) {
        Write-Host "  5. Launch the Desktop GUI:"
        Write-Host "     Search for '0xGen' in Start Menu"
        Write-Host ""
    }

    Write-Host "Documentation:" -ForegroundColor White
    Write-Host "  - Quick Start: https://docs.0xgen.dev/quickstart"
    Write-Host "  - User Guide: https://docs.0xgen.dev/guide"
    Write-Host "  - Plugin Development: https://docs.0xgen.dev/plugins"
    Write-Host ""

    Write-Host "Community:" -ForegroundColor White
    Write-Host "  - GitHub: https://github.com/RowanDark/0xGen"
    Write-Host "  - Issues: https://github.com/RowanDark/0xGen/issues"
    Write-Host ""

    Write-Host "Thank you for installing 0xGen!" -ForegroundColor Green
    Write-Host ""
}

#############################################
# Main Installation Flow
#############################################

function Main {
    if ($Help) {
        Write-Host "Usage: .\install.ps1 [OPTIONS]"
        Write-Host ""
        Write-Host "Options:"
        Write-Host "  -Quick          Quick install with defaults"
        Write-Host "  -CliOnly        Install only CLI tools"
        Write-Host "  -Gui            Include Desktop GUI"
        Write-Host "  -InstallDir     Installation directory (default: $env:LOCALAPPDATA\0xGen\bin)"
        Write-Host "  -Help           Show this help message"
        exit 0
    }

    Write-Header

    # Check for admin rights warning
    if (Test-IsAdmin) {
        Write-Warning "Running as Administrator"
        Write-Info "This is not required for installation"
    }

    # Show quick mode or custom mode
    if (-not $QuickMode -and -not $CliOnly) {
        Write-Host "Installation Modes:"
        Write-Host "  1) Quick Install - Recommended defaults (CLI + plugins)"
        Write-Host "  2) Custom Install - Choose components"
        Write-Host ""
        $modeChoice = Read-Host "? Select mode [1]"
        if ([string]::IsNullOrWhiteSpace($modeChoice)) {
            $modeChoice = "1"
        }

        if ($modeChoice -eq "1") {
            $script:QuickMode = $true
        }
    }

    # Detection
    $sysInfo = Get-SystemInfo

    # Component selection
    Select-Components

    # Check dependencies
    Test-Dependencies

    # Select installation method
    $installMethod = "binary"
    if (Test-CommandExists "scoop") {
        $installMethod = "scoop"
        Write-Info "Using Scoop (recommended for Windows)"
    } else {
        Write-Info "Using pre-built binary installation"
    }

    # Confirm installation
    if (-not $QuickMode) {
        Write-Host ""
        Write-Step "Installation Plan"
        Write-Host "  OS: Windows ($($sysInfo.Arch))"
        Write-Host "  Method: $installMethod"
        Write-Host "  Install CLI: $InstallCLI"
        Write-Host "  Install GUI: $InstallGUI"
        Write-Host "  Install Plugins: $InstallPlugins"
        Write-Host "  Install Docs: $InstallDocs"
        Write-Host ""

        if (-not (Ask-YesNo "Proceed with installation?" $true)) {
            Write-Info "Installation cancelled"
            exit 0
        }
    }

    # Perform installation
    switch ($installMethod) {
        "scoop" {
            Install-ViaScoop
        }
        "binary" {
            Install-ViaBinary
        }
        "source" {
            Install-ViaSource
        }
    }

    # Post-installation
    Invoke-PostInstallSetup

    # Show summary
    Write-Summary
}

# Run main installation
Main
