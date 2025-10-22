# Windows installation

0xgen ships Windows builds in two flavours: an MSI installer for system-wide
deployments and a portable ZIP archive that runs without installation. Both
variants are produced by the release workflow and validated in CI to ensure the
version command and plugin subsystem operate correctly.

## Installer (MSI)

1. Download the `0xgenctl_v<version>_windows_<arch>.msi` asset from the
   [GitHub Releases page](https://github.com/RowanDark/0xgen/releases).
2. Install it with the Windows Installer UI or from PowerShell:

   ```powershell
   msiexec /i .\0xgenctl_v<version>_windows_amd64.msi /qn /norestart
   ```

   Replace `<arch>` with `amd64` or `arm64` depending on your platform.
3. The installer places `0xgenctl.exe` under `C:\Program Files\0xgen`, amends the
   system `PATH`, registers an uninstall entry, and adds Start menu shortcuts for
   the CLI and demo workflow. Open a new PowerShell session and confirm the CLI
   is reachable:

   ```powershell
   0xgenctl --version
   ```

   You can remove 0xgen at any point with:

   ```powershell
   msiexec /x .\0xgenctl_v<version>_windows_amd64.msi /qn /norestart
   ```

### Trusting the proxy certificate

During installation you can opt into the **Trust Galdr proxy certificate**
feature. Enabling it runs `0xgenctl proxy trust --install --quiet` after 0xgen's
files are copied, generating the proxy root certificate if needed and importing
it into the current user's trusted root store. Re-run the command manually if
you later rotate the certificate or install 0xgen for another account.

## Portable ZIP

Each release also provides `0xgenctl_v<version>_windows_<arch>.zip`. Extract it
anywhere (for example, under `C:\Tools\0xgen`) and run the CLI without touching
system state:

```powershell
Expand-Archive -Path .\0xgenctl_v<version>_windows_amd64.zip -DestinationPath C:\Tools\0xgen
C:\Tools\0xgen\0xgenctl.exe --version
```

Portable archives bundle `LICENSE.txt` and `README.txt` alongside the binary so
you can keep the documentation near the executable.

## Scoop bucket

If you prefer package managers, add the 0xgen bucket to Scoop and install the
manifest published from this repository:

```powershell
scoop bucket add glyph https://github.com/RowanDark/0xgen
scoop install 0xgenctl
0xgenctl --version
```

Scoop installs the same signed binary shipped in the portable ZIP.

## WSL interoperability

Mixing Windows and WSL tooling? Use `0xgenctl wsl path` to translate file paths
and follow the [WSL interop guide](../dev/windows-wsl.md) for advice on sharing
proxy certificates between environments.

## Verifying plugin support

To confirm plugin loading works, point `0xgenctl` at one of the sample plugins
shipped in the repository. Compute the SHA-256 hash and ask 0xgen to verify it:

```powershell
$plugin = Resolve-Path 'plugins/samples/passive-header-scan/main.go'
$hash = (Get-FileHash $plugin -Algorithm SHA256).Hash
0xgenctl plugin verify $plugin --hash $hash
```

A successful run prints `signature ok` and the plugin's metadata.

## Code signing

Releases sign Windows executables whenever the project maintains a code-signing
certificate. The CI pipeline re-signs the `0xgenctl.exe` included in each
portable archive before building the MSI, so both distribution formats embed the
same signature. To inspect it locally:

```powershell
Get-AuthenticodeSignature "C:\Program Files\0xgen\0xgenctl.exe"
```

The output should report `Status : Valid` when a certificate is available. If no
certificate is configured, the builds remain unsigned but the packaging and
verification steps still run in CI.
