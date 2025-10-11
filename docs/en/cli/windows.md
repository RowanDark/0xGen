# Windows installation

Glyph ships Windows builds in two flavours: an MSI installer for system-wide
deployments and a portable ZIP archive that runs without installation. Both
variants are produced by the release workflow and validated in CI to ensure the
version command and plugin subsystem operate correctly.

## Installer (MSI)

1. Download the `glyphctl_v<version>_windows_<arch>.msi` asset from the
   [GitHub Releases page](https://github.com/RowanDark/Glyph/releases).
2. Install it with the Windows Installer UI or from PowerShell:

   ```powershell
   msiexec /i .\glyphctl_v<version>_windows_amd64.msi /qn /norestart
   ```

   Replace `<arch>` with `amd64` or `arm64` depending on your platform.
3. The installer places `glyphctl.exe` under `C:\Program Files\Glyph`, amends the
   system `PATH`, registers an uninstall entry, and adds Start menu shortcuts for
   the CLI and demo workflow. Open a new PowerShell session and confirm the CLI
   is reachable:

   ```powershell
   glyphctl --version
   ```

   You can remove Glyph at any point with:

   ```powershell
   msiexec /x .\glyphctl_v<version>_windows_amd64.msi /qn /norestart
   ```

### Trusting the proxy certificate

During installation you can opt into the **Trust Galdr proxy certificate**
feature. Enabling it runs `glyphctl proxy trust --install --quiet` after Glyph's
files are copied, generating the proxy root certificate if needed and importing
it into the current user's trusted root store. Re-run the command manually if
you later rotate the certificate or install Glyph for another account.

## Portable ZIP

Each release also provides `glyphctl_v<version>_windows_<arch>.zip`. Extract it
anywhere (for example, under `C:\Tools\Glyph`) and run the CLI without touching
system state:

```powershell
Expand-Archive -Path .\glyphctl_v<version>_windows_amd64.zip -DestinationPath C:\Tools\Glyph
C:\Tools\Glyph\glyphctl.exe --version
```

Portable archives bundle `LICENSE.txt` and `README.txt` alongside the binary so
you can keep the documentation near the executable.

## Scoop bucket

If you prefer package managers, add the Glyph bucket to Scoop and install the
manifest published from this repository:

```powershell
scoop bucket add glyph https://github.com/RowanDark/Glyph
scoop install glyphctl
glyphctl --version
```

Scoop installs the same signed binary shipped in the portable ZIP.

## WSL interoperability

Mixing Windows and WSL tooling? Use `glyphctl wsl path` to translate file paths
and follow the [WSL interop guide](../dev/windows-wsl.md) for advice on sharing
proxy certificates between environments.

## Verifying plugin support

To confirm plugin loading works, point `glyphctl` at one of the sample plugins
shipped in the repository. Compute the SHA-256 hash and ask Glyph to verify it:

```powershell
$plugin = Resolve-Path 'plugins/samples/passive-header-scan/main.go'
$hash = (Get-FileHash $plugin -Algorithm SHA256).Hash
glyphctl plugin verify $plugin --hash $hash
```

A successful run prints `signature ok` and the plugin's metadata.

## Code signing

Releases sign Windows executables whenever the project maintains a code-signing
certificate. The CI pipeline re-signs the `glyphctl.exe` included in each
portable archive before building the MSI, so both distribution formats embed the
same signature. To inspect it locally:

```powershell
Get-AuthenticodeSignature "C:\Program Files\Glyph\glyphctl.exe"
```

The output should report `Status : Valid` when a certificate is available. If no
certificate is configured, the builds remain unsigned but the packaging and
verification steps still run in CI.
