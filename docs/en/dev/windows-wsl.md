# Windows Subsystem for Linux interop

0xgen supports running under Windows and within Windows Subsystem for Linux
(WSL). This guide captures common workflows when Windows tooling and WSL
processes need to cooperate, including certificate trust and file path
translation.

## Sharing proxy trust between environments

The 0xgen proxy generates a dedicated root certificate the first time it starts.
Windows-based browsers and applications must trust this certificate in order for
HTTPS interception to work without warnings.

The Windows installer includes an optional **Trust Galdr proxy certificate**
feature. When enabled, the installer runs:

```powershell
"C:\\Program Files\\0xgen\\glyphctl.exe" proxy trust --install --quiet
```

This command generates the proxy certificate if it does not already exist and
imports it into the current user's `Cert:\CurrentUser\Root` store. You can run
the same command later if you skipped the installer option or rotated the
certificate. For manual workflows, export the certificate and import it in other
environments:

```powershell
# Windows PowerShell
glyphctl proxy trust --out $env:TEMP\glyph-proxy.cer

# Inside WSL
glyphctl proxy trust --out /tmp/glyph-proxy.pem
```

Copy the exported file into your browser's trust store or a WSL distribution as
needed.

## Translating paths between Windows and WSL

0xgen commands often accept file paths—for example when replaying proxy
captures. Use the `glyphctl wsl path` helper to translate paths instead of
hand-editing separators:

```powershell
# Convert a WSL path so Windows-native tools can open it
PS> glyphctl wsl path --to-windows /mnt/c/Users/alice/out/demo/report.html
C:\Users\alice\out\demo\report.html

# Convert a Windows path before passing it to a CLI running in WSL
$ glyphctl wsl path --to-wsl "D:\\Projects\\0xgen\\replays\\latest.jsonl"
/mnt/d/Projects/0xgen/replays/latest.jsonl
```

The helper rejects unsupported formats, making it easy to catch mistakes in CI
scripts or documentation snippets.

## Recommended output directories

By default, 0xgen writes artefacts under `/out`. On Windows this resolves to the
root of the current drive (for example `C:\out`). When running inside WSL, set
`GLYPH_OUT` to a path under `/mnt/<drive>` so Windows applications can access the
files without additional copies:

```bash
export GLYPH_OUT=/mnt/c/Users/alice/out
```

The proxy certificate helper honours these overrides, so both Windows and WSL
processes rely on the same root certificate material.
