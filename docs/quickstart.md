# Hydro Quickstart

When running `hydro` with potentially destructive scan options you must explicitly acknowledge that you have permission to do so.

```bash
hydro --aggressive --confirm-legal
```

Both the `--aggressive` and `--recursive` flags display a legal reminder banner before execution. If you forget to include the `--confirm-legal` acknowledgement, hydro exits immediately with a non-zero status to keep you safe and compliant.
