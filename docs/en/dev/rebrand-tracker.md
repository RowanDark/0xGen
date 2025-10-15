# Rebrand tracker: brand migration (meta)

> **Status:** Prep work

Create label: `rebrand`

## Checklist

- [ ] 1 Docs surface rename (title/header only)
- [ ] 2 README badges/links (no URLs changed)
- [ ] 3 GUI window title/icon text only
- [ ] 4 CLI banner + `--version` output text
- [ ] 5 Config dir env vars (read new, fall back to old)
- [ ] 6 Binary wrapper: `0xgenctl` → `glyphctl` (alias)
- [ ] 7 Docs URLs: add redirects from the legacy prefix to `/0xgen`
- [ ] 8 `go.mod` module comment only (no path change)
- [ ] 9 Homebrew formula name only (alias keeps glyph)
- [ ] 10 CI job names & artifact names (no paths)
- [ ] 11 Final: repository rename and module path migration
