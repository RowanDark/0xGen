# OSINT Well

OSINT Well orchestrates Amass to enrich Glyph investigations with open-source intelligence such as subdomains and infrastructure relationships.

## Capabilities
- `CAP_EMIT_FINDINGS`
- `CAP_STORAGE`

## Getting started
1. Ensure Amass is installed locally and available on your `PATH`.
2. 2. Use `glyphctl` to run a passive enumeration and normalise the output:
   ```bash
   go build ./cmd/glyphctl
   ./glyphctl osint-well --domain example.com --out ./out/assets.jsonl
   ```
   - Override the Amass binary with `--binary`.
   - Pass extra Amass flags via `--args "-config /path/to/config"`.
   - Adjust the output path with `--out` (defaults to `${GLYPH_OUT:-/out}/assets.jsonl`).
3. `run_amass.sh` wraps the command above for quick experiments.

The normaliser aggregates duplicate hosts, deduplicates addresses/sources, and tags each entry with `amass-passive`. `tests` contain fixtures for the JSONL shape.
