# Scribe

Scribe renders investigation output into human-friendly reports, summarizing findings across the Glyph pipeline.

## Capabilities
- `CAP_REPORT`

## Getting started

`glyphctl report` converts persisted findings into a Markdown summary that includes severity totals, the busiest targets, and the latest findings table.

1. Generate or copy a JSONL file of findings. A representative fixture lives at `plugins/samples/findings.jsonl`.
2. Render the report:
   ```bash
   go run ./cmd/glyphctl -- report --input ./plugins/samples/findings.jsonl --out ./out/report.md
   ```
3. Compare the output with `plugins/samples/report.golden.md` or wire it into downstream automation.

The `internal/reporter` package powers the CLI and exposes helpers for other components that need Markdown summaries.
