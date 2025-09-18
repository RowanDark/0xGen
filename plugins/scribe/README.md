# Scribe

Scribe renders investigation output into human-friendly reports, summarizing findings across the Glyph pipeline.

## Capabilities
- `CAP_REPORT`

## Getting started
Scribe will eventually interface with `glyphctl report` to transform `out/findings.jsonl` into Markdown deliverables. Populate `plugin.js` with rendering logic and expand `tests/sample_fixture.json` with representative findings documents to validate formatting.
