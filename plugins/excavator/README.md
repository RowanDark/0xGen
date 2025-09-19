# Excavator

Excavator is the Playwright-powered crawler foundation for Glyph. It provides a reproducible baseline for scripted reconnaissance of target applications.

## Capabilities
- `CAP_HTTP_PASSIVE`
- `CAP_SPIDER`
- `CAP_EMIT_FINDINGS`

## Getting started
1. Install dependencies:
   ```bash
   npm --prefix plugins/excavator install
   npm --prefix plugins/excavator run install-playwright-browsers
   ```
2. Run the sample crawl (TARGET_URL may be an environment variable or CLI argument):
   ```bash
   TARGET_URL=https://example.com npm --prefix plugins/excavator run crawl
   # or
   npm --prefix plugins/excavator run crawl -- https://example.com
   ```

### Runtime configuration

Excavator keeps crawls predictable and safe:

- `EXCAVATOR_MAX_DEPTH` (default `1`) — maximum link depth to follow from the seed URL.
- `EXCAVATOR_MAX_PAGES` (default `25`) — hard cap on visited pages.
- `EXCAVATOR_ALLOWED_HOSTS` — comma-separated list of additional hostnames permitted during the crawl. The seed host is always included.
- `EXCAVATOR_TIMEOUT_MS` — optional navigation timeout override (defaults to 45s).

All URLs are normalised, deduplicated, and constrained to the allowed host list. Each run emits a stable JSON object containing metadata, discovered links, and script excerpts (see `sample_output.json`). Golden coverage for the crawler lives in `tests/crawl.test.js`.
