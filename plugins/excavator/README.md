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
2. Run the sample crawl (all configuration values may be provided via environment variables or CLI flags):
   ```bash
   TARGET_URL=https://example.com DEPTH=1 npm --prefix plugins/excavator run crawl
   # or
   npm --prefix plugins/excavator run crawl -- --target=https://example.com --depth=1
   ```

### Runtime configuration

Excavator keeps crawls predictable and safe:

- `TARGET_URL` / `--target` — seed URL to crawl (defaults to `https://example.com`).
- `DEPTH` / `--depth` (default `1`) — maximum link depth to follow from the seed URL.
- `MAX_PAGES` / `--max-pages` (default `25`) — hard cap on visited pages.
- `HOST_LIMIT` / `--host-limit` — optional maximum number of hostnames (including the seed host) that the crawler may visit.
- `ALLOWED_HOSTS` / repeated `--allowed-host` / `--allowed-hosts` — additional hostnames permitted during the crawl. The seed host is always included.
- `TIMEOUT` / `--timeout` (milliseconds, default `45000`) — navigation timeout override.

The previous `EXCAVATOR_*` variables remain supported for backwards compatibility.

All URLs are normalised, deduplicated, and constrained to the allowed host list. Each run emits a stable JSON object containing the seed `target`, unique `links`, discovered `scripts`, and crawl `meta` (see `sample_output.json`). Golden coverage for the crawler lives in `tests/crawl.test.js`.
