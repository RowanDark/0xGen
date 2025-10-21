# Excavator

Excavator is the Playwright-powered crawler foundation for 0xgen. It provides a reproducible baseline for scripted reconnaissance of target applications.

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

## Continuous integration

- Manual smoke validation: [Excavator smoke workflow](../../.github/workflows/excavator-smoke.yml)
- Synthetic performance guardrails: [Excavator performance workflow](../../.github/workflows/excavator-perf.yml)

### Performance benchmarking

Run deterministic crawl benchmarks locally to preview CI output:

```bash
npm --prefix plugins/excavator run perf
```

This executes the scenarios declared in `benchmarks/scenarios.json`, compares the measured URLs/minute throughput against the
checked-in baseline, and emits Markdown plus JSON artifacts under `benchmarks/`.

### Runtime configuration

Excavator keeps crawls predictable and safe:

- `TARGET_URL` / `--target` — seed URL to crawl (defaults to `https://example.com`).
- `DEPTH` / `--depth` (default `1`) — maximum same-origin link depth to follow from the seed URL.
- `HOST_LIMIT` / `--host-limit` (default `1`) — cap on the number of unique hostnames the crawler may visit across all depths (including the seed host).
- `TIMEOUT_MS` / `--timeout-ms` (milliseconds, default `45000`) — navigation timeout override.

The previous `EXCAVATOR_*` environment variables remain supported for backwards compatibility.

All URLs are normalised, deduplicated, and constrained to the host limit. Each run emits a stable JSON object containing the seed `target`, unique `links`, discovered `scripts`, and crawl `meta` (see `sample_output.json`). Golden coverage for the crawler lives in `tests/crawl.test.js`. For Playwright usage details see the [Page API documentation](https://playwright.dev/docs/api/class-page).
