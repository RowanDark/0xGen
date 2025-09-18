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

The crawl prints a JSON payload describing discovered links and scripts. `sample_output.json` captures an illustrative output for local tests, and `tests/sample_fixture.json` can be expanded with additional fixtures.
