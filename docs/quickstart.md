# Quickstart: End-to-End Demo

The `make demo` target gives newcomers a five-minute tour of the Glyph stack. It
boots Galdr, captures traffic with Excavator, scans the responses with Seer,
ranks the resulting findings, and renders an HTML report with Scribe. The demo
runs entirely on localhost and falls back to bundled fixtures when external
network access is restricted.

## Prerequisites

* Go 1.21+
* Node.js 20+ and npm
* Make, curl, and Git

Everything else (Glyph binaries, Playwright, etc.) is built on demand. No
external services are required—if Glyph cannot reach `example.com` the demo
feeds Seer a synthetic response that mirrors the HTML shipped in
`examples/quickstart/demo-response.html`.

## Run the pipeline

```bash
make demo
```

The target performs the following steps:

1. Build fresh `glyphd` and `seer` binaries under `out/demo/`.
2. Start `glyphd` with Galdr enabled at `http://127.0.0.1:8080` using
   [`examples/quickstart/galdr-rules.json`](../examples/quickstart/galdr-rules.json)
   so intercepted responses receive deterministic headers and a red-team themed
   HTML body.
3. Launch the Seer plugin and capture a crawl of `http://example.com` with
   Excavator. When Playwright browsers are unavailable, the crawler falls back to
   a lightweight HTTP client that still records a structured
   [`excavator.json`](../examples/quickstart/excavator.json) transcript.
4. Persist proxy history, Seer findings, and ranked output under `out/demo/`.
   If Galdr cannot contact the upstream host, the demo seeds
   [`findings.jsonl`](../examples/quickstart/findings.jsonl) using
   [`cmd/quickstartseed`](../cmd/quickstartseed/main.go) so downstream stages
   still showcase the reporting flow.
5. Render `out/demo/report.html`, an HTML report identical to the checked-in
   reference [`examples/quickstart/report.html`](../examples/quickstart/report.html).

On success the terminal prints:

```
Quickstart report available at out/demo/report.html
```

Open that file in your browser to explore the generated dashboard. The JSONL
artifacts under `out/demo/` and the reference copies in
[`examples/quickstart/`](../examples/quickstart) are handy when writing tests or
inspecting the data Seer emits.

## Inspecting the run

Useful files after the demo completes:

| Path | Description |
| ---- | ----------- |
| `out/demo/glyphd.log` | Galdr / glyphd server logs. |
| `out/demo/seer.log` | Seer plugin output. |
| `out/demo/excavator.json` | Crawl transcript including discovered links. |
| `out/demo/findings.jsonl` | Raw Seer findings (JSONL). |
| `out/demo/ranked.jsonl` | Ranked findings with deterministic scores. |
| `out/demo/report.html` | Final HTML report. |

The `examples/quickstart/` directory mirrors the expected outputs so you can
diff future runs or plug sample data into other tools without re-running the
pipeline.

## Cleaning up

Remove the generated artifacts with:

```bash
rm -rf out/demo
```

Rerun `make demo` at any time to regenerate the report.
