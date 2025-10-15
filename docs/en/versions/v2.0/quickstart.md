# Quickstart: End-to-End Demo

The `glyphctl demo` command gives newcomers a one-minute tour of the 0xgen stack.
It spins up a local demo target, scans the page with Seer, ranks the resulting
findings, and renders a polished HTML report. Everything runs on localhost and
falls back to bundled fixtures when external network access is restricted.

## Prerequisites {#prerequisites}

* Go 1.21+ (for `go run ./cmd/glyphctl demo`) or a downloaded `glyphctl` binary
* Git (to clone this repository)

Everything else (0xgen binaries, Playwright, etc.) is built on demand. No
external services are required—if 0xgen cannot reach `example.com` the demo
feeds Seer a synthetic response that mirrors the HTML shipped in
`examples/quickstart/demo-response.html`.

<div id="run-the-pipeline"></div>
## Getting started {#getting-started}

```bash
glyphctl demo
```

The command performs the following steps:

1. Serve the bundled [`demo target`]({{ config.repo_url }}/blob/main/cmd/glyphctl/demo_assets/target.html)
   locally so no external network access is required.
2. Scan the rendered page with Seer, persisting structured findings to
   `out/demo/findings.jsonl`.
3. Rank the findings deterministically and write `out/demo/ranked.jsonl` for
   downstream tooling.
4. Generate an interactive HTML report identical to the checked-in reference at
   [`examples/quickstart/report.html`]({{ config.repo_url }}/blob/main/examples/quickstart/report.html).

On success the terminal prints the local target URL alongside the absolute path
to `out/demo/report.html`. Open that file in your browser to explore collapsible
cases, thumbnail evidence previews, scope badges, and copy-ready proof-of-concept
snippets. The JSONL artifacts under `out/demo/` and the reference copies in
[`examples/quickstart/`]({{ config.repo_url }}/tree/main/examples/quickstart)
are handy when writing tests or inspecting the data Seer emits.

## Inspecting the run {#inspecting-the-run}

Useful files after the demo completes:

| Path | Description |
| ---- | ----------- |
| `out/demo/excavator.json` | Crawl transcript including discovered links. |
| `out/demo/findings.jsonl` | Raw Seer findings (JSONL). |
| `out/demo/ranked.jsonl` | Ranked findings with deterministic scores. |
| `out/demo/report.html` | Final HTML report. |

The [`examples/quickstart/` directory]({{ config.repo_url }}/tree/main/examples/quickstart)
mirrors the expected outputs so you can diff future runs or plug sample data into
other tools without re-running the pipeline.

## Cleaning up {#cleaning-up}

Remove the generated artifacts with:

```bash
rm -rf out/demo
```

Rerun `glyphctl demo` at any time to regenerate the report.
