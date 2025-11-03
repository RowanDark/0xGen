# Quickstart: End-to-End Demo

The `0xgenctl demo` command gives newcomers a one-minute tour of the 0xgen stack.
It spins up a local demo target, scans the page with Seer, ranks the resulting
findings, and renders a polished HTML report. Everything runs on localhost and
falls back to bundled fixtures when external network access is restricted. After
capturing the artifacts you can import them into the desktop shell via the
**Open artifact** control to explore cases, flows, and metrics in a GUI.

## Prerequisites {#prerequisites}

* Go 1.21+ (for `go run ./cmd/0xgenctl demo`) or a downloaded `0xgenctl` binary
* Git (to clone this repository)
* Optional: the desktop shell in
  [`apps/desktop-shell/README.md`]({{ config.repo_url }}/blob/main/apps/desktop-shell/README.md)
  if you prefer a GUI walkthrough.

Everything else (0xgen binaries, Playwright, etc.) is built on demand. No
external services are required—if 0xgen cannot reach `example.com` the demo
feeds Seer a synthetic response that mirrors the HTML shipped in
[`examples/quickstart/demo-response.html`]({{ config.repo_url }}/blob/main/examples/quickstart/demo-response.html).

<div id="run-the-pipeline"></div>

The interactive sandbox above replays a full `0xgenctl demo` run directly in
your browser so you can preview the pipeline before installing anything. Toggle
**Learn mode** in the lower-right corner to see guided callouts that explain each
stage as it runs.

## Guided walkthrough {#guided-walkthrough}

<div class="learn-step" data-learn-label="1" data-learn-text="Run the CLI to launch the pipeline and generate artifacts for later review.">

```bash
0xgenctl demo
```

</div>

<div class="learn-step" data-learn-label="2" data-learn-text="The dashboard highlights where artifacts land so you can inspect them later.">

```
+--------------------------- Quickstart Dashboard ---------------------------+
| Summary      | Findings (Top 3)           | Artifacts                     |
|--------------|----------------------------|--------------------------------|
| Target: demo | #1 Stored credentials leak | out/demo/report.html          |
| Runtime: 58s | #2 Stale CSP header        | out/demo/findings.jsonl       |
| Cases: 3     | #3 Missing cache control   | out/demo/ranked.jsonl         |
+--------------------------------------------------------------------------+
```

The ASCII layout mirrors the generated HTML report so you can quickly map each
CLI step to the artifacts written on disk or surfaced in the desktop shell.

</div>

<div class="learn-step" data-learn-label="3" data-learn-text="Use the chaptered recap to review the pipeline order without replaying the demo.">

1. **Bootstrap (00:00–00:12):** targets, health checks, and Playwright launch.
2. **Scan (00:13–00:28):** Seer crawls the local target and emits findings.
3. **Rank (00:29–00:44):** deterministic scoring produces `ranked.jsonl`.
4. **Report (00:45–01:00):** HTML dashboard and desktop shell import tips.

Follow the timestamps to reproduce the same flow manually or to narrate the
process during live trainings.

</div>

## What the CLI (and GUI) do {#getting-started}

The command performs the following steps:

1. Serve the bundled [`demo target`]({{ config.repo_url }}/blob/main/cmd/0xgenctl/demo_assets/target.html)
   locally so no external network access is required.
2. Scan the rendered page with Seer, persisting structured findings to
   `out/demo/findings.jsonl`.
3. Rank the findings deterministically and write `out/demo/ranked.jsonl` for
   downstream tooling.
4. Generate an interactive HTML report identical to the checked-in reference at
   [`examples/quickstart/report.html`]({{ config.repo_url }}/blob/main/examples/quickstart/report.html).

On success the terminal prints the local target URL alongside the absolute path
to `out/demo/report.html`. Use the desktop shell's **Open artifact** button to
load the folder in offline mode—the header flips to *Offline mode* and the
navigation unlocks case, flow, and metrics inspectors backed by the generated
bundle.

The JSONL artifacts under `out/demo/` and the reference copies in
[`examples/quickstart/`]({{ config.repo_url }}/tree/main/examples/quickstart)
are handy when writing tests or inspecting the data Seer emits. The CLI output
also surfaces a Case preview so you can immediately inspect the top ranked
finding, including its assigned owner, triage note, and copy-ready
proof-of-concept command without leaving the terminal.

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

Rerun `0xgenctl demo` at any time to regenerate the report or use the desktop
shell to replay the pipeline with Learn mode overlays.
