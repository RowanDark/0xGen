# 0xgen CLI (`0xgenctl`)

`0xgenctl` is the command-line entry point for orchestrating 0xgen. It can build and
launch plugins, inspect findings, and generate analyst-facing reports. This page
summarises the most common workflows; run `0xgenctl --help` to explore every
subcommand.

## Try the demo pipeline {#try-the-demo-pipeline}

Generate a full set of demo artifacts—target traffic, ranked findings, and a
shareable HTML report—with a single command:

```bash
0xgenctl demo
```

The command spins up a local demo target, feeds it to the Seer detector, writes
JSONL outputs under `out/demo/`, and renders `out/demo/report.html`. The output is
safe to share with stakeholders and mirrors the examples under
[`examples/quickstart/`]({{ config.repo_url }}/tree/main/examples/quickstart).

## Inspect configuration {#inspect-configuration}

Print the resolved runtime configuration to confirm the active server address,
authentication token, and output directory:

```bash
0xgenctl config print
```

See the [configuration reference](configuration.md) for the full resolution order and
overridable fields.

## Run plugins locally {#run-plugins-locally}

Use the `plugin run` command to execute a bundled plugin against a running `0xgend`
instance. The example below runs the `emit-on-start` sample for three seconds against
a development daemon:

```bash
0xgenctl plugin run \
  --sample emit-on-start \
  --server 127.0.0.1:50051 \
  --token supersecrettoken \
  --duration 3s
```

Add `--sample` to target the fixture binaries under `plugins/samples/`, or provide a
`--path` to an arbitrary plugin executable.

## Validate findings {#validate-findings}

0xgen emits findings as JSON Lines (JSONL) records that conform to
[`specs/finding.md`]({{ config.repo_url }}/blob/main/specs/finding.md). Lint generated output before shipping it
with:

```bash
0xgenctl findings validate --input out/findings.jsonl
```

The validator reports schema violations and highlights the offending record numbers.

## Generate reports {#generate-reports}

Turn validated findings into Markdown or HTML reports for analysts:

```bash
0xgenctl report \
  --input out/findings.jsonl \
  --format html \
  --out out/report.html
```

The CLI ships both Markdown and HTML renderers; omit `--format` to default to
Markdown. See [`plugins/scribe`]({{ config.repo_url }}/tree/main/plugins/scribe) for the reference templates and
sample output.

## Export cases for downstream tools {#export-cases}

Use `0xgenctl export` to transform findings into cases and serialise them into
machine-consumable formats:

```bash
0xgenctl export \
  --input out/findings.jsonl \
  --format sarif \
  --out out/cases.sarif
```

Available formats include:

* `sarif` – emits a SARIF 2.1.0 log for interoperability with security tooling.
* `jsonl` – writes telemetry followed by individual case entries as newline
  delimited JSON.
* `csv` – generates a spreadsheet-friendly summary of each case and its sources.

Third-party exporters can register additional formats at runtime. When 0xgen
detects custom exporters (for example, from a plugin bundle), `--format` will
list the extra options automatically.
