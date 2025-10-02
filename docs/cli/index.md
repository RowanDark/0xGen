# Glyph CLI (`glyphctl`)

`glyphctl` is the command-line entry point for orchestrating Glyph. It can build and
launch plugins, inspect findings, and generate analyst-facing reports. This page
summarises the most common workflows; run `glyphctl --help` to explore every
subcommand.

## Try the demo pipeline

Generate a full set of demo artifacts—target traffic, ranked findings, and a
shareable HTML report—with a single command:

```bash
glyphctl demo
```

The command spins up a local demo target, feeds it to the Seer detector, writes
JSONL outputs under `out/demo/`, and renders `out/demo/report.html`. The output is
safe to share with stakeholders and mirrors the examples under
[`examples/quickstart/`]({{ config.repo_url }}/tree/main/examples/quickstart).

## Inspect configuration

Print the resolved runtime configuration to confirm the active server address,
authentication token, and output directory:

```bash
glyphctl config print
```

See the [configuration reference](configuration.md) for the full resolution order and
overridable fields.

## Run plugins locally

Use the `plugin run` command to execute a bundled plugin against a running `glyphd`
instance. The example below runs the `emit-on-start` sample for three seconds against
a development daemon:

```bash
glyphctl plugin run \
  --sample emit-on-start \
  --server 127.0.0.1:50051 \
  --token supersecrettoken \
  --duration 3s
```

Add `--sample` to target the fixture binaries under `plugins/samples/`, or provide a
`--path` to an arbitrary plugin executable.

## Validate findings

Glyph emits findings as JSON Lines (JSONL) records that conform to
[`specs/finding.md`]({{ config.repo_url }}/blob/main/specs/finding.md). Lint generated output before shipping it
with:

```bash
glyphctl findings validate --input out/findings.jsonl
```

The validator reports schema violations and highlights the offending record numbers.

## Generate reports

Turn validated findings into Markdown or HTML reports for analysts:

```bash
glyphctl report \
  --input out/findings.jsonl \
  --format html \
  --out out/report.html
```

The CLI ships both Markdown and HTML renderers; omit `--format` to default to
Markdown. See [`plugins/scribe`]({{ config.repo_url }}/tree/main/plugins/scribe) for the reference templates and
sample output.
