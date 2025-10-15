---
search: false
---

# Performance Benchmarks

0xgen now ships with a dedicated microbenchmark harness that exercises the
findings bus using synthetic fan-out workloads. The goal is to maintain a stable
baseline for throughput, latency, memory usage, and error rate so that
regressions are surfaced before they reach `main`.

## Running the benchmarks locally

```bash
go run ./cmd/perfbench --baseline perf/baseline/findings_bus_v1.0.json --threshold 0.10
```

The command executes the default workloads defined in
`internal/perf/workloads.go`, prints a human-readable diff, and exits non-zero
if any metric regresses by more than the configured threshold (10% by default).

The harness records throughput (URLs/events per second), CPU seconds, memory
per event, and error rate. Dynamic workloads simulate JavaScript-heavy pages by
increasing the amount of synthetic work performed for each finding; tune the
`dynamic_work` field in `internal/perf/workloads.go` to model more complex
applications.

To regenerate metrics without failing the build you can omit the baseline and
capture a fresh report:

```bash
go run ./cmd/perfbench --output perf/results/latest.json --history perf/results/history.jsonl --history-markdown perf/results/history.md
```

The optional `--history` flag accumulates runs into a JSONL file, while
`--history-markdown` renders a Markdown summary with sparklines so CI logs and
PRs can visualise trends over time.

## Updating the baseline

If a legitimate change improves performance you can regenerate the baseline and
commit the updated JSON:

```bash
go run ./cmd/perfbench --output perf/baseline/findings_bus_v1.0.json --report-version v1.1.0
```

Always include the diff from `--baseline` in your pull request description so
reviewers can assess the impact.

## Continuous Integration

The CI workflow (`ci.yml`) now includes a `Performance benchmarks` job that runs
`perfbench` on every push and pull request. The job uploads the metrics report
as an artifact (`perf-metrics`) so teams can inspect the raw numbers alongside
the console diff.
