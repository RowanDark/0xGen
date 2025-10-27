---
search: false
---

# 0xgen Observability Guide

0xgen exposes metrics, traces, and structured audit logs to help operators understand plugin
behaviour and diagnose latency throughout the orchestration pipeline. This guide summarises the
available telemetry and provides example tooling configurations.

## Tracing

`0xgend` now emits structured spans that describe plugin lifecycle events, RPC handlers, and network
activity performed on behalf of plugins. New spans cover the full HTTP capture pipeline
(`proxy.capture_flow`), fan-out to plugins (`plugin_bus.dispatch_flow`), plugin execution inside the
supervisor (`plugin.supervisor.task` / `plugin.runner.exec`), replay tooling (`replay.load_flows`,
`replay.write_cases`, etc.), and exporter jobs (`replay.write_flows`, `replay.write_cases`). Tracing
is disabled by default; enable it with the CLI flags below:

```bash
0xgend \
  --trace-endpoint http://otel-collector:4318/v1/traces \
  --trace-service-name 0xgend-prod \
  --trace-sample-ratio 0.5 \
  --trace-file /var/log/oxg/traces.jsonl
```

* `--trace-endpoint` – optional OTLP/HTTP destination for exported spans.
* `--trace-insecure-skip-verify` – disable TLS verification (useful for local testing).
* `--trace-sample-ratio` – probability for sampling new traces (0 disables tracing, 1 samples all).
* `--trace-file` – optional JSONL archive of every exported span (viewable via Chrome trace viewer).
* `--trace-headers` – attach additional HTTP headers when posting OTLP payloads.

A span's `trace_id` is propagated into metrics as Prometheus exemplars and into structured audit
events, allowing Grafana panels to link directly to their originating trace. Outbound HTTP requests
executed through the netgate are wrapped in spans that record latency, response code, capabilities,
and rate-limiter waits. When rate limiting delays a request, `netgate.rate_limit_wait` spans show the
exact wait duration and scope (global or per-host).

Sample OpenTelemetry Collector configuration: [`otel-collector.yaml`](otel-collector.yaml). The
collector accepts spans from 0xgen over OTLP/HTTP, batches them, and forwards to Tempo.

## Metrics

0xgen continues to expose Prometheus metrics at `/metrics`. Notable series include:

* `oxg_rpc_duration_seconds` – latency of core RPC handlers.
* `oxg_plugin_queue_length` – outbound queue depth per plugin.
* `oxg_http_request_duration_seconds` – latency of proxied HTTP requests.
* `oxg_plugin_event_duration_seconds` – time spent handling plugin-sent events.
* `oxg_plugin_queue_dropped_total` – plugin events dropped because outbound queues were saturated.
* `oxg_plugin_event_failures_total` – plugin-emitted events rejected during validation or delivery.
* `oxg_plugin_errors_total` – aggregated plugin-specific errors (capability validation, stream failures).
* `oxg_http_throttle_total` – rate-limiter activations.
* `oxg_flow_dispatch_seconds` – latency for sanitized/raw flow fan-out to plugins.

Legacy `oxg_*` aliases remain for this release but are deprecated and will be removed in the
following cycle.

The Grafana dashboard in [`grafana-dashboard.json`](grafana-dashboard.json) now ships exemplar-aware
panels for HTTP, flow dispatch, and plugin event latency alongside backpressure and error
visualisations. Selecting an exemplar opens the associated trace in Tempo/Jaeger, letting you pivot
from 95th percentile latency straight into a correlated span or drill into plugins repeatedly
hitting queue drops.

## Alerting

Prometheus-style alerts for anomaly detection are provided in [`alerts.yaml`](alerts.yaml):

* **0xgenPluginLatencyCritical** – fires when plugin event handling exceeds the configured
  threshold (default 5s) for three consecutive evaluations.
* **0xgenHTTPFailureRate** – highlights sustained HTTP error rates >20% over five minutes.
* **0xgenQueueBackpressure** – alerts when a plugin queue remains over 80% full for more than
  two minutes, signalling downstream congestion.

Tune thresholds to match your workload, then load the ruleset into your Prometheus server.

## Dashboard Quickstart

1. Import the Grafana JSON into your Grafana instance.
2. Configure the `0xgen` data source to point at your Prometheus server.
3. Enable tracing via the CLI flags above and point `otel-collector.yaml` at your Tempo/Jaeger.
4. After traffic flows, the *Plugin Pipeline Latency* panel shows where time is spent:
   * `plugin_bus.EventStream` spans – plugin handshakes and event loops.
   * `plugin_bus.dispatch_event` spans – server-to-plugin delivery latency.
   * `netgate.http_request` spans – outbound HTTP timings with capability metadata.
   * `netgate.rate_limit_wait` spans – throttle delays with scope and duration.

With metrics, traces, and audit logs sharing the same trace IDs, you can move seamlessly from a
Grafana panel into a trace view and drill into the corresponding audit entries.
