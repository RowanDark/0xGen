---
search: false
---

# 0xgen Telemetry

0xgen now exposes a Prometheus-compatible metrics endpoint that makes it possible to build dashboards and alerts without custom instrumentation.

## Metrics Endpoint

* **Address flag**: `--metrics-addr` (default `:9090`). Set to an empty string to disable the HTTP server.
* **Path**: `/metrics`
* **Format**: Prometheus text (version 0.0.4).

Key exported series include:

| Metric | Type | Description |
| --- | --- | --- |
| `oxg_rpc_requests_total{component,method}` | Counter | Total RPC calls handled by the component. |
| `oxg_rpc_errors_total{component,method,code}` | Counter | Errors emitted during RPC handling. |
| `oxg_plugin_event_duration_seconds_bucket{plugin,event,le}` | Histogram | Latency for processing plugin events (with `_sum` and `_count`). |
| `oxg_plugin_queue_length{plugin}` | Gauge | Depth of each plugin's outbound queue. |
| `oxg_active_plugins` | Gauge | Number of connected plugins. |

## Grafana

The [grafana-dashboard.json](./grafana-dashboard.json) file can be imported into Grafana. It assumes a Prometheus datasource named `Prometheus` and showcases:

* Overall request rate and error rate.
* p50/p95 plugin processing latency using histogram quantiles.
* Queue depth per plugin to monitor backpressure.
* Active plugin connection count.

