---
search: false
---

# 0xgen Telemetry and Crash Insight

0xgen now exposes a Prometheus-compatible metrics endpoint that makes it possible to build dashboards and alerts without custom instrumentation. For post-mortem analysis of fatal errors, see the [crash reporting workflow](./crash-reporting.md) that explains how the desktop shell captures redacted, text-only bundles ready for handoff to maintainers.

## Metrics Endpoint

* **Address flag**: `--metrics-addr` (default `:9090`). Set to an empty string to disable the HTTP server.
* **Path**: `/metrics`
* **Format**: Prometheus text (version 0.0.4).

Key exported series include:

| Metric | Type | Description |
| --- | --- | --- |
| `oxg_rpc_requests_total{component,method}` | Counter | Total RPC calls handled by the component. |
| `oxg_rpc_errors_total{component,method,code}` | Counter | Errors emitted during RPC handling. |
| `oxg_rpc_duration_seconds_bucket{component,method,code,le}` | Histogram | Latency for each RPC handler (with `_sum` and `_count`). |
| `oxg_plugin_event_duration_seconds_bucket{plugin,event,le}` | Histogram | Latency for processing plugin events (with `_sum` and `_count`). |
| `oxg_plugin_queue_length{plugin}` | Gauge | Depth of each plugin's outbound queue. |
| `oxg_active_plugins` | Gauge | Number of connected plugins. |
| `oxg_http_request_duration_seconds_bucket{plugin,capability,method,status,le}` | Histogram | Latency for outbound HTTP requests executed via the NetGate (with `_sum` and `_count`). |
| `oxg_http_throttle_total{scope}` | Counter | Number of outbound HTTP requests delayed by throttling. |
| `oxg_http_backoff_total{status}` | Counter | Number of outbound HTTP retries triggered by upstream status codes. |

Legacy `glyph_*` series remain exported as deprecated aliases for one release cycle to ease dashboard migrations.

### Prometheus scrape configuration

The `/metrics` endpoint is compatible with the Prometheus text exposition format. A minimal scrape job targeting a 0xgen instance running on the default metrics port looks like:

```yaml
scrape_configs:
  - job_name: 0xgen
    scrape_interval: 15s
    static_configs:
      - targets:
          - localhost:9090
```

Adjust `targets` to match your deployment topology and set `metrics-addr` accordingly when launching `glyphd`.

## Grafana

The [grafana-dashboard.json](./grafana-dashboard.json) file can be imported into Grafana. It assumes a Prometheus datasource named `Prometheus` and showcases:

* Overall request rate and error rate.
* p50/p95 plugin processing latency using histogram quantiles.
* Queue depth per plugin to monitor backpressure.
* Active plugin connection count.

