# Plugin Author Guide

0xgen plugins are Go binaries that connect to the platform over gRPC using the SDK
provided in [`sdk/plugin-sdk`]({{ config.repo_url }}/tree/main/sdk/plugin-sdk). This guide documents the
lifecycle hooks exposed by the runtime, the capabilities that can be requested in a
manifest, and the rules for emitting JSONL findings safely.

## Plugin Roster {#plugin-roster}

The following plugins form the foundation of the 0xgen platform. Each directory
under `plugins/` contains a manifest, implementation, documentation, and test
fixtures to accelerate future development.

| Plugin | Description |
| ------ | ----------- |
| `galdr-proxy` | Proxy ingress layer that streams HTTP flows into 0xgen for collaborative analysis. |
| `cartographer` | Surface mapper that catalogs hosts, endpoints, and assets discovered across crawlers. |
| `excavator` | Playwright-powered crawler starter that captures links and scripts from target applications. |
| `raider` | Active testing coordinator that executes offensive playbooks against prioritized targets. |
| `osint-well` | Amass-backed OSINT collector that enriches investigations with external intelligence. |
| `seer` | Passive analytics engine that flags suspicious behavior observed in captured traffic. |
| `scribe` | Reporting pipeline that turns findings into human-friendly Markdown deliverables. |
| `ranker` | Prioritization service that scores leads and findings to focus remediation efforts. |
| `grapher` | Relationship engine that models assets and signals as a navigable graph. |
| `cryptographer` | CyberChef-inspired utility UI for transforming payloads during investigations. |
| `example-hello` | Minimal starter plugin that emits a greeting finding during startup. |

## Getting started {#getting-started}

1. Scaffold a new plugin with `glyph-plugin init`. The CLI generates Node and
   Go projects that already depend on the broker helpers, capability macros, and
   lint/test automation used in production. See the
   [safe starter walkthrough](safe-starter-go.md) for a tour of the generated Go
   project layout. The legacy `make new-plugin` target remains available for
   existing automation but defers to the same templates.
2. Study [`examples/plugin-safe-go/`]({{ config.repo_url }}/tree/main/examples/plugin-safe-go)
   for a compact end-to-end example produced by the scaffolder. It includes a
   manifest, runnable plugin, tests that exercise the fake broker, and a README
   describing the default linting workflow.
3. Run `go test ./...` frequently to execute plugin unit tests alongside the rest
   of the repository. The example plugin test shows how to stand up the
   in-memory broker exposed by [`sdk/plugin-sdk`]({{ config.repo_url }}/tree/main/sdk/plugin-sdk)
   so findings can be asserted without a full 0xgen deployment.

## Lifecycle hooks {#lifecycle-hooks}

Plugins implement behaviour by registering callbacks in `pluginsdk.Hooks` before
calling `pluginsdk.Run` or `pluginsdk.Serve`. The SDK manages the connection to
`0xgend`, performs capability enforcement, and invokes hooks on the same goroutine
that receives events.

### `OnStart(*pluginsdk.Context) error` {#onstart}

Invoked once after the plugin authenticates with `0xgend`. Use the hook for
lightweight initialisation, emitting startup findings, and launching background
goroutines scoped to the supplied context. Returning an error terminates the
plugin immediately.

### `OnHTTPPassive(*pluginsdk.Context, pluginsdk.HTTPPassiveEvent) error` {#onhttppassive}

Triggered for every passive HTTP response streamed to the plugin when
`CAP_HTTP_PASSIVE` is granted. The hook is ideal for analytics that react to
captured traffic. Returning an error stops the event loop and terminates the
plugin.

The SDK automatically wires graceful shutdown through `pluginsdk.Run`, cancelling
the context when the process receives `SIGINT` or `SIGTERM`. Long-running work
should honour `ctx.Context().Done()` to exit promptly.

## Capabilities {#capabilities}

Capabilities gate access to host features. Declare them in `manifest.json` under
`capabilities`, and ensure the same set is configured in `pluginsdk.Config` so the
SDK can enforce permissions locally. At runtime the host injects a
`0XGEN_CAPABILITY_TOKEN` environment variable that must be supplied via
`pluginsdk.Config.CapabilityToken`; the host refuses the handshake if the token is
missing or the plugin requests undeclared privileges.

| Capability | Purpose |
| ---------- | ------- |
| `CAP_EMIT_FINDINGS` | Allows the plugin to emit findings back to the host via `ctx.EmitFinding`. |
| `CAP_HTTP_PASSIVE` | Streams passive HTTP flow events into the plugin. Required when registering `OnHTTPPassive`. |
| `CAP_HTTP_ACTIVE` | Grants access to active HTTP helpers exposed by `internal/netgate` for probe-style plugins. |
| `CAP_WS` | Enables WebSocket interaction primitives for realtime protocol analysis. |
| `CAP_SPIDER` | Permits scheduling crawl jobs through the 0xgen spider/queue components. |
| `CAP_REPORT` | Allows plugins to submit rendered reports that downstream tooling (for example `scribe`) can publish. |
| `CAP_STORAGE` | Grants access to managed storage buckets for large artefacts or binary blobs. |
| `CAP_FLOW_INSPECT` | Enables subscriptions to sanitized HTTP flow events (`FLOW_REQUEST`, `FLOW_RESPONSE`). Sensitive headers and bodies are redacted unless explicitly allowed by program scope, with redacted bodies replaced by `[REDACTED body length=n sha256=digest]`. |
| `CAP_FLOW_INSPECT_RAW` | Grants access to raw HTTP flow events (`FLOW_REQUEST_RAW`, `FLOW_RESPONSE_RAW`). Requires `CAP_FLOW_INSPECT` and delivers unredacted payloads for forensic tooling. |

> **Note**
> Sanitized events include placeholders and the `X-0xgen-Body-Redacted` header when payloads are removed. The placeholder embeds a SHA-256 digest so sanitized consumers can correlate flows without seeing secrets. Raw events honour `--max-body-kb`; truncated payloads receive an `X-0xgen-Raw-Body-Truncated: <bytes>;sha256=<digest>` header so plugins can detect partial content and verify integrity.

Only request capabilities the plugin actively needs. The manifest validator under
`hack/validate_manifests.sh` enforces the whitelist above.

Flow subscriptions use uppercase identifiers in the runtime handshake. Sanitized streams are exposed via `FLOW_REQUEST` and `FLOW_RESPONSE`, while raw byte-for-byte payloads are available through `FLOW_REQUEST_RAW` and `FLOW_RESPONSE_RAW`. Plugins requesting either stream without the corresponding capability are rejected during the handshake. Sanitized flows retain metadata but replace secrets with placeholders and include the `X-0xgen-Body-Redacted` header to convey original body length.

## Emitting findings {#emitting-findings}

Findings are serialised to `findings.jsonl` using the schema defined in
`plugins/findings.schema.json`. The SDK handles common safety checks when calling
`ctx.EmitFinding`, but plugin authors must still:

- Provide non-empty `Type` and `Message` fields. Use reverse-DNS style identifiers
  for `Type` to keep namespaces distinct.
- Populate `Target` and `Evidence` when applicable so analysts can reproduce the
  issue. Empty strings are omitted for compactness.
- Select an appropriate severity (`SeverityInfo`, `SeverityLow`, `SeverityMedium`,
  `SeverityHigh`, or `SeverityCritical`). The SDK normalises timestamps to
  RFC3339 and generates ULIDs automatically when `ID` is left blank.
- Store additional context in the `Metadata` map. Keys must be non-empty strings.

When exporting findings to disk or downstream systems, the host enforces the
schema described in [`specs/finding.md`]({{ config.repo_url }}/blob/main/specs/finding.md). Run
`go run ./cmd/0xgenctl findings validate --input <path>` to verify JSONL output
before distribution.

## Performance and safety guidelines {#performance-and-safety-guidelines}

- **Respect backpressure**: Hooks run on the gRPC receive loop. Avoid blocking
  operations inside handlers. Offload expensive work to goroutines and use the
  provided context for cancellation.
- **Timeout external calls**: Always bound network and filesystem operations with
  timeouts derived from the hook context to prevent hung plugins.
- **Limit memory usage**: Stream large payloads instead of buffering them in
  memory. Persist bulky artefacts with `CAP_STORAGE` rather than embedding them in
  findings.
- **Validate inputs**: Treat host-provided data (including HTTP flows) as
  untrusted. Parse defensively and handle errors gracefully to avoid terminating
  the plugin loop.
- **Log responsibly**: Use the `ctx.Logger()` provided by the SDK so log output is
  correlated with the plugin name. Avoid logging secrets such as authentication
  tokens.

Following these practices keeps plugins responsive, observable, and safe to run in
shared 0xgen deployments.
