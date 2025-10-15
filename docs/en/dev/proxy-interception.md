# Proxy Interception Support Design

## Overview
This document outlines the design for enabling 0xgen to operate as an intercepting HTTP(S) proxy, allowing users to capture, inspect, edit, and replay requests and responses while leveraging the existing plugin pipeline.

## Goals
- Accept inbound HTTP and HTTPS traffic in man-in-the-middle mode.
- Provide user interfaces for inspecting and modifying requests and responses before forwarding them.
- Integrate intercepted flows with the plugin execution pipeline.
- Maintain comprehensive audit logging across sessions.
- Operate on Windows, macOS, and Linux.

## Non-Goals
- Building a full certificate authority management UI (initial version will rely on CLI tooling and documentation).
- Providing browser automation beyond proxy configuration (extensions or devtools remain out of scope).

## Architecture

### Proxy Listener
- Add a new `cmd/glyph/proxy` entry point that starts an HTTP proxy listener.
- Use Go's `net/http` with `golang.org/x/net/proxy` utilities to handle CONNECT tunneling for HTTPS.
- Terminate TLS using a 0xgen-managed root certificate issued per installation. Certificates are stored in the 0xgen data directory with restricted permissions.
- Support dynamic certificate generation per host using `crypto/tls` and `crypto/x509`.

### Flow Pipeline Integration
1. Incoming request hits proxy listener.
2. Listener normalizes the request into 0xgen's internal request model (currently used by plugins).
3. Emit a "flow captured" event to a new interception queue consumed by the orchestrator.
4. The orchestrator pauses forwarding until user approval (UI/CLI). When approved, the request is handed to the plugin pipeline as if it originated from a capture file.
5. Responses returned from upstream are likewise captured, optionally modified, and stored for replay.

### User Interaction
- Extend the desktop UI with an Interceptor view listing captured flows, similar to popular proxy tools.
- Provide CLI commands:
  - `glyph proxy trust` to print or install the root certificate.
  - `glyph proxy intercept` to start proxy mode with optional upstream proxy configuration.
  - `glyph proxy approve <flow-id>` and `glyph proxy edit <flow-id>` to manipulate queued requests.
- Inline editing uses diff-based editing; UI employs a JSON/HTTP message editor with syntax highlighting.

### Browser Integration
- Add helper scripts to configure system/browser proxy settings on macOS (networksetup), Windows (netsh winhttp + registry), and Linux (gsettings + environment variables).
- Provide documentation for manual setup when automation is unavailable.
- Include Selenium/WebDriver snippets for automated testing using the proxy.

### Flow sanitisation & plugin delivery
- The proxy emits a sanitized flow stream by default, redacting sensitive headers (cookies, auth tokens, API keys) and replacing bodies with `[REDACTED body length=n sha256=digest]` so plugins can still correlate payloads without access to raw content. Plugins subscribe via `FLOW_REQUEST` / `FLOW_RESPONSE` and must declare `CAP_FLOW_INSPECT`.
- Plugins with `CAP_FLOW_INSPECT_RAW` may opt into raw events using `FLOW_REQUEST_RAW` / `FLOW_RESPONSE_RAW`. The host enforces capability checks at handshake and records drops when plugin queues back up.
- Sanitized and raw deliveries are counted via `oxg_flow_events_total` and `oxg_flow_events_dropped_total` metrics (with deprecated `glyph_*` aliases), allowing operators to monitor throughput and backpressure.
- Scope policies parsed from YAML (see `--scope-policy`) suppress out-of-scope flows before they reach plugins, ensuring redaction rules align with bounty constraints.

### Flow sampling, truncation, and replay
- `glyphd` exposes tuning flags to balance performance and fidelity:
  - `--proxy-flow-enabled` toggles publishing entirely (defaults to enabled when the bus is available).
  - `--flow-sample-rate` accepts a ratio between `0` and `1` for probabilistic sampling. A value of `0` keeps the proxy online while suppressing flow publications.
  - `--max-body-kb` limits the number of raw body kilobytes captured per event. Values above the limit append the `X-0xgen-Raw-Body-Truncated: <bytes>;sha256=<digest>` header so plugins can detect truncation while verifying integrity; `-1` disables raw body capture entirely, `0` captures headers only.
  - `--proxy-flow-seed` seeds deterministic flow identifiers, aiding replay comparisons when deterministic output is required.
  - `--proxy-flow-log` overrides the sanitized flow transcript path. By default, 0xgen writes `proxy_flows.jsonl` next to the history log for inclusion in replay artefacts.
- Sanitized flow transcripts contain base64-encoded HTTP messages plus metadata (`sequence`, `timestamp_unix`, redaction hints). These are packaged inside replay artefacts as `flows.jsonl`, copied to `flows.replay.jsonl` by `glyphctl replay`.
- Flow ordering remains deterministic via monotonically increasing sequence numbers coupled with the configured seed. The `Seeds` manifest map now includes a `flows` entry when glyphd publishes the seed used during capture.

### Telemetry additions
- `oxg_flow_dispatch_seconds` tracks broadcast latency for sanitized and raw subscriptions independently, complementing the existing event counters (`glyph_*` aliases remain temporarily).
- `oxg_flow_redactions_total` exposes how often the proxy redacts or truncates payloads, split by redaction kind (e.g., `body`, `raw_truncated`).
- Per-plugin queue depth is still exported via `oxg_plugin_queue_length`, making it easy to spot slow consumers alongside the new flow metrics.

### Logging & Audit
- Persist intercepted flows (requests/responses, edits, approvals) in a new `intercepts.db` SQLite database.
- Record timestamps, user identifiers, and plugin execution outcomes.
- Expose export functionality via `glyph proxy export --format json`.

## Security Considerations
- Root certificate generation uses a strong key (RSA 4096 or ECDSA P-256) with 2-year validity, rotated automatically.
- Certificate storage respects OS keychain permissions; warn users if the key cannot be protected.
- Provide clear UI indicators when traffic is being intercepted.
- Support optional passphrase protection for the root private key.
- Ensure edited requests are validated before dispatch to prevent malformed payloads from crashing upstream services.

## Testing Strategy
- Unit tests for certificate management and flow serialization.
- Integration tests using `httptest` to simulate proxy clients and upstream servers.
- End-to-end tests with headless Chrome configured to trust 0xgen's certificate (using Puppeteer) to validate interception and modification.

## Open Questions
- How to handle protocols beyond HTTP(S), e.g., WebSockets or gRPC over HTTP/2?
- Should intercepted flows be versioned for replay/audit histories?
- What is the best UX for resolving conflicts when multiple users edit the same flow?

## Milestones
1. Implement proxy listener and certificate management.
2. Integrate captured flows into plugin pipeline with CLI approval.
3. Ship UI for editing and approving flows.
4. Add automated browser integration scripts and documentation.
5. Harden logging, auditing, and cross-platform support.

