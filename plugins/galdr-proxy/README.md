# Galdr Proxy

Galdr Proxy is the interception layer for Glyph. It terminates client HTTP/HTTPS sessions, applies rules-based modifications, and records a tamper-proof history that other plugins can consume.

## Capabilities
- `CAP_HTTP_ACTIVE`
- `CAP_HTTP_PASSIVE`
- `CAP_WS`

## Running the proxy service

`glyphd` now embeds the proxy. Launch it with your authentication token and enable the interception layer:

```bash
glyphd --token <TOKEN> --enable-proxy --proxy-addr 127.0.0.1:8080 \
  --proxy-rules /out/proxy_rules.json --proxy-history /out/proxy_history.jsonl
```

Key files are written beneath `/out` by default:

| Artifact | Default path | Purpose |
| -------- | ------------ | ------- |
| CA certificate | `/out/galdr_proxy_ca.pem` | Install in your browser/OS trust store |
| CA private key | `/out/galdr_proxy_ca.key` | Used to mint leaf certificates for intercepted hosts |
| History log | `/out/proxy_history.jsonl` | JSONL file containing every intercepted request/response |

Use `--proxy-addr`, `--proxy-rules`, `--proxy-history`, `--proxy-ca-cert`, and `--proxy-ca-key` to override the defaults. For a quick-start ruleset, copy `examples/rules.example.json` into your output directory and point `--proxy-rules` at the copied file.

### Install the Galdr CA

1. Start `glyphd` once so the proxy can generate a root CA and private key.
2. Copy the certificate at `/out/galdr_proxy_ca.pem` (or your custom `--proxy-ca-cert` location) to the workstation running the browser. Treat the matching `*.key` as a secret.
3. Import the PEM into your browser or operating-system trust store. The certificate common name is **Galdr Proxy Root CA**.
   - **macOS Keychain Access:** System → Certificates → File → Import Items… → select the PEM → double-click the imported certificate and set “When using this certificate” to **Always Trust**.
   - **Firefox:** Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import → select the PEM → tick “Trust this CA to identify websites”.
   - **Chrome / Chromium:** Settings → Privacy and security → Security → Manage device certificates → Authorities → Import → trust for identifying websites. On macOS Chrome reuses the system keychain, so follow the Keychain Access steps above.

Remove the trust anchor by deleting the **Galdr Proxy Root CA** entry from the same store. Until the CA is trusted, HTTPS interception will surface browser security warnings.

### Configure your browser/system proxy

1. Point HTTP and HTTPS traffic at the Galdr proxy (default `http://127.0.0.1:8080`).
2. Ensure “Use this proxy for HTTPS” (or equivalent) is enabled so CONNECT requests are intercepted.
3. Navigate to a test site and observe response headers changing when rules are applied.

### Modification rules

Rules live in a JSON file (`/out/proxy_rules.json` by default). Each rule can match on URL substrings and mutate headers or entire bodies for requests and responses. Example:

```json
[
  {
    "name": "inject-cache-buster",
    "match": {"url_contains": "/api/"},
    "request": {"add_headers": {"X-Galdr": "active"}},
    "response": {"remove_headers": ["Cache-Control"], "add_headers": {"X-Galdr-Proxy": "modified"}}
  }
]
```

Save changes to the rules file and the proxy will pick them up automatically within a second.

### History log

Every flow is appended to `/out/proxy_history.jsonl` as JSON Lines. Each entry matches the following schema:

| Field | Type | Description |
| ----- | ---- | ----------- |
| `timestamp` | RFC 3339 string | When the request was completed. |
| `client_ip` | string | Source IP observed by the proxy. |
| `protocol` | string | Transport protocol (e.g., `http`, `https`, `ws`). |
| `method` | string | HTTP method used by the client. |
| `url` | string | Full request URL. |
| `status_code` | integer | Upstream response status code. |
| `latency_ms` | integer | End-to-end latency in milliseconds. |
| `request_size_bytes` | integer | Number of bytes received from the client. |
| `response_size_bytes` | integer | Number of bytes sent back to the client. |
| `request_headers` | object | Map of header name → array of values sent upstream. |
| `response_headers` | object | Map of header name → array of values returned downstream. |
| `matched_rules` | array (optional) | Names of any modification rules applied to the flow. |

The log can be tailed or post-processed by other Glyph plugins for analysis. Override the path with `--proxy-history` if you prefer a custom location.

Example entry:

```json
{"timestamp":"2024-01-01T12:00:00Z","client_ip":"127.0.0.1","protocol":"http","method":"GET","url":"https://example.com/demo","status_code":200,"latency_ms":42,"request_size_bytes":128,"response_size_bytes":512,"request_headers":{"X-Glyph":["on"]},"response_headers":{"X-Glyph-Proxy":["active"]},"matched_rules":["demo-rule"]}
```

### WebSocket traffic

WebSocket upgrade requests are passed through transparently in this MVP. Frame inspection and modification are tracked for a future release.
