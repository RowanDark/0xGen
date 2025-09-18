# Galdr Proxy

Galdr Proxy is the interception layer for Glyph. It terminates client HTTP/HTTPS sessions, applies rules-based modifications, and records a tamper-proof history that other plugins can consume.

## Capabilities
- `CAP_HTTP_ACTIVE`
- `CAP_HTTP_PASSIVE`
- `CAP_WS`

## Running the proxy service

`glyphd` now embeds the proxy. Launch it with your authentication token:

```bash
glyphd --token <TOKEN>
```

Key files are written beneath `/out` by default:

| Artifact | Default path | Purpose |
| -------- | ------------ | ------- |
| CA certificate | `/out/galdr_proxy_ca.pem` | Install in your browser/OS trust store |
| CA private key | `/out/galdr_proxy_ca.key` | Used to mint leaf certificates for intercepted hosts |
| History log | `/out/proxy_history.jsonl` | JSONL file containing every intercepted request/response |

Use `--proxy-port`, `--proxy-rules`, `--proxy-history`, `--proxy-ca-cert`, and `--proxy-ca-key` to override the defaults.

### Generate and trust the CA certificate

1. Start `glyphd` once so the proxy can generate a root CA and private key.
2. Import `/out/galdr_proxy_ca.pem` into your browser or system trust store. The certificate common name is **Galdr Proxy Root CA**.
   - **macOS:** Keychain Access → System → Certificates → import the PEM → set to “Always Trust”.
   - **Firefox:** Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import.
   - **Linux/Windows:** Use the native certificate manager for your distribution.

Until the CA is trusted, HTTPS interception will surface security warnings.

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

Every flow is appended to `/out/proxy_history.jsonl` along with metadata (timestamp, client IP, protocol, matched rules, headers, and payload sizes). The file can be tailed or post-processed by other Glyph plugins for analysis.

### WebSocket traffic

WebSocket upgrade requests are passed through transparently in this MVP. Frame inspection and modification are tracked for a future release.
