# OAST: Out-of-Application Security Testing

## Overview

OAST (Out-of-Application Security Testing) enables detection of blind vulnerabilities by using unique callback URLs that report back when accessed. This is essential for finding:

- Blind SQL Injection
- Blind Cross-Site Scripting (XSS)
- Server-Side Request Forgery (SSRF)
- XML External Entity (XXE) Injection
- Remote Code Execution (RCE)

## How It Works

1. **Generate Callback URL**: 0xGen creates a unique URL for each test
2. **Inject Payload**: Scanner injects the callback URL into the target
3. **Wait for Callback**: If vulnerable, target makes request to callback URL
4. **Record Interaction**: 0xGen logs the callback as proof of vulnerability

## Quick Start

### Enable OAST (Default: Enabled)

```yaml
# config.yaml
oast:
  enabled: true
  mode: local
  port: 8443  # 0 for random
  timeout: 5  # Seconds to wait for callback
```

Or via environment variable:

```bash
export 0XGEN_OAST_ENABLED=true
export 0XGEN_OAST_MODE=local
```

### View Interactions in GUI

1. Open 0xGen GUI
2. Navigate to **OAST** tab
3. Interactions appear in real-time
4. Click interaction for full details

### Programmatic Usage

```bash
# Generate callback URL
0xgen oast generate --test-id my-test

# Check for interactions
0xgen oast check --id oast-1705420800-k7m3np2q-0001

# List all interactions
0xgen oast list --limit 100
```

## Modes

### Local Mode (Default)

Runs HTTP server on localhost. Best for:
- Development
- Internal application testing
- Learning OAST techniques

**Limitations:**
- No DNS callbacks
- Target must be able to reach localhost
- Requires ngrok for external targets

**Example with ngrok:**

```bash
# Terminal 1: Start 0xGen
0xgen start

# Terminal 2: Start ngrok
ngrok http 8443

# Use ngrok URL in payloads
# e.g., http://abc123.ngrok.io/callback/...
```

### Self-Hosted Mode (Future)

Use your own VPS with custom domain. See [Self-Hosted OAST Guide](./oast-selfhosted.md).

### Cloud Mode (Future)

Use 0xGen's hosted OAST service. Free tier: 1000 callbacks/day.

## Testing Blind Vulnerabilities

### Blind SSRF

```bash
# Scan for SSRF
0xgen scan ssrf --url https://target.com/api/fetch

# Payload injected: url=http://oast-123.local:8443/ssrf
# If vulnerable, target makes request to OAST server
```

### Blind SQL Injection

```bash
# Scan for SQLi
0xgen scan sqli --url https://target.com/login --param username

# Payload: ' OR 1=1; EXEC xp_cmdshell 'curl http://oast-456.local:8443/sqli'--
```

### Blind XSS

```bash
# Scan for XSS
0xgen scan xss --url https://target.com/comment --param message

# Payload: <script>new Image().src='http://oast-789.local:8443/xss'</script>
```

### Blind XXE

```bash
# Scan for XXE
0xgen scan xxe --url https://target.com/upload

# Payload includes external entity pointing to OAST server
```

### Blind Command Injection

```bash
# Scan for command injection
0xgen scan cmdi --url https://target.com/ping --param host

# Payload: ; curl http://oast-abc.local:8443/cmdi
```

## Viewing Results

### GUI

OAST panel shows:
- **Real-time callbacks** as they arrive
- **Callback details** (headers, body, IP)
- **Linked tests** (which scan triggered callback)
- **Statistics** (total callbacks, unique IDs)

### CLI

```bash
# List recent interactions
0xgen oast list

# Get specific interaction
0xgen oast get --id oast-123

# Export to JSON
0xgen oast export --format json > interactions.json
```

## Configuration

### Timeout

How long to wait for callbacks:

```yaml
oast:
  timeout: 5  # Seconds (default)
```

Blind vulnerabilities may trigger immediately or after delay (e.g., when admin views logs).

### TTL

How long to keep interactions:

```yaml
oast:
  ttl: 24h  # 24 hours (default)
```

### Port

HTTP server port:

```yaml
oast:
  port: 8443  # Fixed port
  port: 0     # Random port (default)
```

## Troubleshooting

### "OAST is disabled"

Enable in config:

```yaml
oast:
  enabled: true
```

### "No interactions received"

1. **Check target can reach OAST server**

   ```bash
   # From target machine:
   curl http://localhost:8443/callback/test
   ```

2. **Increase timeout**

   ```yaml
   oast:
     timeout: 10  # Wait longer
   ```

3. **Check firewall** (if using ngrok or self-hosted)

4. **Verify payload injection**
   - Check request was sent with OAST URL
   - Check for WAF/filtering

### "Callbacks not linked to tests"

Ensure scanner passes `testID`:

```go
callback, err := oastClient.GenerateCallback(ctx, "test-001")
```

## Best Practices

1. **Use Unique Test IDs**: Makes correlation easier
2. **Set Reasonable Timeouts**: Some callbacks are delayed
3. **Clean Up Old Interactions**: Configure TTL appropriately
4. **Monitor in Real-Time**: Watch GUI for immediate feedback
5. **Export Evidence**: Save callbacks for reports

## Security Considerations

- **Local Mode**: Interactions stay on your machine
- **Self-Hosted**: You control the data
- **Cloud Mode**: Encrypted in transit, deleted after TTL
- **No Sensitive Data**: Never include secrets in callback URLs

## Advanced Usage

### Custom Payloads

```bash
# Generate callback URL
CALLBACK=$(0xgen oast generate --format url)

# Use in custom payload
curl "https://target.com/api?url=http://$CALLBACK/custom"
```

### Webhook Integration

```bash
# Send callback notifications to webhook
0xgen config set oast.webhook https://your-webhook.com/oast
```

### Batch Testing

```bash
# Test multiple endpoints
for url in $(cat urls.txt); do
  0xgen scan ssrf --url "$url" &
done
wait

# View all interactions
0xgen oast list
```

## Programmatic API (Go)

### Client Usage

```go
import "github.com/RowanDark/0xgen/internal/oast"

// Create client
cfg := oast.Config{
    Mode:    oast.ModeLocal,
    Port:    0,
    Host:    "localhost",
    Timeout: 5,
}
client, err := oast.NewClient(cfg, eventBus, logger)

// Start server
ctx := context.Background()
go client.Start(ctx)

// Generate callback
callback, err := client.GenerateCallback(ctx, "test-123")
fmt.Println("Callback URL:", callback.URL)

// Wait for interaction
interaction, err := client.WaitForInteraction(ctx, callback.ID, 5*time.Second)
if interaction != nil {
    fmt.Println("Vulnerability confirmed!")
}
```

### Tester Usage

```go
import "github.com/RowanDark/0xgen/internal/oast"

tester := oast.NewTester(client, logger)
tester.SetTimeout(5 * time.Second)

// Test for blind SSRF
req := httptest.NewRequest("GET", targetURL, nil)
finding, err := tester.TestBlindSSRF(ctx, req, "ssrf-test")
if finding != nil {
    fmt.Printf("Found: %s (Severity: %s)\n", finding.Type, finding.Severity)
}
```

## FAQs

**Q: Can I use OAST with authenticated scanning?**
A: Yes, OAST works with any request. Authentication is separate.

**Q: Does OAST work with GraphQL/gRPC?**
A: Yes, as long as you can inject the callback URL.

**Q: Can I share OAST server with team?**
A: Local mode: No. Self-hosted/Cloud: Yes (future).

**Q: What's the performance impact?**
A: Minimal. HTTP server uses <10MB RAM, <1% CPU.

**Q: Can I use external OAST services (Burp Collaborator, interact.sh)?**
A: Not yet, but you can configure self-hosted mode to use them.

## Related

- [Blind Vulnerability Testing Guide](./blind-vulns.md)
- [Scanner Configuration](./scanner-config.md)
- [API Reference](../api/oast.md)
