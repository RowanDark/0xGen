# Hydra Plugin

AI-powered vulnerability detection engine for 0xGen. Hydra analyzes HTTP traffic using multiple specialized analyzers and AI consensus evaluation to identify security vulnerabilities with high confidence.

## Overview

Hydra is the core AI detection plugin for 0xGen, providing:

- **5 Vulnerability Analyzers**: XSS, SQLi, SSRF, Command Injection, Open Redirect
- **AI Consensus Evaluation**: Multi-stage validation reducing false positives
- **Passive Analysis**: Zero-impact detection from HTTP traffic observation
- **Context-Aware Detection**: Understands application behavior patterns
- **Production-Grade Accuracy**: Optimized for real-world pentesting workflows

## Features

### Vulnerability Detection

| Vulnerability Type | Detection Method | Confidence Level |
|-------------------|------------------|------------------|
| **Cross-Site Scripting (XSS)** | Reflected payloads, context analysis | High (AI-validated) |
| **SQL Injection (SQLi)** | Error patterns, boolean-based, time-based | High (AI-validated) |
| **Server-Side Request Forgery (SSRF)** | Cloud metadata, internal IPs, DNS rebinding | Medium-High |
| **Command Injection** | Shell metacharacters, output patterns | High (AI-validated) |
| **Open Redirect** | URL parameter manipulation, header injection | Medium |

### AI Evaluation Pipeline

```
HTTP Response → Analyzer Detection → AI Evaluator → Confidence Scoring → Finding Emission
```

1. **Analyzer Stage**: Specialized detectors scan for vulnerability patterns
2. **AI Stage**: Machine learning model evaluates findings in context
3. **Decision Stage**: Consensus algorithm determines final confidence
4. **Emission Stage**: High-confidence findings sent to 0xGen core

### Capabilities

- **`CAP_EMIT_FINDINGS`**: Permission to emit vulnerability findings
- **`CAP_HTTP_PASSIVE`**: Observe HTTP traffic without modification
- **`CAP_FLOW_INSPECT`**: Access complete request/response pairs for context
- **`CAP_AI_ANALYSIS`**: Use AI evaluation services for decision-making

## Architecture

### Component Overview

```
plugins/hydra/
├── main.go           # Plugin entry point and hook registration
├── engine.go         # Core analysis engine and coordinator
├── analyzers.go      # Vulnerability-specific detection logic
├── evaluator.go      # AI consensus evaluation
├── manifest.json     # Plugin metadata and capabilities
└── README.md         # This file
```

### Analysis Engine

The `hydraEngine` coordinates all analyzers and manages the AI evaluation pipeline:

```go
type hydraEngine struct {
    analyzers []analyzer        // List of vulnerability detectors
    evaluator aiEvaluator       // AI consensus evaluator
    now       func() time.Time  // Timestamp generator (testable)
}
```

**Key Methods**:
- `process()`: Main entry point for HTTP event analysis
- Iterates through all analyzers
- Collects candidate findings
- Submits to AI evaluator for validation
- Emits high-confidence findings

### Analyzers

Each analyzer implements the `analyzer` interface:

```go
type analyzer interface {
    Analyse(ctx responseContext) *candidateFinding
}
```

**Available Analyzers**:

1. **`xssAnalyzer`**: Detects reflected XSS by searching for injected payloads in responses
   - HTML context detection
   - JavaScript context detection
   - Attribute context detection
   - Event handler injection

2. **`sqliAnalyzer`**: Identifies SQL injection vulnerabilities
   - Database error message patterns
   - Boolean-based blind SQLi
   - Time-based blind SQLi
   - Union-based injection

3. **`ssrfAnalyzer`**: Finds SSRF vulnerabilities
   - Cloud metadata endpoints (AWS, GCP, Azure)
   - Internal IP ranges (RFC1918)
   - Localhost variations
   - DNS rebinding indicators

4. **`commandInjectionAnalyzer`**: Detects OS command injection
   - Shell metacharacter injection
   - Command output patterns
   - Error message analysis
   - Path traversal indicators

5. **`openRedirectAnalyzer`**: Identifies open redirect vulnerabilities
   - URL parameter manipulation
   - HTTP 3xx redirect analysis
   - Location header injection
   - Meta refresh detection

### AI Evaluator

The `aiEvaluator` provides context-aware validation:

```go
type aiEvaluator interface {
    Decide(candidate *candidateFinding) (decision, bool)
}
```

**Decision Types**:
- `decisionEmit`: High confidence, emit finding immediately
- `decisionDrop`: Low confidence, discard candidate
- `decisionDefer`: Uncertain, collect more evidence

**Evaluation Factors**:
- Pattern match strength
- Response context analysis
- Historical false positive rate
- Application behavior baseline
- Request/response correlation

## Usage

### Basic Usage

Hydra is enabled by default in 0xGen:

```bash
# Start 0xGen with Hydra active
0xgend start

# Or explicitly enable
0xgend start --enable-plugin hydra
```

### Configuration

Configure Hydra via 0xGen config file (`~/.0xgen/config.yaml`):

```yaml
plugins:
  hydra:
    enabled: true
    config:
      # AI evaluation threshold (0.0 - 1.0)
      confidence_threshold: 0.75

      # Maximum findings per target
      max_findings_per_target: 100

      # Enable/disable specific analyzers
      analyzers:
        xss: true
        sqli: true
        ssrf: true
        command_injection: true
        open_redirect: true

      # AI model configuration
      ai:
        model: "gpt-4"
        temperature: 0.3
        max_tokens: 500
```

### Command-Line Options

```bash
# Disable Hydra temporarily
0xgend start --disable-plugin hydra

# Adjust AI confidence threshold
0xgend start --plugin-config hydra.confidence_threshold=0.85

# Enable only specific analyzers
0xgend start --plugin-config hydra.analyzers.xss=true --plugin-config hydra.analyzers.sqli=false
```

### Programmatic API

Use Hydra from Go code:

```go
import "github.com/RowanDark/0xgen/plugins/hydra"

// Create Hydra engine
engine := hydra.NewEngine(hydra.Config{
    ConfidenceThreshold: 0.75,
    Analyzers: []string{"xss", "sqli", "ssrf"},
})

// Process HTTP response
finding, err := engine.Analyze(httpResponse)
if err != nil {
    log.Fatal(err)
}

if finding != nil {
    fmt.Printf("Vulnerability detected: %s\n", finding.Type)
}
```

## Detection Examples

### Example 1: Reflected XSS

**Request**:
```http
GET /search?q=<script>alert(1)</script> HTTP/1.1
Host: vulnerable.example.com
```

**Response**:
```http
HTTP/1.1 200 OK
Content-Type: text/html

<html>
  <body>
    <h1>Search results for: <script>alert(1)</script></h1>
  </body>
</html>
```

**Hydra Detection**:
1. `xssAnalyzer` detects injected payload in response
2. AI evaluator confirms HTML context injection
3. Finding emitted:
   ```json
   {
     "type": "xss.reflected",
     "severity": "high",
     "confidence": 0.92,
     "message": "Reflected XSS via 'q' parameter",
     "target": "https://vulnerable.example.com/search?q=...",
     "evidence": {
       "injected_payload": "<script>alert(1)</script>",
       "reflection_context": "html_body",
       "parameter": "q"
     }
   }
   ```

### Example 2: SQL Injection

**Request**:
```http
GET /user?id=1' OR '1'='1 HTTP/1.1
Host: vulnerable.example.com
```

**Response**:
```http
HTTP/1.1 200 OK

You have an error in your SQL syntax near ''1'='1' at line 1
```

**Hydra Detection**:
1. `sqliAnalyzer` detects SQL error message
2. AI evaluator confirms database-specific error pattern
3. Finding emitted with high confidence (0.95)

### Example 3: SSRF to Cloud Metadata

**Request**:
```http
GET /proxy?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
Host: vulnerable.example.com
```

**Response**:
```http
HTTP/1.1 200 OK

ami-id
hostname
instance-id
```

**Hydra Detection**:
1. `ssrfAnalyzer` detects AWS metadata endpoint access
2. AI evaluator confirms cloud metadata pattern
3. Finding emitted as critical severity

## Performance

### Benchmark Results

From pre-alpha performance testing (see `internal/atlas/BENCHMARKS.md`):

| Metric | Value | Notes |
|--------|-------|-------|
| **Throughput** | ~340 targets/sec | Single XSS analyzer |
| **Latency** | ~3ms/target | All analyzers active |
| **Memory** | ~132KB/target | Includes AI evaluation |
| **False Positive Rate** | <5% | With AI validation |
| **False Negative Rate** | ~8% | Complex obfuscation cases |

### Optimization Tips

1. **Disable Unused Analyzers**: Only enable vulnerability types you're testing
   ```yaml
   analyzers:
     xss: true
     sqli: false  # Disable if not testing SQLi
     ssrf: false
   ```

2. **Adjust Confidence Threshold**: Higher threshold = fewer false positives
   ```yaml
   confidence_threshold: 0.85  # Default: 0.75
   ```

3. **Limit Findings**: Prevent finding explosion on large targets
   ```yaml
   max_findings_per_target: 50  # Default: 100
   ```

## Security Considerations

### Sandbox Restrictions

Hydra runs with the following sandbox restrictions:

- **cgroups**: CPU (50%), Memory (512MB), PIDs (256)
- **chroot**: Isolated filesystem (read-only root)
- **Network**: Restricted to localhost and allowed IPs
- **seccomp-bpf**: Syscall filtering (only safe syscalls allowed)
- **Capabilities**: Dropped all Linux capabilities except analysis APIs

### AI Model Security

The AI evaluator communicates with external AI services:

- **TLS Required**: All AI API calls use HTTPS
- **API Key Protection**: Keys stored in secure keyring
- **Rate Limiting**: Built-in rate limits prevent abuse
- **Data Sanitization**: PII is stripped before sending to AI
- **Audit Logging**: All AI decisions logged for review

### Privacy Considerations

Hydra processes potentially sensitive HTTP traffic:

1. **Local Processing First**: Pattern matching done locally
2. **Minimal AI Submission**: Only candidates sent to AI (not all traffic)
3. **PII Stripping**: Sensitive data removed before AI evaluation
4. **Configurable AI**: Can disable AI and use pattern matching only

**Disable AI Mode**:
```yaml
plugins:
  hydra:
    config:
      ai:
        enabled: false  # Use pattern matching only
```

## Troubleshooting

### No Findings Detected

**Symptom**: Hydra loads but doesn't emit findings

**Solutions**:

1. **Check confidence threshold** (too high filters all findings):
   ```bash
   0xgend start --plugin-config hydra.confidence_threshold=0.5
   ```

2. **Verify analyzers are enabled**:
   ```bash
   # Check which analyzers are active
   0xgenctl config get plugins.hydra.analyzers
   ```

3. **Enable debug logging**:
   ```bash
   0xgend start --log-level debug | grep hydra
   ```

4. **Test with known vulnerable target**:
   ```bash
   # DVWA (Damn Vulnerable Web Application)
   docker run -p 8080:80 vulnerables/web-dvwa
   0xgend start --target http://localhost:8080
   ```

### False Positives

**Symptom**: Hydra reports vulnerabilities that don't exist

**Solutions**:

1. **Increase confidence threshold**:
   ```yaml
   confidence_threshold: 0.85  # Stricter validation
   ```

2. **Review AI decisions**:
   ```bash
   # Check AI evaluation logs
   tail -f ~/.0xgen/logs/hydra-ai.log
   ```

3. **Disable problematic analyzer**:
   ```yaml
   analyzers:
     open_redirect: false  # If causing false positives
   ```

### High Memory Usage

**Symptom**: Hydra consumes excessive memory

**Solutions**:

1. **Limit findings per target**:
   ```yaml
   max_findings_per_target: 25  # Reduce from default 100
   ```

2. **Reduce analyzer count**:
   ```yaml
   analyzers:
     xss: true
     sqli: true
     ssrf: false
     command_injection: false
     open_redirect: false
   ```

3. **Check for memory leaks**:
   ```bash
   # Monitor memory usage
   watch -n 1 "ps aux | grep hydra"
   ```

### AI Evaluator Errors

**Symptom**: AI evaluation fails with errors

**Solutions**:

1. **Check API key**:
   ```bash
   # Verify API key is set
   0xgenctl config get plugins.hydra.ai.api_key
   ```

2. **Test AI connectivity**:
   ```bash
   curl -H "Authorization: Bearer YOUR_API_KEY" \
        https://api.openai.com/v1/models
   ```

3. **Disable AI temporarily**:
   ```yaml
   ai:
     enabled: false  # Fall back to pattern matching
   ```

## Development

### Building from Source

```bash
# Navigate to plugin directory
cd plugins/hydra

# Install dependencies
go mod download

# Build plugin binary
go build -o hydra main.go

# Run tests
go test ./...

# Run with race detector
go test -race ./...
```

### Adding a New Analyzer

1. **Implement the `analyzer` interface**:
   ```go
   type myAnalyzer struct{}

   func (a *myAnalyzer) Analyse(ctx responseContext) *candidateFinding {
       // Your detection logic
       if vulnerabilityDetected {
           return &candidateFinding{
               Type:       "my_vulnerability",
               Severity:   SeverityHigh,
               Message:    "Description",
               Evidence:   evidence,
           }
       }
       return nil
   }
   ```

2. **Register analyzer in `engine.go`**:
   ```go
   analyzers := []analyzer{
       &xssAnalyzer{},
       &sqliAnalyzer{},
       &myAnalyzer{},  // Add your analyzer
   }
   ```

3. **Add tests** (`my_analyzer_test.go`):
   ```go
   func TestMyAnalyzer(t *testing.T) {
       analyzer := &myAnalyzer{}
       ctx := responseContext{
           Body: "vulnerable response",
       }
       finding := analyzer.Analyse(ctx)
       assert.NotNil(t, finding)
   }
   ```

4. **Update configuration schema**:
   ```yaml
   analyzers:
     my_vulnerability: true
   ```

### Testing Strategies

**Unit Tests** (fast, isolated):
```bash
go test -run TestXSSAnalyzer ./...
```

**Integration Tests** (slower, realistic):
```bash
go test -run TestHydraEngine ./...
```

**Benchmark Tests**:
```bash
go test -bench=BenchmarkXSSAnalyzer -benchmem ./...
```

**Live Testing** (manual verification):
```bash
# Against DVWA
docker run -p 8080:80 vulnerables/web-dvwa
0xgend start --target http://localhost:8080 --enable-plugin hydra --log-level debug
```

## Roadmap

### Current Status (v2.0.0-alpha)

- ✅ 5 vulnerability analyzers
- ✅ AI consensus evaluation
- ✅ Passive HTTP analysis
- ✅ Context-aware detection
- ✅ <5% false positive rate

### Planned Features (v2.1.0)

- 🔄 DOM-based XSS detection
- 🔄 XML External Entity (XXE) analyzer
- 🔄 Deserialization vulnerability detection
- 🔄 CSRF token analysis
- 🔄 Custom analyzer plugin system

### Future Enhancements (v3.0.0)

- 📋 Active exploitation verification
- 📋 Automatic payload generation
- 📋 Vulnerability chaining detection
- 📋 Machine learning model training interface
- 📋 Real-time threat intelligence integration

## Contributing

We welcome contributions to Hydra! Focus areas:

1. **New Analyzers**: Add detection for additional vulnerability types
2. **AI Models**: Improve evaluation accuracy with better models
3. **Performance**: Optimize analyzer speed and memory usage
4. **Test Coverage**: Add tests for edge cases
5. **Documentation**: Improve detection examples and troubleshooting

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.

## References

- **Plugin SDK**: [docs/en/plugins/sdk-reference.md](../../docs/en/plugins/sdk-reference.md)
- **Atlas Core**: [internal/atlas/README.md](../../internal/atlas/README.md)
- **Security Guide**: [PLUGIN_GUIDE.md](../../PLUGIN_GUIDE.md)
- **Benchmarks**: [internal/atlas/BENCHMARKS.md](../../internal/atlas/BENCHMARKS.md)

## License

MIT License - see [LICENSE](../../LICENSE) for details.

## Version History

- **v2.0.0-alpha** (2025-11-20): Initial release with 5 analyzers and AI evaluation
- **v0.1.0** (2024-Q4): Internal pre-alpha testing
