# Hydra Plugin

Passive vulnerability detection engine for 0xGen. Hydra scans HTTP traffic with five pattern-matching analyzers and applies a threshold-based confidence policy to decide which candidate findings to emit.

## Overview

Hydra is a passive detection plugin for 0xGen, providing:

- **5 Vulnerability Analyzers**: XSS, SQLi, SSRF, Command Injection, Open Redirect — implemented as substring and pattern matching over response bodies and headers
- **Confidence Policy Evaluation**: Per-category minimum-confidence and escalation thresholds decide whether a candidate is emitted and at what severity
- **Passive Analysis**: Zero-impact detection from HTTP traffic observation

There is no machine learning model, inference step, or outbound network call anywhere in the plugin. "Confidence" is a score the analyzers assign based on which patterns matched; the evaluator compares that score against hardcoded thresholds.

## Features

### Vulnerability Detection

| Vulnerability Type | Detection Method | Confidence Level |
|-------------------|------------------|------------------|
| **Cross-Site Scripting (XSS)** | Reflected payloads, context analysis | High |
| **SQL Injection (SQLi)** | Error patterns, boolean-based, time-based | High |
| **Server-Side Request Forgery (SSRF)** | Cloud metadata, internal IPs, DNS rebinding | Medium-High |
| **Command Injection** | Shell metacharacters, output patterns | High |
| **Open Redirect** | URL parameter manipulation, header injection | Medium |

### Detection Pipeline

```
HTTP Response → Analyzer Detection → Confidence Policy → Severity Assignment → Finding Emission
```

1. **Analyzer Stage**: Specialized detectors scan for vulnerability patterns and assign a confidence score
2. **Policy Stage**: Per-category thresholds (`minConfidence`, `escalateThreshold`) decide whether to drop, emit, or escalate the severity of the candidate
3. **Emission Stage**: Findings that clear the threshold are sent to 0xGen core

### Capabilities

- **`CAP_EMIT_FINDINGS`**: Permission to emit vulnerability findings
- **`CAP_HTTP_PASSIVE`**: Observe HTTP traffic without modification
- **`CAP_FLOW_INSPECT`**: Access complete request/response pairs for context
- **`CAP_AI_ANALYSIS`**: Capability name inherited from the plugin SDK; gates the confidence-scoring stage described above, not any model or external service

## Architecture

### Component Overview

```
plugins/hydra/
├── main.go           # Plugin entry point and hook registration
├── engine.go         # Core analysis engine and coordinator
├── analyzers.go      # Vulnerability-specific detection logic
├── llm.go            # Threshold-based confidence policy ("aiEvaluator" implementation)
├── helpers.go        # Shared helpers
├── hooks.go          # Plugin SDK hook wiring
├── manifest.json     # Plugin metadata and capabilities
└── README.md         # This file
```

### Analysis Engine

The `hydraEngine` coordinates all analyzers and applies the confidence policy:

```go
type hydraEngine struct {
    analyzers []analyzer        // List of vulnerability detectors
    evaluator aiEvaluator       // Threshold-based confidence policy (see llm.go)
    now       func() time.Time  // Timestamp generator (testable)
}
```

**Key Methods**:
- `process()`: Main entry point for HTTP event analysis
- Iterates through all analyzers
- Collects candidate findings
- Submits each candidate to the confidence policy
- Emits findings that clear the policy's threshold

### Analyzers

Each analyzer implements the `analyzer` interface:

```go
type analyzer interface {
    ID() string
    Analyse(ctx responseContext) *analysisCandidate
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

### Confidence Policy Evaluator

The `aiEvaluator` interface (implemented in `llm.go` by `llmConsensus`) is a lookup table of hardcoded per-category thresholds — not a model call:

```go
type aiEvaluator interface {
    Decide(candidate *analysisCandidate) (analysisDecision, bool)
}
```

Each vulnerability category has its own policy with two fixed thresholds:

- `minConfidence`: candidates below this score are dropped
- `escalateThreshold`: candidates at or above this score have their severity escalated

For example, the XSS policy drops anything under 0.55 confidence and escalates to high severity at 0.75+. These numbers are compile-time constants; there is no learning, training data, or external evaluation involved.

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

Hydra is a standalone plugin binary started with two flags and a required environment variable:

```bash
./hydra --server 127.0.0.1:50051 --token dev-token
# 0XGEN_CAPABILITY_TOKEN must be set in the environment
```

All five analyzers and their confidence thresholds are currently fixed in code (`engine.go`, `llm.go`) — there is no config file, CLI flag, or environment variable to toggle individual analyzers or adjust thresholds at runtime. Changing that behavior today means editing `newHydraEngine` or the per-category policies in `llm.go`.

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
2. Confidence policy clears the 0.55 minimum for the `xss` category and emits the finding
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
2. Confidence policy clears the 0.5 minimum for the `sqli` category and emits the finding
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
2. Confidence policy clears the 0.55 minimum for the `ssrf` category, escalating to critical severity above 0.75
3. Finding emitted as critical severity

## Performance

### Benchmark Results

From pre-alpha performance testing (see `internal/atlas/BENCHMARKS.md`):

| Metric | Value | Notes |
|--------|-------|-------|
| **Throughput** | ~340 targets/sec | Single XSS analyzer |
| **Latency** | ~3ms/target | All analyzers active |
| **Memory** | ~132KB/target | |

No false-positive or false-negative rate has been measured for Hydra — `internal/atlas/BENCHMARKS.md` covers throughput and latency only, not detection accuracy. Don't cite an accuracy figure for Hydra until one is backed by an actual benchmark in this repo.

### Tuning

The analyzer set and confidence thresholds are fixed in code today (see [Configuration](#configuration)), so tuning Hydra currently means editing `engine.go` or `llm.go` directly and rebuilding the plugin — there is no runtime knob for it yet.

## Security Considerations

### Sandbox Restrictions

Hydra runs with the following sandbox restrictions:

- **cgroups**: CPU (50%), Memory (512MB), PIDs (256)
- **chroot**: Isolated filesystem (read-only root)
- **Network**: Restricted to localhost and allowed IPs
- **seccomp-bpf**: Syscall filtering (only safe syscalls allowed)
- **Capabilities**: Dropped all Linux capabilities except analysis APIs

### Privacy Considerations

Hydra processes potentially sensitive HTTP traffic entirely in-process:

1. **No External Submission**: All analysis (pattern matching and confidence scoring) happens locally in the plugin; nothing is sent off-host
2. **Passive Only**: Hydra observes traffic via `CAP_HTTP_PASSIVE`/`CAP_FLOW_INSPECT` and does not modify requests or responses

## Troubleshooting

### No Findings Detected

**Symptom**: Hydra loads but doesn't emit findings

**Solutions**:

1. **Enable debug logging** to see which candidates are being dropped by the confidence policy:
   ```bash
   0xgend start --log-level debug | grep hydra
   ```

2. **Test with a known vulnerable target**:
   ```bash
   # DVWA (Damn Vulnerable Web Application)
   docker run -p 8080:80 vulnerables/web-dvwa
   0xgend start --target http://localhost:8080
   ```

Remember that the analyzer set and thresholds are fixed at build time (see [Tuning](#tuning)) — there is no runtime config to check.

### High Memory Usage

**Symptom**: Hydra consumes excessive memory

**Solutions**:

1. **Check for memory leaks**:
   ```bash
   # Monitor memory usage
   watch -n 1 "ps aux | grep hydra"
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
- ✅ Threshold-based confidence policy evaluation
- ✅ Passive HTTP analysis

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
2. **Confidence Policies**: Tune per-category thresholds, or make them runtime-configurable instead of compile-time constants
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

- **v2.0.0-alpha** (2025-11-20): Initial release with 5 analyzers and threshold-based confidence evaluation
- **v0.1.0** (2024-Q4): Internal pre-alpha testing
