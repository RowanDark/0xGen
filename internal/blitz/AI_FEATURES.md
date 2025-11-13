# Blitz AI Integration

Blitz integrates advanced AI-powered features to enhance fuzzing effectiveness beyond traditional tools. This document describes the AI capabilities available in Blitz Issue #12.2.

## Overview

Blitz AI features include:

1. **AI Payload Selector** - Contextual payload generation based on endpoint analysis
2. **AI Response Classifier** - Intelligent vulnerability detection and classification
3. **Findings Correlator** - Automatic correlation to CWE/OWASP vulnerability databases

## AI Payload Selector

### Purpose

Instead of using generic wordlists, the AI Payload Selector analyzes your target endpoint and generates contextually relevant payloads based on:

- URL path structure
- Parameter names
- HTTP method
- Content-Type headers
- Inferred application context

### Supported Vulnerability Categories

The AI generates targeted payloads for:

- **SQL Injection** (CWE-89)
  - Triggered for: database-related parameters, API endpoints, search functions
  - Examples: `id`, `query`, `search`, `filter`, `/api/`, `/data/`

- **Cross-Site Scripting (XSS)** (CWE-79)
  - Triggered for: HTML-rendering contexts, comment fields, text inputs
  - Examples: `comment`, `message`, `description`, `/view`, `/render`

- **Command Injection** (CWE-78)
  - Triggered for: system command parameters
  - Examples: `cmd`, `command`, `exec`, `ping`, `/admin/system`

- **Path Traversal** (CWE-22)
  - Triggered for: file system access parameters
  - Examples: `file`, `path`, `filename`, `/download`, `/upload`

- **SSRF** (CWE-918)
  - Triggered for: URL parameters
  - Examples: `url`, `uri`, `link`, `callback`, `webhook`

- **IDOR** (CWE-639)
  - Triggered for: numeric identifiers
  - Examples: `id`, `user_id`, `account_id`, `order_id`

### Usage

```bash
# Enable AI payload generation
0xgenctl blitz run \
  --req request.txt \
  --ai-payloads \
  --attack sniper

# Or enable all AI features
0xgenctl blitz run \
  --req request.txt \
  --ai \
  --attack sniper
```

### Example

Given this request template:

```http
GET /api/search?query={{search}}&limit={{limit}} HTTP/1.1
Host: example.com
```

The AI will:
1. Analyze that `/api/search` suggests a database query
2. Identify `query` parameter as SQL injection candidate
3. Identify `limit` as a numeric parameter (IDOR candidate)
4. Generate targeted SQLi payloads for `query`
5. Generate numeric range payloads for `limit`

### Configuration

```go
aiConfig := &blitz.AIPayloadConfig{
    EnableContextAnalysis:  true,
    MaxPayloadsPerCategory: 15,
    EnableAdvancedPayloads: true,
    CustomPayloads: map[VulnCategory][]string{
        VulnCategorySQLi: {"custom' payload--"},
    },
}
```

## AI Response Classifier

### Purpose

The AI Response Classifier analyzes fuzzing results to automatically detect and classify vulnerabilities based on response patterns.

### Detection Patterns

#### SQL Injection Detection
- MySQL errors: "You have an error in your SQL syntax"
- PostgreSQL errors: "pg_query", "PostgreSQL error"
- SQL Server errors: "unclosed quotation mark"
- Oracle errors: "ORA-00933"
- Generic: "SQLSTATE", "mysql_fetch"

#### XSS Detection
- Script tag reflection: `<script>alert(`
- Event handler reflection: `onerror=alert`
- JavaScript protocol: `javascript:alert`
- SVG-based: `<svg.*onload`

#### Command Execution Detection
- Unix user info: `uid=\d+\(.*\) gid=\d+`
- /etc/passwd: `root:x:0:0`
- Command output: "command not found"
- System info: /proc/cpuinfo patterns

#### Path Traversal Detection
- /etc/passwd contents
- Windows INI files
- Directory listing patterns

#### Information Disclosure
- Stack traces (Python, Java, JavaScript)
- Error messages with line numbers
- Debug mode indicators
- Sensitive data (emails, SSNs, credit cards, API keys)

### Usage

```bash
# Enable AI classification
0xgenctl blitz run \
  --req request.txt \
  --payloads wordlist.txt \
  --ai-classify \
  --attack sniper

# Classifications are used internally for findings correlation
```

### Output

Classifications include:
- **Category**: Type of vulnerability detected
- **Confidence**: Score from 0.0 to 1.0
- **Evidence**: Matched pattern or snippet
- **Message**: Human-readable description
- **CWE**: Common Weakness Enumeration ID
- **OWASP**: OWASP Top 10 mapping
- **Severity**: critical/high/medium/low

## Findings Correlator

### Purpose

The Findings Correlator converts interesting fuzzing results into structured 0xGen findings with:
- CWE/OWASP mappings
- Vulnerability descriptions
- Remediation guidance
- Proof-of-Concept requests
- Reference links

### Findings Output

Findings are emitted in the standard 0xGen findings format:

```json
{
  "version": "0.2",
  "id": "01HQWXYZ...",
  "plugin": "blitz",
  "type": "blitz.sql_error",
  "message": "MySQL syntax error detected - likely SQL injection vulnerability",
  "target": "http://example.com/api/search",
  "evidence": "Payload: ' OR 1=1--\n\nMatched Pattern: you have an error in your sql syntax...",
  "severity": "high",
  "ts": "2025-11-13T12:00:00Z",
  "meta": {
    "cwe": "CWE-89",
    "owasp": "A03:2021-Injection",
    "vulnerability_type": "SQL Injection",
    "remediation": "Use parameterized queries or prepared statements...",
    "poc_request": "GET /api/search?query=%27+OR+1%3D1-- HTTP/1.1\n..."
  }
}
```

### Usage

```bash
# Enable findings correlation and write to file
0xgenctl blitz run \
  --req request.txt \
  --payloads wordlist.txt \
  --ai-findings \
  --findings-output findings.jsonl \
  --attack sniper

# Enable all AI features (recommended)
0xgenctl blitz run \
  --req request.txt \
  --ai \
  --findings-output findings.jsonl \
  --attack sniper
```

### Vulnerability Database

The correlator includes comprehensive vulnerability information:

| Category | CWE | OWASP | Severity |
|----------|-----|-------|----------|
| SQL Injection | CWE-89 | A03:2021 | High |
| XSS | CWE-79 | A03:2021 | Medium |
| Command Injection | CWE-78 | A03:2021 | Critical |
| Path Traversal | CWE-22 | A01:2021 | High |
| Information Disclosure | CWE-200/209 | A04:2021 | Low-Medium |
| Auth Bypass | CWE-287 | A07:2021 | Critical |
| Sensitive Data Exposure | CWE-359 | A01:2021 | High-Critical |

Each finding includes:
- Title and description
- CWE/OWASP references
- Severity assessment
- Remediation steps
- Reference links

## Complete AI Example

Here's a full example using all AI features:

```bash
# Create request template
cat > login.txt <<EOF
POST /api/login HTTP/1.1
Host: example.com
Content-Type: application/json

{"username": "{{user}}", "password": "{{pass}}"}
EOF

# Run Blitz with full AI
0xgenctl blitz run \
  --req login.txt \
  --ai \
  --attack pitchfork \
  --concurrency 10 \
  --rate 50 \
  --findings-output findings.jsonl \
  --export-html report.html

# What happens:
# 1. AI analyzes the endpoint (POST /api/login)
# 2. Identifies username/password as auth parameters
# 3. Generates SQLi payloads for both fields
# 4. Fuzzes with Pitchfork attack (paired payloads)
# 5. Classifies responses with AI
# 6. Correlates anomalies to vulnerabilities
# 7. Emits findings with CWE/OWASP mappings
# 8. Writes findings to JSON Lines file
# 9. Generates HTML report
```

### Output

```
Found 2 insertion point(s)
  [0] user
  [1] pass

🤖 AI Payload Generation enabled - analyzing target context...
Generated 2 AI-powered payload sets

Results will be stored in: blitz_20251113_120000.db
Findings will be written to: findings.jsonl

Progress: 150/150 completed | 0 errors | 3 anomalies | 45.2 req/s

[🔍 FINDING] high - MySQL syntax error detected - likely SQL injection vulnerability (blitz.sql_error)
    CWE-89 | A03:2021-Injection

[🔍 FINDING] high - MySQL warning message exposed (blitz.sql_error)
    CWE-89 | A03:2021-Injection

=== Fuzzing Summary ===
Total Requests:    150
Successful:        147
Failed:            0
Anomalies:         3
Pattern Matches:   2
Findings (AI):     2
Avg Duration:      124ms
Duration Range:    98ms - 456ms

=== AI Features Used ===
✓ AI Payload Generation
✓ AI Response Classification
✓ Findings Correlation

Exported to HTML: report.html
```

## API Usage

```go
package main

import (
    "context"
    "github.com/RowanDark/0xgen/internal/blitz"
    "github.com/RowanDark/0xgen/internal/findings"
)

func main() {
    // Parse request template
    request, _ := blitz.ParseRequest(reqTemplate, markers)

    // Create AI payload selector
    aiConfig := &blitz.AIPayloadConfig{
        EnableContextAnalysis:  true,
        MaxPayloadsPerCategory: 15,
        EnableAdvancedPayloads: true,
    }
    selector := blitz.NewAIPayloadSelector(aiConfig)
    generators := blitz.CreateAIPayloadGenerator(selector, request)

    // Configure engine with AI features
    storage, _ := blitz.NewSQLiteStorage("results.db")
    defer storage.Close()

    config := &blitz.EngineConfig{
        Request:                   request,
        AttackType:                blitz.AttackTypeSniper,
        Generators:                generators,
        Concurrency:               10,
        EnableAIPayloads:          true,
        EnableAIClassification:    true,
        EnableFindingsCorrelation: true,
        FindingsCallback: func(finding *findings.Finding) error {
            // Handle finding
            fmt.Printf("Found: %s - %s\n", finding.Severity, finding.Message)
            return nil
        },
        Storage: storage,
    }

    // Run engine
    engine, _ := blitz.NewEngine(config)
    engine.Run(context.Background(), func(result *blitz.FuzzResult) error {
        // Handle result
        return nil
    })
}
```

## Performance Considerations

- **AI Payload Generation**: Adds ~100-200ms to initialization (one-time cost)
- **AI Classification**: Adds ~1-5ms per anomalous response
- **Findings Correlation**: Adds ~2-10ms per finding generation

Total overhead is minimal (<1%) for typical fuzzing campaigns.

## Comparison with Other Tools

| Feature | Blitz AI | Burp Intruder Pro | ZAP |
|---------|----------|-------------------|-----|
| **Contextual Payloads** | ✓ AI-powered | Manual | Rules-based |
| **Auto-Classification** | ✓ AI + patterns | Manual | Rules-based |
| **CWE/OWASP Mapping** | ✓ Automatic | Manual | Limited |
| **Findings Format** | ✓ Standard | Proprietary | XML |
| **Cost** | Free | $449/year | Free |

## Future Enhancements (Phase 3+)

- LLM integration for natural language payload generation
- Learning from successful exploitation attempts
- Automated exploit chain discovery
- Integration with Claude/Anthropic for advanced reasoning
- Real-time collaboration with Hydra plugin
- Distributed AI model across fuzzing workers

## References

- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [0xGen Findings Specification](../../specs/finding.md)
- [Hydra Plugin Documentation](../../plugins/hydra/)

## License

Part of the 0xGen project. See main LICENSE file.
