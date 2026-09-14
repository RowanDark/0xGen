# Blitz Payload Generation and Response Classification

Blitz includes context-aware payload generation and pattern-based response
classification to enhance fuzzing beyond a plain wordlist. This document
describes those features.

## Overview

Blitz's pattern-based features include:

1. **Context Payload Selector** - Contextual payload generation based on endpoint analysis
2. **Pattern Response Classifier** - Vulnerability detection and classification from regex/literal patterns
3. **Findings Correlator** - Automatic correlation to CWE/OWASP vulnerability databases

None of this relies on a model or external inference call - it is regex
matching, literal string matching, and heuristics over the request/response
data, all of which run locally.

## Context Payload Selector

### Purpose

Instead of using generic wordlists, the Context Payload Selector analyzes your target endpoint and generates contextually relevant payloads based on:

- URL path structure
- Parameter names
- HTTP method
- Content-Type headers
- Inferred application context

### Supported Vulnerability Categories

The selector generates targeted payloads for:

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
# Enable context-aware payload generation
0xgenctl blitz run \
  --req request.txt \
  --ai-payloads \
  --attack sniper

# Or enable all pattern-based features
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

The selector will:
1. Match `/api/search` against known database-query path patterns
2. Identify `query` parameter as a SQL injection candidate by name
3. Identify `limit` as a numeric parameter (IDOR candidate)
4. Generate targeted SQLi payloads for `query`
5. Generate numeric range payloads for `limit`

### Configuration

```go
config := &blitz.ContextPayloadConfig{
    EnableContextAnalysis:  true,
    MaxPayloadsPerCategory: 15,
    EnableAdvancedPayloads: true,
    CustomPayloads: map[VulnCategory][]string{
        VulnCategorySQLi: {"custom' payload--"},
    },
}
```

## Pattern Response Classifier

### Purpose

The Pattern Response Classifier analyzes fuzzing results to detect and classify vulnerabilities by matching response bodies against a fixed table of regexes and literal strings, each with a hardcoded confidence score.

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
# Enable pattern-based classification
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
- **Confidence**: A fixed score (0.0-1.0) hardcoded per pattern, not a measured probability
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

# Enable all pattern-based features (recommended)
0xgenctl blitz run \
  --req request.txt \
  --ai \
  --findings-output findings.jsonl \
  --attack sniper
```

### Vulnerability Database

The correlator includes vulnerability reference information:

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

## Complete Example

Here's a full example using all pattern-based features:

```bash
# Create request template
cat > login.txt <<EOF
POST /api/login HTTP/1.1
Host: example.com
Content-Type: application/json

{"username": "{{user}}", "password": "{{pass}}"}
EOF

# Run Blitz with everything enabled
0xgenctl blitz run \
  --req login.txt \
  --ai \
  --attack pitchfork \
  --concurrency 10 \
  --rate 50 \
  --findings-output findings.jsonl \
  --export-html report.html

# What happens:
# 1. The selector matches the endpoint (POST /api/login) against known patterns
# 2. Identifies username/password as auth parameters
# 3. Generates SQLi payloads for both fields
# 4. Fuzzes with Pitchfork attack (paired payloads)
# 5. Classifies responses against the pattern table
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

Context payload generation enabled - analyzing target context...
Generated 2 context-aware payload sets

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
Findings:          2
Avg Duration:      124ms
Duration Range:    98ms - 456ms

=== Features Used ===
✓ Context Payload Generation
✓ Pattern Response Classification
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

    // Create context payload selector
    config := &blitz.ContextPayloadConfig{
        EnableContextAnalysis:  true,
        MaxPayloadsPerCategory: 15,
        EnableAdvancedPayloads: true,
    }
    selector := blitz.NewContextPayloadSelector(config)
    generators := blitz.CreateContextPayloadGenerator(selector, request)

    // Configure engine with pattern-based features
    storage, _ := blitz.NewSQLiteStorage("results.db")
    defer storage.Close()

    engineConfig := &blitz.EngineConfig{
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
    engine, _ := blitz.NewEngine(engineConfig)
    engine.Run(context.Background(), func(result *blitz.FuzzResult) error {
        // Handle result
        return nil
    })
}
```

## Performance Considerations

- **Context Payload Generation**: Adds ~100-200ms to initialization (one-time cost)
- **Pattern Classification**: Adds ~1-5ms per anomalous response
- **Findings Correlation**: Adds ~2-10ms per finding generation

Total overhead is minimal (<1%) for typical fuzzing campaigns.

## References

- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [0xGen Findings Specification](../../specs/finding.md)
- [Hydra Plugin Documentation](../../plugins/hydra/)

## License

Part of the 0xGen project. See main LICENSE file.
