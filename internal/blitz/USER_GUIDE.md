# Blitz User Guide

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Request Templates](#request-templates)
5. [Position Markers](#position-markers)
6. [Attack Types](#attack-types)
7. [Payload Sources](#payload-sources)
8. [AI-Powered Features](#ai-powered-features)
9. [Running Fuzzing Attacks](#running-fuzzing-attacks)
10. [Analyzing Results](#analyzing-results)
11. [Exporting Data](#exporting-data)
12. [Advanced Usage](#advanced-usage)
13. [Troubleshooting](#troubleshooting)

## Introduction

**Blitz** is an AI-powered web application fuzzer designed to automatically discover security vulnerabilities through intelligent payload generation and anomaly detection. Think of it as Burp Suite Intruder enhanced with artificial intelligence.

### Key Features

- 🎯 **4 Attack Types:** Sniper, Battering Ram, Pitchfork, and Cluster Bomb
- 🤖 **AI Payload Generation:** Context-aware payloads for SQLi, XSS, Command Injection, and more
- 📊 **Smart Anomaly Detection:** AI-powered response classification
- 🔍 **Automatic Findings:** Correlates interesting results to vulnerability findings
- ⚡ **High Performance:** Concurrent execution with rate limiting
- 💾 **Persistent Storage:** SQLite database for result querying
- 📤 **Multiple Export Formats:** CSV, JSON, HTML reports

### When to Use Blitz

Use Blitz for:
- **Authentication Bypass:** Test login forms with various username/password combinations
- **SQL Injection Discovery:** Automatically test parameters with SQLi payloads
- **Cross-Site Scripting (XSS):** Fuzz input fields with XSS vectors
- **Command Injection:** Test for OS command execution vulnerabilities
- **Path Traversal:** Discover directory traversal vulnerabilities
- **IDOR Testing:** Brute-force resource identifiers
- **API Fuzzing:** Test REST/GraphQL APIs with generated payloads
- **Parameter Discovery:** Find hidden parameters and endpoints

## Installation

### Prerequisites

- Go 1.20 or higher
- 0xGen framework installed
- (Optional) SQLite for result persistence

### Build from Source

```bash
# Clone the repository
git clone https://github.com/RowanDark/0xGen
cd 0xGen

# Build 0xgenctl with Blitz support
go build -o 0xgenctl ./cmd/0xgenctl

# Verify installation
./0xgenctl blitz --help
```

### Using with 0xGen Desktop

Blitz is integrated into the 0xGen Desktop GUI. Navigate to the "Blitz" tab from the main menu.

## Quick Start

### Your First Fuzzing Attack

Let's find SQL injection in a vulnerable login form.

1. **Create a request template** (`login-request.txt`):

```http
POST /api/login HTTP/1.1
Host: vulnerable-app.local
Content-Type: application/json

{"username":"{{user}}","password":"{{pass}}"}
```

2. **Run Blitz with simple payloads:**

```bash
0xgenctl blitz run \
  -t login-request.txt \
  -p "admin,root,user" \
  -p "password,123456,admin" \
  --attack-type pitchfork \
  --concurrency 5
```

3. **Review results:**

```bash
# Export to CSV
0xgenctl blitz export \
  --session <session-id> \
  --format csv \
  --output results.csv

# View interesting anomalies
cat results.csv | grep "true" | head
```

That's it! Blitz will test the login form with the provided credentials and flag any interesting responses.

## Request Templates

### Basic Template Structure

A request template is a raw HTTP request with **position markers** indicating where payloads should be injected.

**Example:**

```http
GET /search?query={{search_term}}&page={{page_num}} HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Cookie: session={{session_cookie}}

```

### Supported HTTP Methods

- GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
- Custom methods (e.g., PROPFIND for WebDAV)

### Headers and Body

Include any headers and request body as needed:

```http
POST /api/users HTTP/1.1
Host: api.example.com
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "username": "{{username}}",
  "email": "{{email}}",
  "role": "{{role}}"
}
```

### Loading Templates

**From file:**

```bash
0xgenctl blitz run -t request.txt ...
```

**From stdin:**

```bash
cat request.txt | 0xgenctl blitz run -t - ...
```

**Inline:**

```bash
0xgenctl blitz run -t '
GET /api/user/{{id}} HTTP/1.1
Host: example.com

' ...
```

## Position Markers

Position markers define injection points in your request template.

### Marker Syntax

**Default (Double Braces):**

```http
GET /user/{{user_id}}/profile?role={{role}} HTTP/1.1
```

**Burp-Style (Section Signs):**

```bash
# Configure Blitz to use § markers
export BLITZ_MARKER_OPEN="§"
export BLITZ_MARKER_CLOSE="§"
```

```http
GET /user/§user_id§/profile?role=§role§ HTTP/1.1
```

### Marker Placement

Markers can be placed in:

- **URL paths:** `/user/{{id}}/profile`
- **Query parameters:** `?search={{term}}&page={{num}}`
- **Headers:** `Cookie: session={{session_id}}`
- **Request body:** `{"user":"{{name}}","pass":"{{password}}"}`

### Naming Markers

Use descriptive names for clarity:

```http
POST /api/transfer HTTP/1.1
Host: bank.example.com
Content-Type: application/json

{
  "from_account": "{{source_account_id}}",
  "to_account": "{{dest_account_id}}",
  "amount": "{{transfer_amount}}"
}
```

## Attack Types

Blitz supports four attack strategies inherited from Burp Suite Intruder.

### 1. Sniper

**Use Case:** Test one position at a time with one payload set.

**How it works:**
- Iterates through each position sequentially
- For each position, tries all payloads from the first payload set
- Other positions use their original values

**Example:**

```http
Request: GET /api/user/{{id}}?role={{role}} HTTP/1.1
Payloads: [1, 2, 3, 4, 5]

Requests sent:
1. GET /api/user/1?role={{role}} HTTP/1.1
2. GET /api/user/2?role={{role}} HTTP/1.1
3. GET /api/user/3?role={{role}} HTTP/1.1
4. GET /api/user/4?role={{role}} HTTP/1.1
5. GET /api/user/5?role={{role}} HTTP/1.1
6. GET /api/user/{{id}}?role=1 HTTP/1.1
7. GET /api/user/{{id}}?role=2 HTTP/1.1
...
```

**Total Requests:** `number_of_positions × number_of_payloads`

**Command:**

```bash
0xgenctl blitz run \
  -t request.txt \
  -p "1,2,3,4,5" \
  --attack-type sniper
```

### 2. Battering Ram

**Use Case:** Send the same payload to all positions simultaneously.

**How it works:**
- Takes payloads from the first payload set
- Applies the same payload to all positions at once

**Example:**

```http
Request: POST /login HTTP/1.1
Body: {"user":"{{user}}","pass":"{{pass}}"}

Payloads: [admin, root, test]

Requests sent:
1. {"user":"admin","pass":"admin"}
2. {"user":"root","pass":"root"}
3. {"user":"test","pass":"test"}
```

**Total Requests:** `number_of_payloads`

**Command:**

```bash
0xgenctl blitz run \
  -t login-request.txt \
  -p "admin,root,test" \
  --attack-type battering-ram
```

### 3. Pitchfork

**Use Case:** Pair payloads across positions (parallel iteration).

**How it works:**
- Each position has its own payload set
- Iterates through payload sets in parallel
- Stops when the shortest payload set is exhausted

**Example:**

```http
Request: POST /login HTTP/1.1
Body: {"user":"{{user}}","pass":"{{pass}}"}

Payload Set 1 (users): [admin, root, test]
Payload Set 2 (passwords): [admin123, toor, test123]

Requests sent:
1. {"user":"admin","pass":"admin123"}
2. {"user":"root","pass":"toor"}
3. {"user":"test","pass":"test123"}
```

**Total Requests:** `min(len(payload_set_1), len(payload_set_2), ...)`

**Command:**

```bash
0xgenctl blitz run \
  -t login-request.txt \
  -p "admin,root,test" \
  -p "admin123,toor,test123" \
  --attack-type pitchfork
```

### 4. Cluster Bomb

**Use Case:** Test all combinations of payloads (cartesian product).

**How it works:**
- Each position has its own payload set
- Generates every possible combination of payloads

**Example:**

```http
Request: GET /api/search?query={{query}}&sort={{sort}} HTTP/1.1

Payload Set 1 (query): [test, admin]
Payload Set 2 (sort): [asc, desc]

Requests sent:
1. GET /api/search?query=test&sort=asc HTTP/1.1
2. GET /api/search?query=test&sort=desc HTTP/1.1
3. GET /api/search?query=admin&sort=asc HTTP/1.1
4. GET /api/search?query=admin&sort=desc HTTP/1.1
```

**Total Requests:** `len(payload_set_1) × len(payload_set_2) × ...`

⚠️ **Warning:** Can generate a massive number of requests!

**Command:**

```bash
0xgenctl blitz run \
  -t search-request.txt \
  -p "test,admin" \
  -p "asc,desc" \
  --attack-type cluster-bomb
```

### Choosing the Right Attack Type

| Scenario | Recommended Type |
|----------|------------------|
| Testing single parameter with wordlist | Sniper |
| Brute-force credentials (same user/pass) | Battering Ram |
| Testing credential pairs | Pitchfork |
| Comprehensive parameter combination testing | Cluster Bomb |
| Enumerating user IDs | Sniper |
| Testing multiple injection points independently | Sniper |
| Fuzzing API with many parameters | Cluster Bomb (careful!) |

## Payload Sources

Blitz supports multiple payload sources.

### 1. Comma-Separated Values

**Simple inline payloads:**

```bash
-p "admin,root,user,test,guest"
```

### 2. Wordlist Files

**From text file (one payload per line):**

```bash
# usernames.txt
admin
root
user
test

# Command
-p @usernames.txt
```

**From CSV file (specific column):**

```bash
# creds.csv
username,password,email
admin,admin123,admin@test.com
root,toor,root@test.com

# Use column 0 (username)
-p @creds.csv:0

# Use column 1 (password)
-p @creds.csv:1
```

**From JSON file (JSONPath):**

```bash
# users.json
{
  "users": [
    {"name": "admin", "id": 1},
    {"name": "root", "id": 2}
  ]
}

# Extract names
-p @users.json:users.*.name

# Extract IDs
-p @users.json:users.*.id
```

### 3. Ranges

**Numeric ranges:**

```bash
# Generate: 1, 2, 3, 4, 5
-p "range:1-5"

# With step
-p "range:0-100:10"  # 0, 10, 20, ..., 100
```

**Alphabetic ranges:**

```bash
# Lowercase: a, b, c, ..., z
-p "range:a-z"

# Uppercase: A, B, C, ..., Z
-p "range:A-Z"
```

### 4. Regex Patterns

**Generate payloads matching a regex:**

```bash
# Generate 100 3-digit numbers
-p "regex:[0-9]{3}:100"

# Generate email addresses
-p "regex:[a-z]{5}@[a-z]{3}\\.com:50"
```

### 5. AI-Generated Payloads

**Let AI select contextually relevant payloads:**

```bash
# Enable AI payload generation
--ai-payloads

# AI will analyze the request and generate appropriate payloads
# for SQL injection, XSS, command injection, etc.
```

## AI-Powered Features

### Enabling AI Features

```bash
# Enable all AI features
--ai

# Or individually:
--ai-payloads       # AI payload generation
--ai-classify       # AI response classification
--ai-findings       # Auto-correlate to findings
```

### AI Payload Generation

Blitz analyzes your request template and generates contextually relevant payloads.

**Example:**

```http
GET /api/user/{{id}}/profile?search={{query}} HTTP/1.1
```

**AI Analysis:**
- `{{id}}`: Path parameter, likely numeric → IDOR payloads + SQLi
- `{{query}}`: Search parameter → SQLi + XSS payloads

**Generated Payloads:**
- For `id`: `1' OR '1'='1`, `-1`, `999999`, `../../../etc/passwd`
- For `query`: `<script>alert(1)</script>`, `' OR 1=1--`, `../../etc/passwd`

### AI Response Classification

Blitz uses pattern matching and heuristics to classify responses:

**Detected Vulnerability Types:**
- SQL Errors (CWE-89)
- XSS Reflection (CWE-79)
- Command Execution (CWE-78)
- Path Traversal (CWE-22)
- Error Messages (CWE-209)
- Stack Traces (CWE-209)
- Debug Information (CWE-489)
- Sensitive Data Exposure (CWE-200)
- Authentication Bypass (CWE-287)

**Classification Output:**

```json
{
  "category": "sql_error",
  "confidence": 0.95,
  "evidence": "You have an error in your SQL syntax",
  "message": "MySQL syntax error detected - likely SQL injection vulnerability",
  "severity": "high",
  "cwe": "CWE-89",
  "owasp": "A03:2021-Injection"
}
```

### Findings Correlation

When `--ai-findings` is enabled, Blitz automatically creates findings for interesting results.

**Example Finding:**

```json
{
  "id": "finding-abc123",
  "plugin": "blitz",
  "type": "blitz.sql_error",
  "message": "MySQL syntax error detected - likely SQL injection vulnerability",
  "target": "https://example.com/search?query=test",
  "severity": "high",
  "evidence": "Payload: ' OR '1'='1\n\nMatched Pattern: You have an error in your SQL syntax",
  "metadata": {
    "cwe": "CWE-89",
    "owasp": "A03:2021-Injection",
    "payload": "' OR '1'='1",
    "status_code": "500",
    "remediation": "Use parameterized queries or prepared statements"
  }
}
```

Findings appear in the 0xGen dashboard and can be exported to reports.

## Running Fuzzing Attacks

### Basic Command Structure

```bash
0xgenctl blitz run \
  --template <request-file> \
  --payload <payload-source> \
  [--payload <payload-source>] ... \
  --attack-type <type> \
  [options]
```

### Common Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --template` | Request template file or `-` for stdin | Required |
| `-p, --payload` | Payload source (can be repeated) | Required |
| `--attack-type` | Attack strategy | `sniper` |
| `--concurrency` | Parallel requests | `10` |
| `--rate-limit` | Requests per second (0=unlimited) | `0` |
| `--timeout` | Request timeout in seconds | `10` |
| `--output` | SQLite database path | `blitz-<session>.db` |
| `--ai` | Enable all AI features | `false` |
| `--ai-payloads` | AI payload generation | `false` |
| `--ai-classify` | AI response classification | `false` |
| `--ai-findings` | Auto-create findings | `false` |
| `--findings-output` | Findings output file (JSONL) | None |
| `--follow-redirects` | Follow HTTP redirects | `false` |
| `--proxy` | HTTP proxy URL | None |
| `--user-agent` | Custom User-Agent | Blitz/1.0 |

### Example Commands

**1. Basic IDOR Testing:**

```bash
0xgenctl blitz run \
  -t user-request.txt \
  -p "range:1-1000" \
  --attack-type sniper \
  --concurrency 20
```

**2. Login Brute-Force:**

```bash
0xgenctl blitz run \
  -t login-request.txt \
  -p @usernames.txt \
  -p @passwords.txt \
  --attack-type cluster-bomb \
  --concurrency 5 \
  --rate-limit 10
```

**3. SQLi Discovery with AI:**

```bash
0xgenctl blitz run \
  -t api-request.txt \
  --ai-payloads \
  --ai-classify \
  --ai-findings \
  --findings-output sqli-findings.jsonl \
  --attack-type sniper
```

**4. XSS Fuzzing:**

```bash
0xgenctl blitz run \
  -t search-request.txt \
  -p @xss-payloads.txt \
  --attack-type sniper \
  --concurrency 10 \
  --ai-classify
```

**5. API Parameter Discovery:**

```bash
0xgenctl blitz run \
  -t api-template.txt \
  -p "range:1-100" \
  -p "admin,user,guest" \
  -p "true,false" \
  --attack-type cluster-bomb \
  --concurrency 50
```

## Analyzing Results

### Viewing Results in Real-Time

Blitz outputs progress and interesting results to stdout:

```
[*] Starting Blitz fuzzer...
[*] Session ID: blitz-20250113-abc123
[*] Total jobs: 1000
[*] Concurrency: 10
[*] Rate limit: 0 (unlimited)

[+] Anomaly detected! Status: 500, Payload: ' OR '1'='1, Length: 2341 (delta: +1500)
[!] Classification: sql_error (confidence: 0.95)
[!] Finding created: finding-xyz789

Progress: 256/1000 (25.6%) | RPS: 45.2 | ETA: 16s
```

### Querying the Database

Blitz stores all results in a SQLite database:

```bash
# Query with sqlite3
sqlite3 blitz-session.db "
  SELECT id, status_code, payload, content_len, duration
  FROM results
  WHERE anomaly_interesting = 1
  ORDER BY duration DESC
  LIMIT 10;
"
```

### Filtering Results

**By status code:**

```sql
SELECT * FROM results WHERE status_code = 500;
```

**By response time:**

```sql
SELECT * FROM results WHERE duration > 5000;  -- > 5 seconds
```

**By content length:**

```sql
SELECT * FROM results WHERE content_len > 10000;
```

**By anomaly:**

```sql
SELECT * FROM results WHERE anomaly_interesting = 1;
```

## Exporting Data

### Export Formats

Blitz supports three export formats:

1. **CSV** - For spreadsheet analysis
2. **JSON** - For programmatic processing
3. **HTML** - For visual reports

### Export Command

```bash
0xgenctl blitz export \
  --session <session-id-or-db-path> \
  --format <csv|json|html> \
  --output <output-file> \
  [--filter anomaly]
```

### Examples

**Export all results to CSV:**

```bash
0xgenctl blitz export \
  --session blitz-session.db \
  --format csv \
  --output results.csv
```

**Export only anomalies to JSON:**

```bash
0xgenctl blitz export \
  --session blitz-session.db \
  --format json \
  --filter anomaly \
  --output anomalies.json
```

**Generate HTML report:**

```bash
0xgenctl blitz export \
  --session blitz-session.db \
  --format html \
  --output report.html
```

### CSV Format

```csv
id,timestamp,payload,position,status_code,content_length,duration_ms,anomaly
1,2025-01-13T10:30:00Z,admin,user,200,1024,150,false
2,2025-01-13T10:30:01Z,' OR '1'='1,user,500,2341,250,true
```

### JSON Format

```json
[
  {
    "id": 1,
    "timestamp": "2025-01-13T10:30:00Z",
    "payload": "admin",
    "position_name": "user",
    "status_code": 200,
    "content_length": 1024,
    "duration_ms": 150,
    "anomaly": {
      "is_interesting": false
    }
  },
  {
    "id": 2,
    "timestamp": "2025-01-13T10:30:01Z",
    "payload": "' OR '1'='1",
    "position_name": "user",
    "status_code": 500,
    "content_length": 2341,
    "duration_ms": 250,
    "anomaly": {
      "is_interesting": true,
      "status_code_anomaly": true,
      "content_length_delta": 1500
    }
  }
]
```

## Advanced Usage

### Custom Markers

Configure custom position markers:

```bash
export BLITZ_MARKER_OPEN="{{"
export BLITZ_MARKER_CLOSE="}}"
```

Or use Burp-style markers:

```bash
export BLITZ_MARKER_OPEN="§"
export BLITZ_MARKER_CLOSE="§"
```

### Proxy Configuration

Route requests through a proxy (e.g., Burp Suite):

```bash
--proxy http://127.0.0.1:8080
```

### Custom Headers

Add custom headers in your request template:

```http
GET /api/endpoint HTTP/1.1
Host: api.example.com
X-API-Key: your-api-key
X-Custom-Header: {{header_value}}
Authorization: Bearer {{token}}
```

### Baseline Request

Blitz automatically sends a baseline request (with original values) to establish normal behavior for anomaly detection.

### Rate Limiting

Respect server constraints with rate limiting:

```bash
# 10 requests per second
--rate-limit 10

# 1 request per second
--rate-limit 1
```

### Timeout Configuration

Set request timeout:

```bash
# 30 second timeout
--timeout 30
```

### Follow Redirects

Follow HTTP redirects:

```bash
--follow-redirects
```

## Troubleshooting

### Common Issues

**1. "No positions found in template"**

Check that your markers are correctly placed and use the right delimiters.

```bash
# Verify markers
cat request.txt | grep -E '\{\{.*\}\}'
```

**2. "Connection refused"**

Ensure the target is reachable:

```bash
curl -v http://target-host
```

**3. "Rate limit exceeded"**

The target may be rate-limiting. Reduce `--concurrency` and `--rate-limit`:

```bash
--concurrency 1 --rate-limit 1
```

**4. "Database locked"**

Close any open database connections or use a different database file.

**5. "Too many requests"**

For Cluster Bomb attacks, verify the total request count before running:

```python
# Calculate total requests
positions = 3
payloads_per_position = 100
total = payloads_per_position ** positions  # 100^3 = 1,000,000
```

### Debug Mode

Enable verbose logging:

```bash
--verbose
```

### Dry Run

Preview requests without sending them:

```bash
--dry-run
```

## Best Practices

1. **Start Small:** Begin with a small payload set to verify the template.
2. **Use Rate Limiting:** Respect target servers and avoid detection.
3. **Monitor Progress:** Use verbose mode to track fuzzing progress.
4. **Filter Results:** Focus on anomalies rather than all results.
5. **Leverage AI:** Use `--ai` flags to reduce false positives.
6. **Organize Sessions:** Use descriptive output database names.
7. **Review Findings:** Always manually verify AI-generated findings.
8. **Export Early:** Export results periodically in case of interruption.
9. **Test Safely:** Only test systems you have permission to assess.
10. **Document Results:** Keep notes on interesting findings.

## Next Steps

- [Tutorial: Finding SQL Injection with Blitz](./TUTORIAL_SQLI.md)
- [Tutorial: Fuzzing for XSS with AI Payloads](./TUTORIAL_XSS.md)
- [API Documentation for Plugin Developers](./API_DOCS.md)
- [Blitz GUI Guide](./BLITZ_GUI.md)

## Support

For issues, questions, or feature requests:
- GitHub Issues: https://github.com/RowanDark/0xGen/issues
- Documentation: https://github.com/RowanDark/0xGen/tree/main/internal/blitz

## License

Part of the 0xGen project. See main repository for license details.
