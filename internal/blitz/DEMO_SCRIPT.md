# Blitz Demo Video Script
## "Blitz vs Burp Intruder: Context-Aware Web Fuzzing"

**Duration:** 5 minutes
**Target Audience:** Security professionals, penetration testers
**Goal:** Demonstrate Blitz's advantages over Burp Suite Intruder

---

## Script Outline

### Scene 1: Introduction (0:00 - 0:30)

**[Visual: Split screen showing Burp Suite logo vs 0xGen Blitz logo]**

**Narrator:**
"Welcome to Blitz - the context-aware web fuzzer that takes everything you love about Burp Suite Intruder and supercharges it with target-aware payload generation and pattern-based classification. In the next 5 minutes, I'll show you why Blitz is the future of web application security testing."

**[Visual: Text overlay - "4 Attack Types | Context-Aware Payloads | Pattern Detection | Open Source"]**

---

### Scene 2: Side-by-Side Setup (0:30 - 1:30)

**[Visual: Split screen - Burp Intruder on left, Blitz GUI on right]**

**Narrator:**
"Let's test a vulnerable login form for SQL injection. I'll set up the same attack in both tools."

**[Burp Suite side]**
- Shows captured POST request to `/api/login`
- Highlights username and password fields with § markers
- Loads SQLi wordlist (50 payloads)
- Selects "Cluster Bomb" attack type
- Configures threading to 5

**[Blitz GUI side]**
- Shows the same POST request
- Highlights username and password with {{}} markers
- Enables "--ai-payloads" flag
- Selects "Cluster Bomb" attack type
- Sets concurrency to 5

**Narrator:**
"Notice how similar the setup is - Blitz uses the same attack types you're familiar with: Sniper, Battering Ram, Pitchfork, and Cluster Bomb. But watch what happens when we enable context-aware payloads."

---

### Scene 3: Context-Aware Payload Generation (1:30 - 2:15)

**[Visual: Close-up of Blitz analyzing the request]**

**Narrator:**
"Here's where Blitz gets interesting. Instead of manually selecting payloads, Blitz analyzes your request template."

**[Visual: Animation showing target context analysis]**
```
Analyzing request...
✓ Detected POST method
✓ Detected JSON content type
✓ Parameter 'username' → Database context inferred
✓ Parameter 'password' → Authentication context inferred
✓ Selected vulnerability categories: SQLi, Auth Bypass
✓ Generated 45 context-aware payloads
```

**Narrator:**
"Blitz identified that we're testing a login endpoint with JSON body, and automatically generated 45 SQL injection payloads relevant to authentication bypass. In Burp, you had to manually curate this wordlist."

**[Visual: Comparison of payload lists]**

**Burp Wordlist (manual):**
```
' OR '1'='1
admin' --
' OR 1=1--
```

**Blitz Context-Aware Payloads:**
```
' OR '1'='1
admin' --
' OR 1=1--
{"username":"admin","password":"' OR '1'='1"}  ← JSON-aware
admin')} OR 1=1--  ← Context-aware escaping
' UNION SELECT NULL,user(),database()--  ← Database enumeration
```

**Narrator:**
"See the difference? Blitz generates payloads that understand the JSON context, including proper escaping and structure."

---

### Scene 4: Running the Attack (2:15 - 3:00)

**[Visual: Both tools running simultaneously]**

**Narrator:**
"Let's run both attacks and see what we find."

**[Burp Suite side]**
- Progress bar: 250/2500 requests (10%)
- Table showing results: Status 401, 401, 401, 401...
- No color coding
- User must manually sort and analyze

**[Blitz side]**
- Progress indicator with RPS, ETA, and anomaly counter
- Results table with color-coded status badges
- Real-time classification labels appearing
- Anomaly highlighting in red

**[Visual: Blitz detects anomaly]**

```
[+] Anomaly detected!
    Payload: ' OR '1'='1
    Status: 200 (was 401)
    Length: 523 bytes (+478 from baseline)

[!] Classification: auth_bypass
    Confidence: 0.95
    CWE: CWE-287
    OWASP: A07:2021-Authentication Failures

[✓] Finding created: finding-auth-001
```

**Narrator:**
"Within seconds, Blitz detected an authentication bypass and automatically classified it. In Burp, you'd have to manually review hundreds of responses to find this."

---

### Scene 5: Response Classification (3:00 - 3:45)

**[Visual: Close-up of Blitz's response classifier in action]**

**Narrator:**
"But Blitz doesn't stop at detecting anomalies. Watch as it analyzes each response for vulnerability indicators."

**[Visual: Animation of response classification]**

**Response 1:**
```http
HTTP/1.1 500 Internal Server Error
{"error":"You have an error in your SQL syntax..."}
```
**Classification:** `sql_error` | Confidence: 0.95 | CWE-89

**Response 2:**
```http
HTTP/1.1 200 OK
{"success":true,"user":{"id":1,"username":"admin","role":"admin"}}
```
**Classification:** `auth_bypass` | Confidence: 0.85 | CWE-287

**Response 3:**
```http
HTTP/1.1 401 Unauthorized
{"error":"Invalid credentials"}
```
**Classification:** `none` | Not interesting

**Narrator:**
"Blitz uses 50+ detection patterns to classify responses into vulnerability categories - SQL errors, XSS reflection, command execution, sensitive data exposure, and more. Each finding includes CWE and OWASP mappings."

---

### Scene 6: Findings Integration (3:45 - 4:30)

**[Visual: Blitz findings dashboard]**

**Narrator:**
"Here's the real magic: Blitz automatically converts interesting results into actionable security findings."

**[Visual: Finding detail view]**

```json
Finding: SQL Injection in Login Form
----------------------------------------
Severity: High
CWE: CWE-89 (SQL Injection)
OWASP: A03:2021-Injection

Vulnerability Details:
The application is vulnerable to SQL injection in the
username parameter, allowing authentication bypass.

Proof of Concept:
POST /api/login HTTP/1.1
{"username":"' OR '1'='1","password":"anything"}

Evidence:
- Response status changed from 401 to 200
- Admin account accessed without valid credentials
- Token returned: eyJhbGci...

Remediation:
Use parameterized queries or prepared statements.
Validate and sanitize all user inputs.

References:
- https://owasp.org/www-community/attacks/SQL_Injection
- https://cwe.mitre.org/data/definitions/89.html
```

**Narrator:**
"Each finding includes severity ratings, exploitation details, proof-of-concept requests, and remediation guidance. This is report-ready output that would take hours to compile manually in Burp."

**[Visual: Split comparison]**

**Burp Suite Workflow:**
1. Run Intruder ✓
2. Sort by status code ✓
3. Manually review responses ✗ (tedious)
4. Identify vulnerabilities ✗ (manual)
5. Take notes ✗ (manual)
6. Create finding ✗ (manual)
7. Add CWE/OWASP ✗ (manual)
8. Write remediation ✗ (manual)
9. Generate report ✗ (manual)

**Blitz Workflow:**
1. Run Blitz with --ai-findings ✓
2. Review auto-generated findings ✓
3. Export report ✓
**Done!**

---

### Scene 7: Performance & Features (4:30 - 4:50)

**[Visual: Feature comparison table]**

| Feature | Burp Intruder Pro | Blitz |
|---------|-------------------|-------|
| Attack Types | 4 | 4 ✓ |
| Custom Payloads | ✓ | ✓ |
| Context-Aware Payload Generation | ✗ | ✓ |
| Pattern-Based Classification | ✗ | ✓ |
| Anomaly Detection | Basic | Advanced |
| CWE/OWASP Mapping | ✗ | ✓ |
| Auto Findings | ✗ | ✓ |
| Export Formats | XML, CSV | CSV, JSON, HTML |
| Open Source | ✗ ($399/year) | ✓ (Free) |
| Desktop GUI | ✓ | ✓ |
| CLI Interface | Limited | Full |
| Concurrent Requests | ✓ | ✓ |
| Rate Limiting | ✓ | ✓ |

**Narrator:**
"And Blitz is completely open source and free. No $399 annual license required."

---

### Scene 8: Conclusion & Call to Action (4:50 - 5:00)

**[Visual: Blitz logo with GitHub link]**

**Narrator:**
"Blitz brings context-aware payload generation and pattern-based detection to web fuzzing. Same workflow you love from Burp Intruder, enhanced with context-aware payloads, automatic classification, and automatic findings generation."

**[Visual: Text overlay]**
```
Get Started Today:
github.com/RowanDark/0xGen

Documentation:
docs.0xgen.io/blitz

Tutorial Videos:
youtube.com/0xgen
```

**Narrator:**
"Try Blitz today and experience the future of web application security testing. Links in the description. Happy hunting!"

**[Visual: Fade to black with 0xGen logo]**

---

## Recording Notes

### Equipment Needed

- **Screen Recording:** OBS Studio or ScreenFlow
- **Audio:** USB microphone (Blue Yeti or similar)
- **Video Resolution:** 1920x1080 at 60fps
- **Audio Quality:** 44.1kHz, stereo

### Screen Layout

1. **Split Screen Comparison:**
   - Left: Burp Suite Professional
   - Right: Blitz Desktop GUI
   - 50/50 split

2. **Full Screen Demos:**
   - Blitz target analysis animations
   - Finding detail views
   - Feature comparison tables

3. **Text Overlays:**
   - Use clear, readable font (Ubuntu Mono or SF Mono)
   - High contrast colors
   - Animations for bullet points

### Recording Tips

1. **Pre-record demo data:**
   - Set up vulnerable test app locally
   - Pre-run both tools to ensure smooth demo
   - Have backup recordings in case of errors

2. **Pacing:**
   - Speak clearly and not too fast
   - Pause for 2-3 seconds between scenes
   - Allow visual elements to be absorbed

3. **Highlighting:**
   - Use red circles/boxes to highlight important elements
   - Animate arrows to guide viewer attention
   - Zoom in on small text

4. **Background Music:**
   - Soft, professional tech music
   - Volume: -20dB to -25dB (background only)
   - Fade in/out at beginning and end

### Post-Production

1. **Editing:**
   - Cut any mistakes or long pauses
   - Add smooth transitions between scenes
   - Include animated graphics for payload analysis

2. **Captions:**
   - Add closed captions for accessibility
   - Highlight key terms in different colors

3. **Thumbnail:**
   - Text: "Blitz vs Burp Intruder"
   - Show split screen of both tools
   - Include "Context-Aware" badge
   - High contrast, eye-catching design

### YouTube Upload

**Title:**
"Blitz vs Burp Intruder: Context-Aware Web Fuzzing - Finding SQL Injection in Minutes"

**Description:**
```
In this video, I demonstrate Blitz - an open-source, context-aware web fuzzer that enhances the Burp Suite Intruder workflow with target-aware payload generation and automatic vulnerability detection.

🎯 What You'll Learn:
- How Blitz compares to Burp Suite Intruder
- Context-aware payload generation for SQL injection
- Automatic vulnerability classification with CWE/OWASP mapping
- Converting fuzzing results into actionable security findings
- Why Blitz is free and open source

⚡ Key Features:
✓ 4 Attack Types (Sniper, Battering Ram, Pitchfork, Cluster Bomb)
✓ Context-aware payload generation
✓ Pattern-based anomaly detection and classification
✓ Auto-generated security findings with remediation
✓ Desktop GUI and CLI interfaces
✓ Open source and completely free

🔗 Resources:
GitHub: https://github.com/RowanDark/0xGen
Documentation: https://github.com/RowanDark/0xGen/tree/main/internal/blitz
Tutorial (SQLi): https://github.com/RowanDark/0xGen/blob/main/internal/blitz/TUTORIAL_SQLI.md
Tutorial (XSS): https://github.com/RowanDark/0xGen/blob/main/internal/blitz/TUTORIAL_XSS.md

📚 Chapters:
0:00 - Introduction
0:30 - Side-by-Side Setup
1:30 - Context-Aware Payload Generation
2:15 - Running the Attack
3:00 - Response Classification
3:45 - Findings Integration
4:30 - Feature Comparison
4:50 - Conclusion

#websecurity #penetrationtesting #cybersecurity #appsec #bugbounty #infosec
```

**Tags:**
```
web security, penetration testing, burp suite, sql injection, xss, fuzzing, security testing, bug bounty, infosec, cybersecurity, appsec, vulnerability scanning, ethical hacking, OWASP, CWE
```

---

## Alternative Shorter Version (2 minutes)

For social media / quick demos:

### Quick Demo Script (2:00)

**0:00-0:15 - Hook**
"I'm going to find a SQL injection vulnerability in 30 seconds using context-aware payloads. Watch this."

**0:15-0:45 - Setup**
[Show Blitz GUI] "Here's a login request. I'll mark the injection points and enable context-aware payloads. That's it - no wordlist needed."

**0:45-1:15 - Detection**
[Run attack] "Blitz generated 45 relevant payloads and... there! Authentication bypass detected in 12 seconds with full CWE/OWASP classification."

**1:15-1:45 - Finding**
[Show finding] "Automatic finding generated with PoC, remediation, and references. This is report-ready output."

**1:45-2:00 - CTA**
"Blitz is open source and free. Link in description. Try it today!"

---

## Demo Environment Setup

### Vulnerable Test Application

Use DVWA (Damn Vulnerable Web Application) or create a simple test app:

**Simple Vulnerable Login (Node.js/Express):**

```javascript
const express = require('express');
const app = express();
app.use(express.json());

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  // Intentionally vulnerable SQL query for demo
  const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;

  // Simulate vulnerable behavior
  if (username.includes("' OR '")) {
    // SQLi successful
    res.status(200).json({
      success: true,
      message: "Login successful",
      user: { id: 1, username: "admin", role: "administrator" },
      token: "demo-token-123"
    });
  } else if (username === "admin" && password === "admin123") {
    // Valid credentials
    res.status(200).json({
      success: true,
      message: "Login successful",
      user: { id: 1, username: "admin", role: "administrator" },
      token: "demo-token-123"
    });
  } else if (username.includes("admin'")) {
    // SQL error
    res.status(500).json({
      error: "Database error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''admin'' AND password='...' at line 1"
    });
  } else {
    // Invalid credentials
    res.status(401).json({
      error: "Invalid credentials"
    });
  }
});

app.listen(3000, () => console.log('Vulnerable app running on port 3000'));
```

This ensures consistent, demonstrable vulnerability for the video.

---

**End of Demo Script**

This script provides a complete blueprint for creating a professional, engaging demo video that showcases Blitz's advantages over Burp Suite Intruder.
