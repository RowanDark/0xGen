# Entropy: Randomness Analyzer

## Overview

Entropy is a powerful randomness analysis tool designed to detect weak pseudo-random number generators (PRNGs), predictable session IDs, and other security vulnerabilities related to insufficient randomness. It combines statistical analysis, PRNG fingerprinting, and AI-powered pattern detection to identify tokens that can be predicted or brute-forced.

### Why Entropy Matters

Cryptographically secure randomness is fundamental to web application security. Weak randomness can lead to:

- **Session hijacking**: Predictable session IDs allow attackers to impersonate users
- **CSRF token bypass**: Weak CSRF tokens can be guessed or brute-forced
- **API key prediction**: Predictable API keys expose sensitive operations
- **Password reset token attacks**: Weak reset tokens enable account takeover

Entropy analyzes the randomness quality of these tokens in real-time, detecting vulnerabilities before they can be exploited.

## Quick Start

### 1. Navigate to Entropy Panel

From the 0xGen desktop shell, click on **Entropy** in the top navigation menu.

### 2. Start a Capture Session

Click the **"New Session"** button to open the capture setup panel.

### 3. Select Token Preset

Choose from common token types:

- **Session Cookie (PHPSESSID)**: PHP session tokens
- **Session Cookie (JSESSIONID)**: Java session tokens
- **Authorization Header (Bearer)**: JWT and bearer tokens
- **CSRF Token (X-CSRF-Token)**: Anti-CSRF tokens
- **Custom JSON Field**: Tokens from JSON responses

Or configure a custom extractor by specifying:
- **Location**: cookie, header, or body
- **Name**: The cookie/header name or JSON field path
- **Pattern**: Optional regex pattern for extraction

### 4. Configure Auto-Stop Conditions

Set capture limits:
- **Target Token Count**: Stop after collecting N tokens (recommended: 500-1000)
- **Timeout**: Auto-stop after T seconds (e.g., 3600 = 1 hour)

### 5. Browse Normally

Once the session is started, browse the target application normally. Entropy will automatically capture and analyze matching tokens in the background.

### 6. Review Analysis Results

Click on a session card to view detailed analysis:
- **Randomness Score**: Overall quality (0-100)
- **Risk Level**: low, medium, high, or critical
- **Statistical Test Results**: Chi-squared, Runs, Serial Correlation, Spectral
- **Detected Patterns**: Sequential, timestamp-based, low-entropy
- **PRNG Fingerprint**: Identifies known weak PRNGs
- **Recommendations**: Actionable guidance for developers

## Statistical Tests Explained

### Chi-Squared Test

**What it measures**: Character frequency distribution uniformity

**How it works**: Compares the observed frequency of each character against the expected uniform distribution. For truly random tokens, each character should appear with roughly equal frequency.

**Interpretation**:
- **p-value > 0.01**: PASS - Characters are uniformly distributed
- **p-value ≤ 0.01**: FAIL - Significant character bias detected

**Example**: If analyzing hex tokens (0-9, A-F), each character should appear ~6.25% of the time. Deviations indicate non-random generation.

### Runs Test (Wald-Wolfowitz)

**What it measures**: Sequential independence

**How it works**: Analyzes the number of "runs" (sequences of consecutive similar characters). Too few runs suggest correlation; too many suggest alternation patterns.

**Interpretation**:
- **p-value > 0.01**: PASS - No sequential correlation
- **p-value ≤ 0.01**: FAIL - Tokens show sequential patterns

**Example**: "AAABBBCCC" has few runs (pattern detected), while "ABCABCABC" has many runs (alternation pattern).

### Serial Correlation Test

**What it measures**: Token-to-token correlation

**How it works**: Calculates the correlation coefficient between consecutive tokens converted to numeric values. High correlation suggests predictability.

**Interpretation**:
- **p-value > 0.01**: PASS - Tokens are independent
- **p-value ≤ 0.01**: FAIL - Tokens are correlated (predictable)

**Example**: Sequential tokens like "token_100", "token_101", "token_102" will fail this test.

### Spectral Test (FFT)

**What it measures**: Periodic patterns in frequency domain

**How it works**: Applies Fast Fourier Transform to detect hidden periodic patterns not visible in time domain.

**Interpretation**:
- **p-value > 0.01**: PASS - No periodic patterns
- **p-value ≤ 0.01**: FAIL - Periodic patterns detected

**Example**: Timestamp-based tokens or PRNG outputs often show periodic patterns in FFT analysis.

### Shannon Entropy

**What it measures**: Information density

**How it works**: Calculates the average information per character. Maximum entropy equals log2(charset_size).

**Interpretation**:
- **Hex tokens**: Maximum 4 bits/char (16 possible characters)
- **Alphanumeric**: Maximum ~6 bits/char (62 possible characters)
- **Full ASCII**: Maximum ~7 bits/char

**Example**: "aaaaaaaa" has 0 bits/char (no information), while "aB3x9Kp2" has ~6 bits/char.

### Collision Detection

**What it measures**: Duplicate token frequency

**How it works**: Compares observed collision rate against birthday paradox expectations for truly random data.

**Interpretation**:
- **Rate < 1%**: PASS for samples < 1000 tokens
- **Rate > 5%**: FAIL - Suggests limited keyspace or weak PRNG

**Example**: For 32-bit tokens, ~77,000 samples give 50% collision probability. Earlier collisions suggest weakness.

### Bit Distribution Analysis

**What it measures**: Per-bit position uniformity

**How it works**: Analyzes the frequency of 1-bits at each bit position. Random data should have ~50% ones at each position.

**Interpretation**:
- **Frequency ≈ 0.5**: PASS - Uniform bit distribution
- **Frequency close to 0 or 1**: FAIL - Bit bias detected

**Example**: Some weak PRNGs have bias in specific bit positions (e.g., low-order bits).

## Understanding Results

### Randomness Score (0-100)

Composite score combining all statistical tests:

- **90-100**: Excellent - Cryptographically strong randomness
- **70-89**: Good - Likely secure but review recommendations
- **50-69**: Marginal - Potential weaknesses, further investigation needed
- **Below 50**: Weak - Serious vulnerabilities detected

### Risk Levels

- **Low**: Tokens pass all tests, no patterns detected
- **Medium**: One or two tests failed, or low-confidence patterns
- **High**: Multiple test failures or known weak PRNG detected
- **Critical**: Severe weaknesses, tokens are easily predictable

### Sample Quality

Indicates statistical confidence based on sample size:

- **Insufficient** (< 30 tokens): Results unreliable, collect more samples
- **Marginal** (30-99 tokens): Basic patterns detectable
- **Adequate** (100-499 tokens): Statistical tests reliable
- **Excellent** (500+ tokens): High confidence results

## PRNG Fingerprinting

Entropy includes a database of known weak PRNG implementations:

### Linear Congruential Generator (LCG)

**Signature**: High serial correlation, fails spectral test

**Vulnerability**: Predictable after observing 2-3 consecutive outputs

**Exploit**: Given token_n, can calculate token_{n+1} using: `X_{n+1} = (a × X_n + c) mod m`

**Remediation**: Replace with cryptographically secure PRNG (e.g., /dev/urandom, crypto/rand)

### PHP mt_rand (pre-7.1)

**Signature**: 31-bit output, periodic patterns every 2^31-1 outputs

**Vulnerability**: State recovery from 624 consecutive outputs

**Exploit**: Mersenne Twister state prediction using php_mt_seed tool

**Remediation**: Upgrade to PHP 7.1+ or use random_bytes()

### Java Random

**Signature**: 48-bit seed, fails serial correlation test

**Vulnerability**: Seed recovery from observing consecutive values

**Exploit**: After observing 2 outputs, can compute internal state

**Remediation**: Use java.security.SecureRandom

### Timestamp-Based Generators

**Signature**: Extremely high serial correlation, sequential patterns

**Vulnerability**: Predictable based on request timing

**Exploit**: Generate candidates for current timestamp ±1 second

**Remediation**: Use cryptographic RNG, not time.Now() directly

### User-ID Correlated

**Signature**: Correlation between token values and user IDs

**Vulnerability**: Token can be guessed from user ID

**Exploit**: Enumerate tokens for known user IDs

**Remediation**: Generate tokens independently from user attributes

## Use Cases

### 1. Session Prediction Attacks

**Scenario**: Testing if session IDs are predictable

**Steps**:
1. Create capture session targeting session cookies (e.g., PHPSESSID)
2. Log in/out multiple times to generate fresh sessions
3. Collect 100-500 session tokens
4. Review analysis for serial correlation and PRNG fingerprint
5. If detected: Document in finding with randomness score and exploit guidance

**Expected Results**:
- **Secure**: Randomness score > 85, no PRNG detected
- **Vulnerable**: Score < 70, LCG or sequential pattern detected

### 2. CSRF Token Analysis

**Scenario**: Validating anti-CSRF token strength

**Steps**:
1. Target X-CSRF-Token header or hidden form field
2. Trigger multiple requests requiring CSRF tokens
3. Analyze for predictability and collisions
4. Check if tokens are session-specific or global

**Red Flags**:
- Collision rate > 1% (limited keyspace)
- Sequential patterns (incrementing tokens)
- Same token across sessions (global token)

### 3. API Key Strength Validation

**Scenario**: Assessing generated API key randomness

**Steps**:
1. Create multiple API keys through the application
2. Extract keys from JSON responses
3. Analyze character distribution and entropy
4. Look for timestamp or user-ID correlation

**Security Baseline**:
- Minimum 128-bit effective entropy
- No detectable patterns
- Unique per user/resource

### 4. Password Reset Token Testing

**Scenario**: Checking if reset tokens can be predicted/brute-forced

**Steps**:
1. Trigger multiple password reset requests
2. Extract tokens from emails or URLs
3. Analyze for predictability and reuse
4. Test token lifespan and single-use enforcement

**Critical Checks**:
- Tokens should fail to predict next token
- No timestamp-based generation
- Sufficient entropy (> 100 bits)

## Advanced Features

### Real-Time Capture Mode

Monitor token generation dynamically:

- **Auto-refresh**: Live statistics update every 5 seconds
- **Incremental analysis**: Results update as tokens are captured
- **Confidence tracking**: Sample quality indicator shows statistical reliability
- **Auto-stop**: Automatically stops at target count or timeout

### Session Controls

Manage capture lifecycle:

- **Pause**: Temporarily suspend capture without losing data
- **Resume**: Continue from paused state
- **Stop**: Finalize session and run full analysis

### Advanced Visualizations

Click "Show Advanced Visualizations" to access:

1. **Bit Distribution Heatmap**: Visual representation of bit-level bias
2. **Entropy Histogram**: Distribution of per-token entropy values
3. **Frequency Analysis**: Character frequency vs. expected uniform distribution
4. **Token Scatter Plot**: Length vs. entropy correlation
5. **FFT Spectrum**: Frequency domain analysis for periodic patterns
6. **Time Series**: Rolling entropy over time

### Comparison View

Compare multiple sessions side-by-side:

1. Select sessions using checkboxes
2. Click "Compare" button
3. View delta metrics from baseline
4. Identify regression or improvements

**Use cases**:
- Before/after PRNG upgrade validation
- Production vs. staging environment comparison
- Different token types security comparison

### Export & Reporting

Export results in multiple formats:

- **CSV**: Raw token data for external analysis
- **JSON**: Structured analysis results for automation
- **HTML**: Formatted report for sharing
- **Markdown**: Documentation-friendly format
- **PDF**: Executive summary for stakeholders

## Integration with Testing Workflow

### During Security Assessment

```bash
# 1. Start 0xGen with Entropy plugin enabled
0xgenctl run --target https://example.com --plugins entropy

# 2. Navigate to Entropy panel in desktop shell
# 3. Start capture session for session cookies
# 4. Use target application normally (login, browse, logout, repeat)
# 5. Review analysis after collecting 500+ tokens
# 6. Document findings with screenshots and randomness scores
```

### Automated Testing

```go
// Example: Programmatic entropy analysis
package main

import (
	"github.com/RowanDark/0xGen/plugins/entropy"
)

func TestSessionTokenEntropy(t *testing.T) {
	// Collect tokens
	tokens := []string{
		"a1b2c3d4e5f6g7h8",
		"i9j0k1l2m3n4o5p6",
		// ... 500+ tokens
	}

	// Run analysis
	result := entropy.ChiSquaredTest(tokens)
	if !result.Passed {
		t.Errorf("Session tokens failed chi-squared test: p-value=%.4f", result.PValue)
	}

	score := entropy.CalculateRandomnessScore(tokens)
	if score < 70.0 {
		t.Errorf("Session tokens have weak randomness: score=%.1f/100", score)
	}
}
```

### CI/CD Integration

Add entropy checks to your security pipeline:

```yaml
# .github/workflows/security.yml
name: Security Tests

on: [push, pull_request]

jobs:
  entropy-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Run entropy analysis
        run: |
          # Generate test tokens
          ./scripts/generate_test_tokens.sh > tokens.txt

          # Analyze with Entropy plugin
          0xgenctl entropy analyze --input tokens.txt --output report.json

          # Fail if randomness score < 85
          score=$(jq '.randomnessScore' report.json)
          if (( $(echo "$score < 85" | bc -l) )); then
            echo "::error::Token randomness score $score below threshold 85"
            exit 1
          fi
```

## Comparison with Other Tools

### Entropy vs. Burp Suite Sequencer

| Feature | 0xGen Entropy | Burp Sequencer |
|---------|---------------|----------------|
| **Statistical Tests** | 7 tests (Chi-squared, Runs, Serial Correlation, Spectral, Entropy, Collisions, Bit Distribution) | 6 tests (similar coverage) |
| **PRNG Fingerprinting** | ✅ Detects 7 known weak PRNGs | ❌ No PRNG fingerprinting |
| **AI Pattern Detection** | ✅ 5 pattern types | ❌ Manual analysis only |
| **Real-Time Capture** | ✅ Live statistics, auto-stop | ⚠️ Basic auto-stop |
| **Incremental Analysis** | ✅ Results update as tokens captured | ❌ Analysis only after completion |
| **Visualizations** | ✅ 6 interactive charts (heatmap, FFT, time-series) | ⚠️ Basic charts |
| **Session Comparison** | ✅ Multi-session delta analysis | ❌ Single session only |
| **Export Formats** | ✅ CSV, JSON, HTML, Markdown, PDF | ⚠️ HTML only |
| **Performance** | ✅ < 5ms overhead, < 5s for 1000 tokens | ⚠️ Slower for large datasets |
| **Integration** | ✅ Plugin API, CLI, GUI | ⚠️ GUI only |
| **Cost** | ✅ Open source, free | ❌ Requires Burp Pro license |

### When to Use Entropy

- **You need PRNG fingerprinting**: Automatically identify known weak generators
- **Real-time monitoring**: Track token quality during active testing
- **Automation**: Integrate into CI/CD pipelines via API
- **Comparison analysis**: Compare multiple sessions or environments
- **Advanced visualizations**: Need FFT spectrum or bit distribution heatmaps
- **Budget constraints**: Open-source alternative to commercial tools

### When to Use Burp Sequencer

- **Already using Burp Suite Professional**: Native integration
- **Prefer established tools**: Industry-standard, well-documented
- **Don't need real-time analysis**: Batch analysis is sufficient

## Troubleshooting

### "Insufficient sample size" warning

**Cause**: Less than 30 tokens collected

**Solution**: Continue capturing until you have at least 100 tokens for reliable results

### "Sample quality: marginal" message

**Cause**: Between 30-99 tokens, statistical tests have lower confidence

**Solution**: Collect 500+ tokens for high-confidence analysis

### No tokens being captured

**Checks**:
1. Verify token extractor configuration matches actual response format
2. Check that target application is generating the expected tokens
3. Review browser dev tools to confirm token location (cookie vs. header vs. body)
4. Ensure session is in "active" status, not "paused"

### All tests passing but intuition says tokens are weak

**Possible causes**:
1. Tokens may use cryptographic RNG but have limited keyspace (check collision rate)
2. Sample size may be too small to detect subtle patterns (collect 1000+ tokens)
3. Application may be using two-stage generation (secure random for base, then modification)

**Actions**:
1. Increase sample size to 2000+ tokens
2. Review bit distribution heatmap for subtle biases
3. Check FFT spectrum for periodic patterns
4. Manually inspect tokens for structural patterns

### False positives in PRNG detection

**Cause**: True random data can occasionally exhibit patterns by chance

**Solution**:
1. Check confidence level (< 70% may be false positive)
2. Collect larger sample (500+ tokens)
3. Run comparison analysis with known-good tokens
4. Review all statistical tests, not just PRNG fingerprint

## Best Practices

1. **Collect adequate samples**: Aim for 500-1000 tokens minimum
2. **Use fresh sessions**: Don't mix tokens from different user sessions
3. **Test multiple scenarios**: Analyze tokens under different conditions (time of day, load, etc.)
4. **Document findings**: Export reports with screenshots for evidence
5. **Verify exploitability**: If weakness detected, attempt to predict next token
6. **Re-test after remediation**: Validate fixes with new capture session
7. **Compare environments**: Ensure production uses same RNG as staging/dev

## Security Considerations

- **Avoid capturing sensitive tokens**: Entropy stores tokens in local database
- **Clear sessions after testing**: Delete capture sessions to remove stored tokens
- **Use isolated test accounts**: Don't analyze tokens from production user accounts
- **Respect rate limits**: Auto-stop prevents overwhelming target application
- **Follow responsible disclosure**: Report findings to vendor before public disclosure

## FAQ

**Q: How many tokens do I need for reliable results?**
A: Minimum 100 for basic analysis, 500+ for high confidence statistical testing.

**Q: Can Entropy predict the next token?**
A: Entropy detects if tokens are predictable but doesn't generate predictions. If a weakness is detected, refer to the exploit hint in the PRNG fingerprint section.

**Q: What's the difference between randomness score and risk level?**
A: Randomness score (0-100) is quantitative assessment. Risk level (low/medium/high/critical) combines score with pattern detection and PRNG fingerprinting for actionable categorization.

**Q: Can I analyze tokens from a file instead of live capture?**
A: Yes, use the JSON export format to import pre-collected tokens (API feature).

**Q: How does Entropy compare to NIST randomness tests?**
A: Entropy implements similar statistical tests (runs, spectral, chi-squared) but adds security-focused features like PRNG fingerprinting and AI pattern detection specifically for web tokens.

**Q: Is Entropy suitable for cryptographic RNG testing?**
A: Entropy is designed for web token analysis. For dedicated cryptographic RNG testing, use NIST SP 800-22 test suite or dieharder.

## Further Reading

- [NIST SP 800-22 Rev. 1a: Statistical Test Suite for Random Number Generators](https://csrc.nist.gov/publications/detail/sp/800-22/rev-1a/final)
- [OWASP: Insufficient Randomness](https://owasp.org/www-community/vulnerabilities/Insufficient_Randomness)
- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
- [Breaking Weak PRNGs: mt_rand in PHP](https://www.ambionics.io/blog/php-mt-rand-prediction)
- [Session Prediction Attack Techniques](https://owasp.org/www-community/attacks/Session_Prediction)

## Support

For issues, feature requests, or questions:
- GitHub Issues: https://github.com/RowanDark/0xGen/issues
- Documentation: https://docs.0xgen.dev
- Community: https://discord.gg/0xgen
