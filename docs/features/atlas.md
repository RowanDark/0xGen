# Atlas: Active Vulnerability Scanner

## Overview

Atlas is 0xGen's built-in active vulnerability scanner that automatically detects security vulnerabilities by intelligently testing web applications with crafted payloads. It combines traditional active scanning techniques with AI-powered analysis to minimize false positives and provide actionable remediation advice.

## Key Features

- **Comprehensive Detection**: Finds OWASP Top 10 vulnerabilities including SQL injection, XSS, SSRF, XXE, command injection, and more
- **Intelligent Rate Limiting**: Adaptive throttling prevents overwhelming targets and triggering WAF/IDS
- **Pause & Resume**: Save progress and resume scans without losing work
- **AI-Powered Analysis**: Reduces false positives by up to 50% with intelligent verification
- **CVSS Scoring**: Automatic vulnerability scoring with CWE and OWASP Top 10 mappings
- **Deduplication**: Smart finding aggregation prevents duplicate reports
- **OAST Integration**: Detects blind vulnerabilities with out-of-band callbacks

## Quick Start

### Basic Scan

```bash
# Scan a single URL
atlas scan --url https://target.com

# Scan with default configuration
atlas scan --url https://target.com --depth 2 --intensity 3
```

### With Configuration File

```yaml
# scan.yaml
target:
  url: https://target.com
  type: single_url

config:
  # Detection modules to enable
  enabled_modules:
    - sqli
    - xss
    - ssrf
    - xxe
    - cmdi
    - path_traversal
    - auth

  # Scan parameters
  depth: 2              # Crawling depth (0-4)
  intensity: 3          # Test thoroughness (1-5)
  thoroughness: 3       # Payload coverage (1-5)

  # Performance
  max_concurrency: 10   # Parallel requests
  rate_limit: 50        # Requests per second
  timeout: 10s          # Per-request timeout

  # OAST (Out-of-band)
  enable_oast: true
  oast_timeout: 5s

  # Authentication
  auth:
    type: bearer_token
    token: "your-token-here"
```

```bash
# Run with config file
atlas scan --config scan.yaml
```

## Detection Modules

### SQL Injection (sqli)

Detects SQL injection vulnerabilities using multiple techniques:

- **Error-based**: Analyzes database error messages
- **Boolean-based**: Compares responses to true/false conditions
- **Time-based**: Detects delays from SLEEP/WAITFOR commands
- **UNION-based**: Exploits UNION SELECT queries
- **OAST-based**: Uses out-of-band callbacks for blind SQLi

**Example Finding:**
```
Type: SQL Injection
Severity: Critical
Confidence: Confirmed
Location: Query parameter 'id'
Payload: 1' AND SLEEP(5)--
Evidence: 5-second delay observed
CWE: CWE-89
OWASP: A03:2021 - Injection
CVSS: 9.8 (Critical)
```

### Cross-Site Scripting (xss)

Detects reflected, stored, and DOM-based XSS:

- **Context-aware detection**: Identifies JavaScript, HTML, and attribute contexts
- **Polyglot payloads**: Tests multiple encoding variations
- **Stored XSS**: Uses OAST to detect blind/stored XSS
- **DOM XSS**: Analyzes client-side JavaScript execution

**Contexts Detected:**
- HTML tag injection: `<script>alert(1)</script>`
- Attribute injection: `" onload="alert(1)`
- JavaScript injection: `';alert(1);//`
- URL injection: `javascript:alert(1)`

### Server-Side Request Forgery (ssrf)

Detects SSRF vulnerabilities:

- **Cloud metadata endpoints**: Tests AWS, GCP, Azure metadata services
- **Internal IP ranges**: Attempts to access internal networks
- **File protocols**: Tests file:// and other schemes
- **OAST callbacks**: Confirms blind SSRF with DNS/HTTP callbacks

### XML External Entity (xxe)

Detects XXE injection:

- **File disclosure**: Reads /etc/passwd, c:\windows\win.ini
- **Parameter entities**: Tests DTD-based attacks
- **Blind XXE**: Uses OAST for detection
- **PHP wrappers**: Tests php://filter and data:// schemes

### Command Injection (cmdi)

Detects OS command injection:

- **Command separators**: Tests |, &, ;, &&, ||
- **Time-based detection**: Uses sleep/timeout commands
- **OAST callbacks**: Confirms blind injection with curl/wget
- **Unix & Windows**: Covers both operating systems

### Path Traversal

Detects directory traversal vulnerabilities:

- **Unix paths**: ../../../etc/passwd
- **Windows paths**: ..\..\..\..\windows\win.ini
- **Encoding bypass**: URL and double encoding
- **Null byte injection**: %00 termination

### Authentication Issues (auth)

Detects authentication and access control issues:

- **Missing authentication**: Unprotected sensitive endpoints
- **Broken access control**: Horizontal/vertical privilege escalation
- **Default credentials**: Common username/password combinations
- **Session management**: Weak session tokens, fixation

## Configuration

### Intensity Levels

**1 - Passive**
- No intrusive testing
- Only observes existing behavior
- Safe for production

**2 - Low**
- Basic payloads only
- Minimal server load
- Low false positive rate

**3 - Normal (Default)**
- Standard payload sets
- Balanced speed and coverage
- Recommended for most scans

**4 - High**
- Extended payloads
- More thorough testing
- May trigger WAF/IDS

**5 - Aggressive**
- All payloads + time-based tests
- Maximum coverage
- Only for authorized testing

### Scan Depth

**0 - No Crawling**
- Test only provided URLs
- Fastest option
- Use when you have complete URL list

**1 - Links Only**
- Follow links on target pages
- Basic discovery
- Good for simple sites

**2 - Forms (Default)**
- Discover and test forms
- Moderate coverage
- Balances speed and discovery

**3 - AJAX**
- Execute JavaScript
- Find dynamic endpoints
- Slower but more thorough

**4 - Full Discovery**
- Comprehensive crawling
- Parse sitemap.xml and robots.txt
- Maximum coverage

### Authentication

Atlas supports multiple authentication methods:

**Bearer Token:**
```yaml
auth:
  type: bearer_token
  token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Basic Authentication:**
```yaml
auth:
  type: basic_auth
  username: admin
  password: secret123
```

**Session Cookie:**
```yaml
auth:
  type: session_cookie
  cookies:
    sessionid: "abc123def456"
    csrftoken: "xyz789"
```

**Custom Headers:**
```yaml
auth:
  type: custom
  headers:
    X-API-Key: "your-api-key"
    X-Auth-Token: "your-token"
```

### Rate Limiting

Atlas includes intelligent rate limiting to prevent overwhelming targets:

```yaml
config:
  rate_limit: 50        # Max 50 requests per second
  adaptive: true        # Automatically adjust based on server responses
```

**Adaptive Rate Limiting:**
- Automatically reduces rate on 429 (Too Many Requests)
- Reduces rate on 503 (Service Unavailable)
- Gradually increases rate on successful responses
- Minimum: 1 req/sec, Maximum: 200 req/sec

## Scan Management

### Starting a Scan

```bash
# Basic scan
atlas scan --url https://target.com

# With options
atlas scan \
  --url https://target.com \
  --depth 2 \
  --intensity 3 \
  --modules sqli,xss,ssrf \
  --concurrency 10 \
  --rate-limit 50

# From URL list
atlas scan --urls urls.txt

# With authentication
atlas scan \
  --url https://target.com \
  --auth-token "Bearer eyJhbGc..."
```

### Pausing and Resuming

```bash
# Pause a running scan
atlas scan pause --id scan-123

# Resume a paused scan
atlas scan resume --id scan-123

# Stop a scan (cannot be resumed)
atlas scan stop --id scan-123
```

### Monitoring Progress

```bash
# Get scan status
atlas scan status --id scan-123

# Watch progress (live updates)
atlas scan watch --id scan-123

# Output example:
# Scan ID: scan-123
# State: Running
# Progress: 45.2%
# URLs Tested: 234/518
# Findings: 12 (3 high, 5 medium, 4 low)
# Current Module: xss
# Requests/sec: 48.3
```

### Listing Scans

```bash
# List all scans
atlas scan list

# Filter by state
atlas scan list --state running
atlas scan list --state completed
atlas scan list --state paused

# Filter by workspace
atlas scan list --workspace my-workspace

# Limit results
atlas scan list --limit 10
```

## Findings

### Viewing Findings

```bash
# List all findings for a scan
atlas findings --scan-id scan-123

# Filter by severity
atlas findings --scan-id scan-123 --severity critical,high

# Filter by type
atlas findings --scan-id scan-123 --type "SQL Injection"

# Filter by confidence
atlas findings --scan-id scan-123 --confidence confirmed,firm

# Combine filters
atlas findings \
  --scan-id scan-123 \
  --severity critical,high \
  --confidence confirmed \
  --format json
```

### Finding Details

Each finding includes:

- **Type**: Vulnerability category (SQL Injection, XSS, etc.)
- **Severity**: Critical, High, Medium, Low, Info
- **Confidence**: Confirmed, Firm, Tentative
- **Location**: URL, parameter, method
- **Evidence**: Request, response, payload, proof
- **Classification**: CWE, OWASP Top 10, CVSS score
- **Remediation**: Step-by-step fix instructions
- **References**: Links to documentation

### Managing Findings

```bash
# Mark as false positive
atlas findings mark-fp --id finding-456

# Add note
atlas findings note --id finding-456 \
  --text "Verified with dev team - API only accepts whitelisted IPs"

# Mark as verified
atlas findings verify --id finding-456

# Export findings
atlas findings --scan-id scan-123 --format json > findings.json
atlas findings --scan-id scan-123 --format html > report.html
atlas findings --scan-id scan-123 --format pdf > report.pdf
```

## Performance Tuning

### Optimizing Scan Speed

**Increase Concurrency:**
```yaml
config:
  max_concurrency: 20  # More parallel requests
```

**Reduce Thoroughness:**
```yaml
config:
  intensity: 2         # Fewer payloads
  thoroughness: 2      # Less coverage
```

**Limit Depth:**
```yaml
config:
  depth: 1             # Less crawling
```

### Preventing Server Overload

**Reduce Rate Limit:**
```yaml
config:
  rate_limit: 10       # Slower requests
```

**Enable Adaptive Limiting:**
```yaml
config:
  rate_limit: 50
  adaptive: true       # Auto-adjust to server capacity
```

**Reduce Concurrency:**
```yaml
config:
  max_concurrency: 5   # Fewer parallel requests
```

## Best Practices

1. **Start Conservative**: Begin with intensity 2-3 for initial scans
2. **Use Authentication**: Authenticated scans find more vulnerabilities
3. **Enable OAST**: Detects blind vulnerabilities that other scanners miss
4. **Monitor Rate Limiting**: Watch for 429/503 errors and adjust accordingly
5. **Review False Positives**: Mark and document them for future scans
6. **Scan Regularly**: Integrate into CI/CD pipeline
7. **Respect Scope**: Only scan authorized targets
8. **Test in Staging First**: Validate scan configuration safely
9. **Document Findings**: Add notes and remediation tracking
10. **Verify Critical Findings**: Manually confirm high-severity issues

## Troubleshooting

### Scan Not Progressing

**Symptoms:** Scan stuck at 0% or low progress

**Possible Causes:**
- Target blocking requests
- WAF/IDS interference
- Rate limiting too aggressive
- Authentication issues

**Solutions:**
```bash
# Reduce rate limit
atlas scan update --id scan-123 --rate-limit 10

# Check authentication
atlas scan status --id scan-123 --verbose

# Restart with lower intensity
atlas scan stop --id scan-123
atlas scan --url https://target.com --intensity 2
```

### Too Many 429 Errors

**Symptoms:** Logs show frequent "Too Many Requests" errors

**Solutions:**
```yaml
config:
  rate_limit: 10       # Reduce rate
  adaptive: true       # Enable auto-adjustment
  max_concurrency: 5   # Reduce parallel requests
```

### No Findings Detected

**Possible Causes:**
- Application not vulnerable
- WAF blocking payloads
- Authentication required
- Insufficient scan depth

**Solutions:**
1. Verify target is accessible
2. Check authentication is working
3. Increase depth and intensity
4. Review scan logs for errors
5. Try manual testing to confirm

### OAST Not Working

**Symptoms:** No blind vulnerabilities detected

**Check:**
```bash
# Verify OAST server is running
atlas oast status

# Test OAST connectivity
curl http://your-oast-server.com/health

# Check firewall rules
# Ensure target can reach OAST server
```

**Solutions:**
- Ensure OAST server is accessible from target
- Check DNS resolution
- Verify firewall allows outbound connections
- Increase OAST timeout

### High Memory Usage

**Symptoms:** Atlas consuming excessive memory

**Solutions:**
```yaml
config:
  max_concurrency: 5   # Reduce parallelism
  rate_limit: 20       # Slower requests
```

```bash
# Monitor memory usage
atlas scan status --id scan-123 --metrics

# Restart scan if needed
atlas scan stop --id scan-123
atlas scan resume --id scan-123
```

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  atlas-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Install 0xGen
        run: |
          curl -sSL https://get.0xgen.io | bash

      - name: Start Application
        run: docker-compose up -d

      - name: Run Atlas Scan
        run: |
          SCAN_ID=$(atlas scan \
            --url http://localhost:3000 \
            --intensity 3 \
            --format json | jq -r '.scan_id')

          atlas scan wait --id $SCAN_ID --timeout 30m

          CRITICAL=$(atlas findings \
            --scan-id $SCAN_ID \
            --severity critical \
            --format json | jq '. | length')

          if [ $CRITICAL -gt 0 ]; then
            echo "Found $CRITICAL critical vulnerabilities!"
            exit 1
          fi

      - name: Upload Report
        if: always()
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: findings.json
```

### Jenkins

```groovy
// Jenkinsfile
pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }

        stage('Security Scan') {
            steps {
                script {
                    // Start application
                    sh 'docker-compose up -d'

                    // Run scan
                    def scanId = sh(
                        script: '''
                            atlas scan \
                              --url http://localhost:3000 \
                              --config scan.yaml \
                              --format json | jq -r '.scan_id'
                        ''',
                        returnStdout: true
                    ).trim()

                    // Wait for completion
                    sh "atlas scan wait --id ${scanId} --timeout 30m"

                    // Check for critical findings
                    def critical = sh(
                        script: """
                            atlas findings \
                              --scan-id ${scanId} \
                              --severity critical \
                              --format json | jq '. | length'
                        """,
                        returnStdout: true
                    ).trim().toInteger()

                    if (critical > 0) {
                        error("Found ${critical} critical vulnerabilities!")
                    }
                }
            }
        }
    }

    post {
        always {
            // Export report
            sh 'atlas findings --scan-id $SCAN_ID --format html > report.html'
            publishHTML(target: [
                reportDir: '.',
                reportFiles: 'report.html',
                reportName: 'Security Scan Report'
            ])
        }
    }
}
```

## FAQ

**Q: How long does a scan take?**
A: Depends on target size and configuration. Typical scans: 5-30 minutes. Large applications may take hours.

**Q: Can I scan multiple targets simultaneously?**
A: Yes, each scan runs independently. You can start multiple scans in parallel.

**Q: Does Atlas replace manual testing?**
A: No, Atlas automates common tests but manual testing remains essential for complex vulnerabilities and business logic flaws.

**Q: What's the difference from Burp Scanner?**
A: Atlas is open source, free, and includes AI-powered analysis. It's designed for CI/CD integration and automation.

**Q: Can I create custom detection modules?**
A: Yes, see the [Module Development Guide](../plugins/modules.md) for details.

**Q: How accurate is Atlas?**
A: Atlas has a low false positive rate (~10% with AI enabled) and matches or exceeds commercial scanners for standard vulnerabilities.

**Q: Is Atlas safe to use in production?**
A: Use intensity levels 1-2 for production. Higher intensity levels should only be used in staging/testing environments.

**Q: Does Atlas support GraphQL/REST APIs?**
A: Yes, Atlas can scan both traditional web applications and modern APIs.

**Q: How does OAST integration work?**
A: Atlas uses out-of-band callbacks to detect blind vulnerabilities. It requires an OAST server (included with 0xGen).

**Q: Can Atlas detect zero-days?**
A: Atlas focuses on known vulnerability patterns. While it may occasionally find novel issues, it's not designed for zero-day discovery.

## Support

For issues, questions, or feature requests:

- **GitHub Issues**: https://github.com/0xGen/0xgen/issues
- **Documentation**: https://docs.0xgen.io
- **Discord**: https://discord.gg/0xgen
- **Email**: security@0xgen.io

## License

Atlas is part of 0xGen and released under the Apache 2.0 License.
