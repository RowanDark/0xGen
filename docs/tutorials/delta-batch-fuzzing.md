# Tutorial: Batch Comparison for Fuzzing Analysis

## Overview

This tutorial shows how to use Delta's batch comparison feature to efficiently analyze fuzzing results and identify vulnerabilities. Instead of manually reviewing hundreds of responses, Delta automatically detects outliers and patterns.

**Time Required**: 20 minutes

**Difficulty**: Intermediate

**Prerequisites**:
- 0xGen installed
- Basic fuzzing knowledge
- 20+ captured responses from fuzzing

## Scenario

You're fuzzing a REST API endpoint `/api/user/{id}` to find potential vulnerabilities like SQL injection, IDOR, or error message leakage. You've sent 50 requests with different user IDs and captured all responses. Now you need to analyze them efficiently.

## Step-by-Step Guide

### Step 1: Prepare Fuzzing Dataset

1. **Select your fuzzing target**: `/api/user/{id}`

2. **Create fuzzing payloads** (50 examples):
   ```
   1, 2, 3, ..., 20            # Normal user IDs
   -1, 0, 999999               # Boundary values
   1'; DROP TABLE users--      # SQL injection
   1 OR 1=1                    # SQL injection
   ../../../etc/passwd         # Path traversal
   <script>alert(1)</script>   # XSS
   ${7*7}                      # SSTI
   admin, root, test           # Common usernames
   ```

3. **Send all 50 requests** through 0xGen Proxy or Intruder

4. **Capture all responses** in Flows panel

### Step 2: Export Responses

1. **In Flows panel**, select all 50 requests
2. **Right-click** → "Export Selected"
3. **Choose format**: JSON (for Delta import)
4. **Save as** `fuzzing-results.json`

**Alternative**: Use Delta GUI to load from Flows directly (future feature)

### Step 3: Load into Delta Batch Mode

1. **Navigate to Delta** (/delta in GUI)
2. **Switch to "Batch" mode** (top-right toggle)
3. **Load responses**:
   - For now, copy/paste manually (5 at a time for demo)
   - Production: Import JSON file

**Example Manual Entry:**

Response 1:
```json
{"id": 1, "name": "Alice", "email": "alice@example.com", "status": "active"}
```

Response 2:
```json
{"id": 2, "name": "Bob", "email": "bob@example.com", "status": "active"}
```

Response 3:
```json
{"id": 3, "name": "Charlie", "email": "charlie@example.com", "status": "active"}
```

Response 4 (Outlier - IDOR):
```json
{"id": 5, "name": "Admin", "email": "admin@internal.corp", "status": "active", "role": "admin", "api_key": "sk_live_abc123"}
```

Response 5 (Outlier - SQL Error):
```json
{"error": "SQL syntax error near '1'; DROP TABLE users--'", "trace": "/var/www/api/user.php:142"}
```

### Step 4: Configure Batch Comparison

1. **Baseline Strategy**: Select "All Pairs (N×N)"
   - Most comprehensive for fuzzing analysis
   - Compares every response with every other

2. **Outlier Threshold**: Set to 80%
   - Responses <80% similar to others flagged as outliers
   - Adjust based on expected variance

3. **Enable Options**:
   - ✅ Clustering (group similar responses)
   - ✅ Patterns (detect common fields)
   - ✅ Anomalies (detect unusual status codes, lengths)

4. **Click "Batch Compare"**

### Step 5: Analyze Similarity Matrix

Delta generates an N×N heatmap showing similarity between all pairs:

**Example Matrix (5 responses):**

```
           R1     R2     R3     R4     R5
R1 (normal) 100%   98%    97%    45%    12%
R2 (normal) 98%    100%   96%    46%    10%
R3 (normal) 97%    96%    100%   47%    11%
R4 (IDOR)   45%    46%    47%    100%   15%  ← OUTLIER!
R5 (SQL)    12%    10%    11%    15%    100% ← OUTLIER!
```

**Interpretation:**

- **Cluster 1 (R1-R3)**: 96-98% similar
  - Normal responses
  - Expected behavior
  - Safe to ignore

- **Outlier R4**: 45-47% similarity to cluster
  - Significantly different structure
  - New fields: `role`, `api_key`
  - **Potential IDOR vulnerability!**

- **Outlier R5**: 10-15% similarity to all
  - Completely different response (error)
  - Contains stack trace
  - **Potential SQL injection!**

### Step 6: Review Outliers

Delta automatically highlights outliers in red:

**Outlier #1: Response 4 (User ID 5)**

**Similarity**: 46% (average to others)

**Unique Fields:**
- `role: "admin"`
- `api_key: "sk_live_abc123"`

**Vulnerability**: Insecure Direct Object Reference (IDOR)
- Regular users (IDs 1-3) don't expose admin fields
- User ID 5 returns admin data
- Horizontal privilege escalation possible

**PoC**:
```bash
curl -X GET /api/user/5 -H "Cookie: session=user-token"
→ Returns admin API key! Should return 403 Forbidden.
```

**Outlier #2: Response 5 (SQL Injection Payload)**

**Similarity**: 11% (average to others)

**Content:**
```json
{
  "error": "SQL syntax error near '1'; DROP TABLE users--'",
  "trace": "/var/www/api/user.php:142",
  "timestamp": "2024-01-15T10:30:45Z"
}
```

**Vulnerability**: SQL Injection + Information Disclosure
- Server returns raw SQL error
- Stack trace reveals file path
- Confirms SQL injection vulnerability

**Severity**: Critical

### Step 7: Analyze Clusters

Delta groups similar responses:

**Cluster 1: Normal User Responses**
- **Size**: 45 responses (IDs 1-20, and boundary values with 404)
- **Avg Similarity**: 97.5%
- **Representative**: Response 1

**Cluster 2: 404 Not Found**
- **Size**: 3 responses (IDs 0, -1, 999999)
- **Avg Similarity**: 99.8%
- **Representative**: Response 21

**Singletons (Outliers)**:
- Response 4 (IDOR)
- Response 5 (SQL Injection)

**Insight**: Most responses are normal (cluster 1) or expected errors (cluster 2). Focus on singletons!

### Step 8: Review AI Insights

Delta generates automated insights:

**AI Insights:**
1. "2 responses differ significantly from baseline (< 50% similarity)"
2. "Response 4 contains unique fields: 'role', 'api_key' - potential privilege escalation"
3. "Response 5 has unusual status code: 500 (others are 200 or 404)"
4. "Response 5 contains error messages with SQL keywords - potential SQL injection"
5. "45 responses cluster together (97.5% similarity) - normal behavior"

### Step 9: Check Anomaly Detection

Delta's anomaly detection identifies:

**Unusual Status Codes:**
- Response 5: 500 Internal Server Error (all others: 200 or 404)

**Unusual Content Lengths:**
- Response 4: 487 bytes (others: 120-150 bytes)
- Response 5: 892 bytes (contains stack trace)

**Unique Error Messages:**
- Response 5: SQL syntax error (unique among all 50 responses)

**Anomaly Summary:**
"Found 2 responses with unusual characteristics: 1 with unusual status codes, 2 with unusual content lengths, 1 with unique errors"

### Step 10: Export Results

1. **Click "Export"** → "HTML Report"

2. **Save as** `fuzzing-analysis.html`

**Report Contents:**
- ✅ Similarity matrix (color-coded heatmap)
- ✅ Statistics (mean, median, std dev)
- ✅ Outlier list with details
- ✅ Cluster visualization
- ✅ AI insights
- ✅ Anomaly summary

3. **Attach to case report**:
   - Create case: "API Fuzzing Results - Critical Vulnerabilities"
   - Attach Delta HTML report
   - Add PoC requests for each vulnerability

### Step 11: Create Case for Each Vulnerability

**Case 1: IDOR in /api/user/{id}**

```markdown
# Insecure Direct Object Reference

## Summary
Endpoint /api/user/{id} exposes admin user data including API keys
when accessed with regular user privileges.

## Evidence
- Delta Batch Analysis: Response 4 outlier (46% similarity)
- Unique fields exposed: role, api_key
- PoC: curl -X GET /api/user/5

## Impact
- High: Exposure of admin API keys
- Horizontal privilege escalation
- Potential account takeover

## Remediation
- Implement authorization check (verify user can access requested ID)
- Remove sensitive fields from API response
- Use UUID instead of incremental IDs
```

**Case 2: SQL Injection**

```markdown
# SQL Injection Vulnerability

## Summary
SQL injection in /api/user/{id} endpoint allows database query
manipulation and information disclosure.

## Evidence
- Delta Batch Analysis: Response 5 outlier (11% similarity)
- SQL error message: "SQL syntax error near..."
- Stack trace reveals file path
- Payload: 1'; DROP TABLE users--

## Impact
- Critical: Full database access
- Data exfiltration possible
- Database destruction possible

## Remediation
- Use parameterized queries (prepared statements)
- Sanitize user input
- Disable error message disclosure in production
- Remove stack traces from responses
```

## Advanced Techniques

### Technique 1: Multi-Parameter Fuzzing

Fuzz multiple parameters simultaneously:

**Endpoint**: `/api/search?query={q}&filter={f}&page={p}`

**Payloads**: 200 combinations (10 query × 10 filter × 2 page values)

**Delta Analysis**:
1. Batch compare all 200 responses
2. Use "Median Baseline" strategy (robust to outliers)
3. Outlier threshold: 75% (expect more variance)
4. **Result**: Identifies 3 outliers where `filter` parameter causes errors

### Technique 2: Time-Based Detection

Include response times in batch analysis:

**Configuration**:
- Enable "Response Time Stats" in batch comparison
- Check "Slow Responses" in anomaly detection

**Findings**:
```
Normal responses:     100-150ms
Response 23 (SQLI):   8,500ms ← SQL sleep(5) worked!
```

**Conclusion**: Blind SQL injection confirmed via timing side-channel.

### Technique 3: Pattern Evolution

Track how responses change across fuzzing rounds:

**Round 1**: Initial fuzzing (50 requests)
**Round 2**: Refined payloads based on outliers (30 requests)
**Round 3**: Exploitation attempts (10 requests)

**Delta Process**:
1. Compare Round 1 results → identify outliers
2. Create refined payloads targeting outliers
3. Compare Round 2 results → confirm vulnerabilities
4. Create exploitation payloads
5. Compare Round 3 results → verify exploit success

## Real-World Case Study

### Case: API Gateway Fuzzing

**Target**: E-commerce API
**Endpoint**: `/api/products/{id}`
**Payloads**: 100 product IDs (1-100)
**Time**: 30 seconds to send, 2 minutes to analyze

**Findings**:

**Cluster 1 (90 responses)**: Normal products
- 200 OK
- Product details returned
- 98% similar

**Cluster 2 (8 responses)**: Out of stock
- 200 OK
- `available: false`
- 95% similar to each other, 85% similar to Cluster 1

**Outlier 1 (Product ID 42)**: Admin product
- 200 OK
- Extra fields: `cost_price`, `supplier_id`, `profit_margin`
- **IDOR vulnerability!**

**Outlier 2 (Product ID 77)**: Deleted product
- 500 Internal Server Error
- Stack trace revealed database schema
- **Information disclosure!**

**Impact**:
- Discovered IDOR exposing business data (profit margins)
- Found error handling bug revealing database structure
- Reported to vendor, received $5,000 bounty

**Time Saved**:
- Manual review: ~2 hours
- Delta analysis: ~5 minutes
- **Efficiency gain: 24x faster!**

## Tips & Tricks

### Tip 1: Start Small

Don't batch compare 200 responses immediately:
1. Test with 5-10 responses first
2. Verify outlier detection works
3. Adjust threshold if needed
4. Scale up to full dataset

### Tip 2: Use Meaningful Names

Label responses clearly:
- ❌ "Response 1", "Response 2"
- ✅ "ID=1 Normal", "ID=5 Admin", "SQLi Payload"

Makes it easier to understand outliers!

### Tip 3: Combine with Other Tools

1. **0xGen Flows** → filter interesting requests
2. **Delta Batch** → identify outliers
3. **0xGen Repeater** → exploit vulnerabilities
4. **Delta Simple** → compare exploit attempts
5. **0xGen Cases** → document findings

### Tip 4: Save Intermediate Results

Export Delta results after each fuzzing round:
- Round 1: `fuzzing-round-1.json`
- Round 2: `fuzzing-round-2.json`
- Final: `fuzzing-final-report.html`

### Tip 5: Automate with API

For large-scale fuzzing:

```go
// Pseudocode
responses := runFuzzingCampaign(endpoint, payloads)
batchResult := delta.CompareBatch(responses)

for outlier := range batchResult.Outliers {
    vulnerability := analyzeOutlier(outlier)
    if vulnerability.Severity == "Critical" {
        createCase(vulnerability)
        alert(securityTeam)
    }
}
```

## Common Patterns

### Pattern 1: Error Message Variations

**Cluster 1**: "Invalid user ID"
**Cluster 2**: "User not found"
**Outlier**: "Database connection failed"

**Finding**: Outlier reveals infrastructure details.

### Pattern 2: Privilege Escalation

**Cluster 1**: Regular user data
**Outlier**: Admin data with extra fields

**Finding**: IDOR allowing privilege escalation.

### Pattern 3: Injection Success

**Cluster 1**: Normal responses (200 OK)
**Outlier**: Error response (500) with injection payload echoed

**Finding**: Successful injection, server processed payload.

## Checklist

- [ ] Prepared fuzzing payloads (20-50 variations)
- [ ] Captured all responses from fuzzing campaign
- [ ] Loaded responses into Delta batch mode
- [ ] Configured baseline strategy (all-pairs recommended)
- [ ] Set outlier threshold (80% default)
- [ ] Enabled clustering, patterns, and anomalies
- [ ] Ran batch comparison
- [ ] Reviewed similarity matrix
- [ ] Investigated all outliers
- [ ] Checked AI insights
- [ ] Reviewed anomaly detection results
- [ ] Exported HTML report
- [ ] Created cases for each vulnerability
- [ ] Tested exploitation of findings

## Next Steps

1. **Read**: [Finding Auth Bypass with Delta](./delta-auth-bypass.md)
2. **Learn**: [Delta User Guide](../tools/delta.md)
3. **Explore**: [Delta API Documentation](../api/delta-api.md)

## Questions?

- **GitHub Issues**: https://github.com/RowanDark/0xGen/issues
- **Community**: 0xGen Discord server

---

**Tutorial Version**: 1.0
**Last Updated**: January 2025
**Difficulty**: Intermediate
**Estimated Time**: 20 minutes
