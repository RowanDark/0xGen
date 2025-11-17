# Delta: Semantic Diff Tool

## Overview

Delta is an advanced semantic diffing tool designed for security researchers and penetration testers. Unlike traditional diff tools that perform line-by-line text comparisons, Delta understands the structure and semantics of HTTP responses, JSON, and XML documents, intelligently identifying meaningful changes while filtering out noise.

**Key Features:**
- 🔍 **Semantic Diffing**: Understands JSON, XML, and text structure
- 🤖 **AI-Powered Noise Filtering**: Automatically identifies and filters timestamps, UUIDs, session tokens, and other noise
- 📊 **Batch Comparison**: Compare multiple responses simultaneously to detect outliers and patterns
- 🎯 **Security-Focused**: Designed for finding authentication bypasses, privilege escalation, and session handling issues
- 📈 **Statistical Analysis**: Similarity matrices, clustering, and anomaly detection
- 💾 **Export Options**: JSON, CSV, HTML reports

## Quick Start

### Simple Comparison

1. **Navigate to Delta** in the 0xGen GUI
2. **Select comparison mode**: Simple or Batch
3. **Paste content** in left and right editors
4. **Click "Compare"** or press `Ctrl+D`
5. **Review differences** with color-coded highlighting

### Batch Comparison

1. **Switch to Batch mode** in the header
2. **Load responses** (from Flows, saved artifacts, or manual entry)
3. **Select baseline strategy** (first, median, all-pairs)
4. **Adjust outlier threshold** (default: 80%)
5. **Click "Batch Compare"**
6. **Analyze results**: similarity matrix, outliers, AI insights

## Features

### 1. Text Diff

Delta supports three granularity levels for text comparison:

- **Line-level**: Compare responses line by line (default)
- **Word-level**: Detect changes within lines
- **Character-level**: Precise character-by-character diff

**Example Use Case:**
```
Original Response:
  HTTP/1.1 200 OK
  Set-Cookie: sessionid=abc123; Path=/
  {"user": "admin", "role": "user"}

Modified Response:
  HTTP/1.1 200 OK
  Set-Cookie: sessionid=xyz789; Path=/
  {"user": "admin", "role": "admin"}
```

Delta will highlight:
- 🟢 **Green**: Role changed from "user" to "admin" (critical!)
- 🟡 **Filtered**: Session ID change (noise, expected to change)

### 2. JSON Semantic Diff

Delta parses JSON structure and compares semantically, not textually. This means:

- **Order-insensitive**: `{"a":1,"b":2}` equals `{"b":2,"a":1}`
- **Type-aware**: Detects when `"5"` becomes `5` (string to number)
- **Path tracking**: Shows exact JSON path to changed value
- **Nested objects**: Handles deeply nested structures

**Example:**
```json
// Before
{
  "user": {
    "id": 123,
    "permissions": ["read", "write"],
    "metadata": {
      "created": "2024-01-15T10:00:00Z"
    }
  }
}

// After
{
  "user": {
    "id": 123,
    "permissions": ["read", "write", "admin"],
    "metadata": {
      "created": "2024-01-15T11:30:00Z"
    }
  }
}
```

**Delta Output:**
- ✅ **Signal**: `user.permissions[2]` added "admin" (CRITICAL!)
- 🔇 **Noise**: `user.metadata.created` timestamp changed (filtered)

### 3. XML Semantic Diff

Similar to JSON, Delta understands XML structure:

- **Element comparison**: Detects added/removed/modified elements
- **Attribute tracking**: Highlights attribute changes
- **XPath notation**: Shows exact location of changes
- **Namespace-aware**: Handles XML namespaces correctly

**Example:**
```xml
<!-- Before -->
<user id="123" role="user">
  <name>Alice</name>
  <session token="abc123"/>
</user>

<!-- After -->
<user id="123" role="admin">
  <name>Alice</name>
  <session token="xyz789"/>
</user>
```

**Delta Output:**
- ✅ **Signal**: Attribute `role` changed from "user" to "admin"
- 🔇 **Noise**: Session token change (filtered)

### 4. AI Noise Filtering

Delta's AI-powered noise classifier automatically identifies and filters common noise patterns:

**Filtered Patterns:**
- ⏱️ **Timestamps**: ISO8601, Unix timestamps, RFC2822 dates
- 🔑 **Session IDs & Tokens**: CSRF tokens, API keys, nonces
- 🆔 **UUIDs**: v4, v5, and generic UUID formats
- 📝 **Request IDs**: X-Request-Id, trace IDs
- 🏷️ **ETags & Cache Headers**: If-None-Match, ETag
- 🔢 **Build IDs & Versions**: Semantic version strings
- 🎲 **Random Values**: Base64 encoded random data

**Classification Confidence:**
Each change includes a confidence score (0-100%) indicating the classifier's certainty that it's noise or signal.

**User Override:**
You can manually mark changes as signal or noise to improve the classifier over time.

### 5. Batch Comparison

Compare multiple responses simultaneously to detect patterns and outliers.

**Baseline Strategies:**

1. **First Response**: Compare all others to the first
   - ✅ Fast, simple
   - ❌ Sensitive to first response choice

2. **Median Similarity**: Use response with median avg similarity
   - ✅ Robust to outliers
   - ❌ Requires all-pairs comparison first

3. **User Selected**: Manually pick baseline
   - ✅ Full control
   - ❌ Requires manual selection

4. **All Pairs (N×N)**: Compare every pair
   - ✅ Most comprehensive
   - ❌ Slower for large batches (50 responses max)

**Similarity Matrix:**

Interactive heatmap showing similarity between all response pairs:

```
         Resp1  Resp2  Resp3  Resp4
Resp1    100%   95%    92%    45%  ← Outlier!
Resp2    95%    100%   93%    48%
Resp3    92%    93%    100%   47%
Resp4    45%    48%    47%    100%
```

**Outlier Detection:**

Responses with average similarity below threshold are automatically flagged:
- Default threshold: 80%
- Adjustable via slider
- Highlighted in red in matrix

**Response Clustering:**

Similar responses are automatically grouped:
- Uses 90% similarity threshold
- Shows cluster size and avg similarity
- Identifies representative response per cluster

**AI Insights:**

Automated analysis generates actionable insights:
- "3 responses suggest rate limiting (status 429)"
- "Outlier response has unusual error message"
- "All responses share common structure with varying session tokens"

### 6. Export Options

**JSON Export:**
```json
{
  "type": "json",
  "similarity_score": 85.5,
  "changes": [
    {
      "type": "modified",
      "path": "user.role",
      "old_value": "user",
      "new_value": "admin"
    }
  ],
  "compute_time_ms": 23.5
}
```

**CSV Export:**
```csv
Response,Response 1,Response 2,Response 3
Response 1,100.00,95.20,45.30
Response 2,95.20,100.00,46.80
Response 3,45.30,46.80,100.00
```

**HTML Export:**
Visual report with color-coded similarity matrix, statistics, and insights (standalone HTML file).

## Use Cases

### Finding Authentication Bypass Vulnerabilities

**Scenario**: Testing if privilege escalation is possible by modifying JWT claims.

**Steps:**
1. Capture two responses: one as regular user, one after modifying JWT
2. Use Delta to compare responses
3. Look for differences in role/permissions fields
4. Filter out session tokens, timestamps (noise)
5. Identify critical changes in authorization data

**Example Finding:**
```
Change: user.permissions
Old: ["read"]
New: ["read", "admin"]
→ Privilege escalation successful!
```

### Detecting Session Handling Issues

**Scenario**: Testing if session tokens are properly validated.

**Steps:**
1. Capture response with valid session
2. Capture response with modified/invalid session
3. Compare with Delta
4. Check if server behavior differs
5. Look for subtle differences indicating partial validation

**Red Flags:**
- Different error messages (leaks session structure)
- Different response times (timing attack potential)
- Partial data returned (incomplete validation)

### Analyzing Error Messages

**Scenario**: Fuzzing endpoints to find verbose error messages.

**Steps:**
1. Send 20-50 requests with various invalid inputs
2. Use Batch Comparison with all-pairs strategy
3. Review outliers (responses that differ significantly)
4. Check AI insights for common error patterns
5. Identify verbose error messages that leak internal details

**Example:**
```
Outlier Response #7:
  Status: 500
  Error: "Database query failed: SELECT * FROM users WHERE id='"
  → SQL injection vulnerability!
```

### Batch Comparison for Fuzzing Analysis

**Scenario**: Analyzing results from parameter fuzzing campaign.

**Steps:**
1. Fuzz a parameter with 50 different payloads
2. Load all 50 responses into Delta
3. Use "All Pairs" strategy to compare
4. Check similarity matrix for clusters
5. Investigate outliers (unusual responses)

**What to Look For:**
- **Cluster 1 (95%+ similar)**: Normal responses (no vulnerability)
- **Cluster 2 (different errors)**: Input validation responses
- **Outliers (<80%)**: Potential vulnerabilities!
  - Different status codes
  - Longer/shorter responses
  - Unusual error messages

### Comparing API Versions

**Scenario**: Testing backward compatibility or finding undocumented changes.

**Steps:**
1. Call same endpoint on v1 and v2 API
2. Compare responses with JSON semantic diff
3. Identify added/removed/modified fields
4. Filter timestamps and version numbers
5. Generate report of API changes

**Benefits:**
- Detect breaking changes
- Find undocumented features
- Verify migration path

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+D` / `Cmd+D` | Perform comparison |
| `N` | Next change |
| `P` | Previous change |
| `F` | Toggle noise filter |
| `Ctrl+C` / `Cmd+C` | Copy current change |
| `Ctrl+1` | Switch to Simple mode |
| `Ctrl+2` | Switch to Batch mode |
| `Ctrl+E` | Export as JSON |

## Configuration

### Outlier Threshold

Adjust sensitivity for outlier detection:
- **50-70%**: Very sensitive (more outliers detected)
- **70-85%**: Balanced (default: 80%)
- **85-95%**: Conservative (only major outliers)

### Diff Granularity

Choose comparison level for text:
- **Line**: Fast, suitable for most cases
- **Word**: More detailed, slower
- **Character**: Most precise, slowest

### Noise Filtering

**Auto Mode** (Default): AI classifier automatically filters noise
**Manual Mode**: Review each change and mark as signal/noise
**Disabled**: Show all changes without filtering

## Performance

### Benchmark Results

| Operation | Input Size | Time | Throughput |
|-----------|------------|------|------------|
| Text Diff | 1 KB | 2 ms | 500 KB/s |
| Text Diff | 100 KB | 50 ms | 2 MB/s |
| Text Diff | 1 MB | 450 ms | 2.2 MB/s |
| JSON Diff | 10 KB | 5 ms | 2 MB/s |
| Batch (10) | 10 KB each | 120 ms | 45 comps/s |
| Batch (50) | 10 KB each | 2.8 s | 1225 comps (all-pairs) |

### Memory Usage

- Small diffs (<100KB): ~5 MB RAM
- Large diffs (1MB): ~50 MB RAM
- Batch comparison (20 responses): ~30 MB RAM
- Noise classifier: ~10 MB RAM (loaded once)

### Optimization Tips

1. **Use baseline strategy** instead of all-pairs for large batches
2. **Enable noise filtering** to reduce change count
3. **Choose line granularity** for faster text diffs
4. **Limit batch size** to 20-30 responses for best performance

## Troubleshooting

### "Similarity score is 0% but responses look identical"

**Cause**: Content encoding differences (Base64, URL encoding, etc.)

**Solution**: Decode both responses before comparison

### "Too many changes detected"

**Cause**: Responses differ significantly or noise filtering is off

**Solutions:**
- Enable noise filtering (press `F`)
- Check if responses are from same endpoint
- Verify content types match

### "Outliers not detected in batch comparison"

**Cause**: Outlier threshold too low

**Solution**: Increase threshold slider (try 85-90%)

### "Export fails with large responses"

**Cause**: Memory limit or browser restriction

**Solution:**
- Export to JSON (most efficient)
- Split batch into smaller groups
- Use CSV for matrix only

### "Slow performance with large responses"

**Cause**: High diff complexity or large input size

**Solutions:**
- Use line granularity instead of character
- Filter responses before comparison
- Upgrade to faster hardware 😊

## Integration with 0xGen Workflows

### From Flows Panel

1. Select two flows in Flows panel
2. Right-click → "Compare Selected"
3. Delta opens with flows pre-loaded
4. Review differences
5. Add findings to case report

### From Cases Panel

1. Select case with multiple evidence items
2. Click "Compare Evidence"
3. Delta compares all evidence in case
4. Generates comparative analysis
5. Exports as case report supplement

### Programmatic Access (Plugin API)

```go
import "github.com/RowanDark/0xgen/internal/delta"

engine := delta.NewEngine()

// Simple diff
result, err := engine.Diff(delta.DiffRequest{
    Left:  []byte(response1),
    Right: []byte(response2),
    Type:  delta.DiffTypeJSON,
})

// Batch comparison
batchEngine := delta.NewBatchComparisonEngine()
batchResult, err := batchEngine.CompareBatch(delta.BatchComparisonRequest{
    Responses: responses,
    DiffType: delta.DiffTypeJSON,
    BaselineStrategy: delta.BaselineAllPairs,
    OutlierThreshold: 80.0,
    EnableClustering: true,
    EnablePatterns: true,
    EnableAnomalies: true,
})

// Export
exporter := delta.NewBatchExporter()
csvData, err := exporter.ExportCSV(batchResult)
htmlReport, err := exporter.ExportHTML(batchResult)
```

## Best Practices

### 1. Always Enable Noise Filtering

Default settings filter 60-80% of changes, leaving only meaningful differences.

### 2. Use Batch Comparison for Fuzzing

Instead of manually reviewing 50 responses, let Delta identify the outliers automatically.

### 3. Export Results to Case Report

Preserve comparison results as evidence:
- JSON for detailed analysis
- HTML for reports to clients
- CSV for further processing in Excel

### 4. Combine with Other Tools

- **Use Proxy** to capture requests
- **Use Flows** to filter relevant responses
- **Use Delta** to find differences
- **Use Cases** to document findings

### 5. Learn the Keyboard Shortcuts

Keyboard navigation is 10x faster than mouse clicking.

### 6. Adjust Outlier Threshold Based on Context

- **Tight endpoint (same logic)**: 85-90% threshold
- **Varied endpoints**: 70-80% threshold
- **Fuzzing results**: 80% (default)

## Comparison with Other Tools

### Delta vs Burp Comparer

| Feature | Delta | Burp Comparer |
|---------|-------|---------------|
| Semantic JSON diff | ✅ Yes | ❌ No |
| Semantic XML diff | ✅ Yes | ❌ No |
| AI noise filtering | ✅ Yes | ❌ No |
| Batch comparison | ✅ Yes | ❌ No |
| Outlier detection | ✅ Yes | ❌ No |
| Similarity matrix | ✅ Yes | ❌ No |
| Export options | ✅ 3 formats | ✅ Text only |
| Free/Open Source | ✅ Yes | ❌ No |

### Delta vs `diff` Command

| Feature | Delta | diff |
|---------|-------|------|
| JSON semantic | ✅ Yes | ❌ No |
| Noise filtering | ✅ Yes | ❌ No |
| GUI | ✅ Yes | ❌ No |
| Color coding | ✅ Yes | ⚠️ Limited |
| Batch mode | ✅ Yes | ❌ No |
| Speed | ⚠️ Fast | ✅ Very fast |

## FAQs

**Q: Can Delta compare binary responses?**
A: Currently, Delta supports text, JSON, and XML. Binary diff support is planned for a future release.

**Q: How many responses can I compare in batch mode?**
A: Maximum 50 responses. For best performance, 10-20 is recommended.

**Q: Can I save comparison results?**
A: Yes! Export to JSON, CSV, or HTML. JSON export includes full results for re-importing.

**Q: Does Delta work offline?**
A: Yes, all diff computation is local. AI filtering uses rule-based patterns, not cloud APIs.

**Q: Can I customize noise patterns?**
A: Yes, via plugin API you can add custom noise pattern definitions.

**Q: What's the maximum response size?**
A: Tested up to 10 MB. Larger responses may be slow depending on hardware.

## Future Features

- Binary diff support (images, PDFs, protobuf)
- Custom noise pattern editor in GUI
- Diff history and comparison chains
- Real-time diff streaming for large responses
- Integration with AI models for security insights
- Collaborative sharing of comparison results

## Support

- **Documentation**: `/docs/tools/delta.md` (this file)
- **API Docs**: `/docs/api/delta-api.md`
- **Tutorials**: `/docs/tutorials/delta-*.md`
- **Issues**: https://github.com/RowanDark/0xGen/issues
- **Community**: 0xGen Discord server

## License

Delta is part of the 0xGen project, licensed under [LICENSE].

---

**Version**: 1.0.0
**Last Updated**: January 2025
**Contributors**: 0xGen Team
