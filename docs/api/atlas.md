# Atlas API Reference

## Overview

This document describes the programmatic API for interacting with the Atlas active scanner. All examples use Go, but the concepts apply to REST API integrations as well.

## Core Types

### Scan

```go
type Scan struct {
    ID          string        // Unique scan identifier
    Name        string        // Human-readable scan name
    Target      Target        // Scan target configuration
    Config      ScanConfig    // Scan configuration
    State       ScanState     // Current state
    Progress    Progress      // Execution progress
    Findings    []*Finding    // Detected vulnerabilities
    StartTime   time.Time     // Scan start time
    EndTime     *time.Time    // Scan completion time (if finished)
    Duration    time.Duration // Total execution time
    CreatedBy   string        // User who created the scan
    WorkspaceID string        // Workspace association
    Tags        []string      // Custom tags
}
```

### Target

```go
type Target struct {
    Type    TargetType // single_url, url_list, domain, cidr
    URLs    []string   // Target URLs
    BaseURL string     // Base URL for single_url type
    Scope   *Scope     // Scope constraints
}

type Scope struct {
    IncludePatterns []string // Regex patterns to include
    ExcludePatterns []string // Regex patterns to exclude
    MaxDepth        int      // Maximum crawl depth
}
```

### ScanConfig

```go
type ScanConfig struct {
    // Modules
    EnabledModules  []string      // Modules to run (sqli, xss, ssrf, etc.)

    // Intensity
    Depth           int           // Crawling depth (0-4)
    Intensity       int           // Test thoroughness (1-5)
    Thoroughness    int           // Payload coverage (1-5)

    // Performance
    MaxConcurrency  int           // Max parallel requests
    RateLimit       int           // Requests per second
    Timeout         time.Duration // Per-request timeout

    // OAST
    EnableOAST      bool          // Enable out-of-band testing
    OASTTimeout     time.Duration // Wait time for callbacks

    // Authentication
    Auth            *AuthConfig   // Authentication configuration

    // HTTP Options
    FollowRedirects bool                 // Follow HTTP redirects
    VerifySSL       bool                 // Verify SSL certificates
    CustomHeaders   map[string]string    // Custom HTTP headers
    CustomCookies   map[string]string    // Custom cookies
    UserAgent       string               // User-Agent header
}
```

### Finding

```go
type Finding struct {
    ID          string        // Unique finding identifier
    ScanID      string        // Associated scan ID
    Type        string        // Vulnerability type
    Severity    Severity      // critical, high, medium, low, info
    Confidence  Confidence    // confirmed, firm, tentative
    Title       string        // Finding title
    Description string        // Detailed description

    // Location
    URL         string        // Vulnerable URL
    Method      string        // HTTP method
    Parameter   string        // Vulnerable parameter
    Location    ParamLocation // query, body, header, cookie, path

    // Evidence
    Request     string        // Full HTTP request
    Response    string        // Full HTTP response
    Payload     string        // Attack payload used
    Proof       string        // Evidence of vulnerability

    // Classification
    CWE         string        // CWE identifier
    OWASP       string        // OWASP Top 10 category
    CVSS        float64       // CVSS base score

    // Remediation
    Remediation string        // Fix instructions
    References  []string      // Reference links

    // Metadata
    DetectedBy    string      // Module that found it
    DetectedAt    time.Time   // Detection timestamp
    Verified      bool        // Manually verified
    FalsePositive bool        // Marked as false positive
}
```

## Orchestrator API

### Creating an Orchestrator

```go
import (
    "github.com/RowanDark/0xgen/internal/atlas"
    "github.com/RowanDark/0xgen/internal/atlas/modules"
    "github.com/RowanDark/0xgen/internal/atlas/storage"
)

// Create storage backend
db, err := storage.New("atlas.db", logger)
if err != nil {
    log.Fatal(err)
}

// Create event bus
eventBus := atlas.NewBus()

// Create modules
detectionModules := []atlas.Module{
    modules.NewSQLiModule(logger, oastClient),
    modules.NewXSSModule(logger, oastClient),
    modules.NewSSRFModule(logger, oastClient),
    // ... add more modules
}

// Create orchestrator
orchestrator := atlas.NewOrchestrator(
    detectionModules,
    db,
    oastClient,
    eventBus,
    logger,
)
```

### Starting a Scan

```go
// Create scan configuration
scan := &atlas.Scan{
    ID:   uuid.New().String(),
    Name: "Production API Scan",
    Target: atlas.Target{
        Type: atlas.TargetTypeSingleURL,
        URLs: []string{"https://api.example.com"},
        Scope: &atlas.Scope{
            IncludePatterns: []string{"^https://api\\.example\\.com/.*"},
            MaxDepth:        2,
        },
    },
    Config: atlas.ScanConfig{
        EnabledModules: []string{"sqli", "xss", "ssrf"},
        Depth:          2,
        Intensity:      3,
        MaxConcurrency: 10,
        RateLimit:      50,
        Timeout:        10 * time.Second,
        EnableOAST:     true,
        Auth: &atlas.AuthConfig{
            Type:  atlas.AuthTypeBearer,
            Token: "eyJhbGciOiJIUzI1NiIs...",
        },
    },
    WorkspaceID: "workspace-123",
    CreatedBy:   "user@example.com",
    Tags:        []string{"api", "production"},
}

// Start the scan
ctx := context.Background()
err := orchestrator.StartScan(ctx, scan)
if err != nil {
    log.Fatalf("Failed to start scan: %v", err)
}

fmt.Printf("Scan started: %s\n", scan.ID)
```

### Monitoring Progress

```go
// Get scan status
status, err := orchestrator.GetScanStatus(scanID)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("State: %s\n", status.State)
fmt.Printf("Progress: %.1f%%\n", status.Progress.PercentComplete*100)
fmt.Printf("URLs Tested: %d/%d\n",
    status.Progress.URLsTested,
    status.Progress.URLsDiscovered)
fmt.Printf("Findings: %d\n", len(status.Findings))
fmt.Printf("Requests/sec: %.1f\n",
    float64(status.Progress.RequestsSent) / time.Since(status.StartTime).Seconds())
```

### Subscribing to Events

```go
// Subscribe to scan events
eventBus.Subscribe("atlas.scan.started", func(data interface{}) {
    scan := data.(*atlas.Scan)
    fmt.Printf("Scan started: %s\n", scan.ID)
})

eventBus.Subscribe("atlas.scan.progress", func(data interface{}) {
    progress := data.(map[string]interface{})
    fmt.Printf("Progress: %.1f%%\n", progress["percent"].(float64)*100)
})

eventBus.Subscribe("atlas.finding.detected", func(data interface{}) {
    finding := data.(*atlas.Finding)
    fmt.Printf("Found %s: %s\n", finding.Severity, finding.Title)
})

eventBus.Subscribe("atlas.scan.completed", func(data interface{}) {
    scan := data.(*atlas.Scan)
    fmt.Printf("Scan completed: %s (%d findings)\n",
        scan.ID, len(scan.Findings))
})
```

### Pausing and Resuming

```go
// Pause a running scan
err := orchestrator.PauseScan(scanID)
if err != nil {
    log.Fatal(err)
}

// Resume a paused scan
err = orchestrator.ResumeScan(ctx, scanID)
if err != nil {
    log.Fatal(err)
}

// Stop a scan (cannot be resumed)
err = orchestrator.StopScan(scanID)
if err != nil {
    log.Fatal(err)
}
```

## Storage API

### Querying Scans

```go
// Get a specific scan
scan, err := storage.GetScan(ctx, scanID)
if err != nil {
    log.Fatal(err)
}

// List scans with filters
scans, err := storage.ListScans(ctx, storage.ScanFilter{
    WorkspaceID: "workspace-123",
    State:       atlas.ScanStateCompleted,
    Limit:       10,
})
if err != nil {
    log.Fatal(err)
}

for _, scan := range scans {
    fmt.Printf("%s: %s (%s)\n", scan.ID, scan.Name, scan.State)
}
```

### Querying Findings

```go
// Get findings for a scan
findings, err := storage.GetFindingsByScan(ctx, scanID)
if err != nil {
    log.Fatal(err)
}

// Filter by severity
highSeverity := []*atlas.Finding{}
for _, f := range findings {
    if f.Severity == atlas.SeverityHigh || f.Severity == atlas.SeverityCritical {
        highSeverity = append(highSeverity, f)
    }
}

fmt.Printf("Found %d high/critical findings\n", len(highSeverity))
```

### Marking False Positives

```go
finding, err := storage.GetFinding(ctx, findingID)
if err != nil {
    log.Fatal(err)
}

finding.FalsePositive = true
finding.Metadata = map[string]interface{}{
    "fp_reason": "Whitelisted IP addresses only",
    "verified_by": "security-team",
    "verified_at": time.Now(),
}

err = storage.UpdateFinding(ctx, finding)
if err != nil {
    log.Fatal(err)
}
```

## Module Development

### Creating a Custom Module

```go
type CustomModule struct {
    logger     atlas.Logger
    oastClient atlas.OASTClient
}

func NewCustomModule(logger atlas.Logger, oast atlas.OASTClient) *CustomModule {
    return &CustomModule{
        logger:     logger,
        oastClient: oast,
    }
}

func (m *CustomModule) Name() string {
    return "custom-detector"
}

func (m *CustomModule) Description() string {
    return "Detects custom vulnerability patterns"
}

func (m *CustomModule) Scan(ctx context.Context, target *atlas.ScanTarget) ([]*atlas.Finding, error) {
    var findings []*atlas.Finding

    // Test for vulnerability
    payload := "custom-payload"
    testURL := target.URL + "?test=" + payload

    resp, err := http.Get(testURL)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)

    // Check if vulnerable
    if strings.Contains(string(body), "vulnerability-indicator") {
        finding := &atlas.Finding{
            Type:       "Custom Vulnerability",
            Severity:   atlas.SeverityHigh,
            Confidence: atlas.ConfidenceConfirmed,
            Title:      "Custom vulnerability detected",
            URL:        testURL,
            Payload:    payload,
            Proof:      string(body),
        }
        findings = append(findings, finding)
    }

    return findings, nil
}

func (m *CustomModule) SupportsTarget(target *atlas.ScanTarget) bool {
    // Only scan HTTP/HTTPS
    return strings.HasPrefix(target.URL, "http://") ||
           strings.HasPrefix(target.URL, "https://")
}
```

## Advanced Features

### Rate Limiting

```go
// Create rate limiter
rateLimiter := atlas.NewRateLimiter(
    50,    // 50 requests per second
    10,    // Burst of 10
    true,  // Adaptive (automatically adjust based on server responses)
)

// Get current rate
currentRate := rateLimiter.GetCurrentRate()
fmt.Printf("Current rate: %d req/sec\n", currentRate)

// Get statistics
stats := rateLimiter.GetStats()
fmt.Printf("Success: %d, Errors: %d, Active hosts: %d\n",
    stats.SuccessCount, stats.ErrorCount, stats.ActiveHosts)
```

### Deduplication

```go
// Create deduplicator
dedup := atlas.NewDeduplicator()

// Deduplicate findings
for _, finding := range findings {
    dedup.Deduplicate(finding)
}

// Get unique findings
uniqueFindings := dedup.GetFindings()

// Sort by severity
sortedFindings := dedup.SortBySeverity(uniqueFindings)

fmt.Printf("Original: %d, Unique: %d\n",
    len(findings), len(uniqueFindings))
```

### CVSS Scoring

```go
// Create CVSS calculator
calc := atlas.NewCVSSCalculator()

// Calculate score
cvss := calc.CalculateCVSS(finding)
finding.CVSS = cvss

// Get classifications
finding.CWE = calc.GetCWE(finding)
finding.OWASP = calc.GetOWASP(finding)
finding.Remediation = calc.GetRemediation(finding)

// Map to severity
severity := calc.SeverityFromCVSS(cvss)
fmt.Printf("CVSS: %.1f (%s)\n", cvss, severity)
```

### False Positive Detection

```go
// Create FP detector
detector := atlas.NewFalsePositiveDetector()

// Add custom rules
detector.AddRule(atlas.FPRule{
    Type:       "SQL Injection",
    Pattern:    "test environment",
    Confidence: 0.4,
    Reason:     "Test environment with fake data",
    Action:     atlas.FPActionFlag,
})

// Analyze finding
analysis := detector.Analyze(finding)

if analysis.IsProbablyFalsePositive {
    fmt.Printf("Likely false positive (%.0f%% confidence)\n",
        analysis.Confidence*100)
    fmt.Printf("Reasons: %s\n", strings.Join(analysis.Reasons, ", "))
}
```

## Error Handling

### Common Errors

```go
var (
    ErrScanNotFound     = errors.New("scan not found")
    ErrScanAlreadyExists = errors.New("scan already exists")
    ErrScanFailed       = errors.New("scan execution failed")
    ErrInvalidConfig    = errors.New("invalid scan configuration")
    ErrModuleNotFound   = errors.New("module not found")
)
```

### Error Handling Example

```go
err := orchestrator.StartScan(ctx, scan)
if err != nil {
    switch {
    case errors.Is(err, atlas.ErrScanAlreadyExists):
        fmt.Println("Scan already running")
    case errors.Is(err, atlas.ErrInvalidConfig):
        fmt.Println("Invalid scan configuration")
    default:
        log.Fatalf("Unexpected error: %v", err)
    }
}
```

## Best Practices

### Resource Management

```go
// Always use contexts with timeouts
ctx, cancel := context.WithTimeout(context.Background(), 1*time.Hour)
defer cancel()

// Close storage connections
defer storage.Close()

// Stop scans on shutdown
defer orchestrator.StopAllScans()
```

### Concurrent Scans

```go
// Use sync.WaitGroup for multiple scans
var wg sync.WaitGroup

for _, target := range targets {
    wg.Add(1)
    go func(t string) {
        defer wg.Done()

        scan := createScan(t)
        orchestrator.StartScan(ctx, scan)
        waitForCompletion(scan.ID)
    }(target)
}

wg.Wait()
```

### Performance Optimization

```go
// Use appropriate concurrency
config := atlas.ScanConfig{
    MaxConcurrency: runtime.NumCPU() * 2,  // 2x CPU cores
    RateLimit:      100,                    // Adjust based on target
    Timeout:        10 * time.Second,
}

// Enable connection pooling
requester := atlas.NewRequester(config, rateLimiter, logger)

// Monitor performance
monitor := atlas.NewPerformanceMonitor()
metrics := monitor.GetMetrics()
fmt.Printf("Avg request time: %v\n", metrics.AvgRequestTime)
fmt.Printf("Requests/sec: %.1f\n", metrics.RequestsPerSecond)
```

## Examples

See the `/examples` directory for complete examples:

- `examples/atlas/basic-scan.go` - Basic scanning example
- `examples/atlas/authenticated-scan.go` - Scanning with authentication
- `examples/atlas/custom-module.go` - Custom detection module
- `examples/atlas/ci-integration.go` - CI/CD integration
- `examples/atlas/batch-scanning.go` - Scanning multiple targets

## Support

For API questions and issues:

- **GitHub Issues**: https://github.com/0xGen/0xgen/issues
- **API Documentation**: https://docs.0xgen.io/api
- **Discord**: https://discord.gg/0xgen
