# Blitz API Documentation for Plugin Developers

## Overview

This documentation provides comprehensive guidance for developers who want to extend Blitz, create custom payload generators, integrate Blitz into their tools, or build plugins for the 0xGen framework.

**Target Audience:**
- Plugin developers
- Security tool creators
- Custom integration developers
- Contributors to the Blitz project

**What You'll Learn:**
- Blitz architecture and core types
- Creating custom payload generators
- Building attack strategies
- Implementing custom classifiers
- Integrating with the findings system
- Creating storage backends
- Building GUI extensions

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Core Types and Interfaces](#core-types-and-interfaces)
3. [Payload Generators](#payload-generators)
4. [Attack Strategies](#attack-strategies)
5. [Analyzers and Classifiers](#analyzers-and-classifiers)
6. [Findings Correlation](#findings-correlation)
7. [Storage Backends](#storage-backends)
8. [Engine Configuration](#engine-configuration)
9. [Examples](#examples)
10. [Testing](#testing)
11. [Contributing](#contributing)

## Architecture Overview

### Component Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    Blitz Engine                          │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │  Template  │  │   Attack     │  │    Payload     │  │
│  │   Parser   │─▶│   Strategy   │─▶│   Generators   │  │
│  └────────────┘  └──────────────┘  └────────────────┘  │
│                           │                             │
│                           ▼                             │
│                  ┌──────────────┐                       │
│                  │  Job Queue   │                       │
│                  └──────────────┘                       │
│                           │                             │
│                           ▼                             │
│         ┌─────────────────────────────────┐            │
│         │      Worker Pool (HTTP)         │            │
│         └─────────────────────────────────┘            │
│                           │                             │
│                           ▼                             │
│  ┌────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │  Anomaly   │◀─│   Response   │─▶│      AI        │  │
│  │  Detector  │  │   Analyzer   │  │  Classifier    │  │
│  └────────────┘  └──────────────┘  └────────────────┘  │
│                           │                             │
│                           ▼                             │
│  ┌────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │  Storage   │  │   Findings   │  │    Export      │  │
│  │  Backend   │  │  Correlator  │  │    Formats     │  │
│  └────────────┘  └──────────────┘  └────────────────┘  │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Request Template** → Parsed to extract positions
2. **Payload Generators** → Generate payloads for each position
3. **Attack Strategy** → Combines payloads into attack jobs
4. **Worker Pool** → Executes HTTP requests concurrently
5. **Response Analyzer** → Detects anomalies
6. **AI Classifier** → Classifies vulnerabilities
7. **Findings Correlator** → Creates security findings
8. **Storage** → Persists results
9. **Export** → Formats for output

## Core Types and Interfaces

### Package Import

```go
import "github.com/RowanDark/0xgen/internal/blitz"
```

### Request and Position

```go
// Request represents an HTTP request template with injection positions
type Request struct {
    Method   string
    URL      string
    Headers  map[string]string
    Body     string
    Positions []Position
}

// Position marks an injection point in the request
type Position struct {
    Index int       // Position index (0-based)
    Name  string    // Descriptive name (e.g., "user_id")
    Start int       // Start byte offset in raw request
    End   int       // End byte offset in raw request
}

// Markers define position delimiters
type Markers struct {
    Open  string    // Opening marker (default: "{{")
    Close string    // Closing marker (default: "}}")
}
```

### Fuzzing Results

```go
// FuzzResult represents the result of a single fuzzing request
type FuzzResult struct {
    ID            int64
    SessionID     string
    Timestamp     time.Time
    Request       RequestSnapshot
    Response      ResponseSnapshot
    Payload       string
    PositionIndex int
    PositionName  string
    Duration      int64  // Milliseconds
    StatusCode    int
    ContentLen    int
    Error         string
    Anomaly       *AnomalyIndicator
}

// RequestSnapshot captures the request details
type RequestSnapshot struct {
    Method  string
    URL     string
    Headers map[string]string
    Body    string
}

// ResponseSnapshot captures the response details
type ResponseSnapshot struct {
    StatusCode  int
    Headers     map[string]string
    Body        string
    ContentType string
}

// AnomalyIndicator flags interesting responses
type AnomalyIndicator struct {
    IsInteresting        bool
    StatusCodeAnomaly    bool
    ContentLengthDelta   int
    ResponseTimeFactor   float64
    PatternAnomalies     int
}
```

## Payload Generators

### PayloadGenerator Interface

All payload generators must implement this interface:

```go
// PayloadGenerator generates a list of payloads for fuzzing
type PayloadGenerator interface {
    Generate() ([]string, error)
}
```

### Built-in Generators

#### WordlistGenerator

Loads payloads from text, CSV, or JSON files.

```go
type WordlistGenerator struct {
    FilePath string    // Path to wordlist file
    Column   int       // CSV column (0-based, optional)
    JSONPath string    // JSONPath expression (optional)
}

func (g *WordlistGenerator) Generate() ([]string, error)
```

**Example:**

```go
// Text file
gen := &blitz.WordlistGenerator{
    FilePath: "/path/to/wordlist.txt",
}

// CSV file, column 2
gen := &blitz.WordlistGenerator{
    FilePath: "/path/to/credentials.csv",
    Column:   1,
}

// JSON file with JSONPath
gen := &blitz.WordlistGenerator{
    FilePath: "/path/to/data.json",
    JSONPath: "users.*.username",
}

payloads, err := gen.Generate()
```

#### RangeGenerator

Generates numeric or alphabetic ranges.

```go
type RangeGenerator struct {
    Start interface{}  // int or string
    End   interface{}  // int or string
    Step  int          // Step size
}

func (g *RangeGenerator) Generate() ([]string, error)
```

**Example:**

```go
// Numeric range: 1, 2, 3, 4, 5
gen := &blitz.RangeGenerator{
    Start: 1,
    End:   5,
    Step:  1,
}

// Alphabetic range: a, b, c, ..., z
gen := &blitz.RangeGenerator{
    Start: "a",
    End:   "z",
    Step:  1,
}

// Range with step: 0, 10, 20, ..., 100
gen := &blitz.RangeGenerator{
    Start: 0,
    End:   100,
    Step:  10,
}
```

#### CustomGenerator

Uses a static list of payloads.

```go
type CustomGenerator struct {
    Values []string
}

func (g *CustomGenerator) Generate() ([]string, error)
```

**Example:**

```go
gen := &blitz.CustomGenerator{
    Values: []string{
        "' OR '1'='1",
        "admin' --",
        "<script>alert(1)</script>",
    },
}
```

#### RegexGenerator

Generates payloads matching a regular expression.

```go
type RegexGenerator struct {
    Pattern string  // Regex pattern
    Limit   int     // Maximum number of payloads
}

func (g *RegexGenerator) Generate() ([]string, error)
```

**Example:**

```go
// Generate 100 3-digit numbers
gen := &blitz.RegexGenerator{
    Pattern: "[0-9]{3}",
    Limit:   100,
}

// Generate email addresses
gen := &blitz.RegexGenerator{
    Pattern: "[a-z]{5}@[a-z]{3}\\.com",
    Limit:   50,
}
```

### Creating a Custom Payload Generator

**Example: Database-Specific SQLi Generator**

```go
package mypackage

import "github.com/RowanDark/0xgen/internal/blitz"

// MySQLPayloadGenerator generates MySQL-specific SQLi payloads
type MySQLPayloadGenerator struct {
    Advanced bool  // Include advanced payloads
}

func (g *MySQLPayloadGenerator) Generate() ([]string, error) {
    payloads := []string{
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "' UNION SELECT NULL, version()--",
        "' UNION SELECT NULL, user()--",
        "' UNION SELECT NULL, database()--",
    }

    if g.Advanced {
        payloads = append(payloads,
            "' UNION SELECT NULL, schema_name FROM information_schema.schemata--",
            "' UNION SELECT NULL, table_name FROM information_schema.tables WHERE table_schema=database()--",
            "' AND 1=0 UNION SELECT NULL, column_name FROM information_schema.columns WHERE table_name='users'--",
        )
    }

    return payloads, nil
}

// Usage
gen := &MySQLPayloadGenerator{Advanced: true}
payloads, err := gen.Generate()
```

**Example: Time-Based Blind SQLi Generator**

```go
type TimeBasedSQLiGenerator struct {
    Database string  // mysql, postgres, mssql, oracle
    Delay    int     // Delay in seconds
}

func (g *TimeBasedSQLiGenerator) Generate() ([]string, error) {
    delay := g.Delay
    if delay == 0 {
        delay = 5
    }

    var payloads []string

    switch g.Database {
    case "mysql":
        payloads = []string{
            fmt.Sprintf("' AND SLEEP(%d)--", delay),
            fmt.Sprintf("' OR SLEEP(%d)--", delay),
            fmt.Sprintf("1' AND SLEEP(%d) AND '1'='1", delay),
        }
    case "postgres":
        payloads = []string{
            fmt.Sprintf("' AND pg_sleep(%d)--", delay),
            fmt.Sprintf("1' AND pg_sleep(%d) AND '1'='1", delay),
        }
    case "mssql":
        payloads = []string{
            fmt.Sprintf("'; WAITFOR DELAY '00:00:0%d'--", delay),
            fmt.Sprintf("1'; WAITFOR DELAY '00:00:0%d'--", delay),
        }
    }

    return payloads, nil
}
```

## Attack Strategies

### AttackStrategy Interface

```go
// AttackStrategy defines how payloads are combined across positions
type AttackStrategy interface {
    GenerateJobs(positions []Position, payloadSets [][]string) ([]AttackJob, error)
}

// AttackJob represents a single fuzzing request
type AttackJob struct {
    PayloadMap map[int]string  // Position index → Payload
}
```

### Built-in Strategies

#### 1. Sniper Strategy

Tests one position at a time with one payload set.

```go
type SniperStrategy struct{}

func (s *SniperStrategy) GenerateJobs(positions []Position, payloadSets [][]string) ([]AttackJob, error)
```

**Implementation:**

```go
func (s *SniperStrategy) GenerateJobs(positions []Position, payloadSets [][]string) ([]AttackJob, error) {
    if len(payloadSets) == 0 {
        return nil, fmt.Errorf("no payload sets provided")
    }

    payloads := payloadSets[0]
    var jobs []AttackJob

    for _, pos := range positions {
        for _, payload := range payloads {
            job := AttackJob{
                PayloadMap: map[int]string{pos.Index: payload},
            }
            jobs = append(jobs, job)
        }
    }

    return jobs, nil
}
```

#### 2. Battering Ram Strategy

Applies the same payload to all positions.

```go
type BatteringRamStrategy struct{}
```

**Implementation:**

```go
func (s *BatteringRamStrategy) GenerateJobs(positions []Position, payloadSets [][]string) ([]AttackJob, error) {
    if len(payloadSets) == 0 {
        return nil, fmt.Errorf("no payload sets provided")
    }

    payloads := payloadSets[0]
    var jobs []AttackJob

    for _, payload := range payloads {
        job := AttackJob{
            PayloadMap: make(map[int]string),
        }
        for _, pos := range positions {
            job.PayloadMap[pos.Index] = payload
        }
        jobs = append(jobs, job)
    }

    return jobs, nil
}
```

#### 3. Pitchfork Strategy

Pairs payloads across positions (parallel iteration).

```go
type PitchforkStrategy struct{}
```

#### 4. Cluster Bomb Strategy

Generates all combinations (cartesian product).

```go
type ClusterBombStrategy struct{}
```

### Creating a Custom Attack Strategy

**Example: Hybrid Strategy** (Sniper for first position, Battering Ram for others)

```go
type HybridStrategy struct {
    PrimaryPosition int  // Index of position to sniper
}

func (s *HybridStrategy) GenerateJobs(positions []Position, payloadSets [][]string) ([]AttackJob, error) {
    if len(positions) == 0 || len(payloadSets) == 0 {
        return nil, fmt.Errorf("empty positions or payload sets")
    }

    var jobs []AttackJob
    primaryPayloads := payloadSets[0]
    secondaryPayload := "default_value"
    if len(payloadSets) > 1 && len(payloadSets[1]) > 0 {
        secondaryPayload = payloadSets[1][0]
    }

    for _, payload := range primaryPayloads {
        job := AttackJob{
            PayloadMap: make(map[int]string),
        }

        // Sniper on primary position
        job.PayloadMap[s.PrimaryPosition] = payload

        // Battering Ram on others
        for _, pos := range positions {
            if pos.Index != s.PrimaryPosition {
                job.PayloadMap[pos.Index] = secondaryPayload
            }
        }

        jobs = append(jobs, job)
    }

    return jobs, nil
}
```

## Analyzers and Classifiers

### Analyzer

The Analyzer detects anomalies by comparing responses to a baseline.

```go
type Analyzer struct {
    baseline *BaselineMetrics
}

type BaselineMetrics struct {
    StatusCode    int
    ContentLength int
    ResponseTime  int64
    Headers       map[string]string
}

func (a *Analyzer) SetBaseline(result *FuzzResult)
func (a *Analyzer) Analyze(result *FuzzResult) *AnomalyIndicator
```

**Anomaly Detection Logic:**

- **Status Code Change:** Different from baseline
- **Content Length Delta:** Significant difference (> 20%)
- **Response Time Factor:** Much slower or faster (> 2x or < 0.5x)
- **Pattern Matching:** Custom regex patterns

### AI Classifier

Classifies responses for vulnerability patterns.

```go
type AIClassifier struct {
    patterns map[ClassificationCategory][]classificationPattern
}

type Classification struct {
    Category   ClassificationCategory
    Confidence float64
    Evidence   string
    Message    string
    Severity   string
    CWE        string
    OWASP      string
}

func (c *AIClassifier) Classify(response *FuzzResult) []Classification
func (c *AIClassifier) ClassifyWithContext(result *FuzzResult, payload string) []Classification
```

### Creating a Custom Classifier

**Example: API Error Classifier**

```go
package mypackage

import (
    "regexp"
    "strings"
    "github.com/RowanDark/0xgen/internal/blitz"
)

type APIErrorClassifier struct {
    patterns map[string]*regexp.Regexp
}

func NewAPIErrorClassifier() *APIErrorClassifier {
    return &APIErrorClassifier{
        patterns: map[string]*regexp.Regexp{
            "rate_limit":     regexp.MustCompile(`(?i)rate\s+limit\s+exceeded`),
            "auth_failure":   regexp.MustCompile(`(?i)(unauthorized|invalid\s+token|authentication\s+failed)`),
            "not_found":      regexp.MustCompile(`(?i)(not\s+found|resource\s+does\s+not\s+exist)`),
            "server_error":   regexp.MustCompile(`(?i)(internal\s+server\s+error|500)`),
        },
    }
}

func (c *APIErrorClassifier) Classify(result *blitz.FuzzResult) []blitz.Classification {
    var classifications []blitz.Classification
    body := strings.ToLower(result.Response.Body)

    for category, pattern := range c.patterns {
        if match := pattern.FindString(result.Response.Body); match != "" {
            classifications = append(classifications, blitz.Classification{
                Category:   blitz.ClassificationCategory(category),
                Confidence: 0.90,
                Evidence:   match,
                Message:    fmt.Sprintf("API %s detected", category),
                Severity:   c.getSeverity(category),
            })
        }
    }

    return classifications
}

func (c *APIErrorClassifier) getSeverity(category string) string {
    switch category {
    case "server_error":
        return "high"
    case "auth_failure":
        return "medium"
    default:
        return "low"
    }
}
```

## Findings Correlation

### FindingsCorrelator

Converts fuzzing results to 0xGen findings.

```go
type FindingsCorrelator struct {
    classifier *AIClassifier
    sessionID  string
}

func NewFindingsCorrelator(sessionID string) *FindingsCorrelator

func (fc *FindingsCorrelator) CorrelateResult(result *FuzzResult) []*findings.Finding
func (fc *FindingsCorrelator) BatchCorrelate(results []*FuzzResult) []*findings.Finding
```

### Custom Finding Correlation

**Example: Custom Findings for API Vulnerabilities**

```go
package mypackage

import (
    "github.com/RowanDark/0xgen/internal/blitz"
    "github.com/RowanDark/0xgen/internal/findings"
)

type APIFindingsCorrelator struct {
    sessionID string
}

func (c *APIFindingsCorrelator) CorrelateResult(result *blitz.FuzzResult) *findings.Finding {
    // Only process API-specific anomalies
    if !strings.Contains(result.Request.URL, "/api/") {
        return nil
    }

    // Check for IDOR vulnerability
    if result.StatusCode == 200 && result.Anomaly != nil {
        return &findings.Finding{
            Version:    findings.SchemaVersion,
            ID:         findings.NewID(),
            Plugin:     "api-fuzzer",
            Type:       "api.idor",
            Message:    "Potential IDOR vulnerability - unauthorized resource access",
            Target:     result.Request.URL,
            Evidence:   fmt.Sprintf("Payload: %s returned 200 OK", result.Payload),
            Severity:   findings.SeverityHigh,
            DetectedAt: findings.NewTimestamp(result.Timestamp),
            Metadata: map[string]string{
                "payload":     result.Payload,
                "status_code": fmt.Sprintf("%d", result.StatusCode),
                "cwe":         "CWE-639",
                "owasp":       "A01:2021-Broken Access Control",
            },
        }
    }

    return nil
}
```

## Storage Backends

### Storage Interface

```go
type Storage interface {
    Store(result *FuzzResult) error
    Query(filters QueryFilters) ([]*FuzzResult, error)
    Close() error
}

type QueryFilters struct {
    SessionID         string
    StatusCode        int
    AnomalyOnly       bool
    Limit             int
    Offset            int
}
```

### Built-in: SQLiteStorage

```go
type SQLiteStorage struct {
    db        *sql.DB
    sessionID string
}

func NewSQLiteStorage(dbPath, sessionID string) (*SQLiteStorage, error)
```

### Creating a Custom Storage Backend

**Example: PostgreSQL Storage**

```go
package mypackage

import (
    "database/sql"
    _ "github.com/lib/pq"
    "github.com/RowanDark/0xgen/internal/blitz"
)

type PostgreSQLStorage struct {
    db        *sql.DB
    sessionID string
}

func NewPostgreSQLStorage(connStr, sessionID string) (*PostgreSQLStorage, error) {
    db, err := sql.Open("postgres", connStr)
    if err != nil {
        return nil, err
    }

    // Create table
    _, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS blitz_results (
            id SERIAL PRIMARY KEY,
            session_id VARCHAR(255),
            timestamp TIMESTAMP,
            payload TEXT,
            status_code INT,
            content_len INT,
            duration_ms BIGINT,
            anomaly_interesting BOOLEAN,
            response_body TEXT
        )
    `)
    if err != nil {
        return nil, err
    }

    return &PostgreSQLStorage{
        db:        db,
        sessionID: sessionID,
    }, nil
}

func (s *PostgreSQLStorage) Store(result *blitz.FuzzResult) error {
    _, err := s.db.Exec(`
        INSERT INTO blitz_results (session_id, timestamp, payload, status_code, content_len, duration_ms, anomaly_interesting, response_body)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `, s.sessionID, result.Timestamp, result.Payload, result.StatusCode, result.ContentLen, result.Duration, result.Anomaly != nil && result.Anomaly.IsInteresting, result.Response.Body)
    return err
}

func (s *PostgreSQLStorage) Query(filters blitz.QueryFilters) ([]*blitz.FuzzResult, error) {
    // Implement query logic
    // ...
}

func (s *PostgreSQLStorage) Close() error {
    return s.db.Close()
}
```

## Engine Configuration

### EngineConfig

```go
type EngineConfig struct {
    Request                   *Request
    AttackType                AttackType
    Generators                []PayloadGenerator
    Concurrency               int
    RateLimit                 float64
    Timeout                   time.Duration
    Storage                   Storage
    FollowRedirects           bool
    Proxy                     string
    UserAgent                 string
    EnableAIPayloads          bool
    EnableAIClassification    bool
    EnableFindingsCorrelation bool
    FindingsCallback          func(*findings.Finding) error
}
```

### Creating and Running an Engine

```go
package main

import (
    "context"
    "fmt"
    "github.com/RowanDark/0xgen/internal/blitz"
)

func main() {
    // Parse request template
    markers := blitz.Markers{Open: "{{", Close: "}}"}
    req, err := blitz.ParseRequest(requestTemplate, markers)
    if err != nil {
        panic(err)
    }

    // Create payload generators
    generators := []blitz.PayloadGenerator{
        &blitz.WordlistGenerator{FilePath: "payloads.txt"},
        &blitz.RangeGenerator{Start: 1, End: 100, Step: 1},
    }

    // Configure storage
    storage, err := blitz.NewSQLiteStorage("results.db", "session-123")
    if err != nil {
        panic(err)
    }
    defer storage.Close()

    // Configure engine
    config := &blitz.EngineConfig{
        Request:                req,
        AttackType:             blitz.AttackTypeSniper,
        Generators:             generators,
        Concurrency:            10,
        RateLimit:              0, // Unlimited
        Timeout:                10 * time.Second,
        Storage:                storage,
        EnableAIClassification: true,
    }

    // Create and run engine
    engine, err := blitz.NewEngine(config)
    if err != nil {
        panic(err)
    }

    ctx := context.Background()
    err = engine.Run(ctx, func(result *blitz.FuzzResult) error {
        if result.Anomaly != nil && result.Anomaly.IsInteresting {
            fmt.Printf("[+] Anomaly: %s → Status %d\n", result.Payload, result.StatusCode)
        }
        return nil
    })
    if err != nil {
        panic(err)
    }
}
```

## Examples

### Example 1: Simple SQLi Fuzzer

```go
package main

import (
    "context"
    "fmt"
    "github.com/RowanDark/0xgen/internal/blitz"
)

func main() {
    // Request template
    template := `POST /api/login HTTP/1.1
Host: example.com
Content-Type: application/json

{"username":"{{user}}","password":"{{pass}}"}`

    markers := blitz.Markers{Open: "{{", Close: "}}"}
    req, _ := blitz.ParseRequest(template, markers)

    // SQLi payloads
    sqliGen := &blitz.CustomGenerator{
        Values: []string{
            "' OR '1'='1",
            "admin' --",
            "' OR 1=1--",
        },
    }

    config := &blitz.EngineConfig{
        Request:     req,
        AttackType:  blitz.AttackTypeSniper,
        Generators:  []blitz.PayloadGenerator{sqliGen},
        Concurrency: 5,
    }

    engine, _ := blitz.NewEngine(config)
    engine.Run(context.Background(), func(result *blitz.FuzzResult) error {
        fmt.Printf("%s → %d\n", result.Payload, result.StatusCode)
        return nil
    })
}
```

### Example 2: IDOR Testing with AI

```go
package main

import (
    "context"
    "github.com/RowanDark/0xgen/internal/blitz"
)

func main() {
    template := `GET /api/user/{{user_id}}/profile HTTP/1.1
Host: api.example.com
Authorization: Bearer abc123`

    markers := blitz.Markers{Open: "{{", Close: "}}"}
    req, _ := blitz.ParseRequest(template, markers)

    // Test IDs 1-1000
    idGen := &blitz.RangeGenerator{
        Start: 1,
        End:   1000,
        Step:  1,
    }

    storage, _ := blitz.NewSQLiteStorage("idor-test.db", "idor-session")
    defer storage.Close()

    config := &blitz.EngineConfig{
        Request:                req,
        AttackType:             blitz.AttackTypeSniper,
        Generators:             []blitz.PayloadGenerator{idGen},
        Concurrency:            20,
        RateLimit:              50, // 50 req/sec
        Storage:                storage,
        EnableAIClassification: true,
    }

    engine, _ := blitz.NewEngine(config)
    engine.Run(context.Background(), nil)

    // Query interesting results
    results, _ := storage.Query(blitz.QueryFilters{
        AnomalyOnly: true,
    })

    for _, result := range results {
        fmt.Printf("Interesting: ID %s returned %d\n", result.Payload, result.StatusCode)
    }
}
```

## Testing

### Unit Testing Payload Generators

```go
package mypackage_test

import (
    "testing"
    "mypackage"
)

func TestMySQLPayloadGenerator(t *testing.T) {
    gen := &mypackage.MySQLPayloadGenerator{Advanced: false}
    payloads, err := gen.Generate()

    if err != nil {
        t.Fatalf("Generate failed: %v", err)
    }

    if len(payloads) == 0 {
        t.Error("Expected payloads, got none")
    }

    // Check for expected payload
    found := false
    for _, p := range payloads {
        if p == "' OR '1'='1" {
            found = true
            break
        }
    }

    if !found {
        t.Error("Expected basic SQLi payload not found")
    }
}
```

### Integration Testing

```go
func TestBlitzEngine_Integration(t *testing.T) {
    template := `GET /test?q={{query}} HTTP/1.1
Host: localhost:8080`

    markers := blitz.Markers{Open: "{{", Close: "}}"}
    req, _ := blitz.ParseRequest(template, markers)

    gen := &blitz.CustomGenerator{
        Values: []string{"test1", "test2", "test3"},
    }

    config := &blitz.EngineConfig{
        Request:     req,
        AttackType:  blitz.AttackTypeSniper,
        Generators:  []blitz.PayloadGenerator{gen},
        Concurrency: 1,
    }

    engine, _ := blitz.NewEngine(config)

    results := []*blitz.FuzzResult{}
    err := engine.Run(context.Background(), func(r *blitz.FuzzResult) error {
        results = append(results, r)
        return nil
    })

    if err != nil {
        t.Fatalf("Engine run failed: %v", err)
    }

    if len(results) != 3 {
        t.Errorf("Expected 3 results, got %d", len(results))
    }
}
```

## Contributing

### Contribution Guidelines

1. **Code Style:** Follow Go conventions (gofmt, golint)
2. **Testing:** Add unit tests for new features
3. **Documentation:** Update API docs and examples
4. **Commits:** Use descriptive commit messages
5. **Pull Requests:** Include description and test results

### Submitting a Payload Generator

```markdown
## My Custom Generator

**Description:** Generates payloads for [specific use case]

**Example:**
```go
gen := &MyGenerator{Option: value}
payloads, _ := gen.Generate()
```

**Tests:** Included in `my_generator_test.go`
**Documentation:** Added to API_DOCS.md
```

### Reporting Bugs

Use GitHub Issues with:
- Clear description
- Steps to reproduce
- Expected vs actual behavior
- Environment details (Go version, OS)
- Code samples if applicable

## Additional Resources

- **Blitz Source Code:** https://github.com/RowanDark/0xGen/tree/main/internal/blitz
- **User Guide:** [USER_GUIDE.md](./USER_GUIDE.md)
- **Tutorials:** [TUTORIAL_SQLI.md](./TUTORIAL_SQLI.md), [TUTORIAL_XSS.md](./TUTORIAL_XSS.md)
- **0xGen Framework:** https://github.com/RowanDark/0xGen

---

**Questions?** Open an issue on GitHub or join our community discussions.
