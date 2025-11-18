# Entropy Plugin API Documentation

## Overview

The Entropy plugin provides a comprehensive API for randomness analysis, PRNG fingerprinting, and pattern detection. This document covers both the Go plugin API (for extension developers) and the TypeScript/IPC API (for GUI integration).

## Table of Contents

1. [Go Plugin API](#go-plugin-api)
2. [TypeScript IPC API](#typescript-ipc-api)
3. [Data Structures](#data-structures)
4. [Code Examples](#code-examples)
5. [Error Handling](#error-handling)

---

## Go Plugin API

### Core Types

#### `EntropyAnalysis`

Represents the complete analysis results for a token capture session.

```go
type EntropyAnalysis struct {
    CaptureSessionID int64          // Session identifier
    TokenCount       int             // Number of tokens analyzed
    TokenLength      int             // Average token length
    CharacterSet     []rune          // Unique characters found

    // Statistical test results
    ChiSquared        TestResult
    Runs              TestResult
    SerialCorrelation TestResult
    Spectral          TestResult
    ShannonEntropy    float64        // Bits per character
    CollisionRate     float64        // Percentage of duplicates
    BitDistribution   []float64      // Per-bit 1-frequency

    // Pattern detection
    DetectedPRNG     *PRNGSignature
    DetectedPatterns []Pattern
    Recommendations  []string

    // Assessment
    RandomnessScore  float64        // 0-100 composite score
    Risk             RiskLevel      // low, medium, high, critical

    // Confidence metrics
    ConfidenceLevel  float64        // 0-1, statistical confidence
    ReliabilityScore float64        // 0-100, sample quality
    TokensNeeded     int            // Recommended additional samples
    SampleQuality    string         // "insufficient", "marginal", "adequate", "excellent"
}
```

#### `TestResult`

Statistical test outcome.

```go
type TestResult struct {
    PValue      float64  // Statistical p-value
    Passed      bool     // true if p-value > 0.01
    Confidence  float64  // Test-specific confidence score
    Description string   // Human-readable explanation
}
```

#### `PRNGSignature`

Known weak PRNG detection.

```go
type PRNGSignature struct {
    Name        string   // PRNG name (e.g., "Linear Congruential Generator")
    Weakness    string   // Description of vulnerability
    ExploitHint string   // How to exploit this weakness
    Confidence  float64  // 0-1, detection confidence
}
```

#### `Pattern`

Detected predictability pattern.

```go
type Pattern struct {
    Type        string   // "sequential", "timestamp", "low_entropy", etc.
    Confidence  float64  // 0-1, pattern confidence
    Description string   // Human-readable description
    Evidence    string   // Supporting evidence (e.g., "tokens increment by 100")
}
```

#### `CaptureSession`

Real-time capture session.

```go
type CaptureSession struct {
    ID               int64
    Name             string
    Extractor        TokenExtractor
    StartedAt        time.Time
    CompletedAt      *time.Time
    PausedAt         *time.Time
    TokenCount       int
    Status           CaptureStatus  // "active", "paused", "stopped"
    TargetCount      int            // Auto-stop at N tokens
    TimeoutSeconds   int            // Auto-stop after N seconds
    StopReason       *StopReason    // Why session stopped
    LastAnalyzedAt   *time.Time
    LastAnalysisCount int
    AnalysisInterval int            // Analyze every N tokens
}
```

### Statistical Functions

#### `ChiSquaredTest`

Tests character frequency distribution uniformity.

```go
func ChiSquaredTest(tokens []string) TestResult
```

**Parameters:**
- `tokens`: Slice of token strings to analyze

**Returns:**
- `TestResult` with p-value and pass/fail status

**Example:**
```go
tokens := []string{"a1b2c3", "d4e5f6", "g7h8i9"}
result := ChiSquaredTest(tokens)
if result.Passed {
    fmt.Printf("Chi-squared test passed (p=%.4f)\n", result.PValue)
} else {
    fmt.Printf("Non-uniform distribution detected (p=%.4f)\n", result.PValue)
}
```

#### `RunsTest`

Tests for sequential independence using Wald-Wolfowitz runs test.

```go
func RunsTest(tokens []string) TestResult
```

**Example:**
```go
tokens := []string{"aaa", "bbb", "aaa", "bbb"}  // Alternating pattern
result := RunsTest(tokens)
fmt.Printf("Runs test: p=%.4f, passed=%v\n", result.PValue, result.Passed)
```

#### `SerialCorrelationTest`

Tests token-to-token correlation.

```go
func SerialCorrelationTest(tokens []string) TestResult
```

**Example:**
```go
// Sequential tokens will fail
tokens := []string{"token_100", "token_101", "token_102"}
result := SerialCorrelationTest(tokens)
if !result.Passed {
    fmt.Println("Warning: Tokens show serial correlation!")
}
```

#### `SpectralTest`

Applies FFT to detect periodic patterns.

```go
func SpectralTest(tokens []string) TestResult
```

**Example:**
```go
tokens := generateTimestampTokens(100)  // Periodic pattern
result := SpectralTest(tokens)
fmt.Printf("Spectral test: p=%.4f\n", result.PValue)
```

#### `CalculateEntropy`

Computes Shannon entropy in bits per character.

```go
func CalculateEntropy(tokens []string) float64
```

**Example:**
```go
tokens := []string{"abc123", "def456", "ghi789"}
entropy := CalculateEntropy(tokens)
fmt.Printf("Shannon entropy: %.2f bits/char\n", entropy)

// For hex tokens, max entropy is 4 bits
if entropy < 3.5 {
    fmt.Println("Warning: Low entropy detected!")
}
```

#### `DetectCollisions`

Detects duplicate tokens.

```go
func DetectCollisions(tokens []string) (collisionRate float64, result TestResult)
```

**Example:**
```go
tokens := make([]string, 1000)
// ... populate tokens ...
rate, result := DetectCollisions(tokens)
fmt.Printf("Collision rate: %.2f%%\n", rate*100)
if rate > 0.05 {
    fmt.Println("High collision rate suggests limited keyspace!")
}
```

#### `AnalyzeBitDistribution`

Analyzes per-bit position frequency.

```go
func AnalyzeBitDistribution(tokens []string) []float64
```

**Returns:** Slice of frequencies (0.0-1.0) for each bit position

**Example:**
```go
tokens := generateCryptoRandomTokens(1000, 16)
distribution := AnalyzeBitDistribution(tokens)
for i, freq := range distribution {
    bias := math.Abs(freq - 0.5)
    if bias > 0.1 {
        fmt.Printf("Bit %d has bias: %.3f\n", i, bias)
    }
}
```

### PRNG Fingerprinting

#### `FingerprintPRNG`

Identifies known weak PRNGs.

```go
func FingerprintPRNG(analysis *EntropyAnalysis, tokens []string) *PRNGSignature
```

**Parameters:**
- `analysis`: Partial analysis with statistical test results
- `tokens`: Original token slice

**Returns:**
- `*PRNGSignature` if known PRNG detected, `nil` otherwise

**Example:**
```go
// Run statistical tests first
analysis := &EntropyAnalysis{
    ChiSquared:        ChiSquaredTest(tokens),
    Runs:              RunsTest(tokens),
    SerialCorrelation: SerialCorrelationTest(tokens),
    Spectral:          SpectralTest(tokens),
}

// Attempt fingerprinting
prng := FingerprintPRNG(analysis, tokens)
if prng != nil {
    fmt.Printf("Detected: %s\n", prng.Name)
    fmt.Printf("Weakness: %s\n", prng.Weakness)
    fmt.Printf("Exploit: %s\n", prng.ExploitHint)
    fmt.Printf("Confidence: %.0f%%\n", prng.Confidence*100)
}
```

### Pattern Detection

#### `DetectSequentialPattern`

Detects incrementing or decrementing sequences.

```go
func DetectSequentialPattern(tokens []string) *Pattern
```

**Example:**
```go
tokens := []string{"100", "200", "300", "400"}
pattern := DetectSequentialPattern(tokens)
if pattern != nil {
    fmt.Printf("Sequential pattern: %s (confidence: %.0f%%)\n",
        pattern.Description, pattern.Confidence*100)
}
```

#### `DetectLowEntropyPattern`

Detects limited character sets or low information density.

```go
func DetectLowEntropyPattern(tokens []string, entropy float64, charSet []rune) *Pattern
```

**Example:**
```go
tokens := []string{"1234", "5678", "9012"}  // Only digits
entropy := CalculateEntropy(tokens)
charSet := GetCharacterSet(tokens)
pattern := DetectLowEntropyPattern(tokens, entropy, charSet)
if pattern != nil {
    fmt.Printf("Low entropy: %s\n", pattern.Description)
}
```

#### `DetectTimestampPattern`

Detects timestamp-based generation.

```go
func DetectTimestampPattern(samples []TokenSample) *Pattern
```

**Parameters:**
- `samples`: Token samples with capture timestamps

**Example:**
```go
// Tokens captured at known intervals
samples := []TokenSample{
    {TokenValue: "1609459200", CapturedAt: time.Unix(1609459200, 0)},
    {TokenValue: "1609459260", CapturedAt: time.Unix(1609459260, 0)},
    {TokenValue: "1609459320", CapturedAt: time.Unix(1609459320, 0)},
}
pattern := DetectTimestampPattern(samples)
if pattern != nil {
    fmt.Println("Tokens correlate with capture time!")
}
```

#### `DetectRepeatedSubstrings`

Detects recurring substrings across tokens.

```go
func DetectRepeatedSubstrings(tokens []string) *Pattern
```

**Example:**
```go
tokens := []string{"prefix_123", "prefix_456", "prefix_789"}
pattern := DetectRepeatedSubstrings(tokens)
if pattern != nil {
    fmt.Printf("Repeated prefix detected: %s\n", pattern.Evidence)
}
```

### Full Analysis Workflow

#### `EntropyEngine.AnalyzeSession`

Complete analysis of a capture session.

```go
func (e *EntropyEngine) AnalyzeSession(sessionID int64) (*EntropyAnalysis, error)
```

**Example:**
```go
// Create engine
storage, err := NewStorage("entropy.db")
if err != nil {
    log.Fatal(err)
}
defer storage.Close()

engine := NewEntropyEngine(storage, time.Now)

// Create session and add tokens
session, err := storage.CreateSession("test", TokenExtractor{}, 0, 0)
if err != nil {
    log.Fatal(err)
}

tokens := []string{"abc123", "def456", "ghi789", /* ... */}
for _, token := range tokens {
    storage.AddTokenSample(session.ID, token, len(token), "")
}

// Run full analysis
analysis, err := engine.AnalyzeSession(session.ID)
if err != nil {
    log.Fatal(err)
}

// Review results
fmt.Printf("Randomness Score: %.1f/100\n", analysis.RandomnessScore)
fmt.Printf("Risk Level: %s\n", analysis.Risk)
fmt.Printf("Sample Quality: %s\n", analysis.SampleQuality)

for _, rec := range analysis.Recommendations {
    fmt.Printf("- %s\n", rec)
}
```

### Real-Time Session Management

#### `SessionManager.StartSession`

Start a new capture session.

```go
func (sm *SessionManager) StartSession(
    name string,
    extractor TokenExtractor,
    targetCount int,
    timeoutSeconds int,
) (*CaptureSession, error)
```

**Example:**
```go
manager := NewSessionManager(storage, engine, time.Now)

session, err := manager.StartSession(
    "Production Session IDs",
    TokenExtractor{
        Location: "cookie",
        Name:     "PHPSESSID",
    },
    1000,   // Stop after 1000 tokens
    3600,   // Or after 1 hour
)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Session %d started\n", session.ID)
```

#### `SessionManager.OnTokenCaptured`

Process a captured token (call from HTTP passive hook).

```go
func (sm *SessionManager) OnTokenCaptured(
    sessionID int64,
    token string,
    requestID string,
) error
```

**Example:**
```go
// In plugin's OnHTTPPassive hook
func (h *entropyHooks) OnHTTPPassive(
    ctx *pluginsdk.Context,
    event pluginsdk.HTTPPassiveEvent,
) error {
    // Extract token from response
    token := extractSessionID(event.Response)
    if token == "" {
        return nil
    }

    // Process with session manager
    err := h.sessionManager.OnTokenCaptured(
        h.activeSessionID,
        token,
        event.Request.ID,
    )
    if err != nil {
        ctx.Log.Error("Token capture failed: %v", err)
    }

    return nil
}
```

#### Session Control

```go
// Pause active session
func (sm *SessionManager) PauseSession(sessionID int64) error

// Resume paused session
func (sm *SessionManager) ResumeSession(sessionID int64) error

// Stop session (final)
func (sm *SessionManager) StopSession(sessionID int64, reason StopReason) error
```

**Example:**
```go
// Pause for manual inspection
err := manager.PauseSession(session.ID)
if err != nil {
    log.Fatal(err)
}

// ... manual inspection ...

// Resume capture
err = manager.ResumeSession(session.ID)
if err != nil {
    log.Fatal(err)
}

// Stop when done
err = manager.StopSession(session.ID, StopReasonManual)
```

---

## TypeScript IPC API

### Session Management

#### `listEntropySessions()`

Retrieve all capture sessions.

```typescript
async function listEntropySessions(): Promise<CaptureSession[]>
```

**Example:**
```typescript
import { listEntropySessions } from '../lib/ipc';

const sessions = await listEntropySessions();
console.log(`Found ${sessions.length} sessions`);
sessions.forEach(s => {
    console.log(`- ${s.name}: ${s.tokenCount} tokens (${s.status})`);
});
```

#### `startEntropySession()`

Start a new capture session.

```typescript
async function startEntropySession(
    payload: StartEntropySessionPayload
): Promise<CaptureSession>

type StartEntropySessionPayload = {
    name: string;
    extractor: TokenExtractor;
    targetCount?: number;
    timeoutSeconds?: number;
};
```

**Example:**
```typescript
import { startEntropySession } from '../lib/ipc';

const session = await startEntropySession({
    name: "Test Session",
    extractor: {
        location: "cookie",
        name: "PHPSESSID",
        pattern: ""
    },
    targetCount: 500,
    timeoutSeconds: 1800  // 30 minutes
});

console.log(`Started session ${session.id}`);
```

#### Session Controls

```typescript
async function pauseEntropySession(id: number): Promise<void>
async function resumeEntropySession(id: number): Promise<void>
async function stopEntropySession(id: number): Promise<void>
```

**Example:**
```typescript
// Pause
await pauseEntropySession(sessionId);
console.log("Session paused");

// Resume
await resumeEntropySession(sessionId);
console.log("Session resumed");

// Stop
await stopEntropySession(sessionId);
console.log("Session stopped");
```

### Analysis Results

#### `getEntropyAnalysis()`

Retrieve analysis results for a session.

```typescript
async function getEntropyAnalysis(
    sessionId: number
): Promise<EntropyAnalysis | null>
```

**Example:**
```typescript
import { getEntropyAnalysis } from '../lib/ipc';

const analysis = await getEntropyAnalysis(sessionId);
if (!analysis) {
    console.log("No analysis available yet");
    return;
}

console.log(`Randomness Score: ${analysis.randomnessScore.toFixed(1)}/100`);
console.log(`Risk Level: ${analysis.risk}`);
console.log(`Sample Quality: ${analysis.sampleQuality}`);

// Check if any tests failed
const failedTests = [];
if (!analysis.chiSquared.passed) failedTests.push("Chi-Squared");
if (!analysis.runs.passed) failedTests.push("Runs");
if (!analysis.serialCorrelation.passed) failedTests.push("Serial Correlation");
if (!analysis.spectral.passed) failedTests.push("Spectral");

if (failedTests.length > 0) {
    console.warn(`Failed tests: ${failedTests.join(", ")}`);
}

// Check for PRNG detection
if (analysis.detectedPRNG) {
    console.error(`Weak PRNG detected: ${analysis.detectedPRNG.name}`);
    console.error(`Vulnerability: ${analysis.detectedPRNG.weakness}`);
}
```

#### `getIncrementalStats()`

Get live statistics (updated during capture).

```typescript
async function getIncrementalStats(
    sessionId: number
): Promise<IncrementalStats | null>
```

**Example:**
```typescript
import { getIncrementalStats } from '../lib/ipc';

// Poll for live updates
const intervalId = setInterval(async () => {
    const stats = await getIncrementalStats(sessionId);
    if (!stats) return;

    console.log(`Tokens: ${stats.tokenCount}`);
    console.log(`Current Entropy: ${stats.currentEntropy.toFixed(2)} bits`);
    console.log(`Collisions: ${stats.collisionCount}`);
    console.log(`Reliability: ${stats.reliabilityScore.toFixed(0)}%`);

    if (stats.reliabilityScore >= 95) {
        console.log("High confidence reached!");
        clearInterval(intervalId);
    }
}, 5000);  // Update every 5 seconds
```

### Data Retrieval

#### `getTokenSamples()`

Retrieve captured tokens.

```typescript
async function getTokenSamples(
    sessionId: number,
    limit?: number
): Promise<TokenSample[]>
```

**Example:**
```typescript
import { getTokenSamples } from '../lib/ipc';

// Get first 100 tokens
const tokens = await getTokenSamples(sessionId, 100);

// Analyze token patterns manually
const tokenValues = tokens.map(t => t.tokenValue);
console.log("Sample tokens:", tokenValues.slice(0, 5));
```

### Comparison

#### `compareSessions()`

Compare multiple sessions.

```typescript
async function compareSessions(
    sessionIds: number[]
): Promise<SessionComparison[]>
```

**Example:**
```typescript
import { compareSessions } from '../lib/ipc';

const comparisons = await compareSessions([session1.id, session2.id, session3.id]);

comparisons.forEach(comp => {
    console.log(`\n${comp.sessionName}:`);
    if (comp.analysis) {
        console.log(`  Randomness: ${comp.analysis.randomnessScore.toFixed(1)}`);
        console.log(`  Risk: ${comp.analysis.risk}`);
    }

    if (comp.deltaFromBaseline) {
        const delta = comp.deltaFromBaseline;
        console.log(`  Delta from baseline:`);
        console.log(`    Randomness: ${delta.randomnessScoreDelta > 0 ? '+' : ''}${delta.randomnessScoreDelta.toFixed(1)}`);
        console.log(`    Entropy: ${delta.entropyDelta > 0 ? '+' : ''}${delta.entropyDelta.toFixed(2)}`);
    }
});
```

### Export

#### `exportEntropySession()`

Export token data (CSV/JSON).

```typescript
async function exportEntropySession(
    sessionId: number,
    format: 'csv' | 'json'
): Promise<string>
```

**Example:**
```typescript
import { exportEntropySession } from '../lib/ipc';

// Export as JSON
const jsonData = await exportEntropySession(sessionId, 'json');
const parsed = JSON.parse(jsonData);
console.log(`Exported ${parsed.tokens.length} tokens`);

// Export as CSV
const csvData = await exportEntropySession(sessionId, 'csv');
console.log(csvData);  // token,length,captured_at\n...
```

#### `exportEntropyReport()`

Export formatted report (HTML/Markdown/PDF).

```typescript
async function exportEntropyReport(
    sessionId: number,
    format: 'html' | 'markdown' | 'pdf'
): Promise<string>
```

**Example:**
```typescript
import { exportEntropyReport } from '../lib/ipc';

// Generate HTML report
const htmlReport = await exportEntropyReport(sessionId, 'html');

// Save to file
const blob = new Blob([htmlReport], { type: 'text/html' });
const url = URL.createObjectURL(blob);
const a = document.createElement('a');
a.href = url;
a.download = `entropy-report-${sessionId}.html`;
a.click();
```

---

## Data Structures

### Complete TypeScript Interfaces

```typescript
interface CaptureSession {
    id: number;
    name: string;
    extractor: TokenExtractor;
    startedAt: string;  // ISO 8601
    completedAt?: string | null;
    pausedAt?: string | null;
    tokenCount: number;
    status: 'active' | 'paused' | 'stopped';
    targetCount?: number;
    timeout?: number;
    stopReason?: 'manual' | 'target_reached' | 'timeout' | 'pattern_detected' | 'error' | null;
    lastAnalyzedAt?: string | null;
    lastAnalysisCount: number;
    analysisInterval: number;
}

interface TokenExtractor {
    pattern: string;
    location: string;  // "cookie", "header", "body"
    name: string;
}

interface EntropyAnalysis {
    captureSessionId: number;
    tokenCount: number;
    tokenLength: number;
    characterSet: string[];
    chiSquared: TestResult;
    runs: TestResult;
    serialCorrelation: TestResult;
    spectral: TestResult;
    shannonEntropy: number;
    collisionRate: number;
    bitDistribution: number[];
    detectedPRNG?: PRNGSignature | null;
    detectedPatterns: Pattern[];
    recommendations: string[];
    randomnessScore: number;
    risk: 'low' | 'medium' | 'high' | 'critical';
    confidenceLevel: number;
    reliabilityScore: number;
    tokensNeeded: number;
    sampleQuality: string;
}

interface TestResult {
    pValue: number;
    passed: boolean;
    confidence: number;
    description: string;
}

interface Pattern {
    type: string;
    confidence: number;
    description: string;
    evidence: string;
}

interface PRNGSignature {
    name: string;
    weakness: string;
    exploitHint: string;
    confidence: number;
}

interface IncrementalStats {
    tokenCount: number;
    charFrequency: Record<string, number>;
    totalChars: number;
    collisionCount: number;
    currentEntropy: number;
    minSampleSize: number;
    confidenceLevel: number;
    tokensNeeded: number;
    reliabilityScore: number;
    lastUpdated: string;
}

interface TokenSample {
    id: number;
    captureSessionId: number;
    tokenValue: string;
    tokenLength: number;
    capturedAt: string;
    sourceRequestId?: string;
}

interface SessionComparison {
    sessionId: number;
    sessionName: string;
    analysis: EntropyAnalysis | null;
    stats: IncrementalStats | null;
    deltaFromBaseline?: {
        randomnessScoreDelta: number;
        entropyDelta: number;
        collisionRateDelta: number;
    } | null;
}
```

---

## Error Handling

### Go Error Handling

```go
// Always check errors
analysis, err := engine.AnalyzeSession(sessionID)
if err != nil {
    if errors.Is(err, ErrSessionNotFound) {
        return nil, fmt.Errorf("session %d not found", sessionID)
    }
    if errors.Is(err, ErrInsufficientSamples) {
        return nil, fmt.Errorf("need at least 30 tokens, have %d", tokenCount)
    }
    return nil, fmt.Errorf("analysis failed: %w", err)
}
```

### TypeScript Error Handling

```typescript
try {
    const analysis = await getEntropyAnalysis(sessionId);
    // ... use analysis ...
} catch (error) {
    if (error instanceof Error) {
        toast.error('Analysis failed', { description: error.message });
    } else {
        toast.error('Unknown error occurred');
    }
    console.error('Entropy analysis error:', error);
}
```

---

## Complete Working Example

### Go: Analyze Tokens from File

```go
package main

import (
    "bufio"
    "fmt"
    "log"
    "os"
    "time"
)

func main() {
    // Read tokens from file
    file, err := os.Open("tokens.txt")
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()

    var tokens []string
    scanner := bufio.Scanner(file)
    for scanner.Scan() {
        tokens = append(tokens, scanner.Text())
    }

    if len(tokens) < 30 {
        log.Fatalf("Insufficient tokens: need 30+, have %d", len(tokens))
    }

    // Initialize storage and engine
    storage, err := NewStorage(":memory:")
    if err != nil {
        log.Fatal(err)
    }
    defer storage.Close()

    engine := NewEntropyEngine(storage, time.Now)

    // Create session
    session, err := storage.CreateSession("file-import", TokenExtractor{}, 0, 0)
    if err != nil {
        log.Fatal(err)
    }

    // Add tokens
    for _, token := range tokens {
        err := storage.AddTokenSample(session.ID, token, len(token), "")
        if err != nil {
            log.Printf("Warning: failed to add token: %v", err)
        }
    }

    // Analyze
    fmt.Printf("Analyzing %d tokens...\n", len(tokens))
    analysis, err := engine.AnalyzeSession(session.ID)
    if err != nil {
        log.Fatal(err)
    }

    // Print results
    fmt.Printf("\n=== Entropy Analysis Results ===\n")
    fmt.Printf("Randomness Score: %.1f/100\n", analysis.RandomnessScore)
    fmt.Printf("Risk Level: %s\n", analysis.Risk)
    fmt.Printf("Sample Quality: %s\n\n", analysis.SampleQuality)

    fmt.Println("Statistical Tests:")
    fmt.Printf("  Chi-Squared:        p=%.4f, %s\n", analysis.ChiSquared.PValue, passStatus(analysis.ChiSquared.Passed))
    fmt.Printf("  Runs Test:          p=%.4f, %s\n", analysis.Runs.PValue, passStatus(analysis.Runs.Passed))
    fmt.Printf("  Serial Correlation: p=%.4f, %s\n", analysis.SerialCorrelation.PValue, passStatus(analysis.SerialCorrelation.Passed))
    fmt.Printf("  Spectral Test:      p=%.4f, %s\n", analysis.Spectral.PValue, passStatus(analysis.Spectral.Passed))

    fmt.Printf("\nShannon Entropy: %.2f bits/char\n", analysis.ShannonEntropy)
    fmt.Printf("Collision Rate: %.2f%%\n", analysis.CollisionRate*100)

    if analysis.DetectedPRNG != nil {
        fmt.Printf("\n⚠️  WEAK PRNG DETECTED: %s\n", analysis.DetectedPRNG.Name)
        fmt.Printf("   Vulnerability: %s\n", analysis.DetectedPRNG.Weakness)
        fmt.Printf("   Exploit: %s\n", analysis.DetectedPRNG.ExploitHint)
    }

    if len(analysis.DetectedPatterns) > 0 {
        fmt.Println("\nDetected Patterns:")
        for _, pattern := range analysis.DetectedPatterns {
            fmt.Printf("  - %s (%.0f%% confidence)\n", pattern.Description, pattern.Confidence*100)
        }
    }

    fmt.Println("\nRecommendations:")
    for _, rec := range analysis.Recommendations {
        fmt.Printf("  • %s\n", rec)
    }
}

func passStatus(passed bool) string {
    if passed {
        return "✓ PASS"
    }
    return "✗ FAIL"
}
```

### TypeScript: React Component

```typescript
import { useState, useEffect } from 'react';
import {
    listEntropySessions,
    getEntropyAnalysis,
    type CaptureSession,
    type EntropyAnalysis
} from '../lib/ipc';

export function EntropyDashboard() {
    const [sessions, setSessions] = useState<CaptureSession[]>([]);
    const [selectedId, setSelectedId] = useState<number | null>(null);
    const [analysis, setAnalysis] = useState<EntropyAnalysis | null>(null);

    useEffect(() => {
        // Load sessions on mount
        loadSessions();

        // Auto-refresh every 5 seconds
        const interval = setInterval(loadSessions, 5000);
        return () => clearInterval(interval);
    }, []);

    const loadSessions = async () => {
        try {
            const data = await listEntropySessions();
            setSessions(data);
        } catch (error) {
            console.error('Failed to load sessions:', error);
        }
    };

    const handleSelectSession = async (id: number) => {
        setSelectedId(id);
        try {
            const analysisData = await getEntropyAnalysis(id);
            setAnalysis(analysisData);
        } catch (error) {
            console.error('Failed to load analysis:', error);
        }
    };

    return (
        <div className="grid grid-cols-2 gap-4">
            <div>
                <h2>Sessions</h2>
                {sessions.map(session => (
                    <div
                        key={session.id}
                        onClick={() => handleSelectSession(session.id)}
                        className={selectedId === session.id ? 'selected' : ''}
                    >
                        <h3>{session.name}</h3>
                        <p>{session.tokenCount} tokens ({session.status})</p>
                    </div>
                ))}
            </div>

            <div>
                {analysis && (
                    <>
                        <h2>Analysis Results</h2>
                        <p>Randomness Score: {analysis.randomnessScore.toFixed(1)}/100</p>
                        <p>Risk: {analysis.risk.toUpperCase()}</p>

                        {analysis.detectedPRNG && (
                            <div className="alert alert-danger">
                                <strong>Weak PRNG Detected:</strong> {analysis.detectedPRNG.name}
                                <p>{analysis.detectedPRNG.weakness}</p>
                            </div>
                        )}

                        <h3>Recommendations</h3>
                        <ul>
                            {analysis.recommendations.map((rec, i) => (
                                <li key={i}>{rec}</li>
                            ))}
                        </ul>
                    </>
                )}
            </div>
        </div>
    );
}
```

---

## Support

For questions or issues with the Entropy plugin API:

- **GitHub Issues**: https://github.com/RowanDark/0xGen/issues
- **Documentation**: https://docs.0xgen.dev/api/entropy
- **Examples**: https://github.com/RowanDark/0xGen/tree/main/examples/entropy
