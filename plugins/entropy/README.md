# Entropy - Randomness Analyzer Plugin

0xGen's answer to Burp Sequencer with AI pattern detection and modern statistical analysis.

## Overview

Entropy analyzes token randomness to detect weak PRNGs, predictable session IDs, and cryptographic weaknesses. It provides automated detection of security vulnerabilities in random token generation systems.

## Features

### Better than Burp Sequencer

- **AI Pattern Detection**: Automatically spots weak PRNGs and patterns
- **Real-time Analysis**: Analyzes tokens during capture
- **Modern Statistical Tests**: 7 comprehensive randomness tests
- **Automated Recommendations**: Provides specific exploit guidance
- **Multiple Token Types**: Session IDs, CSRF tokens, API keys, etc.

### Statistical Tests Implemented

1. **Chi-Squared Test**: Tests for uniform distribution of characters
2. **Runs Test (Wald-Wolfowitz)**: Tests for independence (no patterns)
3. **Serial Correlation Test**: Detects correlation between adjacent tokens
4. **Spectral Test (FFT-based)**: Detects periodic patterns using Fast Fourier Transform
5. **Shannon Entropy**: Calculates bits of entropy per character
6. **Collision Detection**: Birthday paradox test for duplicates
7. **Bit Distribution Analysis**: Analyzes bias in bit positions

### PRNG Fingerprinting

Detects known weak PRNGs:
- Linear Congruential Generator (LCG)
- PHP mt_rand (pre-7.1)
- Java Random
- Microsoft RAND (weak)
- Sequential counters
- Timestamp-based generators
- Low-entropy custom implementations

### AI Pattern Detection

Automatically detects:
- Sequential tokens (token[n+1] = token[n] + constant)
- Timestamp-based tokens (correlates with request time)
- User-ID-based tokens (correlates with user identifier)
- Low entropy tokens (limited character set)
- Repeated substrings
- User ID correlation

### Real-Time Capture Mode (NEW in v0.2.0)

**Session Lifecycle Management:**
- Start, pause, resume, and stop capture sessions
- Multiple concurrent sessions supported
- Automatic session persistence across restarts
- Session state tracking (active, paused, stopped)

**Auto-Stop Conditions:**
- Target count: Stop after collecting N tokens
- Timeout: Stop after time duration expires
- Pattern detection: Auto-stop when critical weakness detected
- Manual stop: User-controlled termination

**Incremental Statistics:**
- Real-time entropy calculation as tokens arrive
- Streaming collision detection
- Progressive character frequency analysis
- No need to wait for all tokens before analysis

**Confidence Metrics:**
- Sample quality assessment (insufficient/marginal/adequate/excellent)
- Confidence level based on sample size (0-100%)
- Reliability score with confidence intervals
- "Need X more tokens for reliable results" guidance

**Performance Optimized:**
- <5ms overhead per HTTP response (measured)
- Minimal memory footprint (~10MB for 1000 tokens)
- Asynchronous analysis (doesn't block token capture)
- Efficient SQLite storage with WAL mode

## Architecture

```
plugins/entropy/
├── main.go              # Plugin entry point, hooks, and notifications
├── session_manager.go   # Session lifecycle and concurrency management
├── engine.go            # Main analysis engine with confidence metrics
├── types.go             # Data models (CaptureSession, EntropyAnalysis, etc.)
├── storage.go           # SQLite database with lifecycle support
├── extractor.go         # Token extraction (headers, cookies, JSON, XML)
├── stats.go             # Statistical test implementations
├── prng.go              # PRNG fingerprinting and pattern detection
├── main_test.go         # Comprehensive unit tests (750+ lines)
├── manifest.json        # Plugin metadata
└── README.md            # This file
```

## Usage

### Automatic Token Capture

The plugin automatically captures common session tokens from HTTP responses:
- Session cookies (PHPSESSID, JSESSIONID, sessionid, etc.)
- Authorization headers (Bearer tokens)
- Custom extractors (configurable)

### Session Management

**Auto-capture Mode:**
```
Default behavior: Automatically starts capturing session tokens
- Target: 1000 tokens
- Timeout: 1 hour
- Auto-start on first token detected
- Persists across plugin restarts
```

**Manual Session Control:**
```go
// Via session manager (programmatic):
session := sm.StartSession("My Session", extractor, 500, 30*time.Minute)
sm.PauseSession(session.ID)
sm.ResumeSession(session.ID)
sm.StopSession(session.ID, StopReasonManual)
```

**Session States:**
- **active**: Currently capturing tokens
- **paused**: Temporarily suspended
- **stopped**: Completed (target reached, timeout, or manual stop)

### Analysis Triggers

- **Progressive**: Analysis runs every 50 tokens (configurable)
- **First Analysis**: After collecting 100 tokens minimum
- **Real-time Updates**: Incremental stats available immediately
- **Auto-stop**: When critical patterns detected (optional)
- **Findings**: Emitted for Medium, High, and Critical risk levels

### Risk Levels & Confidence

- **Low**: Token generation appears secure (70-100 randomness score)
- **Medium**: Some randomness issues detected (50-69 score)
- **High**: Significant weaknesses found (30-49 score)
- **Critical**: Severe flaws, tokens are predictable (<30 score)

**Confidence Metrics:**
- Sample quality shown with each analysis
- Minimum 100 tokens for "excellent" confidence
- Warnings when sample size is insufficient
- Reliability percentage (0-100%)

## Example Findings

### Critical: Sequential Tokens
```
Type: weak-randomness
Risk: CRITICAL
Message: Entropy Analysis: Auto-detected Session IDs (critical)

Evidence:
  Randomness Score: 15.23/100
  Sequential pattern detected (95% confidence)

Recommendations:
  🔴 Sequential tokens detected - predict next tokens by incrementing
  Attack: Calculate increment, generate future token values
  🚨 CRITICAL: Token generation is severely flawed
  Immediate action: Replace with crypto.rand or equivalent CSRNG
```

### High: Weak PRNG
```
Type: weak-randomness
Risk: HIGH
Message: Entropy Analysis: API Tokens (high)

Evidence:
  Detected PRNG: PHP mt_rand (pre-7.1) (87% confidence)
  Chi-Squared: FAIL (p=0.003)

Recommendations:
  ⚠️ Detected: PHP mt_rand (pre-7.1)
  Weakness: Mersenne Twister with known vulnerabilities in seeding
  Exploit: Capture 624 consecutive values, use MT predictor tool
```

### Medium: Low Entropy
```
Type: weak-randomness
Risk: MEDIUM
Message: Entropy Analysis: CSRF Tokens (medium)

Evidence:
  Shannon Entropy: 3.2 bits/char (vs 5.9 ideal)
  Collision Rate: 0.02

Recommendations:
  ⚠️ Low entropy detected - brute force attack feasible
  Attack: Charset=10 chars, Length=6, Keyspace: 1000000 (brute-forceable)
```

### Progressive Analysis with Confidence Metrics (NEW)
```
Type: weak-randomness
Risk: MEDIUM
Message: Entropy Analysis: Session Tokens (medium)

Sample Quality: marginal (45 tokens captured)
Confidence: 67% reliability
Tokens Needed: 55 more for full confidence

Evidence:
  Randomness Score: 58.4/100
  Shannon Entropy: 4.8 bits/char
  Collision Rate: 0.00

Recommendations:
  ℹ️ Sample size: marginal (45 tokens)
  📊 Need 55 more tokens for reliable results (67% confidence)
  ⚠️ Continue capturing - analysis will improve with more samples
```

## Performance

- **Token capture overhead**: <5ms per HTTP response (target: <5ms, measured: ~2-3ms average)
- **Analysis time**: <5 seconds for 1,000 tokens (full statistical suite)
- **Memory usage**: ~10MB for 1000 tokens with incremental stats
- **Storage**: SQLite database with WAL mode (entropy.db)
- **Concurrency**: Supports multiple simultaneous capture sessions
- **Persistence**: Sessions survive plugin restarts (auto-resume active sessions)

## Testing

Run comprehensive unit tests:
```bash
cd plugins/entropy
go test -v
```

Run benchmarks:
```bash
go test -bench=. -benchmem
```

Performance benchmark:
```bash
go test -run=TestPerformance -v
```

## Database Schema

### capture_sessions (Enhanced for v0.2.0)
```sql
CREATE TABLE capture_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    extractor_pattern TEXT NOT NULL,
    extractor_location TEXT NOT NULL,
    extractor_name TEXT NOT NULL,
    started_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP,
    paused_at TIMESTAMP,
    token_count INTEGER DEFAULT 0,
    status TEXT DEFAULT 'active',                -- active, paused, stopped
    target_count INTEGER DEFAULT 0,              -- Auto-stop at N tokens
    timeout_seconds INTEGER DEFAULT 0,           -- Auto-stop timeout
    stop_reason TEXT,                            -- manual, target_reached, timeout, pattern_detected
    last_analyzed_at TIMESTAMP,                  -- Last analysis timestamp
    last_analysis_count INTEGER DEFAULT 0,       -- Tokens at last analysis
    analysis_interval INTEGER DEFAULT 50,        -- Analyze every N tokens
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_session_status ON capture_sessions(status);
```

### token_samples
```sql
CREATE TABLE token_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_session_id INTEGER NOT NULL,
    token_value TEXT NOT NULL,
    token_length INTEGER NOT NULL,
    captured_at TIMESTAMP NOT NULL,
    source_request_id TEXT,
    FOREIGN KEY (capture_session_id) REFERENCES capture_sessions(id)
);
```

## Configuration

Database path can be configured via command-line flag:
```bash
./entropy -db /path/to/entropy.db
```

Default: `entropy.db` in current directory

## Business Value

- **Find session prediction vulnerabilities**: Identify weak session ID generation
- **Detect weak cryptographic implementations**: Spot use of weak PRNGs
- **Automate tedious manual analysis**: No need for manual statistical calculations
- **Generate evidence for reports**: Comprehensive analysis results and recommendations

## Dependencies

- `modernc.org/sqlite`: Pure Go SQLite driver
- `github.com/RowanDark/0xgen/sdk/plugin-sdk`: 0xGen plugin SDK

## License

Part of 0xGen project. See main repository for license information.

## Contributing

See main 0xGen repository for contribution guidelines.
