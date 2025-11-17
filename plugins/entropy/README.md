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

## Architecture

```
plugins/entropy/
├── main.go          # Plugin entry point and hooks
├── engine.go        # Main analysis engine
├── types.go         # Data models and types
├── storage.go       # SQLite database layer
├── extractor.go     # Token extraction (headers, cookies, JSON, XML)
├── stats.go         # Statistical test implementations
├── prng.go          # PRNG fingerprinting and pattern detection
├── main_test.go     # Comprehensive unit tests
├── manifest.json    # Plugin metadata
└── README.md        # This file
```

## Usage

### Automatic Token Capture

The plugin automatically captures common session tokens from HTTP responses:
- Session cookies (PHPSESSID, JSESSIONID, sessionid, etc.)
- Authorization headers (Bearer tokens)
- Custom extractors (configurable)

### Analysis Triggers

- Analysis runs automatically after collecting 100 tokens
- Continues analysis every 50 tokens thereafter
- Emits findings for Medium, High, and Critical risk levels

### Risk Levels

- **Low**: Token generation appears secure
- **Medium**: Some randomness issues detected
- **High**: Significant weaknesses found
- **Critical**: Severe flaws, tokens are predictable

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

## Performance

- **Analysis time**: <5 seconds for 1,000 tokens (tested)
- **Memory usage**: Minimal (~10MB for 1000 tokens)
- **Storage**: SQLite database (entropy.db)

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

### capture_sessions
```sql
CREATE TABLE capture_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    extractor_pattern TEXT NOT NULL,
    extractor_location TEXT NOT NULL,
    extractor_name TEXT NOT NULL,
    started_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP,
    token_count INTEGER DEFAULT 0
);
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
