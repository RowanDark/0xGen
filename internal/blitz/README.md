# Blitz - AI-Powered Fuzzer

Blitz is 0xGen's answer to Burp Intruder, featuring AI-enhanced payload selection and real-time anomaly detection. It's designed to be significantly better than Burp Intruder while remaining free and open-source.

## Features

### Core Capabilities

- **4 Attack Types**: Sniper, Battering Ram, Pitchfork, and Cluster Bomb
- **Smart Payload Generators**: Support for wordlists (txt, csv, json), ranges (numeric and character), and regex patterns
- **Concurrent Execution**: Handle 100+ concurrent requests with configurable rate limiting
- **Real-time Anomaly Detection**: Automatically identify interesting responses based on status codes, response times, and content length deviations
- **Pattern Matching**: Regex-based pattern matching for finding sensitive data and error messages
- **SQLite Storage**: Persistent storage of all results with queryable database
- **Multiple Export Formats**: CSV, JSON, and beautiful HTML reports

### Advanced Features

- **Retry Logic**: Configurable retry attempts with exponential backoff
- **Response Analysis**: Track baseline metrics and detect deviations
- **Result Correlation**: Store and query results by various criteria
- **Progress Tracking**: Real-time progress updates during fuzzing

## Architecture

### Components

1. **Template System** (`template.go`)
   - Parse HTTP request templates with insertion markers
   - Support for custom marker delimiters (default: `{{}}`, also supports Burp-style `§§`)
   - Multiple position rendering strategies

2. **Attack Types** (`attack_types.go`)
   - **Sniper**: Targets one position at a time
   - **Battering Ram**: Uses same payload across all positions
   - **Pitchfork**: Pairs payloads from multiple lists in parallel
   - **Cluster Bomb**: Tests all possible payload combinations

3. **Payload Generators** (`payloads.go`)
   - **WordlistGenerator**: Load from txt, csv, or json files
   - **RangeGenerator**: Generate numeric (1-100) or character (a-z) ranges
   - **RegexGenerator**: Generate payloads from regex patterns
   - **StaticGenerator**: Use a fixed list of payloads

4. **Response Analyzer** (`analyzer.go`)
   - Baseline metric tracking
   - Status code anomaly detection
   - Content length deviation analysis
   - Response time anomaly detection
   - Regex pattern matching

5. **Storage System** (`storage.go`)
   - SQLite database with WAL mode for concurrency
   - Indexed queries for fast filtering
   - Session-based result organization

6. **Export System** (`export.go`)
   - CSV export for data analysis
   - JSON export for programmatic processing
   - HTML reports with beautiful UI

7. **Fuzzing Engine** (`engine.go`)
   - Worker pool for concurrent execution
   - Rate limiting and retry logic
   - Real-time result processing

## Usage

### Basic Example

```bash
# Simple sniper attack with wordlist
0xgenctl blitz run \
  --req request.txt \
  --payloads wordlist.txt \
  --attack sniper \
  --concurrency 10
```

### Request Template Format

Create a file with your HTTP request and use `{{}}` markers for insertion points:

```http
GET /api/user/{{id}}/profile HTTP/1.1
Host: example.com
X-API-Key: {{api_key}}
User-Agent: Mozilla/5.0

```

### Attack Types

#### Sniper
One position at a time with all payloads:
```bash
0xgenctl blitz run --req request.txt --payloads wordlist.txt --attack sniper
```

#### Battering Ram
Same payload in all positions:
```bash
0xgenctl blitz run --req request.txt --payloads wordlist.txt --attack battering-ram
```

#### Pitchfork
Pair payloads from multiple lists:
```bash
0xgenctl blitz run --req request.txt \
  --payload1 usernames.txt \
  --payload2 passwords.txt \
  --attack pitchfork
```

#### Cluster Bomb
All combinations (cartesian product):
```bash
0xgenctl blitz run --req request.txt \
  --payload1 ids.txt \
  --payload2 tokens.txt \
  --attack cluster-bomb
```

### Advanced Options

```bash
0xgenctl blitz run \
  --req request.txt \
  --payloads wordlist.txt \
  --attack sniper \
  --concurrency 50 \
  --rate 100 \
  --retries 3 \
  --patterns "error,exception,SQL" \
  --anomaly \
  --output results.db \
  --export-html report.html
```

### Payload Sources

**Wordlist file:**
```bash
--payloads /path/to/wordlist.txt
```

**Numeric range:**
```bash
--payloads "1-1000"
```

**Character range:**
```bash
--payloads "a-z"
```

**Comma-separated list:**
```bash
--payloads "admin,user,guest"
```

**CSV file (specific column):**
```bash
--payloads users.csv
```

**JSON array:**
```bash
--payloads data.json
```

### Pattern Matching

Add regex patterns to search in responses:

```bash
--patterns "(?i)error,SQL.*syntax,password.*incorrect"
```

Common patterns are built-in for detecting:
- Error messages
- SQL errors
- Stack traces
- Email addresses
- Credit card numbers
- SSNs

### Export Results

Export during fuzzing:
```bash
--export-csv results.csv \
--export-json results.json \
--export-html report.html
```

Or export later from database:
```bash
0xgenctl blitz export \
  --db results.db \
  --format html \
  --output report.html
```

## API Usage

### Programmatic Usage

```go
package main

import (
    "context"
    "fmt"
    "github.com/RowanDark/0xgen/internal/blitz"
)

func main() {
    // Parse request template
    markers, _ := blitz.ParseMarkers("{{}}")
    request, _ := blitz.ParseRequest(requestTemplate, markers)

    // Create payload generator
    gen := blitz.NewStaticGenerator("test", []string{"payload1", "payload2"})

    // Configure analyzer
    analyzerConfig := &blitz.AnalyzerConfig{
        EnableAnomalyDetection: true,
    }

    // Create storage
    storage, _ := blitz.NewSQLiteStorage("results.db")
    defer storage.Close()

    // Configure engine
    config := &blitz.EngineConfig{
        Request:     request,
        AttackType:  blitz.AttackTypeSniper,
        Generators:  []blitz.PayloadGenerator{gen},
        Concurrency: 10,
        Analyzer:    analyzerConfig,
        Storage:     storage,
    }

    // Create and run engine
    engine, _ := blitz.NewEngine(config)

    err := engine.Run(context.Background(), func(result *blitz.FuzzResult) error {
        if result.Anomaly != nil && result.Anomaly.IsInteresting {
            fmt.Printf("Found anomaly: %s\n", result.Payload)
        }
        return nil
    })

    if err != nil {
        panic(err)
    }

    // Get statistics
    stats, _ := storage.GetStats()
    fmt.Printf("Total requests: %d\n", stats.TotalRequests)
    fmt.Printf("Anomalies: %d\n", stats.AnomalyCount)
}
```

## Performance

- Handles 100+ concurrent requests without crashes
- SQLite WAL mode for concurrent writes
- Configurable rate limiting per host
- Memory-efficient result streaming
- Retry logic for transient failures

## Comparison with Burp Intruder

| Feature | Blitz | Burp Intruder |
|---------|-------|---------------|
| **Price** | Free | $449/year (Pro) |
| **Attack Types** | 4 (all) | 4 (1 free) |
| **Concurrency** | 100+ | Limited in Free |
| **Anomaly Detection** | Built-in AI | Manual |
| **Pattern Matching** | Regex built-in | Limited |
| **Storage** | SQLite | Memory |
| **Export Formats** | CSV, JSON, HTML | Limited |
| **CLI** | Full CLI | GUI only |
| **Scriptable** | Go API | Extensions |

## Future Enhancements (Phase 3+)

- AI-powered payload generation
- Smart payload selection based on response patterns
- Distributed fuzzing across multiple workers
- Real-time UI for live monitoring
- Integration with finding correlation system
- Custom scripting for advanced logic

## License

Part of the 0xGen project. See main LICENSE file.
