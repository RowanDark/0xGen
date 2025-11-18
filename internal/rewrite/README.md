# Rewrite Engine - Traffic Transformation Rules

## Overview

The Rewrite engine is 0xGen's powerful traffic transformation system - a sophisticated alternative to Burp Suite's Match/Replace functionality. It provides:

- **Visual rule builder** - Structured rule definition (drag-and-drop UI to be added in #16.2)
- **Variable extraction and reuse** - Capture values from one request and inject into another
- **Conditional rules** - If-then-else logic with multiple condition types
- **Rule testing sandbox** - Preview changes before applying (UI in #16.3)
- **Rule library** - Import/export/share rules as JSON
- **Performance optimized** - Minimal proxy overhead (<10ms per request)

## Architecture

The Rewrite engine consists of several components:

1. **Rule Data Model** (`types.go`) - Defines rule structure with scope, conditions, and actions
2. **Variable System** (`variables.go`) - Manages variable storage, extraction, and substitution
3. **Rule Matcher** (`matcher.go`) - Evaluates conditions to determine if rules apply
4. **Rule Executor** (`executor.go`) - Executes actions on matching requests/responses
5. **Engine** (`engine.go`) - Orchestrates all components and manages rule lifecycle
6. **Storage** (`storage.go`) - Persists rules in SQLite database

## Quick Start

### Creating a Rewrite Engine

```go
package main

import (
    "log"
    "log/slog"

    "github.com/RowanDark/0xgen/internal/rewrite"
)

func main() {
    config := rewrite.Config{
        DatabasePath: "/path/to/rules.db",
        Logger:       slog.Default(),
    }

    engine, err := rewrite.NewEngine(config)
    if err != nil {
        log.Fatal(err)
    }
    defer engine.Close()

    // Engine is ready to use
}
```

### Creating Rules

#### Example 1: Add Custom Header

```go
rule := &rewrite.Rule{
    Name:        "add-api-key",
    Description: "Add API key to all API requests",
    Enabled:     true,
    Priority:    100,

    Scope: rewrite.RuleScope{
        Direction:  rewrite.DirectionRequest,
        URLPattern: `^https://api\.example\.com/.*`,
    },

    Actions: []rewrite.Action{
        {
            Type:     rewrite.ActionAdd,
            Location: rewrite.LocationHeader,
            Name:     "X-API-Key",
            Value:    "secret-key-123",
        },
    },
}

err := engine.CreateRule(context.Background(), rule)
```

#### Example 2: Extract and Reuse Token

```go
// Rule 1: Extract token from login response
extractRule := &rewrite.Rule{
    Name:     "extract-token",
    Enabled:  true,
    Priority: 100,

    Scope: rewrite.RuleScope{
        Direction:  rewrite.DirectionResponse,
        URLPattern: `.*/login$`,
    },

    Conditions: []rewrite.Condition{
        {
            Type:     rewrite.ConditionContains,
            Location: rewrite.LocationBody,
            Pattern:  "token",
        },
    },

    Actions: []rewrite.Action{
        {
            Type:      rewrite.ActionExtract,
            Location:  rewrite.LocationBody,
            Pattern:   `"token":"(?P<auth_token>[^"]+)"`,
            ExtractTo: "auth_token",
        },
    },
}

// Rule 2: Inject token into subsequent requests
injectRule := &rewrite.Rule{
    Name:     "inject-token",
    Enabled:  true,
    Priority: 50,

    Scope: rewrite.RuleScope{
        Direction:  rewrite.DirectionRequest,
        URLPattern: `^https://api\.example\.com/.*`,
    },

    Actions: []rewrite.Action{
        {
            Type:     rewrite.ActionAdd,
            Location: rewrite.LocationHeader,
            Name:     "Authorization",
            Value:    "Bearer ${auth_token}",  // Variable substitution
        },
    },
}
```

#### Example 3: Replace Values with Regex

```go
rule := &rewrite.Rule{
    Name:     "mask-email",
    Enabled:  true,
    Priority: 10,

    Scope: rewrite.RuleScope{
        Direction: rewrite.DirectionResponse,
    },

    Actions: []rewrite.Action{
        {
            Type:     rewrite.ActionReplace,
            Location: rewrite.LocationBody,
            Pattern:  `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
            Value:    "***@***.***",
        },
    },
}
```

#### Example 4: Conditional Transformation

```go
rule := &rewrite.Rule{
    Name:     "encode-payload",
    Enabled:  true,
    Priority: 50,

    Scope: rewrite.RuleScope{
        Direction: rewrite.DirectionRequest,
        Methods:   []string{"POST", "PUT"},
    },

    Conditions: []rewrite.Condition{
        {
            Type:     rewrite.ConditionExists,
            Location: rewrite.LocationHeader,
            Name:     "X-Encode-Payload",
        },
    },

    Actions: []rewrite.Action{
        {
            Type:      rewrite.ActionTransform,
            Location:  rewrite.LocationBody,
            Transform: "base64",
            Name:      "encoded_payload", // Store in variable
        },
        {
            Type:     rewrite.ActionReplace,
            Location: rewrite.LocationBody,
            Pattern:  ".*",
            Value:    "${encoded_payload}",
        },
    },
}
```

### Processing Requests

```go
// Process request through rewrite engine
func handleRequest(req *http.Request) (*http.Request, error) {
    return engine.ProcessRequest(req)
}

// Process response through rewrite engine
func handleResponse(resp *http.Response) (*http.Response, error) {
    return engine.ProcessResponse(resp)
}
```

## Rule Components

### Scope

Determines when a rule should be evaluated:

- **Direction**: `DirectionRequest`, `DirectionResponse`, or `DirectionBoth`
- **Methods**: HTTP methods to match (e.g., `["GET", "POST"]`)
- **URLPattern**: Regex pattern for URL matching
- **ContentType**: Regex pattern for Content-Type header

### Conditions

Multiple condition types are supported:

- `ConditionMatch` - Exact string match
- `ConditionNotMatch` - Not equal
- `ConditionContains` - Contains substring
- `ConditionRegex` - Regex pattern match
- `ConditionJSONPath` - JSON path exists
- `ConditionXPath` - XPath exists (future)
- `ConditionLength` - Length comparison (e.g., `>100`, `<=50`)
- `ConditionExists` - Header/cookie exists

Each condition can be negated with the `Negate` field.

### Actions

Actions define what to do when a rule matches:

- `ActionReplace` - Replace content (supports regex)
- `ActionRemove` - Remove header/cookie/parameter
- `ActionAdd` - Add header/cookie/parameter
- `ActionExtract` - Extract value to variable (supports named groups)
- `ActionTransform` - Apply transformation (base64, url, html, md5, sha256, etc.)
- `ActionSetVariable` - Set variable directly
- `ActionComputeHash` - Compute hash of value

### Locations

Where to operate:

- `LocationHeader` - HTTP header
- `LocationCookie` - Cookie value
- `LocationBody` - Request/response body
- `LocationURL` - Full URL
- `LocationPath` - URL path
- `LocationQuery` - Query parameter
- `LocationStatus` - Response status code
- `LocationMethod` - Request method

## Variable System

### Built-in Variables

- `${timestamp}` - Current Unix timestamp
- `${timestamp_ms}` - Current Unix timestamp in milliseconds
- `${random}` - Random 16-character string
- `${uuid}` - Random UUID
- `${request.method}` - Current request method
- `${request.url}` - Current request URL

### Variable Scopes

- **Global** - Persists across all requests
- **Session** - Per-session (future enhancement)
- **Request** - Single request only

### Variable Substitution

Variables can be used in action values with special syntax:

- `${varname}` - Simple substitution
- `${varname:default}` - With default value
- `${varname|transform}` - With transformation
- `${varname:default|transform}` - Both

Example: `"Bearer ${token:guest123|base64}"`

### Transformations

Available transformations:

- **Encoding**: `base64`, `url`, `html`, `hex`
- **Decoding**: `base64_decode`, `url_decode`, `html_decode`, `hex_decode`
- **Hashing**: `md5`, `sha1`, `sha256`
- **String**: `uppercase`, `lowercase`

## Rule Management API

```go
// Create rule
err := engine.CreateRule(ctx, rule)

// Get rule by ID
rule, err := engine.GetRule(ctx, ruleID)

// Update rule
err := engine.UpdateRule(ctx, rule)

// Delete rule
err := engine.DeleteRule(ctx, ruleID)

// List all rules
rules, err := engine.ListRules(ctx)

// Enable/disable rules
err := engine.EnableRule(ctx, ruleID)
err := engine.DisableRule(ctx, ruleID)

// Import/export rules
err := engine.ImportRules(ctx, rules)
rules, err := engine.ExportRules(ctx)
```

## Performance Metrics

The engine tracks performance metrics:

```go
metrics := engine.GetMetrics()

fmt.Printf("Total Requests: %d\n", metrics.TotalRequests)
fmt.Printf("Total Responses: %d\n", metrics.TotalResponses)
fmt.Printf("Rules Applied: %d\n", metrics.RulesApplied)
fmt.Printf("Average Latency: %v\n", metrics.AverageLatency)

// Slow rules (>50ms) are automatically logged
for ruleID, latency := range metrics.SlowRules {
    fmt.Printf("Rule %d: %v\n", ruleID, latency)
}
```

## Integration with Proxy

The engine integrates seamlessly with 0xGen's proxy:

```go
// In proxy.go
type Proxy struct {
    // ... existing fields ...
    rewrite *rewrite.Engine
}

// Process request
func (p *Proxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
    // Apply rewrite rules to request
    req, err := p.rewrite.ProcessRequest(req)
    if err != nil {
        // Handle error
    }

    // ... existing proxy logic ...

    // Apply rewrite rules to response
    resp, err := p.rewrite.ProcessResponse(resp)
    if err != nil {
        // Handle error
    }
}
```

## Testing

Comprehensive unit tests are provided for all components:

```bash
go test ./internal/rewrite/... -v
```

### Performance Benchmark

```bash
go test ./internal/rewrite/... -bench=. -benchmem
```

Target performance with 100 active rules: <50ms total overhead per request.

## Future Enhancements

The following features are planned for subsequent issues:

- **Issue #16.2**: Visual GUI rule builder with drag-and-drop
- **Issue #16.3**: Testing sandbox for previewing rule changes
- **Issue #16.4**: Advanced features (rule library, sharing, templates)
- **Issue #16.5**: Performance optimizations and caching

## Examples

See `examples/rewrite/` directory for complete working examples:

- `basic_rules.json` - Simple rule examples
- `advanced_rules.json` - Complex conditional rules
- `api_testing.json` - API testing automation rules
- `security_bypass.json` - Security testing rules

## License

Part of 0xGen project.
