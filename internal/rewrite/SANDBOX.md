# Rewrite Testing Sandbox

## Overview

The Rewrite Testing Sandbox provides an isolated environment for testing rules before applying them to live traffic. It enables you to:

- **Test rules safely** without affecting production traffic
- **Preview changes** with detailed before/after comparison
- **Validate rules** for common mistakes and performance issues
- **Save test cases** for regression testing
- **Track execution** with detailed logging

## Quick Start

```go
// Create sandbox
sandbox := rewrite.NewSandbox(engine, logger)

// Test a request
input := &rewrite.TestRequestInput{
    Method: "GET",
    URL:    "https://api.example.com/users",
    Headers: map[string]string{
        "Authorization": "Bearer token123",
    },
    Body: "",
}

result, err := sandbox.TestRequest(ctx, input, ruleIDs)
if err != nil {
    log.Fatal(err)
}

// Check results
fmt.Printf("Success: %v\n", result.Success)
fmt.Printf("Rules executed: %d\n", result.ExecutionLog.RulesExecuted)
fmt.Printf("Rules matched: %d\n", result.ExecutionLog.RulesMatched)
fmt.Printf("Actions applied: %d\n", result.ExecutionLog.ActionsApplied)
fmt.Printf("Duration: %v\n", result.Duration)
```

## Components

### 1. Sandbox Environment

The sandbox provides isolated rule execution:

```go
type Sandbox struct {
    engine    *Engine
    logger    *slog.Logger
    validator *Validator
}
```

#### Testing Requests

```go
input := &TestRequestInput{
    Method:  "POST",
    URL:     "https://api.example.com/data",
    Headers: map[string]string{
        "Content-Type": "application/json",
        "User-Agent":   "TestClient/1.0",
    },
    Body: `{"key":"value"}`,
}

// Test specific rules
result, err := sandbox.TestRequest(ctx, input, []int{1, 2, 3})

// Test all active rules
result, err := sandbox.TestRequest(ctx, input, nil)
```

#### Testing Responses

```go
input := &TestResponseInput{
    StatusCode: 200,
    Headers: map[string]string{
        "Content-Type": "application/json",
        "Server":       "nginx/1.18.0",
    },
    Body: `{"status":"ok"}`,
}

result, err := sandbox.TestResponse(ctx, input, ruleIDs)
```

### 2. Execution Log

Track exactly what each rule did:

```go
type ExecutionLog struct {
    Steps          []ExecutionStep
    TotalDuration  time.Duration
    RulesExecuted  int
    RulesMatched   int
    ActionsApplied int
    Variables      map[string]string
    Errors         []string
}

type ExecutionStep struct {
    RuleID         int
    RuleName       string
    Priority       int
    Matched        bool
    MatchReason    string // Why it matched/didn't match
    ActionsApplied []ActionResult
    Variables      map[string]string
    Duration       time.Duration
    Errors         []string
}

type ActionResult struct {
    ActionType ActionType
    Location   Location
    Name       string
    OldValue   string
    NewValue   string
    Success    bool
    Error      string
}
```

#### Example Usage

```go
for _, step := range result.ExecutionLog.Steps {
    fmt.Printf("Rule: %s (priority %d)\n", step.RuleName, step.Priority)

    if step.Matched {
        fmt.Printf("  ✓ Matched: %s\n", step.MatchReason)
        fmt.Printf("  Applied %d actions in %v\n",
            len(step.ActionsApplied), step.Duration)

        for _, action := range step.ActionsApplied {
            if action.Success {
                fmt.Printf("    - %s %s[%s]: %s → %s\n",
                    action.ActionType, action.Location, action.Name,
                    action.OldValue, action.NewValue)
            } else {
                fmt.Printf("    - %s failed: %s\n",
                    action.ActionType, action.Error)
            }
        }
    } else {
        fmt.Printf("  ✗ Not matched: %s\n", step.MatchReason)
    }
}
```

### 3. Diff Comparison

See exactly what changed:

```go
type DiffResult struct {
    HeaderChanges  []HeaderDiff
    BodyChanged    bool
    BodyDiff       string
    URLChanged     bool
    URLDiff        string
    StatusChanged  bool
    OldStatus      int
    NewStatus      int
}

type HeaderDiff struct {
    Name     string
    OldValue string
    NewValue string
    Action   string // "added", "removed", "modified"
}
```

#### Example Usage

```go
if !result.Diff.IsEmpty() {
    fmt.Println("Changes detected:")

    // Header changes
    for _, h := range result.Diff.HeaderChanges {
        switch h.Action {
        case "added":
            fmt.Printf("  + Header %s: %s\n", h.Name, h.NewValue)
        case "removed":
            fmt.Printf("  - Header %s: %s\n", h.Name, h.OldValue)
        case "modified":
            fmt.Printf("  ~ Header %s: %s → %s\n",
                h.Name, h.OldValue, h.NewValue)
        }
    }

    // Body changes
    if result.Diff.BodyChanged {
        fmt.Println("\nBody diff:")
        fmt.Println(result.Diff.BodyDiff)
    }

    // URL changes
    if result.Diff.URLChanged {
        fmt.Println("\nURL diff:")
        fmt.Println(result.Diff.URLDiff)
    }

    // Status changes
    if result.Diff.StatusChanged {
        fmt.Printf("\nStatus: %d → %d\n",
            result.Diff.OldStatus, result.Diff.NewStatus)
    }
}
```

### 4. Validation & Warnings

Detect common mistakes automatically:

```go
type ValidationError struct {
    RuleID      int
    RuleName    string
    Severity    Severity    // error, warning, info
    Type        ErrorType   // regex, conflict, performance, etc.
    Message     string
    Suggestion  string
    Location    string
}
```

#### Warning Types

**1. Regex Errors**
- Invalid syntax
- Overly broad patterns (`.*`, `.+`)
- Catastrophic backtracking risks

**2. Logic Issues**
- Contradictory conditions
- Conflicting actions (add + remove same header)
- Potential infinite loops

**3. Performance Warnings**
- Complex regex patterns
- Body operations on large responses
- Nested quantifiers

**4. Security Warnings**
- Hardcoded secrets
- Removing security headers
- Unsafe transformations

#### Example Usage

```go
if len(result.Warnings) > 0 {
    fmt.Println("\n⚠️  Warnings:")

    for _, w := range result.Warnings {
        icon := "ℹ️"
        switch w.Severity {
        case SeverityError:
            icon = "❌"
        case SeverityWarning:
            icon = "⚠️"
        }

        fmt.Printf("%s [%s] %s\n", icon, w.Type, w.Message)

        if w.Location != "" {
            fmt.Printf("   Location: %s\n", w.Location)
        }

        if w.Suggestion != "" {
            fmt.Printf("   Suggestion: %s\n", w.Suggestion)
        }
    }
}
```

### 5. Test Case Management

Save and rerun tests for regression testing:

```go
// Create test case manager
manager := rewrite.NewTestCaseManager(storage, sandbox, logger)

// Create a test case
testCase := &rewrite.TestCase{
    Name:        "test-api-auth",
    Description: "Test API authentication header injection",
    Type:        rewrite.TestCaseTypeRequest,
    Input: &rewrite.TestRequestInput{
        Method:  "GET",
        URL:     "https://api.example.com/users",
        Headers: map[string]string{},
        Body:    "",
    },
    ExpectedOutput: &rewrite.TestRequestInput{
        Method: "GET",
        URL:    "https://api.example.com/users",
        Headers: map[string]string{
            "Authorization": "Bearer token123",
        },
        Body: "",
    },
    RuleIDs: []int{authRule.ID},
    Tags:    []string{"api", "auth"},
}

// Save test case
err := manager.CreateTestCase(ctx, testCase)

// Run single test case
result, err := manager.RunTestCase(ctx, testCase.ID)
if result.Passed {
    fmt.Println("✓ Test passed")
} else {
    fmt.Printf("✗ Test failed:\n")
    for _, failure := range result.Failures {
        fmt.Printf("  - %s\n", failure)
    }
}

// Run all test cases
results, err := manager.RunAllTestCases(ctx)
passed := 0
failed := 0
for _, r := range results {
    if r.Passed {
        passed++
    } else {
        failed++
    }
}
fmt.Printf("Results: %d passed, %d failed\n", passed, failed)
```

## Complete Example

```go
package main

import (
    "context"
    "fmt"
    "log"
    "log/slog"

    "github.com/RowanDark/0xgen/internal/rewrite"
)

func main() {
    // Create engine
    config := rewrite.Config{
        DatabasePath: "rules.db",
        Logger:       slog.Default(),
    }

    engine, err := rewrite.NewEngine(config)
    if err != nil {
        log.Fatal(err)
    }
    defer engine.Close()

    // Create sandbox
    sandbox := rewrite.NewSandbox(engine, config.Logger)

    ctx := context.Background()

    // Create a rule to test
    rule := &rewrite.Rule{
        Name:        "inject-api-key",
        Description: "Add API key to requests",
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

    err = engine.CreateRule(ctx, rule)
    if err != nil {
        log.Fatal(err)
    }

    // Test the rule
    input := &rewrite.TestRequestInput{
        Method: "GET",
        URL:    "https://api.example.com/users",
        Headers: map[string]string{
            "User-Agent": "TestClient/1.0",
        },
        Body: "",
    }

    result, err := sandbox.TestRequest(ctx, input, nil)
    if err != nil {
        log.Fatal(err)
    }

    // Print results
    fmt.Printf("=== Sandbox Test Results ===\n")
    fmt.Printf("Success: %v\n", result.Success)
    fmt.Printf("Duration: %v\n", result.Duration)
    fmt.Printf("\n")

    // Execution log
    fmt.Printf("=== Execution Log ===\n")
    fmt.Printf("Rules executed: %d\n", result.ExecutionLog.RulesExecuted)
    fmt.Printf("Rules matched: %d\n", result.ExecutionLog.RulesMatched)
    fmt.Printf("Actions applied: %d\n", result.ExecutionLog.ActionsApplied)
    fmt.Printf("\n")

    for _, step := range result.ExecutionLog.Steps {
        fmt.Printf("Rule: %s\n", step.RuleName)
        if step.Matched {
            fmt.Printf("  ✓ Matched (%s)\n", step.MatchReason)
            for _, action := range step.ActionsApplied {
                if action.Success {
                    fmt.Printf("    %s %s[%s]: '%s' → '%s'\n",
                        action.ActionType, action.Location, action.Name,
                        action.OldValue, action.NewValue)
                }
            }
        } else {
            fmt.Printf("  ✗ Not matched (%s)\n", step.MatchReason)
        }
    }
    fmt.Printf("\n")

    // Diff
    if !result.Diff.IsEmpty() {
        fmt.Printf("=== Changes ===\n")
        for _, h := range result.Diff.HeaderChanges {
            switch h.Action {
            case "added":
                fmt.Printf("+ Header %s: %s\n", h.Name, h.NewValue)
            case "removed":
                fmt.Printf("- Header %s: %s\n", h.Name, h.OldValue)
            case "modified":
                fmt.Printf("~ Header %s: %s → %s\n",
                    h.Name, h.OldValue, h.NewValue)
            }
        }
        fmt.Printf("\n")
    }

    // Warnings
    if len(result.Warnings) > 0 {
        fmt.Printf("=== Warnings ===\n")
        for _, w := range result.Warnings {
            fmt.Printf("[%s] %s\n", w.Type, w.Message)
            if w.Suggestion != "" {
                fmt.Printf("  Suggestion: %s\n", w.Suggestion)
            }
        }
        fmt.Printf("\n")
    }

    // Modified output
    fmt.Printf("=== Modified Request ===\n")
    fmt.Printf("%v\n", result.ModifiedInput)
}
```

## Performance

The sandbox is designed to complete tests in <1 second:

- Rule execution is the same as production (minimal overhead)
- Diff generation is optimized for common cases
- Validation runs in parallel where possible
- Test cases are cached for quick re-execution

## Best Practices

1. **Test Before Deploy**
   - Always test rules in sandbox before enabling
   - Use multiple test inputs to cover edge cases
   - Save test cases for regression testing

2. **Review Warnings**
   - Address all errors before enabling rules
   - Consider warnings seriously (performance, security)
   - Use suggestions to improve rules

3. **Use Expected Outputs**
   - Define expected outputs for critical test cases
   - Run tests after rule modifications
   - Fail builds if tests don't pass

4. **Monitor Performance**
   - Check execution duration for each rule
   - Optimize slow rules (>50ms)
   - Use simpler patterns where possible

5. **Organize Test Cases**
   - Group related tests with tags
   - Name tests descriptively
   - Document expected behavior

## Integration with CI/CD

```bash
# Run all test cases
0xgenctl rewrite test run-all

# Run specific test case
0xgenctl rewrite test run --id 123

# Run tests for specific rule
0xgenctl rewrite test run --rule-id 456

# Fail if any test fails (for CI)
0xgenctl rewrite test run-all --fail-fast
```

## Future Enhancements

Planned for upcoming issues:

- **Issue #16.3**: Visual GUI for sandbox testing
- **Issue #16.4**: Test case templates and sharing
- **Advanced diff**: Integration with Delta engine for better diffs
- **Performance profiling**: Detailed timing breakdown
- **Fuzzing**: Automatic generation of test inputs

## See Also

- [Rewrite Core Engine](README.md)
- [Rule Syntax Guide](RULES.md)
- [Variable System](VARIABLES.md)
