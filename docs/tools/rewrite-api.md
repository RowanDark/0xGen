# Rewrite API Documentation

## Overview

The Rewrite API provides programmatic access to the traffic transformation engine. This documentation is intended for plugin developers and integrators.

## Plugin API

### Go Interface

```go
package rewrite

// RewriteAPI provides programmatic access to rule management
type RewriteAPI interface {
    // Rule Management
    CreateRule(rule *Rule) (id int, err error)
    GetRule(id int) (*Rule, error)
    UpdateRule(rule *Rule) error
    DeleteRule(id int) error
    ListRules(includeDisabled bool) ([]*Rule, error)

    // Rule Control
    EnableRule(id int) error
    DisableRule(id int) error

    // Testing
    TestRule(rule *Rule, req *http.Request) (*ExecutionLog, error)
    TestRuleOnResponse(rule *Rule, resp *http.Response) (*ExecutionLog, error)

    // Import/Export
    ImportRules(rules []*Rule) (imported int, err error)
    ExportRules() ([]*Rule, error)

    // Metrics
    GetMetrics() (*Metrics, error)
}
```

### Usage Example

```go
package main

import (
    "github.com/RowanDark/0xgen/internal/rewrite"
)

func main() {
    // Initialize engine
    engine, err := rewrite.NewEngine("./rewrite.db")
    if err != nil {
        panic(err)
    }
    defer engine.Close()

    // Create a rule
    rule := &rewrite.Rule{
        Name:        "Add Custom Header",
        Description: "Adds X-Custom header to all requests",
        Enabled:     true,
        Priority:    10,
        Scope: rewrite.RuleScope{
            Direction:  rewrite.DirectionRequest,
            URLPattern: ".*",
        },
        Actions: []rewrite.Action{
            {
                Type:     rewrite.ActionAdd,
                Location: rewrite.LocationHeader,
                Name:     "X-Custom",
                Value:    "custom-value",
            },
        },
    }

    id, err := engine.CreateRule(rule)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Created rule with ID: %d\n", id)
}
```

## Data Structures

### Rule

```go
type Rule struct {
    ID          int         `json:"id"`
    Name        string      `json:"name"`
    Description string      `json:"description"`
    Enabled     bool        `json:"enabled"`
    Priority    int         `json:"priority"`
    Scope       RuleScope   `json:"scope"`
    Conditions  []Condition `json:"conditions"`
    Actions     []Action    `json:"actions"`
    CreatedAt   time.Time   `json:"created_at"`
    ModifiedAt  time.Time   `json:"modified_at"`
    Version     int         `json:"version"`
}
```

### RuleScope

```go
type RuleScope struct {
    Direction   Direction `json:"direction"`
    Methods     []string  `json:"methods,omitempty"`
    URLPattern  string    `json:"url_pattern"`
    ContentType string    `json:"content_type,omitempty"`
}

type Direction string

const (
    DirectionRequest  Direction = "request"
    DirectionResponse Direction = "response"
    DirectionBoth     Direction = "both"
)
```

### Condition

```go
type Condition struct {
    Type          ConditionType `json:"type"`
    Location      Location      `json:"location"`
    Name          string        `json:"name,omitempty"`
    Pattern       string        `json:"pattern,omitempty"`
    Operator      string        `json:"operator,omitempty"`
    CaseSensitive bool          `json:"case_sensitive"`
    Negate        bool          `json:"negate"`
}

type ConditionType string

const (
    ConditionMatch    ConditionType = "match"
    ConditionNotMatch ConditionType = "not_match"
    ConditionContains ConditionType = "contains"
    ConditionRegex    ConditionType = "regex"
    ConditionJSONPath ConditionType = "jsonpath"
    ConditionXPath    ConditionType = "xpath"
    ConditionLength   ConditionType = "length"
    ConditionExists   ConditionType = "exists"
)
```

### Action

```go
type Action struct {
    Type     ActionType `json:"type"`
    Location Location   `json:"location"`
    Name     string     `json:"name,omitempty"`
    Value    string     `json:"value,omitempty"`
}

type ActionType string

const (
    ActionReplace     ActionType = "replace"
    ActionRemove      ActionType = "remove"
    ActionAdd         ActionType = "add"
    ActionExtract     ActionType = "extract"
    ActionTransform   ActionType = "transform"
    ActionSetVariable ActionType = "set_variable"
    ActionComputeHash ActionType = "compute_hash"
)
```

### Location

```go
type Location string

const (
    LocationHeader Location = "header"
    LocationCookie Location = "cookie"
    LocationBody   Location = "body"
    LocationURL    Location = "url"
    LocationStatus Location = "status"
    LocationMethod Location = "method"
    LocationPath   Location = "path"
    LocationQuery  Location = "query"
)
```

### ExecutionLog

```go
type ExecutionLog struct {
    Steps          []ExecutionStep   `json:"steps"`
    TotalDuration  time.Duration     `json:"total_duration"`
    RulesExecuted  int               `json:"rules_executed"`
    RulesMatched   int               `json:"rules_matched"`
    ActionsApplied int               `json:"actions_applied"`
    Variables      map[string]string `json:"variables"`
    Errors         []string          `json:"errors"`
}

type ExecutionStep struct {
    RuleID         int              `json:"rule_id"`
    RuleName       string           `json:"rule_name"`
    Priority       int              `json:"priority"`
    Matched        bool             `json:"matched"`
    MatchReason    string           `json:"match_reason"`
    ActionsApplied []ActionResult   `json:"actions_applied"`
    Variables      map[string]string `json:"variables"`
    Duration       time.Duration    `json:"duration"`
    Errors         []string         `json:"errors"`
}
```

### Metrics

```go
type Metrics struct {
    TotalRequests   int64            `json:"total_requests"`
    TotalResponses  int64            `json:"total_responses"`
    RulesApplied    int64            `json:"rules_applied"`
    AverageLatency  float64          `json:"average_latency_ms"`
    SlowRules       map[string]float64 `json:"slow_rules"`
}
```

## REST API Endpoints

### Rule Management

#### List Rules

```http
GET /api/v1/rewrite/rules
```

**Response:**
```json
{
  "rules": [
    {
      "id": 1,
      "name": "Add API Key",
      "description": "Adds X-API-Key header",
      "enabled": true,
      "priority": 10,
      "scope": {
        "direction": "request",
        "url_pattern": ".*"
      },
      "conditions": [],
      "actions": [
        {
          "type": "add",
          "location": "header",
          "name": "X-API-Key",
          "value": "secret"
        }
      ]
    }
  ]
}
```

#### Create Rule

```http
POST /api/v1/rewrite/rules
Content-Type: application/json

{
  "name": "Add API Key",
  "description": "Adds X-API-Key header to all requests",
  "enabled": true,
  "priority": 10,
  "scope": {
    "direction": "request",
    "url_pattern": ".*"
  },
  "actions": [
    {
      "type": "add",
      "location": "header",
      "name": "X-API-Key",
      "value": "secret-key-123"
    }
  ]
}
```

**Response:**
```json
{
  "rule": {
    "id": 1,
    "name": "Add API Key",
    "enabled": true,
    ...
  }
}
```

#### Get Rule

```http
GET /api/v1/rewrite/rules/{id}
```

**Response:**
```json
{
  "rule": {
    "id": 1,
    "name": "Add API Key",
    ...
  }
}
```

#### Update Rule

```http
PUT /api/v1/rewrite/rules/{id}
Content-Type: application/json

{
  "name": "Updated Rule Name",
  "enabled": false,
  ...
}
```

#### Delete Rule

```http
DELETE /api/v1/rewrite/rules/{id}
```

**Response:** `204 No Content`

### Import/Export

#### Import Rules

```http
POST /api/v1/rewrite/rules/import
Content-Type: application/json

{
  "rules": [
    {
      "name": "Rule 1",
      ...
    },
    {
      "name": "Rule 2",
      ...
    }
  ]
}
```

**Response:**
```json
{
  "imported": 2
}
```

#### Export Rules

```http
GET /api/v1/rewrite/rules/export
```

**Response:**
```json
{
  "rules": [
    { ... },
    { ... }
  ]
}
```

### Sandbox Testing

#### Test Request

```http
POST /api/v1/rewrite/sandbox/test-request
Content-Type: application/json

{
  "input": {
    "method": "GET",
    "url": "https://example.com/api/users",
    "headers": {
      "Authorization": "Bearer token123"
    },
    "body": ""
  },
  "rule_ids": [1, 2, 3]
}
```

**Response:**
```json
{
  "success": true,
  "original_input": { ... },
  "modified_input": { ... },
  "execution_log": {
    "steps": [
      {
        "rule_id": 1,
        "rule_name": "Add API Key",
        "matched": true,
        "actions_applied": [
          {
            "action_type": "add",
            "location": "header",
            "name": "X-API-Key",
            "old_value": "",
            "new_value": "secret",
            "success": true
          }
        ],
        "duration": 0.5
      }
    ],
    "total_duration": 0.5,
    "rules_executed": 1,
    "rules_matched": 1,
    "actions_applied": 1
  },
  "diff": {
    "header_changes": [
      {
        "name": "X-API-Key",
        "old_value": "",
        "new_value": "secret",
        "action": "added"
      }
    ],
    "body_changed": false
  },
  "warnings": [],
  "duration": 0.5
}
```

#### Test Response

```http
POST /api/v1/rewrite/sandbox/test-response
Content-Type: application/json

{
  "input": {
    "status_code": 200,
    "headers": {
      "Content-Type": "application/json",
      "X-Powered-By": "Express"
    },
    "body": "{\"data\": \"value\"}"
  },
  "rule_ids": [4, 5]
}
```

### Test Cases

#### List Test Cases

```http
GET /api/v1/rewrite/test-cases
```

#### Create Test Case

```http
POST /api/v1/rewrite/test-cases
Content-Type: application/json

{
  "name": "CSRF Bypass Test",
  "description": "Verify CSRF token is added",
  "type": "request",
  "input": {
    "method": "POST",
    "url": "https://target.com/api/action",
    "headers": {},
    "body": ""
  },
  "expected_output": {
    "headers": {
      "X-CSRF-Token": "valid-token"
    }
  },
  "rule_ids": [1],
  "tags": ["csrf", "bypass"]
}
```

#### Run Test Case

```http
POST /api/v1/rewrite/test-cases/run
Content-Type: application/json

{
  "id": 1
}
```

#### Run All Test Cases

```http
POST /api/v1/rewrite/test-cases/run-all
```

### Metrics

#### Get Metrics

```http
GET /api/v1/rewrite/metrics
```

**Response:**
```json
{
  "total_requests": 1523,
  "total_responses": 1520,
  "rules_applied": 4569,
  "average_latency": 2.3,
  "slow_rules": {
    "Complex Regex Rule": 5.2
  }
}
```

## Error Responses

All API errors follow this format:

```json
{
  "error": "Rule not found",
  "code": "RULE_NOT_FOUND",
  "details": {
    "rule_id": 999
  }
}
```

**Common Error Codes:**
- `RULE_NOT_FOUND` - Rule with specified ID doesn't exist
- `INVALID_RULE` - Rule validation failed
- `INVALID_REGEX` - Regular expression is invalid
- `RULE_CONFLICT` - Rule conflicts with existing rule
- `TEST_FAILED` - Sandbox test execution failed

## Rate Limiting

The API has no rate limiting by default. For production deployments, consider adding rate limiting at the reverse proxy level.

## Authentication

The Rewrite API inherits authentication from the main 0xGen API server. Include the appropriate authentication headers with all requests.

## Versioning

The API is versioned via the URL path (`/api/v1/`). Breaking changes will result in a new API version.

## Examples

### curl Examples

```bash
# List all rules
curl http://localhost:8713/api/v1/rewrite/rules

# Create a rule
curl -X POST http://localhost:8713/api/v1/rewrite/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Add Header",
    "enabled": true,
    "priority": 10,
    "scope": {
      "direction": "request",
      "url_pattern": ".*"
    },
    "actions": [{
      "type": "add",
      "location": "header",
      "name": "X-Custom",
      "value": "test"
    }]
  }'

# Test in sandbox
curl -X POST http://localhost:8713/api/v1/rewrite/sandbox/test-request \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "method": "GET",
      "url": "https://example.com",
      "headers": {},
      "body": ""
    },
    "rule_ids": [1]
  }'

# Export rules
curl http://localhost:8713/api/v1/rewrite/rules/export > rules.json

# Import rules
curl -X POST http://localhost:8713/api/v1/rewrite/rules/import \
  -H "Content-Type: application/json" \
  -d @rules.json
```

### Python Example

```python
import requests

API_BASE = "http://localhost:8713/api/v1/rewrite"

# Create a rule
rule = {
    "name": "Add API Key",
    "enabled": True,
    "priority": 10,
    "scope": {
        "direction": "request",
        "url_pattern": ".*"
    },
    "actions": [{
        "type": "add",
        "location": "header",
        "name": "X-API-Key",
        "value": "secret"
    }]
}

response = requests.post(f"{API_BASE}/rules", json=rule)
created_rule = response.json()["rule"]
print(f"Created rule ID: {created_rule['id']}")

# Test the rule
test_input = {
    "input": {
        "method": "GET",
        "url": "https://api.example.com/users",
        "headers": {},
        "body": ""
    },
    "rule_ids": [created_rule['id']]
}

response = requests.post(f"{API_BASE}/sandbox/test-request", json=test_input)
result = response.json()
print(f"Test passed: {result['success']}")
```
