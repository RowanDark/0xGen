package rewrite

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// Performance benchmarks for Rewrite engine

func BenchmarkSingleRuleExecution(b *testing.B) {
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench.db")

	engine, err := NewEngine(dbPath)
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	// Simple rule with one action
	rule := &Rule{
		Name:     "Simple Header Add",
		Enabled:  true,
		Priority: 10,
		Scope:    RuleScope{Direction: DirectionRequest, URLPattern: ".*"},
		Actions: []Action{
			{Type: ActionAdd, Location: LocationHeader, Name: "X-Bench", Value: "test"},
		},
	}
	engine.CreateRule(rule)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "https://example.com", nil)
		engine.ProcessRequest(req, fmt.Sprintf("bench-%d", i))
	}
}

func BenchmarkTenRules(b *testing.B) {
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench.db")

	engine, err := NewEngine(dbPath)
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	// Create 10 rules
	for i := 0; i < 10; i++ {
		rule := &Rule{
			Name:     fmt.Sprintf("Rule %d", i),
			Enabled:  true,
			Priority: i * 10,
			Scope:    RuleScope{Direction: DirectionRequest, URLPattern: ".*"},
			Actions: []Action{
				{Type: ActionAdd, Location: LocationHeader, Name: fmt.Sprintf("X-Rule-%d", i), Value: "test"},
			},
		}
		engine.CreateRule(rule)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "https://example.com", nil)
		engine.ProcessRequest(req, fmt.Sprintf("bench-%d", i))
	}
}

func BenchmarkHundredRules(b *testing.B) {
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench.db")

	engine, err := NewEngine(dbPath)
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	// Create 100 rules
	for i := 0; i < 100; i++ {
		rule := &Rule{
			Name:     fmt.Sprintf("Rule %d", i),
			Enabled:  true,
			Priority: i,
			Scope:    RuleScope{Direction: DirectionRequest, URLPattern: ".*"},
			Actions: []Action{
				{Type: ActionAdd, Location: LocationHeader, Name: fmt.Sprintf("X-Rule-%d", i), Value: "test"},
			},
		}
		engine.CreateRule(rule)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "https://example.com", nil)
		engine.ProcessRequest(req, fmt.Sprintf("bench-%d", i))
	}
}

func BenchmarkThousandRules(b *testing.B) {
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench.db")

	engine, err := NewEngine(dbPath)
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	// Create 1000 rules
	for i := 0; i < 1000; i++ {
		rule := &Rule{
			Name:     fmt.Sprintf("Rule %d", i),
			Enabled:  true,
			Priority: i,
			Scope:    RuleScope{Direction: DirectionRequest, URLPattern: ".*"},
			Actions: []Action{
				{Type: ActionAdd, Location: LocationHeader, Name: fmt.Sprintf("X-Rule-%d", i), Value: "test"},
			},
		}
		engine.CreateRule(rule)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "https://example.com", nil)
		engine.ProcessRequest(req, fmt.Sprintf("bench-%d", i))
	}
}

func BenchmarkComplexRegexMatching(b *testing.B) {
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench.db")

	engine, err := NewEngine(dbPath)
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	// Rule with complex regex
	rule := &Rule{
		Name:     "Complex Regex",
		Enabled:  true,
		Priority: 10,
		Scope: RuleScope{
			Direction:  DirectionRequest,
			URLPattern: `^https?://(?:api|www)\.example\.com/v[0-9]+/users/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`,
		},
		Actions: []Action{
			{Type: ActionAdd, Location: LocationHeader, Name: "X-Matched", Value: "true"},
		},
	}
	engine.CreateRule(rule)

	urls := []string{
		"https://api.example.com/v1/users/550e8400-e29b-41d4-a716-446655440000",
		"https://www.example.com/v2/users/6ba7b810-9dad-11d1-80b4-00c04fd430c8",
		"https://other.example.com/v1/users/test", // Won't match
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", urls[i%len(urls)], nil)
		engine.ProcessRequest(req, fmt.Sprintf("bench-%d", i))
	}
}

func BenchmarkSimpleMatchVsRegex(b *testing.B) {
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench.db")

	engine, err := NewEngine(dbPath)
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	// Simple string match condition
	rule := &Rule{
		Name:     "Simple Match",
		Enabled:  true,
		Priority: 10,
		Scope:    RuleScope{Direction: DirectionRequest, URLPattern: ".*"},
		Conditions: []Condition{
			{
				Type:     ConditionContains,
				Location: LocationHeader,
				Name:     "User-Agent",
				Pattern:  "Mozilla",
			},
		},
		Actions: []Action{
			{Type: ActionAdd, Location: LocationHeader, Name: "X-Browser", Value: "true"},
		},
	}
	engine.CreateRule(rule)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "https://example.com", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
		engine.ProcessRequest(req, fmt.Sprintf("bench-%d", i))
	}
}

func BenchmarkBodyRewriting(b *testing.B) {
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench.db")

	engine, err := NewEngine(dbPath)
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	rule := &Rule{
		Name:     "Body Replace",
		Enabled:  true,
		Priority: 10,
		Scope:    RuleScope{Direction: DirectionRequest, URLPattern: ".*"},
		Actions: []Action{
			{Type: ActionReplace, Location: LocationBody, Name: "old", Value: "new"},
		},
	}
	engine.CreateRule(rule)

	body := bytes.Repeat([]byte("This is old data that needs to be replaced. "), 100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "https://example.com", bytes.NewReader(body))
		engine.ProcessRequest(req, fmt.Sprintf("bench-%d", i))
	}
}

func BenchmarkVariableSubstitution(b *testing.B) {
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench.db")

	engine, err := NewEngine(dbPath)
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	rule := &Rule{
		Name:     "Variable Substitution",
		Enabled:  true,
		Priority: 10,
		Scope:    RuleScope{Direction: DirectionRequest, URLPattern: ".*"},
		Actions: []Action{
			{
				Type:     ActionAdd,
				Location: LocationHeader,
				Name:     "X-Timestamp",
				Value:    "${timestamp}",
			},
			{
				Type:     ActionAdd,
				Location: LocationHeader,
				Name:     "X-UUID",
				Value:    "${uuid}",
			},
			{
				Type:     ActionAdd,
				Location: LocationHeader,
				Name:     "X-Method",
				Value:    "${request.method}",
			},
		},
	}
	engine.CreateRule(rule)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "https://example.com", nil)
		engine.ProcessRequest(req, fmt.Sprintf("bench-%d", i))
	}
}

func BenchmarkJSONPathCondition(b *testing.B) {
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench.db")

	engine, err := NewEngine(dbPath)
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	rule := &Rule{
		Name:     "JSONPath Check",
		Enabled:  true,
		Priority: 10,
		Scope:    RuleScope{Direction: DirectionRequest, URLPattern: ".*"},
		Conditions: []Condition{
			{
				Type:     ConditionJSONPath,
				Location: LocationBody,
				Pattern:  "user.role",
			},
		},
		Actions: []Action{
			{Type: ActionAdd, Location: LocationHeader, Name: "X-Has-Role", Value: "true"},
		},
	}
	engine.CreateRule(rule)

	body := []byte(`{"user":{"id":123,"role":"admin","permissions":["read","write","delete"]}}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "https://example.com", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		engine.ProcessRequest(req, fmt.Sprintf("bench-%d", i))
	}
}

func BenchmarkMultipleConditions(b *testing.B) {
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench.db")

	engine, err := NewEngine(dbPath)
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	rule := &Rule{
		Name:     "Multiple Conditions",
		Enabled:  true,
		Priority: 10,
		Scope:    RuleScope{Direction: DirectionRequest, URLPattern: ".*"},
		Conditions: []Condition{
			{Type: ConditionExists, Location: LocationHeader, Name: "Authorization"},
			{Type: ConditionContains, Location: LocationHeader, Name: "Content-Type", Pattern: "json"},
			{Type: ConditionMatch, Location: LocationMethod, Pattern: "POST"},
		},
		Actions: []Action{
			{Type: ActionAdd, Location: LocationHeader, Name: "X-All-Matched", Value: "true"},
		},
	}
	engine.CreateRule(rule)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "https://example.com", nil)
		req.Header.Set("Authorization", "Bearer token")
		req.Header.Set("Content-Type", "application/json")
		engine.ProcessRequest(req, fmt.Sprintf("bench-%d", i))
	}
}

func BenchmarkSandboxExecution(b *testing.B) {
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench.db")

	engine, err := NewEngine(dbPath)
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	sandbox := NewSandbox(engine)

	rule := &Rule{
		Name:     "Sandbox Test Rule",
		Enabled:  true,
		Priority: 10,
		Scope:    RuleScope{Direction: DirectionRequest, URLPattern: ".*"},
		Actions: []Action{
			{Type: ActionAdd, Location: LocationHeader, Name: "X-Sandboxed", Value: "true"},
		},
	}
	id, _ := engine.CreateRule(rule)
	ruleIDs := []int{id}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "https://example.com", nil)
		sandbox.TestRequest(req, ruleIDs)
	}
}

func BenchmarkRuleValidation(b *testing.B) {
	rule := &Rule{
		Name:        "Validation Test",
		Description: "Test rule for validation benchmark",
		Enabled:     true,
		Priority:    10,
		Scope: RuleScope{
			Direction:  DirectionRequest,
			Methods:    []string{"GET", "POST"},
			URLPattern: `^https://api\.example\.com/v[0-9]+/.*$`,
		},
		Conditions: []Condition{
			{
				Type:     ConditionRegex,
				Location: LocationHeader,
				Name:     "Authorization",
				Pattern:  `^Bearer [a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$`,
			},
		},
		Actions: []Action{
			{Type: ActionAdd, Location: LocationHeader, Name: "X-Validated", Value: "true"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule.Validate()
	}
}

// Benchmark with realistic traffic patterns
func BenchmarkRealisticTraffic(b *testing.B) {
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench.db")

	engine, err := NewEngine(dbPath)
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	// Set up realistic rules
	rules := []*Rule{
		{
			Name:     "Auth Header Check",
			Enabled:  true,
			Priority: 100,
			Scope:    RuleScope{Direction: DirectionRequest, URLPattern: `^https://api\..*`},
			Conditions: []Condition{
				{Type: ConditionExists, Location: LocationHeader, Name: "Authorization"},
			},
			Actions: []Action{
				{Type: ActionSetVariable, Name: "has_auth", Value: "true"},
			},
		},
		{
			Name:     "Add Request ID",
			Enabled:  true,
			Priority: 90,
			Scope:    RuleScope{Direction: DirectionRequest, URLPattern: ".*"},
			Actions: []Action{
				{Type: ActionAdd, Location: LocationHeader, Name: "X-Request-ID", Value: "${uuid}"},
			},
		},
		{
			Name:     "Add Timestamp",
			Enabled:  true,
			Priority: 80,
			Scope:    RuleScope{Direction: DirectionRequest, URLPattern: ".*"},
			Actions: []Action{
				{Type: ActionAdd, Location: LocationHeader, Name: "X-Timestamp", Value: "${timestamp}"},
			},
		},
		{
			Name:     "Remove Sensitive Headers",
			Enabled:  true,
			Priority: 70,
			Scope:    RuleScope{Direction: DirectionResponse, URLPattern: ".*"},
			Actions: []Action{
				{Type: ActionRemove, Location: LocationHeader, Name: "X-Powered-By"},
				{Type: ActionRemove, Location: LocationHeader, Name: "Server"},
			},
		},
	}

	for _, rule := range rules {
		engine.CreateRule(rule)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "https://api.example.com/v1/users", nil)
		req.Header.Set("Authorization", "Bearer token123")
		req.Header.Set("Content-Type", "application/json")
		engine.ProcessRequest(req, fmt.Sprintf("bench-%d", i))
	}
}
