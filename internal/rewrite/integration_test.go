package rewrite

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// Integration tests for complete Rewrite workflows

func TestIntegration_FullRewriteWorkflow(t *testing.T) {
	// Setup
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	engine, err := NewEngine(Config{DatabasePath: dbPath})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()

	// Create a rule
	rule := &Rule{
		Name:        "Add API Key Header",
		Description: "Adds X-API-Key header to all API requests",
		Enabled:     true,
		Priority:    10,
		Scope: RuleScope{
			Direction:  DirectionRequest,
			URLPattern: `^https://api\.example\.com/.*`,
		},
		Actions: []Action{
			{
				Type:     ActionAdd,
				Location: LocationHeader,
				Name:     "X-API-Key",
				Value:    "secret-key-123",
			},
		},
	}

	// Create the rule
	if err := engine.CreateRule(ctx, rule); err != nil {
		t.Fatalf("Failed to create rule: %v", err)
	}

	// Verify rule was created
	retrieved, err := engine.GetRule(ctx, rule.ID)
	if err != nil {
		t.Fatalf("Failed to get rule: %v", err)
	}
	if retrieved.Name != rule.Name {
		t.Errorf("Rule name mismatch: got %s, want %s", retrieved.Name, rule.Name)
	}

	// Create a test request
	req := httptest.NewRequest("GET", "https://api.example.com/users", nil)

	// Process the request through the engine
	engine.ProcessRequest(req)

	// Verify the header was added
	apiKey := req.Header.Get("X-API-Key")
	if apiKey != "secret-key-123" {
		t.Errorf("X-API-Key header = %s, want secret-key-123", apiKey)
	}
}

func TestIntegration_MultipleRulesWithPriority(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	engine, err := NewEngine(Config{DatabasePath: dbPath})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()

	// Create rules with different priorities
	rules := []*Rule{
		{
			Name:     "Low Priority Rule",
			Enabled:  true,
			Priority: 1,
			Scope:    RuleScope{Direction: DirectionRequest, URLPattern: ".*"},
			Actions: []Action{
				{Type: ActionAdd, Location: LocationHeader, Name: "X-Order", Value: "first"},
			},
		},
		{
			Name:     "High Priority Rule",
			Enabled:  true,
			Priority: 100,
			Scope:    RuleScope{Direction: DirectionRequest, URLPattern: ".*"},
			Actions: []Action{
				{Type: ActionReplace, Location: LocationHeader, Name: "X-Order", Value: "second"},
			},
		},
	}

	for _, rule := range rules {
		if err := engine.CreateRule(ctx, rule); err != nil {
			t.Fatalf("Failed to create rule: %v", err)
		}
	}

	// Process request
	req := httptest.NewRequest("GET", "https://example.com", nil)
	engine.ProcessRequest(req)

	// High priority rule should have executed last, replacing the value
	order := req.Header.Get("X-Order")
	if order != "second" {
		t.Errorf("X-Order = %s, want second (high priority rule should execute last)", order)
	}
}

func TestIntegration_VariablePassingBetweenRules(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	engine, err := NewEngine(Config{DatabasePath: dbPath})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()

	// Rule 1: Extract value and store in variable
	rule1 := &Rule{
		Name:     "Extract Token",
		Enabled:  true,
		Priority: 100,
		Scope:    RuleScope{Direction: DirectionRequest, URLPattern: ".*"},
		Actions: []Action{
			{
				Type:     ActionExtract,
				Location: LocationHeader,
				Name:     "Authorization",
				Value:    `Bearer (.+)`,
			},
		},
	}

	// Rule 2: Use extracted variable
	rule2 := &Rule{
		Name:     "Use Token",
		Enabled:  true,
		Priority: 50,
		Scope:    RuleScope{Direction: DirectionRequest, URLPattern: ".*"},
		Actions: []Action{
			{
				Type:     ActionAdd,
				Location: LocationHeader,
				Name:     "X-Token-Copy",
				Value:    "${extracted_1}",
			},
		},
	}

	engine.CreateRule(ctx, rule1)
	engine.CreateRule(ctx, rule2)

	// Create request with Authorization header
	req := httptest.NewRequest("GET", "https://example.com", nil)
	req.Header.Set("Authorization", "Bearer my-secret-token")

	engine.ProcessRequest(req)

	// Check if variable was extracted and used
	tokenCopy := req.Header.Get("X-Token-Copy")
	if tokenCopy != "my-secret-token" {
		t.Errorf("X-Token-Copy = %s, want my-secret-token", tokenCopy)
	}
}

func TestIntegration_ConditionalRuleExecution(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	engine, err := NewEngine(Config{DatabasePath: dbPath})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()

	// Rule with condition
	rule := &Rule{
		Name:     "Conditional Header Add",
		Enabled:  true,
		Priority: 10,
		Scope:    RuleScope{Direction: DirectionRequest, URLPattern: ".*"},
		Conditions: []Condition{
			{
				Type:     ConditionExists,
				Location: LocationHeader,
				Name:     "X-Trigger",
			},
		},
		Actions: []Action{
			{Type: ActionAdd, Location: LocationHeader, Name: "X-Conditional", Value: "triggered"},
		},
	}

	engine.CreateRule(ctx, rule)

	// Request without trigger header
	req1 := httptest.NewRequest("GET", "https://example.com", nil)
	engine.ProcessRequest(req1)
	if req1.Header.Get("X-Conditional") != "" {
		t.Error("X-Conditional should not be set without trigger")
	}

	// Request with trigger header
	req2 := httptest.NewRequest("GET", "https://example.com", nil)
	req2.Header.Set("X-Trigger", "yes")
	engine.ProcessRequest(req2)
	if req2.Header.Get("X-Conditional") != "triggered" {
		t.Error("X-Conditional should be set when trigger is present")
	}
}

func TestIntegration_ResponseRewriting(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	engine, err := NewEngine(Config{DatabasePath: dbPath})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()

	// Rule to modify response
	rule := &Rule{
		Name:     "Modify Response",
		Enabled:  true,
		Priority: 10,
		Scope:    RuleScope{Direction: DirectionResponse, URLPattern: ".*"},
		Actions: []Action{
			{Type: ActionRemove, Location: LocationHeader, Name: "X-Powered-By"},
			{Type: ActionAdd, Location: LocationHeader, Name: "X-Modified", Value: "true"},
		},
	}

	engine.CreateRule(ctx, rule)

	// Create response
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader([]byte("test body"))),
		// Request must be set: the engine matches response rules against
		// the URL/method of the originating request.
		Request: httptest.NewRequest("GET", "https://example.com", nil),
	}
	resp.Header.Set("X-Powered-By", "Go")
	resp.Header.Set("Content-Type", "text/plain")

	// Process response
	engine.ProcessResponse(resp)

	// Verify modifications
	if resp.Header.Get("X-Powered-By") != "" {
		t.Error("X-Powered-By should have been removed")
	}
	if resp.Header.Get("X-Modified") != "true" {
		t.Error("X-Modified should have been added")
	}
}

func TestIntegration_RulePersistence(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	ctx := context.Background()

	// Create engine and add rule
	engine1, err := NewEngine(Config{DatabasePath: dbPath})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	rule := &Rule{
		Name:     "Persistent Rule",
		Enabled:  true,
		Priority: 10,
		Scope:    RuleScope{Direction: DirectionRequest, URLPattern: ".*"},
		Actions: []Action{
			{Type: ActionAdd, Location: LocationHeader, Name: "X-Persistent", Value: "yes"},
		},
	}

	if err := engine1.CreateRule(ctx, rule); err != nil {
		t.Fatalf("Failed to create rule: %v", err)
	}
	id := rule.ID
	engine1.Close()

	// Reopen engine and verify rule exists
	engine2, err := NewEngine(Config{DatabasePath: dbPath})
	if err != nil {
		t.Fatalf("Failed to reopen engine: %v", err)
	}
	defer engine2.Close()

	retrieved, err := engine2.GetRule(ctx, id)
	if err != nil {
		t.Fatalf("Failed to get rule after restart: %v", err)
	}

	if retrieved.Name != "Persistent Rule" {
		t.Errorf("Rule name = %s, want Persistent Rule", retrieved.Name)
	}

	// Verify rule still works
	req := httptest.NewRequest("GET", "https://example.com", nil)
	engine2.ProcessRequest(req)

	if req.Header.Get("X-Persistent") != "yes" {
		t.Error("Persistent rule should still work after restart")
	}
}

func TestIntegration_ImportExport(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	exportPath := filepath.Join(tmpDir, "rules.json")

	engine, err := NewEngine(Config{DatabasePath: dbPath})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()

	// Create some rules
	rules := []*Rule{
		{
			Name:     "Rule 1",
			Enabled:  true,
			Priority: 10,
			Scope:    RuleScope{Direction: DirectionRequest, URLPattern: ".*"},
			Actions:  []Action{{Type: ActionAdd, Location: LocationHeader, Name: "X-R1", Value: "1"}},
		},
		{
			Name:     "Rule 2",
			Enabled:  true,
			Priority: 20,
			Scope:    RuleScope{Direction: DirectionRequest, URLPattern: ".*"},
			Actions:  []Action{{Type: ActionAdd, Location: LocationHeader, Name: "X-R2", Value: "2"}},
		},
	}

	for _, rule := range rules {
		engine.CreateRule(ctx, rule)
	}

	// Export rules
	exported, err := engine.ListRules(ctx)
	if err != nil {
		t.Fatalf("Failed to list rules: %v", err)
	}

	if len(exported) != 2 {
		t.Errorf("Exported %d rules, want 2", len(exported))
	}

	// Delete all rules
	for _, rule := range exported {
		engine.DeleteRule(ctx, rule.ID)
	}

	// Verify deletion
	remaining, _ := engine.ListRules(ctx)
	if len(remaining) != 0 {
		t.Errorf("Should have 0 rules after deletion, got %d", len(remaining))
	}

	// Import rules back
	for _, rule := range exported {
		rule.ID = 0 // Clear ID for import
		engine.CreateRule(ctx, rule)
	}

	// Verify import
	imported, _ := engine.ListRules(ctx)
	if len(imported) != 2 {
		t.Errorf("Imported %d rules, want 2", len(imported))
	}

	// Clean up export file if it exists
	os.Remove(exportPath)
}

func TestIntegration_SandboxTesting(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	engine, err := NewEngine(Config{DatabasePath: dbPath})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()

	// Create sandbox
	sandbox := NewSandbox(engine, nil)

	// Create rule
	rule := &Rule{
		Name:     "Test Rule",
		Enabled:  true,
		Priority: 10,
		Scope:    RuleScope{Direction: DirectionRequest, URLPattern: ".*"},
		Actions: []Action{
			{Type: ActionAdd, Location: LocationHeader, Name: "X-Sandboxed", Value: "true"},
		},
	}

	if err := engine.CreateRule(ctx, rule); err != nil {
		t.Fatalf("Failed to create rule: %v", err)
	}

	// Test in sandbox
	input := &TestRequestInput{
		Method: "GET",
		URL:    "https://example.com",
	}
	result, err := sandbox.TestRequest(ctx, input, []int{rule.ID})
	if err != nil {
		t.Fatalf("Sandbox test failed: %v", err)
	}

	if !result.Success {
		t.Error("Sandbox test should succeed")
	}

	if result.ExecutionLog.RulesMatched != 1 {
		t.Errorf("RulesMatched = %d, want 1", result.ExecutionLog.RulesMatched)
	}
}

func TestIntegration_BodyRewriting(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	engine, err := NewEngine(Config{DatabasePath: dbPath})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()

	// Rule to replace body content
	rule := &Rule{
		Name:     "Replace Body Content",
		Enabled:  true,
		Priority: 10,
		Scope:    RuleScope{Direction: DirectionRequest, URLPattern: ".*"},
		Conditions: []Condition{
			{
				Type:     ConditionContains,
				Location: LocationBody,
				Pattern:  "OLD_VALUE",
			},
		},
		Actions: []Action{
			{
				Type:     ActionReplace,
				Location: LocationBody,
				Name:     "OLD_VALUE",
				Value:    "NEW_VALUE",
			},
		},
	}

	engine.CreateRule(ctx, rule)

	// Create request with body
	body := []byte(`{"key": "OLD_VALUE", "other": "data"}`)
	req := httptest.NewRequest("POST", "https://example.com", bytes.NewReader(body))

	engine.ProcessRequest(req)

	// Read modified body
	modifiedBody, _ := io.ReadAll(req.Body)
	expected := `{"key": "NEW_VALUE", "other": "data"}`
	if string(modifiedBody) != expected {
		t.Errorf("Modified body = %s, want %s", string(modifiedBody), expected)
	}
}

func TestIntegration_CSRFBypassScenario(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	engine, err := NewEngine(Config{DatabasePath: dbPath})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()

	// Real-world scenario: Bypass CSRF token check by adding valid token
	rule := &Rule{
		Name:        "CSRF Token Injection",
		Description: "Adds CSRF token to requests missing it",
		Enabled:     true,
		Priority:    10,
		Scope: RuleScope{
			Direction:  DirectionRequest,
			Methods:    []string{"POST", "PUT", "DELETE"},
			URLPattern: `.*`,
		},
		Conditions: []Condition{
			{
				Type:     ConditionNotMatch,
				Location: LocationHeader,
				Name:     "X-CSRF-Token",
				Pattern:  ".+",
			},
		},
		Actions: []Action{
			{
				Type:     ActionAdd,
				Location: LocationHeader,
				Name:     "X-CSRF-Token",
				Value:    "valid-csrf-token-abc123",
			},
		},
	}

	engine.CreateRule(ctx, rule)

	// POST request without CSRF token
	req := httptest.NewRequest("POST", "https://target.com/api/action", nil)
	engine.ProcessRequest(req)

	token := req.Header.Get("X-CSRF-Token")
	if token != "valid-csrf-token-abc123" {
		t.Errorf("CSRF token = %s, want valid-csrf-token-abc123", token)
	}

	// GET request should not be modified (not in methods list)
	req2 := httptest.NewRequest("GET", "https://target.com/api/data", nil)
	engine.ProcessRequest(req2)

	if req2.Header.Get("X-CSRF-Token") != "" {
		t.Error("GET request should not have CSRF token added")
	}
}

func TestIntegration_JWTManipulation(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	engine, err := NewEngine(Config{DatabasePath: dbPath})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()

	// Extract JWT and store as variable
	extractRule := &Rule{
		Name:     "Extract JWT",
		Enabled:  true,
		Priority: 100,
		Scope:    RuleScope{Direction: DirectionRequest, URLPattern: ".*"},
		Actions: []Action{
			{
				Type:  ActionSetVariable,
				Name:  "jwt_token",
				Value: "${request.header.Authorization}",
			},
		},
	}

	// Add extracted token to different header
	forwardRule := &Rule{
		Name:     "Forward JWT",
		Enabled:  true,
		Priority: 50,
		Scope:    RuleScope{Direction: DirectionRequest, URLPattern: ".*"},
		Actions: []Action{
			{
				Type:     ActionAdd,
				Location: LocationHeader,
				Name:     "X-Forwarded-Auth",
				Value:    "${jwt_token}",
			},
		},
	}

	engine.CreateRule(ctx, extractRule)
	engine.CreateRule(ctx, forwardRule)

	req := httptest.NewRequest("GET", "https://example.com", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")

	engine.ProcessRequest(req)

	forwarded := req.Header.Get("X-Forwarded-Auth")
	if forwarded != "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." {
		t.Errorf("Forwarded auth = %s, want original JWT", forwarded)
	}
}
