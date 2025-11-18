package rewrite

import (
	"context"
	"log/slog"
	"os"
	"testing"
)

func TestSandboxTestRequest(t *testing.T) {
	// Create temp database
	dbPath := "/tmp/sandbox_test_request.db"
	defer os.Remove(dbPath)

	// Create engine
	config := Config{
		DatabasePath: dbPath,
		Logger:       slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	engine, err := NewEngine(config)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	// Create sandbox
	sandbox := NewSandbox(engine, config.Logger)

	ctx := context.Background()

	// Create a test rule
	rule := &Rule{
		Name:     "add-test-header",
		Enabled:  true,
		Priority: 10,
		Scope: RuleScope{
			Direction: DirectionRequest,
		},
		Actions: []Action{
			{
				Type:     ActionAdd,
				Location: LocationHeader,
				Name:     "X-Test",
				Value:    "sandbox",
			},
		},
	}

	err = engine.CreateRule(ctx, rule)
	if err != nil {
		t.Fatalf("CreateRule failed: %v", err)
	}

	// Test request
	input := &TestRequestInput{
		Method: "GET",
		URL:    "https://example.com/test",
		Headers: map[string]string{
			"User-Agent": "TestAgent",
		},
		Body: "",
	}

	result, err := sandbox.TestRequest(ctx, input, nil)
	if err != nil {
		t.Fatalf("TestRequest failed: %v", err)
	}

	// Verify result
	if !result.Success {
		t.Error("TestRequest should succeed")
	}

	if result.ExecutionLog == nil {
		t.Fatal("ExecutionLog is nil")
	}

	if result.ExecutionLog.RulesExecuted != 1 {
		t.Errorf("RulesExecuted = %d, want 1", result.ExecutionLog.RulesExecuted)
	}

	if result.ExecutionLog.RulesMatched != 1 {
		t.Errorf("RulesMatched = %d, want 1", result.ExecutionLog.RulesMatched)
	}

	if result.ExecutionLog.ActionsApplied != 1 {
		t.Errorf("ActionsApplied = %d, want 1", result.ExecutionLog.ActionsApplied)
	}

	// Check diff
	if result.Diff == nil {
		t.Fatal("Diff is nil")
	}

	if len(result.Diff.HeaderChanges) != 1 {
		t.Errorf("HeaderChanges = %d, want 1", len(result.Diff.HeaderChanges))
	}

	if result.Diff.HeaderChanges[0].Name != "X-Test" {
		t.Errorf("Header name = %s, want X-Test", result.Diff.HeaderChanges[0].Name)
	}

	if result.Diff.HeaderChanges[0].Action != "added" {
		t.Errorf("Header action = %s, want added", result.Diff.HeaderChanges[0].Action)
	}
}

func TestSandboxTestResponse(t *testing.T) {
	// Create temp database
	dbPath := "/tmp/sandbox_test_response.db"
	defer os.Remove(dbPath)

	// Create engine
	config := Config{
		DatabasePath: dbPath,
		Logger:       slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	engine, err := NewEngine(config)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	// Create sandbox
	sandbox := NewSandbox(engine, config.Logger)

	ctx := context.Background()

	// Create a test rule
	rule := &Rule{
		Name:     "remove-server-header",
		Enabled:  true,
		Priority: 10,
		Scope: RuleScope{
			Direction: DirectionResponse,
		},
		Actions: []Action{
			{
				Type:     ActionRemove,
				Location: LocationHeader,
				Name:     "Server",
			},
		},
	}

	err = engine.CreateRule(ctx, rule)
	if err != nil {
		t.Fatalf("CreateRule failed: %v", err)
	}

	// Test response
	input := &TestResponseInput{
		StatusCode: 200,
		Headers: map[string]string{
			"Server":       "Apache/2.4",
			"Content-Type": "text/html",
		},
		Body: "<html>Test</html>",
	}

	result, err := sandbox.TestResponse(ctx, input, nil)
	if err != nil {
		t.Fatalf("TestResponse failed: %v", err)
	}

	// Verify result
	if !result.Success {
		t.Error("TestResponse should succeed")
	}

	if result.ExecutionLog.RulesMatched != 1 {
		t.Errorf("RulesMatched = %d, want 1", result.ExecutionLog.RulesMatched)
	}

	// Check diff
	if result.Diff == nil {
		t.Fatal("Diff is nil")
	}

	if len(result.Diff.HeaderChanges) != 1 {
		t.Errorf("HeaderChanges = %d, want 1", len(result.Diff.HeaderChanges))
	}

	if result.Diff.HeaderChanges[0].Action != "removed" {
		t.Errorf("Header action = %s, want removed", result.Diff.HeaderChanges[0].Action)
	}
}

func TestSandboxMultipleRules(t *testing.T) {
	// Create temp database
	dbPath := "/tmp/sandbox_test_multiple.db"
	defer os.Remove(dbPath)

	// Create engine
	config := Config{
		DatabasePath: dbPath,
		Logger:       slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	engine, err := NewEngine(config)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	// Create sandbox
	sandbox := NewSandbox(engine, config.Logger)

	ctx := context.Background()

	// Create multiple rules
	rules := []*Rule{
		{
			Name:     "add-header-1",
			Enabled:  true,
			Priority: 100,
			Scope:    RuleScope{Direction: DirectionRequest},
			Actions: []Action{
				{Type: ActionAdd, Location: LocationHeader, Name: "X-Rule-1", Value: "first"},
			},
		},
		{
			Name:     "add-header-2",
			Enabled:  true,
			Priority: 50,
			Scope:    RuleScope{Direction: DirectionRequest},
			Actions: []Action{
				{Type: ActionAdd, Location: LocationHeader, Name: "X-Rule-2", Value: "second"},
			},
		},
	}

	for _, rule := range rules {
		if err := engine.CreateRule(ctx, rule); err != nil {
			t.Fatalf("CreateRule failed: %v", err)
		}
	}

	// Test request
	input := &TestRequestInput{
		Method:  "GET",
		URL:     "https://example.com",
		Headers: map[string]string{},
		Body:    "",
	}

	result, err := sandbox.TestRequest(ctx, input, nil)
	if err != nil {
		t.Fatalf("TestRequest failed: %v", err)
	}

	// Verify both rules executed
	if result.ExecutionLog.RulesExecuted != 2 {
		t.Errorf("RulesExecuted = %d, want 2", result.ExecutionLog.RulesExecuted)
	}

	// Verify both rules matched
	if result.ExecutionLog.RulesMatched != 2 {
		t.Errorf("RulesMatched = %d, want 2", result.ExecutionLog.RulesMatched)
	}

	// Verify both headers added
	if len(result.Diff.HeaderChanges) != 2 {
		t.Errorf("HeaderChanges = %d, want 2", len(result.Diff.HeaderChanges))
	}

	// Verify priority order (higher priority first)
	if len(result.ExecutionLog.Steps) != 2 {
		t.Fatal("Expected 2 execution steps")
	}

	if result.ExecutionLog.Steps[0].Priority < result.ExecutionLog.Steps[1].Priority {
		t.Error("Rules not executed in priority order")
	}
}

func TestSandboxConditionalRule(t *testing.T) {
	// Create temp database
	dbPath := "/tmp/sandbox_test_conditional.db"
	defer os.Remove(dbPath)

	// Create engine
	config := Config{
		DatabasePath: dbPath,
		Logger:       slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	engine, err := NewEngine(config)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	// Create sandbox
	sandbox := NewSandbox(engine, config.Logger)

	ctx := context.Background()

	// Create a conditional rule
	rule := &Rule{
		Name:     "conditional-rule",
		Enabled:  true,
		Priority: 10,
		Scope: RuleScope{
			Direction: DirectionRequest,
		},
		Conditions: []Condition{
			{
				Type:     ConditionExists,
				Location: LocationHeader,
				Name:     "Authorization",
			},
		},
		Actions: []Action{
			{
				Type:     ActionAdd,
				Location: LocationHeader,
				Name:     "X-Authenticated",
				Value:    "true",
			},
		},
	}

	err = engine.CreateRule(ctx, rule)
	if err != nil {
		t.Fatalf("CreateRule failed: %v", err)
	}

	// Test 1: Request without Authorization header (should not match)
	input1 := &TestRequestInput{
		Method:  "GET",
		URL:     "https://example.com",
		Headers: map[string]string{},
		Body:    "",
	}

	result1, err := sandbox.TestRequest(ctx, input1, nil)
	if err != nil {
		t.Fatalf("TestRequest failed: %v", err)
	}

	if result1.ExecutionLog.RulesMatched != 0 {
		t.Errorf("Rule should not match without Authorization header")
	}

	// Test 2: Request with Authorization header (should match)
	input2 := &TestRequestInput{
		Method: "GET",
		URL:    "https://example.com",
		Headers: map[string]string{
			"Authorization": "Bearer token123",
		},
		Body: "",
	}

	result2, err := sandbox.TestRequest(ctx, input2, nil)
	if err != nil {
		t.Fatalf("TestRequest failed: %v", err)
	}

	if result2.ExecutionLog.RulesMatched != 1 {
		t.Errorf("Rule should match with Authorization header")
	}

	if len(result2.Diff.HeaderChanges) != 1 {
		t.Errorf("Should have one header change")
	}
}

func TestSandboxBodyModification(t *testing.T) {
	// Create temp database
	dbPath := "/tmp/sandbox_test_body.db"
	defer os.Remove(dbPath)

	// Create engine
	config := Config{
		DatabasePath: dbPath,
		Logger:       slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	engine, err := NewEngine(config)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	// Create sandbox
	sandbox := NewSandbox(engine, config.Logger)

	ctx := context.Background()

	// Create a rule that modifies body
	rule := &Rule{
		Name:     "replace-body",
		Enabled:  true,
		Priority: 10,
		Scope: RuleScope{
			Direction: DirectionRequest,
		},
		Actions: []Action{
			{
				Type:     ActionReplace,
				Location: LocationBody,
				Pattern:  "old",
				Value:    "new",
			},
		},
	}

	err = engine.CreateRule(ctx, rule)
	if err != nil {
		t.Fatalf("CreateRule failed: %v", err)
	}

	// Test request with body
	input := &TestRequestInput{
		Method:  "POST",
		URL:     "https://example.com",
		Headers: map[string]string{},
		Body:    "This is old text",
	}

	result, err := sandbox.TestRequest(ctx, input, nil)
	if err != nil {
		t.Fatalf("TestRequest failed: %v", err)
	}

	// Verify body was modified
	if !result.Diff.BodyChanged {
		t.Error("Body should be changed")
	}

	if result.Diff.BodyDiff == "" {
		t.Error("Body diff should not be empty")
	}
}

func TestSandboxPerformance(t *testing.T) {
	// Create temp database
	dbPath := "/tmp/sandbox_test_perf.db"
	defer os.Remove(dbPath)

	// Create engine
	config := Config{
		DatabasePath: dbPath,
		Logger:       slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	engine, err := NewEngine(config)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	// Create sandbox
	sandbox := NewSandbox(engine, config.Logger)

	ctx := context.Background()

	// Create a simple rule
	rule := &Rule{
		Name:     "perf-test",
		Enabled:  true,
		Priority: 10,
		Scope:    RuleScope{Direction: DirectionRequest},
		Actions: []Action{
			{Type: ActionAdd, Location: LocationHeader, Name: "X-Test", Value: "test"},
		},
	}

	engine.CreateRule(ctx, rule)

	// Test request
	input := &TestRequestInput{
		Method:  "GET",
		URL:     "https://example.com",
		Headers: map[string]string{},
		Body:    "",
	}

	// Run test
	result, err := sandbox.TestRequest(ctx, input, nil)
	if err != nil {
		t.Fatalf("TestRequest failed: %v", err)
	}

	// Verify performance (should complete in <1 second)
	if result.Duration.Seconds() > 1.0 {
		t.Errorf("Sandbox execution too slow: %v", result.Duration)
	}

	t.Logf("Sandbox execution time: %v", result.Duration)
}
