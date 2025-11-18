package rewrite

import (
	"context"
	"log/slog"
	"os"
	"testing"
)

func TestTestCaseManager(t *testing.T) {
	// Create temp database
	dbPath := "/tmp/testcase_test.db"
	defer os.Remove(dbPath)

	// Create engine and components
	config := Config{
		DatabasePath: dbPath,
		Logger:       slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	engine, err := NewEngine(config)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	sandbox := NewSandbox(engine, config.Logger)
	manager := NewTestCaseManager(engine.storage, sandbox, config.Logger)

	ctx := context.Background()

	// Create a test rule
	rule := &Rule{
		Name:     "test-rule",
		Enabled:  true,
		Priority: 10,
		Scope:    RuleScope{Direction: DirectionRequest},
		Actions: []Action{
			{Type: ActionAdd, Location: LocationHeader, Name: "X-Test", Value: "test"},
		},
	}

	err = engine.CreateRule(ctx, rule)
	if err != nil {
		t.Fatalf("CreateRule failed: %v", err)
	}

	// Create a test case
	testCase := &TestCase{
		Name:        "test-add-header",
		Description: "Test adding a header",
		Type:        TestCaseTypeRequest,
		Input: &TestRequestInput{
			Method:  "GET",
			URL:     "https://example.com",
			Headers: map[string]string{},
			Body:    "",
		},
		RuleIDs: []int{rule.ID},
		Tags:    []string{"header", "add"},
	}

	// Test Create
	err = manager.CreateTestCase(ctx, testCase)
	if err != nil {
		t.Fatalf("CreateTestCase failed: %v", err)
	}

	if testCase.ID == 0 {
		t.Error("Test case ID not set")
	}

	// Test Get
	retrieved, err := manager.GetTestCase(ctx, testCase.ID)
	if err != nil {
		t.Fatalf("GetTestCase failed: %v", err)
	}

	if retrieved.Name != testCase.Name {
		t.Errorf("Name = %s, want %s", retrieved.Name, testCase.Name)
	}

	if retrieved.Type != testCase.Type {
		t.Errorf("Type = %s, want %s", retrieved.Type, testCase.Type)
	}

	// Test List
	testCases, err := manager.ListTestCases(ctx)
	if err != nil {
		t.Fatalf("ListTestCases failed: %v", err)
	}

	if len(testCases) != 1 {
		t.Errorf("ListTestCases returned %d, want 1", len(testCases))
	}

	// Test Run
	result, err := manager.RunTestCase(ctx, testCase.ID)
	if err != nil {
		t.Fatalf("RunTestCase failed: %v", err)
	}

	if result.TestCaseID != testCase.ID {
		t.Errorf("TestCaseID = %d, want %d", result.TestCaseID, testCase.ID)
	}

	if !result.Passed {
		t.Errorf("Test case should pass. Failures: %v", result.Failures)
	}

	if result.SandboxResult == nil {
		t.Error("SandboxResult is nil")
	}

	// Test Delete
	err = manager.DeleteTestCase(ctx, testCase.ID)
	if err != nil {
		t.Fatalf("DeleteTestCase failed: %v", err)
	}

	// Verify deletion
	_, err = manager.GetTestCase(ctx, testCase.ID)
	if err == nil {
		t.Error("GetTestCase should fail after deletion")
	}
}

func TestTestCaseWithExpectedOutput(t *testing.T) {
	// Create temp database
	dbPath := "/tmp/testcase_expected_test.db"
	defer os.Remove(dbPath)

	// Create engine and components
	config := Config{
		DatabasePath: dbPath,
		Logger:       slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	engine, err := NewEngine(config)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	sandbox := NewSandbox(engine, config.Logger)
	manager := NewTestCaseManager(engine.storage, sandbox, config.Logger)

	ctx := context.Background()

	// Create a rule
	rule := &Rule{
		Name:     "add-header",
		Enabled:  true,
		Priority: 10,
		Scope:    RuleScope{Direction: DirectionRequest},
		Actions: []Action{
			{Type: ActionAdd, Location: LocationHeader, Name: "X-Test", Value: "expected"},
		},
	}

	engine.CreateRule(ctx, rule)

	// Create test case with expected output
	testCase := &TestCase{
		Name: "test-with-expected",
		Type: TestCaseTypeRequest,
		Input: &TestRequestInput{
			Method:  "GET",
			URL:     "https://example.com",
			Headers: map[string]string{},
			Body:    "",
		},
		ExpectedOutput: &TestRequestInput{
			Method: "GET",
			URL:    "https://example.com",
			Headers: map[string]string{
				"X-Test": "expected",
			},
			Body: "",
		},
		RuleIDs: []int{rule.ID},
	}

	err = manager.CreateTestCase(ctx, testCase)
	if err != nil {
		t.Fatalf("CreateTestCase failed: %v", err)
	}

	// Run test case
	result, err := manager.RunTestCase(ctx, testCase.ID)
	if err != nil {
		t.Fatalf("RunTestCase failed: %v", err)
	}

	// Should pass because output matches expected
	if !result.Passed {
		t.Errorf("Test should pass. Failures: %v", result.Failures)
	}
}

func TestTestCaseFailure(t *testing.T) {
	// Create temp database
	dbPath := "/tmp/testcase_failure_test.db"
	defer os.Remove(dbPath)

	// Create engine and components
	config := Config{
		DatabasePath: dbPath,
		Logger:       slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	engine, err := NewEngine(config)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	sandbox := NewSandbox(engine, config.Logger)
	manager := NewTestCaseManager(engine.storage, sandbox, config.Logger)

	ctx := context.Background()

	// Create a rule
	rule := &Rule{
		Name:     "add-wrong-header",
		Enabled:  true,
		Priority: 10,
		Scope:    RuleScope{Direction: DirectionRequest},
		Actions: []Action{
			{Type: ActionAdd, Location: LocationHeader, Name: "X-Test", Value: "wrong"},
		},
	}

	engine.CreateRule(ctx, rule)

	// Create test case with different expected output
	testCase := &TestCase{
		Name: "test-failure",
		Type: TestCaseTypeRequest,
		Input: &TestRequestInput{
			Method:  "GET",
			URL:     "https://example.com",
			Headers: map[string]string{},
			Body:    "",
		},
		ExpectedOutput: &TestRequestInput{
			Method: "GET",
			URL:    "https://example.com",
			Headers: map[string]string{
				"X-Test": "expected", // Different from what rule adds
			},
			Body: "",
		},
		RuleIDs: []int{rule.ID},
	}

	err = manager.CreateTestCase(ctx, testCase)
	if err != nil {
		t.Fatalf("CreateTestCase failed: %v", err)
	}

	// Run test case
	result, err := manager.RunTestCase(ctx, testCase.ID)
	if err != nil {
		t.Fatalf("RunTestCase failed: %v", err)
	}

	// Should fail because output doesn't match expected
	if result.Passed {
		t.Error("Test should fail due to mismatched expected output")
	}

	if len(result.Failures) == 0 {
		t.Error("Should have failures")
	}
}

func TestRunAllTestCases(t *testing.T) {
	// Create temp database
	dbPath := "/tmp/testcase_runall_test.db"
	defer os.Remove(dbPath)

	// Create engine and components
	config := Config{
		DatabasePath: dbPath,
		Logger:       slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	engine, err := NewEngine(config)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	sandbox := NewSandbox(engine, config.Logger)
	manager := NewTestCaseManager(engine.storage, sandbox, config.Logger)

	ctx := context.Background()

	// Create a rule
	rule := &Rule{
		Name:     "test-rule",
		Enabled:  true,
		Priority: 10,
		Scope:    RuleScope{Direction: DirectionRequest},
		Actions: []Action{
			{Type: ActionAdd, Location: LocationHeader, Name: "X-Test", Value: "test"},
		},
	}

	engine.CreateRule(ctx, rule)

	// Create multiple test cases
	for i := 1; i <= 3; i++ {
		testCase := &TestCase{
			Name: "test-case-" + string(rune('0'+i)),
			Type: TestCaseTypeRequest,
			Input: &TestRequestInput{
				Method:  "GET",
				URL:     "https://example.com",
				Headers: map[string]string{},
				Body:    "",
			},
			RuleIDs: []int{rule.ID},
		}

		err = manager.CreateTestCase(ctx, testCase)
		if err != nil {
			t.Fatalf("CreateTestCase failed: %v", err)
		}
	}

	// Run all test cases
	results, err := manager.RunAllTestCases(ctx)
	if err != nil {
		t.Fatalf("RunAllTestCases failed: %v", err)
	}

	if len(results) != 3 {
		t.Errorf("RunAllTestCases returned %d results, want 3", len(results))
	}

	// All should pass
	for _, result := range results {
		if !result.Passed {
			t.Errorf("Test case %s failed: %v", result.TestCaseName, result.Failures)
		}
	}
}

func TestTestCaseResponse(t *testing.T) {
	// Create temp database
	dbPath := "/tmp/testcase_response_test.db"
	defer os.Remove(dbPath)

	// Create engine and components
	config := Config{
		DatabasePath: dbPath,
		Logger:       slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	engine, err := NewEngine(config)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	sandbox := NewSandbox(engine, config.Logger)
	manager := NewTestCaseManager(engine.storage, sandbox, config.Logger)

	ctx := context.Background()

	// Create a response rule
	rule := &Rule{
		Name:     "remove-server",
		Enabled:  true,
		Priority: 10,
		Scope:    RuleScope{Direction: DirectionResponse},
		Actions: []Action{
			{Type: ActionRemove, Location: LocationHeader, Name: "Server"},
		},
	}

	engine.CreateRule(ctx, rule)

	// Create test case for response
	testCase := &TestCase{
		Name: "test-response",
		Type: TestCaseTypeResponse,
		Input: &TestResponseInput{
			StatusCode: 200,
			Headers: map[string]string{
				"Server":       "Apache/2.4",
				"Content-Type": "text/html",
			},
			Body: "<html>Test</html>",
		},
		RuleIDs: []int{rule.ID},
	}

	err = manager.CreateTestCase(ctx, testCase)
	if err != nil {
		t.Fatalf("CreateTestCase failed: %v", err)
	}

	// Run test case
	result, err := manager.RunTestCase(ctx, testCase.ID)
	if err != nil {
		t.Fatalf("RunTestCase failed: %v", err)
	}

	if !result.Passed {
		t.Errorf("Test case should pass. Failures: %v", result.Failures)
	}

	// Verify the sandbox result
	if result.SandboxResult == nil {
		t.Fatal("SandboxResult is nil")
	}

	if result.SandboxResult.Diff == nil {
		t.Fatal("Diff is nil")
	}

	if len(result.SandboxResult.Diff.HeaderChanges) != 1 {
		t.Errorf("Expected 1 header change, got %d", len(result.SandboxResult.Diff.HeaderChanges))
	}
}
