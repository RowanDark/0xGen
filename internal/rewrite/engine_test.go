package rewrite

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestEngineCreation(t *testing.T) {
	// Create temp database
	dbPath := "/tmp/rewrite_test.db"
	defer os.Remove(dbPath)

	config := Config{
		DatabasePath: dbPath,
		Logger:       slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	engine, err := NewEngine(config)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	if engine == nil {
		t.Fatal("Engine is nil")
	}
}

func TestEngineRuleCRUD(t *testing.T) {
	// Create temp database
	dbPath := "/tmp/rewrite_crud_test.db"
	defer os.Remove(dbPath)

	config := Config{
		DatabasePath: dbPath,
		Logger:       slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	engine, err := NewEngine(config)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()

	// Create a rule
	rule := &Rule{
		Name:        "test-rule",
		Description: "Test rule",
		Enabled:     true,
		Priority:    10,
		Scope: RuleScope{
			Direction: DirectionRequest,
			Methods:   []string{"GET"},
		},
		Actions: []Action{
			{
				Type:     ActionAdd,
				Location: LocationHeader,
				Name:     "X-Test",
				Value:    "test",
			},
		},
	}

	// Create
	err = engine.CreateRule(ctx, rule)
	if err != nil {
		t.Fatalf("CreateRule failed: %v", err)
	}

	if rule.ID == 0 {
		t.Error("Rule ID not set after creation")
	}

	// Read
	retrieved, err := engine.GetRule(ctx, rule.ID)
	if err != nil {
		t.Fatalf("GetRule failed: %v", err)
	}

	if retrieved.Name != rule.Name {
		t.Errorf("Retrieved rule name = %s, want %s", retrieved.Name, rule.Name)
	}

	// Update
	retrieved.Description = "Updated description"
	err = engine.UpdateRule(ctx, retrieved)
	if err != nil {
		t.Fatalf("UpdateRule failed: %v", err)
	}

	updated, err := engine.GetRule(ctx, rule.ID)
	if err != nil {
		t.Fatalf("GetRule after update failed: %v", err)
	}

	if updated.Description != "Updated description" {
		t.Errorf("Description not updated: got %s", updated.Description)
	}

	// List
	rules, err := engine.ListRules(ctx)
	if err != nil {
		t.Fatalf("ListRules failed: %v", err)
	}

	if len(rules) != 1 {
		t.Errorf("ListRules returned %d rules, want 1", len(rules))
	}

	// Delete
	err = engine.DeleteRule(ctx, rule.ID)
	if err != nil {
		t.Fatalf("DeleteRule failed: %v", err)
	}

	// Verify deletion
	_, err = engine.GetRule(ctx, rule.ID)
	if err == nil {
		t.Error("GetRule should fail after deletion")
	}
}

func TestEngineEnableDisable(t *testing.T) {
	// Create temp database
	dbPath := "/tmp/rewrite_enable_test.db"
	defer os.Remove(dbPath)

	config := Config{
		DatabasePath: dbPath,
		Logger:       slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	engine, err := NewEngine(config)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()

	// Create a rule
	rule := &Rule{
		Name:    "test-rule",
		Enabled: true,
		Scope: RuleScope{
			Direction: DirectionRequest,
		},
		Actions: []Action{
			{
				Type:     ActionAdd,
				Location: LocationHeader,
				Name:     "X-Test",
				Value:    "test",
			},
		},
	}

	err = engine.CreateRule(ctx, rule)
	if err != nil {
		t.Fatalf("CreateRule failed: %v", err)
	}

	// Disable
	err = engine.DisableRule(ctx, rule.ID)
	if err != nil {
		t.Fatalf("DisableRule failed: %v", err)
	}

	disabled, err := engine.GetRule(ctx, rule.ID)
	if err != nil {
		t.Fatalf("GetRule failed: %v", err)
	}

	if disabled.Enabled {
		t.Error("Rule should be disabled")
	}

	// Enable
	err = engine.EnableRule(ctx, rule.ID)
	if err != nil {
		t.Fatalf("EnableRule failed: %v", err)
	}

	enabled, err := engine.GetRule(ctx, rule.ID)
	if err != nil {
		t.Fatalf("GetRule failed: %v", err)
	}

	if !enabled.Enabled {
		t.Error("Rule should be enabled")
	}
}

func TestProcessRequest(t *testing.T) {
	// Create temp database
	dbPath := "/tmp/rewrite_process_test.db"
	defer os.Remove(dbPath)

	config := Config{
		DatabasePath: dbPath,
		Logger:       slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	engine, err := NewEngine(config)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()

	// Create a rule that adds a header
	rule := &Rule{
		Name:     "add-header",
		Enabled:  true,
		Priority: 10,
		Scope: RuleScope{
			Direction: DirectionRequest,
		},
		Actions: []Action{
			{
				Type:     ActionAdd,
				Location: LocationHeader,
				Name:     "X-Rewrite",
				Value:    "processed",
			},
		},
	}

	err = engine.CreateRule(ctx, rule)
	if err != nil {
		t.Fatalf("CreateRule failed: %v", err)
	}

	// Create a request
	req, _ := http.NewRequest("GET", "https://example.com", nil)

	// Process request
	processed, err := engine.ProcessRequest(req)
	if err != nil {
		t.Fatalf("ProcessRequest failed: %v", err)
	}

	// Check header was added
	if processed.Header.Get("X-Rewrite") != "processed" {
		t.Errorf("Header not added: got %s", processed.Header.Get("X-Rewrite"))
	}
}

func TestGetActiveRules(t *testing.T) {
	// Create temp database
	dbPath := "/tmp/rewrite_active_test.db"
	defer os.Remove(dbPath)

	config := Config{
		DatabasePath: dbPath,
		Logger:       slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	engine, err := NewEngine(config)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()

	// Create rules with different directions and priorities
	rules := []*Rule{
		{
			Name:     "request-high",
			Enabled:  true,
			Priority: 100,
			Scope:    RuleScope{Direction: DirectionRequest},
			Actions:  []Action{{Type: ActionAdd, Location: LocationHeader, Name: "X-1", Value: "1"}},
		},
		{
			Name:     "request-low",
			Enabled:  true,
			Priority: 10,
			Scope:    RuleScope{Direction: DirectionRequest},
			Actions:  []Action{{Type: ActionAdd, Location: LocationHeader, Name: "X-2", Value: "2"}},
		},
		{
			Name:     "response",
			Enabled:  true,
			Priority: 50,
			Scope:    RuleScope{Direction: DirectionResponse},
			Actions:  []Action{{Type: ActionAdd, Location: LocationHeader, Name: "X-3", Value: "3"}},
		},
		{
			Name:     "disabled",
			Enabled:  false,
			Priority: 200,
			Scope:    RuleScope{Direction: DirectionRequest},
			Actions:  []Action{{Type: ActionAdd, Location: LocationHeader, Name: "X-4", Value: "4"}},
		},
	}

	for _, rule := range rules {
		if err := engine.CreateRule(ctx, rule); err != nil {
			t.Fatalf("CreateRule failed: %v", err)
		}
	}

	// Get active request rules
	activeRequest := engine.GetActiveRules(DirectionRequest)
	if len(activeRequest) != 2 {
		t.Errorf("GetActiveRules(Request) = %d, want 2", len(activeRequest))
	}

	// Check priority order (higher first)
	if activeRequest[0].Priority < activeRequest[1].Priority {
		t.Error("Rules not sorted by priority")
	}

	// Get active response rules
	activeResponse := engine.GetActiveRules(DirectionResponse)
	if len(activeResponse) != 1 {
		t.Errorf("GetActiveRules(Response) = %d, want 1", len(activeResponse))
	}
}

func TestEngineMetrics(t *testing.T) {
	// Create temp database
	dbPath := "/tmp/rewrite_metrics_test.db"
	defer os.Remove(dbPath)

	config := Config{
		DatabasePath: dbPath,
		Logger:       slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	engine, err := NewEngine(config)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()

	// Create a simple rule
	rule := &Rule{
		Name:    "test-rule",
		Enabled: true,
		Scope:   RuleScope{Direction: DirectionRequest},
		Actions: []Action{{Type: ActionAdd, Location: LocationHeader, Name: "X-Test", Value: "test"}},
	}

	err = engine.CreateRule(ctx, rule)
	if err != nil {
		t.Fatalf("CreateRule failed: %v", err)
	}

	// Process some requests
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest("GET", "https://example.com", nil)
		engine.ProcessRequest(req)
	}

	// Get metrics
	metrics := engine.GetMetrics()

	if metrics.TotalRequests != 5 {
		t.Errorf("TotalRequests = %d, want 5", metrics.TotalRequests)
	}

	if metrics.RulesApplied != 5 {
		t.Errorf("RulesApplied = %d, want 5", metrics.RulesApplied)
	}
}

func TestImportExportRules(t *testing.T) {
	// Create temp database
	dbPath := "/tmp/rewrite_import_test.db"
	defer os.Remove(dbPath)

	config := Config{
		DatabasePath: dbPath,
		Logger:       slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	engine, err := NewEngine(config)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()

	// Create rules to import
	importRules := []*Rule{
		{
			Name:     "imported-1",
			Enabled:  true,
			Priority: 10,
			Scope:    RuleScope{Direction: DirectionRequest},
			Actions:  []Action{{Type: ActionAdd, Location: LocationHeader, Name: "X-1", Value: "1"}},
		},
		{
			Name:     "imported-2",
			Enabled:  true,
			Priority: 20,
			Scope:    RuleScope{Direction: DirectionResponse},
			Actions:  []Action{{Type: ActionAdd, Location: LocationHeader, Name: "X-2", Value: "2"}},
		},
	}

	// Import
	err = engine.ImportRules(ctx, importRules)
	if err != nil {
		t.Fatalf("ImportRules failed: %v", err)
	}

	// Export
	exported, err := engine.ExportRules(ctx)
	if err != nil {
		t.Fatalf("ExportRules failed: %v", err)
	}

	if len(exported) != 2 {
		t.Errorf("ExportRules returned %d rules, want 2", len(exported))
	}
}

func BenchmarkProcessRequest(b *testing.B) {
	// Create temp database
	dbPath := "/tmp/rewrite_bench_test.db"
	defer os.Remove(dbPath)

	config := Config{
		DatabasePath: dbPath,
		Logger:       slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	engine, err := NewEngine(config)
	if err != nil {
		b.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()

	// Create a simple rule
	rule := &Rule{
		Name:    "bench-rule",
		Enabled: true,
		Scope:   RuleScope{Direction: DirectionRequest},
		Actions: []Action{{Type: ActionAdd, Location: LocationHeader, Name: "X-Test", Value: "test"}},
	}

	engine.CreateRule(ctx, rule)

	// Benchmark
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("GET", "https://example.com", nil)
		engine.ProcessRequest(req)
	}
}

func TestProcessRequestWithBody(t *testing.T) {
	// Create temp database
	dbPath := "/tmp/rewrite_body_test.db"
	defer os.Remove(dbPath)

	config := Config{
		DatabasePath: dbPath,
		Logger:       slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	engine, err := NewEngine(config)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

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

	// Create a request with body
	body := bytes.NewReader([]byte("This is old content"))
	req, _ := http.NewRequest("POST", "https://example.com", body)

	// Process request
	processed, err := engine.ProcessRequest(req)
	if err != nil {
		t.Fatalf("ProcessRequest failed: %v", err)
	}

	// Read the processed body
	processedBody, err := CaptureRequestBody(processed)
	if err != nil {
		t.Fatalf("Failed to read processed body: %v", err)
	}

	expected := "This is new content"
	if string(processedBody) != expected {
		t.Errorf("Body = %s, want %s", string(processedBody), expected)
	}
}
