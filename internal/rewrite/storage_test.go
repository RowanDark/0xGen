package rewrite

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"
)

// setupTestStorage creates a new storage instance for testing
func setupTestStorage(t *testing.T) (*Storage, func()) {
	t.Helper()

	dbPath := "/tmp/rewrite_storage_test.db"
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))

	storage, err := NewStorage(dbPath, logger)
	if err != nil {
		t.Fatalf("NewStorage failed: %v", err)
	}

	cleanup := func() {
		storage.Close()
		os.Remove(dbPath)
	}

	return storage, cleanup
}

// TestSearchRules_CorruptedJSON tests that SearchRules returns error for corrupted JSON
func TestSearchRules_CorruptedJSON(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Insert rule with corrupted scope_methods JSON
	_, err := storage.db.Exec(`
		INSERT INTO rules (
			name, description, enabled, priority, scope_direction,
			scope_methods, conditions, actions,
			created_at, modified_at, version
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, "test-rule", "Test rule", true, 1, "request",
		"invalid-json{{{", "[]", "[]",
		time.Now().Unix(), time.Now().Unix(), 1)
	if err != nil {
		t.Fatalf("Failed to insert test rule: %v", err)
	}

	// SearchRules should return error for corrupted JSON
	_, err = storage.SearchRules(ctx, "test")
	if err == nil {
		t.Error("SearchRules should return error for corrupted JSON")
	}
	if !strings.Contains(err.Error(), "unmarshal") {
		t.Errorf("Error should mention unmarshal, got: %v", err)
	}
	if !strings.Contains(err.Error(), "scope methods") {
		t.Errorf("Error should mention scope methods, got: %v", err)
	}
}

// TestSearchRules_CorruptedConditionsJSON tests corrupted conditions JSON
func TestSearchRules_CorruptedConditionsJSON(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Insert rule with corrupted conditions JSON
	_, err := storage.db.Exec(`
		INSERT INTO rules (
			name, description, enabled, priority, scope_direction,
			scope_methods, conditions, actions,
			created_at, modified_at, version
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, "test-rule-conditions", "Test rule", true, 1, "request",
		"[]", "{not-valid-json", "[]",
		time.Now().Unix(), time.Now().Unix(), 1)
	if err != nil {
		t.Fatalf("Failed to insert test rule: %v", err)
	}

	// SearchRules should return error
	_, err = storage.SearchRules(ctx, "test")
	if err == nil {
		t.Error("SearchRules should return error for corrupted conditions JSON")
	}
	if !strings.Contains(err.Error(), "conditions") {
		t.Errorf("Error should mention conditions, got: %v", err)
	}
}

// TestSearchRules_CorruptedActionsJSON tests corrupted actions JSON
func TestSearchRules_CorruptedActionsJSON(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Insert rule with corrupted actions JSON
	_, err := storage.db.Exec(`
		INSERT INTO rules (
			name, description, enabled, priority, scope_direction,
			scope_methods, conditions, actions,
			created_at, modified_at, version
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, "test-rule-actions", "Test rule", true, 1, "request",
		"[]", "[]", "broken}}}",
		time.Now().Unix(), time.Now().Unix(), 1)
	if err != nil {
		t.Fatalf("Failed to insert test rule: %v", err)
	}

	// SearchRules should return error
	_, err = storage.SearchRules(ctx, "test")
	if err == nil {
		t.Error("SearchRules should return error for corrupted actions JSON")
	}
	if !strings.Contains(err.Error(), "actions") {
		t.Errorf("Error should mention actions, got: %v", err)
	}
}

// TestSearchRules_CorruptedTagsJSON tests corrupted tags JSON
func TestSearchRules_CorruptedTagsJSON(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Insert rule with corrupted tags JSON
	_, err := storage.db.Exec(`
		INSERT INTO rules (
			name, description, enabled, priority, scope_direction,
			scope_methods, conditions, actions, tags,
			created_at, modified_at, version
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, "test-rule-tags", "Test rule", true, 1, "request",
		"[]", "[]", "[]", "[invalid tags",
		time.Now().Unix(), time.Now().Unix(), 1)
	if err != nil {
		t.Fatalf("Failed to insert test rule: %v", err)
	}

	// SearchRules should return error
	_, err = storage.SearchRules(ctx, "test")
	if err == nil {
		t.Error("SearchRules should return error for corrupted tags JSON")
	}
	if !strings.Contains(err.Error(), "tags") {
		t.Errorf("Error should mention tags, got: %v", err)
	}
}

// TestListRules_CorruptedJSON tests that ListRules returns error for corrupted JSON
func TestListRules_CorruptedJSON(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	// Insert rule with corrupted scope_methods JSON
	_, err := storage.db.Exec(`
		INSERT INTO rules (
			name, description, enabled, priority, scope_direction,
			scope_methods, conditions, actions,
			created_at, modified_at, version
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, "test-list-rule", "Test rule", true, 1, "request",
		"not-json-array", "[]", "[]",
		time.Now().Unix(), time.Now().Unix(), 1)
	if err != nil {
		t.Fatalf("Failed to insert test rule: %v", err)
	}

	// ListRules should return error for corrupted JSON
	_, err = storage.ListRules()
	if err == nil {
		t.Error("ListRules should return error for corrupted JSON")
	}
	if !strings.Contains(err.Error(), "unmarshal") {
		t.Errorf("Error should mention unmarshal, got: %v", err)
	}
}

// TestListRules_CorruptedConditionsJSON tests corrupted conditions in ListRules
func TestListRules_CorruptedConditionsJSON(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	// Insert rule with corrupted conditions JSON
	_, err := storage.db.Exec(`
		INSERT INTO rules (
			name, description, enabled, priority, scope_direction,
			scope_methods, conditions, actions,
			created_at, modified_at, version
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, "test-list-conditions", "Test rule", true, 1, "request",
		"[]", "corrupted{conditions}", "[]",
		time.Now().Unix(), time.Now().Unix(), 1)
	if err != nil {
		t.Fatalf("Failed to insert test rule: %v", err)
	}

	// ListRules should return error
	_, err = storage.ListRules()
	if err == nil {
		t.Error("ListRules should return error for corrupted conditions JSON")
	}
	if !strings.Contains(err.Error(), "conditions") {
		t.Errorf("Error should mention conditions, got: %v", err)
	}
}

// TestGetRule_CorruptedJSON tests that GetRule returns error for corrupted JSON
func TestGetRule_CorruptedJSON(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Insert rule with corrupted scope_methods JSON
	result, err := storage.db.Exec(`
		INSERT INTO rules (
			name, description, enabled, priority, scope_direction,
			scope_methods, conditions, actions,
			created_at, modified_at, version
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, "test-get-rule", "Test rule", true, 1, "request",
		"{{invalid json}}", "[]", "[]",
		time.Now().Unix(), time.Now().Unix(), 1)
	if err != nil {
		t.Fatalf("Failed to insert test rule: %v", err)
	}

	id, _ := result.LastInsertId()

	// GetRule should return error for corrupted JSON
	_, err = storage.GetRule(ctx, int(id))
	if err == nil {
		t.Error("GetRule should return error for corrupted JSON")
	}
	if !strings.Contains(err.Error(), "unmarshal") {
		t.Errorf("Error should mention unmarshal, got: %v", err)
	}
}

// TestStorage_ValidJSON tests that valid JSON works correctly
func TestStorage_ValidJSON(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Create a valid rule
	rule := &Rule{
		Name:        "valid-rule",
		Description: "A valid test rule",
		Enabled:     true,
		Priority:    10,
		Scope: RuleScope{
			Direction:  DirectionRequest,
			Methods:    []string{"GET", "POST"},
			URLPattern: "/api/*",
		},
		Conditions: []Condition{
			{
				Field:    "header:Content-Type",
				Operator: "contains",
				Value:    "json",
			},
		},
		Actions: []Action{
			{
				Type:     ActionAdd,
				Location: LocationHeader,
				Name:     "X-Test",
				Value:    "test-value",
			},
		},
		Tags:       []string{"test", "valid"},
		Author:     "test-author",
		CreatedAt:  time.Now(),
		ModifiedAt: time.Now(),
		Version:    1,
	}

	// Create rule
	err := storage.CreateRule(ctx, rule)
	if err != nil {
		t.Fatalf("CreateRule failed: %v", err)
	}

	// Get rule
	retrieved, err := storage.GetRule(ctx, rule.ID)
	if err != nil {
		t.Fatalf("GetRule failed: %v", err)
	}

	// Verify fields
	if retrieved.Name != rule.Name {
		t.Errorf("Name = %s, want %s", retrieved.Name, rule.Name)
	}
	if len(retrieved.Scope.Methods) != 2 {
		t.Errorf("Scope.Methods length = %d, want 2", len(retrieved.Scope.Methods))
	}
	if len(retrieved.Conditions) != 1 {
		t.Errorf("Conditions length = %d, want 1", len(retrieved.Conditions))
	}
	if len(retrieved.Actions) != 1 {
		t.Errorf("Actions length = %d, want 1", len(retrieved.Actions))
	}
	if len(retrieved.Tags) != 2 {
		t.Errorf("Tags length = %d, want 2", len(retrieved.Tags))
	}

	// List rules
	rules, err := storage.ListRules()
	if err != nil {
		t.Fatalf("ListRules failed: %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("ListRules returned %d rules, want 1", len(rules))
	}

	// Search rules
	searchResults, err := storage.SearchRules(ctx, "valid")
	if err != nil {
		t.Fatalf("SearchRules failed: %v", err)
	}
	if len(searchResults) != 1 {
		t.Errorf("SearchRules returned %d rules, want 1", len(searchResults))
	}
}

// TestStorage_EmptyJSON tests that empty JSON fields work correctly
func TestStorage_EmptyJSON(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Insert rule with empty JSON arrays (valid)
	_, err := storage.db.Exec(`
		INSERT INTO rules (
			name, description, enabled, priority, scope_direction,
			scope_methods, conditions, actions,
			created_at, modified_at, version
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, "empty-json-rule", "Test rule", true, 1, "request",
		"[]", "[]", "[]",
		time.Now().Unix(), time.Now().Unix(), 1)
	if err != nil {
		t.Fatalf("Failed to insert test rule: %v", err)
	}

	// ListRules should succeed with empty arrays
	rules, err := storage.ListRules()
	if err != nil {
		t.Fatalf("ListRules should succeed with empty JSON: %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(rules))
	}

	// SearchRules should succeed
	results, err := storage.SearchRules(ctx, "empty")
	if err != nil {
		t.Fatalf("SearchRules should succeed with empty JSON: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}
}

// TestStorage_MultipleRulesWithOneCorrupted tests that one corrupted rule fails the whole operation
func TestStorage_MultipleRulesWithOneCorrupted(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	ctx := context.Background()

	// Insert valid rule
	_, err := storage.db.Exec(`
		INSERT INTO rules (
			name, description, enabled, priority, scope_direction,
			scope_methods, conditions, actions,
			created_at, modified_at, version
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, "valid-rule-1", "Valid rule", true, 1, "request",
		`["GET"]`, "[]", "[]",
		time.Now().Unix(), time.Now().Unix(), 1)
	if err != nil {
		t.Fatalf("Failed to insert valid rule: %v", err)
	}

	// Insert corrupted rule
	_, err = storage.db.Exec(`
		INSERT INTO rules (
			name, description, enabled, priority, scope_direction,
			scope_methods, conditions, actions,
			created_at, modified_at, version
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, "corrupted-rule", "Corrupted rule", true, 0, "request",
		"not-json", "[]", "[]",
		time.Now().Unix(), time.Now().Unix(), 1)
	if err != nil {
		t.Fatalf("Failed to insert corrupted rule: %v", err)
	}

	// ListRules should fail because of corrupted rule
	_, err = storage.ListRules()
	if err == nil {
		t.Error("ListRules should fail when encountering corrupted rule")
	}

	// SearchRules should also fail
	_, err = storage.SearchRules(ctx, "rule")
	if err == nil {
		t.Error("SearchRules should fail when encountering corrupted rule")
	}
}
