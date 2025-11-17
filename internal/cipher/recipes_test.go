package cipher

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRecipeManagerSaveAndGet(t *testing.T) {
	rm := NewRecipeManager("")

	recipe := &Recipe{
		Name:        "test-recipe",
		Description: "A test recipe",
		Tags:        []string{"test", "example"},
		Pipeline: Pipeline{
			Operations: []OperationConfig{
				{Name: "base64_encode"},
			},
			Reversible: true,
		},
	}

	err := rm.SaveRecipe(recipe)
	if err != nil {
		t.Fatalf("SaveRecipe failed: %v", err)
	}

	retrieved, exists := rm.GetRecipe("test-recipe")
	if !exists {
		t.Fatal("recipe should exist")
	}

	if retrieved.Name != recipe.Name {
		t.Errorf("expected name %q, got %q", recipe.Name, retrieved.Name)
	}

	if retrieved.Description != recipe.Description {
		t.Errorf("expected description %q, got %q", recipe.Description, retrieved.Description)
	}

	if retrieved.CreatedAt == "" {
		t.Error("CreatedAt should be set")
	}

	if retrieved.UpdatedAt == "" {
		t.Error("UpdatedAt should be set")
	}
}

func TestRecipeManagerList(t *testing.T) {
	rm := NewRecipeManager("")

	recipes := []*Recipe{
		{
			Name:        "recipe1",
			Description: "First recipe",
			Pipeline:    Pipeline{Operations: []OperationConfig{{Name: "base64_encode"}}},
		},
		{
			Name:        "recipe2",
			Description: "Second recipe",
			Pipeline:    Pipeline{Operations: []OperationConfig{{Name: "url_encode"}}},
		},
	}

	for _, recipe := range recipes {
		if err := rm.SaveRecipe(recipe); err != nil {
			t.Fatalf("SaveRecipe failed: %v", err)
		}
	}

	list := rm.ListRecipes()
	if len(list) != 2 {
		t.Errorf("expected 2 recipes, got %d", len(list))
	}
}

func TestRecipeManagerDelete(t *testing.T) {
	rm := NewRecipeManager("")

	recipe := &Recipe{
		Name:        "to-delete",
		Description: "Will be deleted",
		Pipeline:    Pipeline{Operations: []OperationConfig{{Name: "base64_encode"}}},
	}

	rm.SaveRecipe(recipe)

	err := rm.DeleteRecipe("to-delete")
	if err != nil {
		t.Fatalf("DeleteRecipe failed: %v", err)
	}

	_, exists := rm.GetRecipe("to-delete")
	if exists {
		t.Error("recipe should not exist after deletion")
	}
}

func TestRecipeManagerPersistence(t *testing.T) {
	// Create temp directory for recipes
	tempDir := t.TempDir()

	rm := NewRecipeManager(tempDir)

	recipe := &Recipe{
		Name:        "persistent-recipe",
		Description: "Should persist to disk",
		Tags:        []string{"persistent"},
		Pipeline: Pipeline{
			Operations: []OperationConfig{
				{Name: "base64_encode"},
				{Name: "url_encode"},
			},
			Reversible: true,
		},
	}

	err := rm.SaveRecipe(recipe)
	if err != nil {
		t.Fatalf("SaveRecipe failed: %v", err)
	}

	// Create new manager pointing to same directory
	rm2 := NewRecipeManager(tempDir)
	err = rm2.LoadRecipes()
	if err != nil {
		t.Fatalf("LoadRecipes failed: %v", err)
	}

	retrieved, exists := rm2.GetRecipe("persistent-recipe")
	if !exists {
		t.Fatal("recipe should exist after loading from disk")
	}

	if retrieved.Description != recipe.Description {
		t.Errorf("expected description %q, got %q", recipe.Description, retrieved.Description)
	}

	if len(retrieved.Pipeline.Operations) != 2 {
		t.Errorf("expected 2 operations, got %d", len(retrieved.Pipeline.Operations))
	}
}

func TestRecipeManagerSearch(t *testing.T) {
	rm := NewRecipeManager("")

	recipes := []*Recipe{
		{
			Name:        "jwt-decoder",
			Description: "Decodes JWT tokens",
			Tags:        []string{"jwt", "decode"},
			Pipeline:    Pipeline{Operations: []OperationConfig{{Name: "jwt_decode"}}},
		},
		{
			Name:        "base64-chain",
			Description: "Double base64 encoding",
			Tags:        []string{"base64", "encoding"},
			Pipeline:    Pipeline{Operations: []OperationConfig{{Name: "base64_encode"}}},
		},
		{
			Name:        "jwt-signer",
			Description: "Signs JWT tokens",
			Tags:        []string{"jwt", "sign"},
			Pipeline:    Pipeline{Operations: []OperationConfig{{Name: "jwt_sign"}}},
		},
	}

	for _, recipe := range recipes {
		rm.SaveRecipe(recipe)
	}

	// Search by tag
	results := rm.SearchRecipes("jwt")
	if len(results) != 2 {
		t.Errorf("expected 2 JWT recipes, got %d", len(results))
	}

	// Search by name
	results = rm.SearchRecipes("decoder")
	if len(results) != 1 {
		t.Errorf("expected 1 decoder recipe, got %d", len(results))
	}

	// Search by description
	results = rm.SearchRecipes("Double")
	if len(results) != 1 {
		t.Errorf("expected 1 recipe with 'Double' in description, got %d", len(results))
	}
}

func TestRecipeManagerEmptyName(t *testing.T) {
	rm := NewRecipeManager("")

	recipe := &Recipe{
		Name:     "",
		Pipeline: Pipeline{Operations: []OperationConfig{{Name: "base64_encode"}}},
	}

	err := rm.SaveRecipe(recipe)
	if err == nil {
		t.Error("expected error when saving recipe with empty name")
	}
}

func TestRecipeManagerDeletePersistent(t *testing.T) {
	tempDir := t.TempDir()
	rm := NewRecipeManager(tempDir)

	recipe := &Recipe{
		Name:        "to-delete-from-disk",
		Description: "Will be deleted from disk",
		Pipeline:    Pipeline{Operations: []OperationConfig{{Name: "base64_encode"}}},
	}

	rm.SaveRecipe(recipe)

	// Verify file exists
	recipePath := filepath.Join(tempDir, "to-delete-from-disk.json")
	if _, err := os.Stat(recipePath); os.IsNotExist(err) {
		t.Fatal("recipe file should exist")
	}

	// Delete recipe
	err := rm.DeleteRecipe("to-delete-from-disk")
	if err != nil {
		t.Fatalf("DeleteRecipe failed: %v", err)
	}

	// Verify file is deleted
	if _, err := os.Stat(recipePath); !os.IsNotExist(err) {
		t.Error("recipe file should be deleted")
	}
}

func TestRecipeManagerLoadMultipleRecipes(t *testing.T) {
	// This test verifies that loading multiple recipes from disk
	// results in distinct recipe objects (regression test for pointer bug)
	tempDir := t.TempDir()
	rm := NewRecipeManager(tempDir)

	// Save multiple recipes
	recipes := []*Recipe{
		{
			Name:        "recipe-alpha",
			Description: "First recipe",
			Tags:        []string{"alpha"},
			Pipeline:    Pipeline{Operations: []OperationConfig{{Name: "base64_encode"}}},
		},
		{
			Name:        "recipe-beta",
			Description: "Second recipe",
			Tags:        []string{"beta"},
			Pipeline:    Pipeline{Operations: []OperationConfig{{Name: "url_encode"}}},
		},
		{
			Name:        "recipe-gamma",
			Description: "Third recipe",
			Tags:        []string{"gamma"},
			Pipeline:    Pipeline{Operations: []OperationConfig{{Name: "hex_encode"}}},
		},
	}

	for _, recipe := range recipes {
		if err := rm.SaveRecipe(recipe); err != nil {
			t.Fatalf("SaveRecipe failed: %v", err)
		}
	}

	// Load recipes in a new manager
	rm2 := NewRecipeManager(tempDir)
	if err := rm2.LoadRecipes(); err != nil {
		t.Fatalf("LoadRecipes failed: %v", err)
	}

	// Verify each recipe is distinct and has correct data
	for _, expected := range recipes {
		retrieved, exists := rm2.GetRecipe(expected.Name)
		if !exists {
			t.Fatalf("recipe %q should exist after loading", expected.Name)
		}

		if retrieved.Name != expected.Name {
			t.Errorf("recipe %q: expected name %q, got %q", expected.Name, expected.Name, retrieved.Name)
		}

		if retrieved.Description != expected.Description {
			t.Errorf("recipe %q: expected description %q, got %q", expected.Name, expected.Description, retrieved.Description)
		}

		if len(retrieved.Tags) != len(expected.Tags) || (len(retrieved.Tags) > 0 && retrieved.Tags[0] != expected.Tags[0]) {
			t.Errorf("recipe %q: tags mismatch, expected %v, got %v", expected.Name, expected.Tags, retrieved.Tags)
		}

		if len(retrieved.Pipeline.Operations) != 1 {
			t.Errorf("recipe %q: expected 1 operation, got %d", expected.Name, len(retrieved.Pipeline.Operations))
		} else if retrieved.Pipeline.Operations[0].Name != expected.Pipeline.Operations[0].Name {
			t.Errorf("recipe %q: expected operation %q, got %q",
				expected.Name,
				expected.Pipeline.Operations[0].Name,
				retrieved.Pipeline.Operations[0].Name)
		}
	}

	// Verify we loaded exactly 3 recipes
	allRecipes := rm2.ListRecipes()
	if len(allRecipes) != 3 {
		t.Errorf("expected 3 recipes, got %d", len(allRecipes))
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple-name", "simple-name"},
		{"name with spaces", "name_with_spaces"},
		{"special!@#$%chars", "specialchars"},
		{"CamelCase123", "CamelCase123"},
		{"", "recipe"},
		{"!!!!", "recipe"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeFilename(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}
