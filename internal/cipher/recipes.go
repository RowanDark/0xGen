package cipher

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RecipeManager handles storage and retrieval of recipes
type RecipeManager struct {
	recipes   map[string]*Recipe
	storePath string
	mu        sync.RWMutex
}

// NewRecipeManager creates a new recipe manager
func NewRecipeManager(storePath string) *RecipeManager {
	return &RecipeManager{
		recipes:   make(map[string]*Recipe),
		storePath: storePath,
	}
}

// SaveRecipe stores a recipe
func (rm *RecipeManager) SaveRecipe(recipe *Recipe) error {
	if recipe.Name == "" {
		return fmt.Errorf("recipe name cannot be empty")
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	if recipe.CreatedAt == "" {
		recipe.CreatedAt = now
	}
	recipe.UpdatedAt = now

	rm.recipes[recipe.Name] = recipe

	// Persist to disk if store path is configured
	if rm.storePath != "" {
		return rm.persistRecipe(recipe)
	}

	return nil
}

// GetRecipe retrieves a recipe by name
func (rm *RecipeManager) GetRecipe(name string) (*Recipe, bool) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	recipe, exists := rm.recipes[name]
	return recipe, exists
}

// ListRecipes returns all recipes
func (rm *RecipeManager) ListRecipes() []*Recipe {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	recipes := make([]*Recipe, 0, len(rm.recipes))
	for _, recipe := range rm.recipes {
		recipes = append(recipes, recipe)
	}

	return recipes
}

// DeleteRecipe removes a recipe
func (rm *RecipeManager) DeleteRecipe(name string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	delete(rm.recipes, name)

	// Remove from disk if store path is configured
	if rm.storePath != "" {
		recipePath := filepath.Join(rm.storePath, sanitizeFilename(name)+".json")
		if err := os.Remove(recipePath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to delete recipe file: %w", err)
		}
	}

	return nil
}

// LoadRecipes loads all recipes from the store path
func (rm *RecipeManager) LoadRecipes() error {
	if rm.storePath == "" {
		return nil
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Create directory if it doesn't exist
	if err := os.MkdirAll(rm.storePath, 0755); err != nil {
		return fmt.Errorf("failed to create recipes directory: %w", err)
	}

	// Read all recipe files
	entries, err := os.ReadDir(rm.storePath)
	if err != nil {
		return fmt.Errorf("failed to read recipes directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		recipePath := filepath.Join(rm.storePath, entry.Name())
		data, err := os.ReadFile(recipePath)
		if err != nil {
			return fmt.Errorf("failed to read recipe %s: %w", entry.Name(), err)
		}

		var recipe Recipe
		if err := json.Unmarshal(data, &recipe); err != nil {
			return fmt.Errorf("failed to parse recipe %s: %w", entry.Name(), err)
		}

		rm.recipes[recipe.Name] = &recipe
	}

	return nil
}

// persistRecipe writes a single recipe to disk
func (rm *RecipeManager) persistRecipe(recipe *Recipe) error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(rm.storePath, 0755); err != nil {
		return fmt.Errorf("failed to create recipes directory: %w", err)
	}

	data, err := json.MarshalIndent(recipe, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize recipe: %w", err)
	}

	recipePath := filepath.Join(rm.storePath, sanitizeFilename(recipe.Name)+".json")
	if err := os.WriteFile(recipePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write recipe file: %w", err)
	}

	return nil
}

// sanitizeFilename converts a recipe name to a safe filename
func sanitizeFilename(name string) string {
	// Simple sanitization - replace unsafe characters
	safe := ""
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			safe += string(r)
		} else if r == ' ' {
			safe += "_"
		}
	}
	if safe == "" {
		safe = "recipe"
	}
	return safe
}

// SearchRecipes finds recipes by tag or name pattern
func (rm *RecipeManager) SearchRecipes(query string) []*Recipe {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	results := make([]*Recipe, 0)
	for _, recipe := range rm.recipes {
		// Check if query matches name or tags
		if contains(recipe.Name, query) || contains(recipe.Description, query) {
			results = append(results, recipe)
			continue
		}

		for _, tag := range recipe.Tags {
			if contains(tag, query) {
				results = append(results, recipe)
				break
			}
		}
	}

	return results
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if toLower(s[i+j]) != toLower(substr[j]) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func toLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
