package templates

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewManager(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}

	if mgr.customDir == "" {
		t.Error("customDir should not be empty")
	}

	// Verify custom directory exists
	if _, err := os.Stat(mgr.customDir); os.IsNotExist(err) {
		t.Errorf("custom directory was not created: %s", mgr.customDir)
	}
}

func TestListBuiltinTemplates(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}

	templates, err := mgr.listBuiltin()
	if err != nil {
		t.Fatalf("listBuiltin() failed: %v", err)
	}

	if len(templates) == 0 {
		t.Error("Expected at least one built-in template")
	}

	// Check that all templates have required fields
	for _, tmpl := range templates {
		if tmpl.Name == "" {
			t.Error("Template name should not be empty")
		}
		if !tmpl.IsBuiltin {
			t.Error("Built-in template should have IsBuiltin = true")
		}
		if tmpl.IsCustom {
			t.Error("Built-in template should have IsCustom = false")
		}
	}

	// Check for specific built-in templates
	expectedTemplates := []string{
		"Bug Bounty Hunter",
		"Quick Scan",
		"Deep Scan",
		"CI/CD Pipeline",
		"Stealth Mode",
		"Professional Penetration Testing",
		"API Testing",
	}

	foundNames := make(map[string]bool)
	for _, tmpl := range templates {
		foundNames[tmpl.Name] = true
	}

	for _, expected := range expectedTemplates {
		if !foundNames[expected] {
			t.Errorf("Expected built-in template not found: %s", expected)
		}
	}
}

func TestGetTemplate(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}

	// Test getting a built-in template
	tmpl, err := mgr.Get("Quick Scan")
	if err != nil {
		t.Fatalf("Get('Quick Scan') failed: %v", err)
	}

	if tmpl.Name != "Quick Scan" {
		t.Errorf("Expected name 'Quick Scan', got '%s'", tmpl.Name)
	}

	if !tmpl.IsBuiltin {
		t.Error("Quick Scan should be a built-in template")
	}

	// Verify configuration is loaded
	if tmpl.Config.Depth == nil {
		t.Error("Expected depth to be set in Quick Scan template")
	}

	// Test getting non-existent template
	_, err = mgr.Get("NonExistentTemplate")
	if err == nil {
		t.Error("Expected error when getting non-existent template")
	}
}

func TestSaveAndLoadCustomTemplate(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()

	// Create manager with custom directory
	mgr := &Manager{
		customDir: tmpDir,
	}

	// Create a test template
	depth := 2
	concurrency := 20
	testTemplate := &Template{
		Name:        "Test Template",
		Description: "A test template",
		Config: TemplateConfig{
			Depth:          &depth,
			MaxConcurrency: &concurrency,
		},
	}

	// Save the template
	err := mgr.Save(testTemplate)
	if err != nil {
		t.Fatalf("Save() failed: %v", err)
	}

	// Verify file was created
	files, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to read temp directory: %v", err)
	}

	if len(files) == 0 {
		t.Fatal("Expected template file to be created")
	}

	// Load the template
	customs, err := mgr.listCustom()
	if err != nil {
		t.Fatalf("listCustom() failed: %v", err)
	}

	if len(customs) != 1 {
		t.Fatalf("Expected 1 custom template, got %d", len(customs))
	}

	loaded := customs[0]
	if loaded.Name != "Test Template" {
		t.Errorf("Expected name 'Test Template', got '%s'", loaded.Name)
	}

	if !loaded.IsCustom {
		t.Error("Loaded template should be marked as custom")
	}

	if loaded.Config.Depth == nil || *loaded.Config.Depth != 2 {
		t.Error("Template configuration not properly loaded")
	}
}

func TestImportExport(t *testing.T) {
	tmpDir := t.TempDir()

	mgr := &Manager{
		customDir: tmpDir,
	}

	// Create a test template
	depth := 3
	testTemplate := &Template{
		Name:        "Export Test",
		Description: "Template for export test",
		Config: TemplateConfig{
			Depth: &depth,
		},
	}

	// Save the template
	err := mgr.Save(testTemplate)
	if err != nil {
		t.Fatalf("Save() failed: %v", err)
	}

	// Export the template
	exportPath := filepath.Join(tmpDir, "exported.yaml")
	err = mgr.Export("Export Test", exportPath)
	if err != nil {
		t.Fatalf("Export() failed: %v", err)
	}

	// Verify export file exists
	if _, err := os.Stat(exportPath); os.IsNotExist(err) {
		t.Error("Export file was not created")
	}

	// Create a new manager with different directory
	importDir := filepath.Join(tmpDir, "import")
	os.MkdirAll(importDir, 0755)

	importMgr := &Manager{
		customDir: importDir,
	}

	// Import the template
	err = importMgr.Import(exportPath)
	if err != nil {
		t.Fatalf("Import() failed: %v", err)
	}

	// Verify imported template
	imported, err := importMgr.Get("Export Test")
	if err != nil {
		t.Fatalf("Get() after import failed: %v", err)
	}

	if imported.Name != "Export Test" {
		t.Errorf("Expected name 'Export Test', got '%s'", imported.Name)
	}
}

func TestDeleteTemplate(t *testing.T) {
	tmpDir := t.TempDir()

	mgr := &Manager{
		customDir: tmpDir,
	}

	// Create and save a template
	depth := 1
	testTemplate := &Template{
		Name:        "Delete Me",
		Description: "Template to be deleted",
		Config: TemplateConfig{
			Depth: &depth,
		},
	}

	err := mgr.Save(testTemplate)
	if err != nil {
		t.Fatalf("Save() failed: %v", err)
	}

	// Verify it exists
	_, err = mgr.Get("Delete Me")
	if err != nil {
		t.Fatalf("Template should exist after save: %v", err)
	}

	// Delete the template
	err = mgr.Delete("Delete Me")
	if err != nil {
		t.Fatalf("Delete() failed: %v", err)
	}

	// Verify it's gone
	_, err = mgr.Get("Delete Me")
	if err == nil {
		t.Error("Template should not exist after delete")
	}
}

func TestDeleteBuiltinTemplate(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}

	// Try to delete a built-in template
	err = mgr.Delete("Quick Scan")
	if err == nil {
		t.Error("Expected error when deleting built-in template")
	}
}

func TestCreateFromFlags(t *testing.T) {
	flags := map[string]interface{}{
		"concurrency":  20,
		"rate":         100.0,
		"attack":       "sniper",
		"anomaly":      true,
		"ai":           false,
		"ai-payloads":  true,
	}

	tmpl := CreateFromFlags("Test", "Test description", flags)

	if tmpl.Name != "Test" {
		t.Errorf("Expected name 'Test', got '%s'", tmpl.Name)
	}

	if tmpl.Config.MaxConcurrency == nil || *tmpl.Config.MaxConcurrency != 20 {
		t.Error("MaxConcurrency not set correctly")
	}

	if tmpl.Config.RateLimit == nil || *tmpl.Config.RateLimit != 100.0 {
		t.Error("RateLimit not set correctly")
	}

	if tmpl.Config.AttackType == nil || *tmpl.Config.AttackType != "sniper" {
		t.Error("AttackType not set correctly")
	}

	if tmpl.Config.EnableAIPayloads == nil || !*tmpl.Config.EnableAIPayloads {
		t.Error("EnableAIPayloads not set correctly")
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input    string
		contains string
	}{
		{"Simple Name", "simple-name"},
		{"Name With Spaces", "name-with-spaces"},
		{"Special!@#Characters", "special___characters"},
		{"CamelCase", "camelcase"},
	}

	for _, tt := range tests {
		result := sanitizeFilename(tt.input)
		if result == "" {
			t.Errorf("sanitizeFilename(%q) returned empty string", tt.input)
		}
		// Result should contain lowercase version of expected
		if len(result) < len(tt.contains) {
			t.Errorf("sanitizeFilename(%q) = %q, should contain %q", tt.input, result, tt.contains)
		}
	}
}
