package templates

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed builtin/*.yaml
var builtinTemplates embed.FS

// Template represents a scan template with configuration presets.
type Template struct {
	Name        string       `yaml:"name"`
	Description string       `yaml:"description"`
	Config      TemplateConfig `yaml:"config"`

	// Metadata (not stored in YAML)
	Path      string
	IsBuiltin bool
	IsCustom  bool
}

// TemplateConfig contains the scan configuration parameters.
type TemplateConfig struct {
	// Scan depth and coverage
	Depth        *int     `yaml:"depth,omitempty"`
	Intensity    *int     `yaml:"intensity,omitempty"`
	Thoroughness *int     `yaml:"thoroughness,omitempty"`

	// Performance and rate limiting
	MaxConcurrency *int     `yaml:"max_concurrency,omitempty"`
	RateLimit      *float64 `yaml:"rate_limit,omitempty"`
	Timeout        *string  `yaml:"timeout,omitempty"`

	// Module configuration
	EnableOAST      *bool    `yaml:"enable_oast,omitempty"`
	EnabledModules  []string `yaml:"enabled_modules,omitempty"`
	DisabledModules []string `yaml:"disabled_modules,omitempty"`

	// Attack configuration (for blitz)
	AttackType *string `yaml:"attack_type,omitempty"`
	Markers    *string `yaml:"markers,omitempty"`

	// Analysis configuration
	EnableAnomaly *bool    `yaml:"enable_anomaly,omitempty"`
	Patterns      []string `yaml:"patterns,omitempty"`

	// AI features
	EnableAI           *bool `yaml:"enable_ai,omitempty"`
	EnableAIPayloads   *bool `yaml:"enable_ai_payloads,omitempty"`
	EnableAIClassify   *bool `yaml:"enable_ai_classify,omitempty"`
	EnableAIFindings   *bool `yaml:"enable_ai_findings,omitempty"`

	// Stealth options
	RandomizeUserAgent *bool `yaml:"randomize_user_agent,omitempty"`

	// Request configuration
	MaxRetries *int `yaml:"max_retries,omitempty"`
}

// Manager handles template operations.
type Manager struct {
	customDir string
}

// NewManager creates a new template manager.
func NewManager() (*Manager, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("determine home directory: %w", err)
	}

	customDir := filepath.Join(home, ".0xgen", "templates")

	// Ensure custom templates directory exists
	if err := os.MkdirAll(customDir, 0755); err != nil {
		return nil, fmt.Errorf("create templates directory: %w", err)
	}

	return &Manager{
		customDir: customDir,
	}, nil
}

// List returns all available templates (built-in and custom).
func (m *Manager) List() ([]*Template, error) {
	var templates []*Template

	// Load built-in templates
	builtins, err := m.listBuiltin()
	if err != nil {
		return nil, fmt.Errorf("list built-in templates: %w", err)
	}
	templates = append(templates, builtins...)

	// Load custom templates
	customs, err := m.listCustom()
	if err != nil {
		return nil, fmt.Errorf("list custom templates: %w", err)
	}
	templates = append(templates, customs...)

	// Sort by name
	sort.Slice(templates, func(i, j int) bool {
		// Built-in templates first
		if templates[i].IsBuiltin != templates[j].IsBuiltin {
			return templates[i].IsBuiltin
		}
		return templates[i].Name < templates[j].Name
	})

	return templates, nil
}

// listBuiltin loads all built-in templates from embedded filesystem.
func (m *Manager) listBuiltin() ([]*Template, error) {
	var templates []*Template

	entries, err := fs.ReadDir(builtinTemplates, "builtin")
	if err != nil {
		return nil, fmt.Errorf("read builtin directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		data, err := fs.ReadFile(builtinTemplates, filepath.Join("builtin", entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read builtin template %s: %w", entry.Name(), err)
		}

		var tmpl Template
		if err := yaml.Unmarshal(data, &tmpl); err != nil {
			return nil, fmt.Errorf("parse builtin template %s: %w", entry.Name(), err)
		}

		tmpl.Path = fmt.Sprintf("builtin/%s", entry.Name())
		tmpl.IsBuiltin = true
		tmpl.IsCustom = false

		templates = append(templates, &tmpl)
	}

	return templates, nil
}

// listCustom loads all custom templates from user directory.
func (m *Manager) listCustom() ([]*Template, error) {
	var templates []*Template

	entries, err := os.ReadDir(m.customDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return templates, nil
		}
		return nil, fmt.Errorf("read custom directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		path := filepath.Join(m.customDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read custom template %s: %w", entry.Name(), err)
		}

		var tmpl Template
		if err := yaml.Unmarshal(data, &tmpl); err != nil {
			return nil, fmt.Errorf("parse custom template %s: %w", entry.Name(), err)
		}

		tmpl.Path = path
		tmpl.IsBuiltin = false
		tmpl.IsCustom = true

		templates = append(templates, &tmpl)
	}

	return templates, nil
}

// Get retrieves a template by name.
func (m *Manager) Get(name string) (*Template, error) {
	templates, err := m.List()
	if err != nil {
		return nil, err
	}

	for _, tmpl := range templates {
		if tmpl.Name == name {
			return tmpl, nil
		}
	}

	return nil, fmt.Errorf("template not found: %s", name)
}

// Save saves a template to the custom directory.
func (m *Manager) Save(tmpl *Template) error {
	if tmpl.Name == "" {
		return errors.New("template name is required")
	}

	// Sanitize name for filename
	filename := sanitizeFilename(tmpl.Name) + ".yaml"
	path := filepath.Join(m.customDir, filename)

	data, err := yaml.Marshal(tmpl)
	if err != nil {
		return fmt.Errorf("marshal template: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write template: %w", err)
	}

	return nil
}

// Import imports a template from a file.
func (m *Manager) Import(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read template file: %w", err)
	}

	var tmpl Template
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	if tmpl.Name == "" {
		return errors.New("template name is required")
	}

	return m.Save(&tmpl)
}

// Export exports a template to a file.
func (m *Manager) Export(name, outputPath string) error {
	tmpl, err := m.Get(name)
	if err != nil {
		return err
	}

	data, err := yaml.Marshal(tmpl)
	if err != nil {
		return fmt.Errorf("marshal template: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("write template file: %w", err)
	}

	return nil
}

// Delete removes a custom template.
func (m *Manager) Delete(name string) error {
	tmpl, err := m.Get(name)
	if err != nil {
		return err
	}

	if tmpl.IsBuiltin {
		return errors.New("cannot delete built-in template")
	}

	if err := os.Remove(tmpl.Path); err != nil {
		return fmt.Errorf("delete template: %w", err)
	}

	return nil
}

// CreateFromFlags creates a template from command-line flags.
func CreateFromFlags(name, description string, flags map[string]interface{}) *Template {
	tmpl := &Template{
		Name:        name,
		Description: description,
		Config:      TemplateConfig{},
	}

	// Map flags to template config
	if v, ok := flags["concurrency"].(int); ok {
		tmpl.Config.MaxConcurrency = &v
	}
	if v, ok := flags["rate"].(float64); ok {
		tmpl.Config.RateLimit = &v
	}
	if v, ok := flags["attack"].(string); ok {
		tmpl.Config.AttackType = &v
	}
	if v, ok := flags["markers"].(string); ok {
		tmpl.Config.Markers = &v
	}
	if v, ok := flags["anomaly"].(bool); ok {
		tmpl.Config.EnableAnomaly = &v
	}
	if v, ok := flags["ai"].(bool); ok {
		tmpl.Config.EnableAI = &v
	}
	if v, ok := flags["ai-payloads"].(bool); ok {
		tmpl.Config.EnableAIPayloads = &v
	}
	if v, ok := flags["ai-classify"].(bool); ok {
		tmpl.Config.EnableAIClassify = &v
	}
	if v, ok := flags["ai-findings"].(bool); ok {
		tmpl.Config.EnableAIFindings = &v
	}
	if v, ok := flags["retries"].(int); ok {
		tmpl.Config.MaxRetries = &v
	}
	if v, ok := flags["patterns"].(string); ok && v != "" {
		tmpl.Config.Patterns = strings.Split(v, ",")
	}

	return tmpl
}

// ApplyToFlags applies template configuration to command flags.
func (t *Template) ApplyToFlags(flags map[string]interface{}) {
	cfg := t.Config

	// Only apply values that are set in template and not overridden by flags
	if cfg.MaxConcurrency != nil {
		if _, exists := flags["concurrency"]; !exists {
			flags["concurrency"] = *cfg.MaxConcurrency
		}
	}
	if cfg.RateLimit != nil {
		if _, exists := flags["rate"]; !exists {
			flags["rate"] = *cfg.RateLimit
		}
	}
	if cfg.AttackType != nil {
		if _, exists := flags["attack"]; !exists {
			flags["attack"] = *cfg.AttackType
		}
	}
	if cfg.Markers != nil {
		if _, exists := flags["markers"]; !exists {
			flags["markers"] = *cfg.Markers
		}
	}
	if cfg.EnableAnomaly != nil {
		if _, exists := flags["anomaly"]; !exists {
			flags["anomaly"] = *cfg.EnableAnomaly
		}
	}
	if cfg.EnableAI != nil {
		if _, exists := flags["ai"]; !exists {
			flags["ai"] = *cfg.EnableAI
		}
	}
	if cfg.EnableAIPayloads != nil {
		if _, exists := flags["ai-payloads"]; !exists {
			flags["ai-payloads"] = *cfg.EnableAIPayloads
		}
	}
	if cfg.EnableAIClassify != nil {
		if _, exists := flags["ai-classify"]; !exists {
			flags["ai-classify"] = *cfg.EnableAIClassify
		}
	}
	if cfg.EnableAIFindings != nil {
		if _, exists := flags["ai-findings"]; !exists {
			flags["ai-findings"] = *cfg.EnableAIFindings
		}
	}
	if cfg.MaxRetries != nil {
		if _, exists := flags["retries"]; !exists {
			flags["retries"] = *cfg.MaxRetries
		}
	}
	if len(cfg.Patterns) > 0 {
		if _, exists := flags["patterns"]; !exists {
			flags["patterns"] = strings.Join(cfg.Patterns, ",")
		}
	}
}

// sanitizeFilename converts a template name to a safe filename.
func sanitizeFilename(name string) string {
	// Replace spaces with hyphens
	name = strings.ReplaceAll(name, " ", "-")
	// Remove or replace unsafe characters
	name = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, name)
	// Convert to lowercase
	name = strings.ToLower(name)
	// Add timestamp to ensure uniqueness
	timestamp := time.Now().Format("20060102")
	return fmt.Sprintf("%s-%s", name, timestamp)
}
