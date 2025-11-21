package comparison

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// BaselineManager manages baseline scans for comparison.
type BaselineManager struct {
	configDir string
}

// NewBaselineManager creates a new baseline manager.
func NewBaselineManager() (*BaselineManager, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("determine home directory: %w", err)
	}

	configDir := filepath.Join(home, ".0xgen")

	// Ensure config directory exists
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("create config directory: %w", err)
	}

	return &BaselineManager{
		configDir: configDir,
	}, nil
}

// SetBaseline sets a scan as the baseline for a target.
func (m *BaselineManager) SetBaseline(scanID, target, name, setBy string, findings int) error {
	baseline := Baseline{
		ScanID:   scanID,
		Target:   target,
		SetAt:    time.Now().UTC(),
		SetBy:    setBy,
		Name:     name,
		Findings: findings,
	}

	// Save baseline to file
	path := m.getBaselinePath(target)
	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write baseline: %w", err)
	}

	return nil
}

// GetBaseline retrieves the baseline for a target.
func (m *BaselineManager) GetBaseline(target string) (*Baseline, error) {
	path := m.getBaselinePath(target)

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no baseline set for target: %s", target)
		}
		return nil, fmt.Errorf("read baseline: %w", err)
	}

	var baseline Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, fmt.Errorf("unmarshal baseline: %w", err)
	}

	return &baseline, nil
}

// ListBaselines returns all baselines.
func (m *BaselineManager) ListBaselines() ([]Baseline, error) {
	pattern := filepath.Join(m.configDir, "baseline_*.json")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("glob baselines: %w", err)
	}

	var baselines []Baseline
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			continue // Skip unreadable files
		}

		var baseline Baseline
		if err := json.Unmarshal(data, &baseline); err != nil {
			continue // Skip invalid files
		}

		baselines = append(baselines, baseline)
	}

	return baselines, nil
}

// DeleteBaseline removes the baseline for a target.
func (m *BaselineManager) DeleteBaseline(target string) error {
	path := m.getBaselinePath(target)

	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("no baseline set for target: %s", target)
		}
		return fmt.Errorf("delete baseline: %w", err)
	}

	return nil
}

// getBaselinePath returns the file path for a target's baseline.
func (m *BaselineManager) getBaselinePath(target string) string {
	// Sanitize target for filename
	sanitized := sanitizeTarget(target)
	return filepath.Join(m.configDir, fmt.Sprintf("baseline_%s.json", sanitized))
}

// sanitizeTarget converts a target URL to a safe filename.
func sanitizeTarget(target string) string {
	// Remove protocol
	sanitized := target
	if len(sanitized) > 0 {
		sanitized = sanitized[:]
	}

	// Replace unsafe characters
	replacements := map[rune]rune{
		':':  '_',
		'/':  '_',
		'\\': '_',
		'?':  '_',
		'&':  '_',
		'=':  '_',
		'#':  '_',
		'@':  '_',
		'!':  '_',
		'$':  '_',
		'%':  '_',
		'^':  '_',
		'*':  '_',
		'(':  '_',
		')':  '_',
		'+':  '_',
		'{':  '_',
		'}':  '_',
		'[':  '_',
		']':  '_',
		'|':  '_',
		';':  '_',
		'\'': '_',
		'"':  '_',
		'<':  '_',
		'>':  '_',
		',':  '_',
		' ':  '_',
	}

	result := ""
	for _, r := range sanitized {
		if replacement, exists := replacements[r]; exists {
			result += string(replacement)
		} else {
			result += string(r)
		}
	}

	// Limit length
	if len(result) > 100 {
		result = result[:100]
	}

	return result
}

// HasBaseline checks if a baseline exists for a target.
func (m *BaselineManager) HasBaseline(target string) bool {
	path := m.getBaselinePath(target)
	_, err := os.Stat(path)
	return err == nil
}
