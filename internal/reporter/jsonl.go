package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/RowanDark/Glyph/internal/findings"
)

// JSONL handles persisting findings to a JSON Lines file.
type JSONL struct {
	path string
	mu   sync.Mutex
}

// NewJSONL creates a reporter that writes findings to the provided path.
func NewJSONL(path string) *JSONL {
	return &JSONL{path: path}
}

// Write appends the given finding to the JSONL file.
func (r *JSONL) Write(f findings.Finding) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(r.path), 0o755); err != nil {
		return fmt.Errorf("create findings directory: %w", err)
	}

	file, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open findings file: %w", err)
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(f); err != nil {
		return fmt.Errorf("encode finding: %w", err)
	}
	return nil
}

// ReadAll loads every finding stored in the JSONL file.
func (r *JSONL) ReadAll() ([]findings.Finding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	file, err := os.Open(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open findings file: %w", err)
	}
	defer file.Close()

	dec := json.NewDecoder(file)
	var out []findings.Finding
	for {
		var f findings.Finding
		if err := dec.Decode(&f); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("decode finding: %w", err)
		}
		out = append(out, f)
	}
	return out, nil
}

// ReadJSONL reads findings from an arbitrary JSONL file path without creating a reporter.
func ReadJSONL(path string) ([]findings.Finding, error) {
	r := NewJSONL(path)
	return r.ReadAll()
}
