package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/RowanDark/Glyph/internal/findings"
)

// JSONL handles persisting findings to a JSON Lines file.
type JSONL struct {
	path   string
	writer *findings.Writer
	mu     sync.Mutex
}

type jsonlConfig struct {
	path    string
	options []findings.WriterOption
}

// JSONLOption configures optional behaviour for the writer.
type JSONLOption func(*jsonlConfig)

// WithMaxBytes overrides the rotation threshold. A value <= 0 disables rotation.
func WithMaxBytes(limit int64) JSONLOption {
	return func(cfg *jsonlConfig) {
		cfg.options = append(cfg.options, findings.WithMaxBytes(limit))
	}
}

// WithBufferLength overrides the buffer used while writing to disk.
func WithBufferLength(length int) JSONLOption {
	return func(cfg *jsonlConfig) {
		cfg.options = append(cfg.options, findings.WithBufferSize(length))
	}
}

// WithMaxFiles controls how many rotated files are retained.
func WithMaxFiles(count int) JSONLOption {
	return func(cfg *jsonlConfig) {
		cfg.options = append(cfg.options, findings.WithMaxRotations(count))
	}
}

// NewJSONL creates a reporter that writes findings to the provided path.
func NewJSONL(path string, opts ...JSONLOption) *JSONL {
	cfg := jsonlConfig{path: path}
	for _, opt := range opts {
		opt(&cfg)
	}
	writer := findings.NewWriter(cfg.path, cfg.options...)
	return &JSONL{path: writer.Path(), writer: writer}
}

// Write appends the given finding to the JSONL file.
func (r *JSONL) Write(f findings.Finding) error {
	return r.writer.Write(f)
}

// Close flushes any buffered data to disk.
func (r *JSONL) Close() error {
	return r.writer.Close()
}

// ReadAll loads every finding stored in the JSONL file.
const (
	jsonlReadRetries = 2
	jsonlRetryDelay  = 25 * time.Millisecond
)

func (r *JSONL) ReadAll() ([]findings.Finding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var (
		file *os.File
		err  error
	)
	for attempt := 0; attempt < jsonlReadRetries; attempt++ {
		file, err = os.Open(r.path)
		if err != nil {
			if os.IsNotExist(err) {
				if attempt+1 < jsonlReadRetries {
					time.Sleep(jsonlRetryDelay)
					continue
				}
				return nil, nil
			}
			return nil, fmt.Errorf("open findings file: %w", err)
		}
		break
	}
	if file == nil {
		return nil, nil
	}
	defer func() {
		_ = file.Close()
	}()

	dec := json.NewDecoder(file)
	dec.DisallowUnknownFields()

	var out []findings.Finding
	for {
		var f findings.Finding
		if err := dec.Decode(&f); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("decode finding: %w", err)
		}
		if err := f.Validate(); err != nil {
			return nil, fmt.Errorf("invalid finding: %w", err)
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
