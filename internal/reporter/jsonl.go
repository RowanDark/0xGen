package reporter

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/RowanDark/Glyph/internal/findings"
)

const (
	defaultMaxBytes  int64 = 5 << 20
	defaultBufferLen       = 64 << 10
)

// JSONL handles persisting findings to a JSON Lines file.
type JSONL struct {
	path     string
	maxBytes int64
	bufLen   int
	mu       sync.Mutex
	file     *os.File
	writer   *bufio.Writer
	written  int64
}

// JSONLOption configures optional behaviour for the writer.
type JSONLOption func(*JSONL)

// WithMaxBytes overrides the rotation threshold. A value <= 0 disables
// rotation.
func WithMaxBytes(limit int64) JSONLOption {
	return func(j *JSONL) {
		j.maxBytes = limit
	}
}

// WithBufferLength overrides the buffer used while writing to disk.
func WithBufferLength(length int) JSONLOption {
	return func(j *JSONL) {
		if length > 0 {
			j.bufLen = length
		}
	}
}

// NewJSONL creates a reporter that writes findings to the provided path.
func NewJSONL(path string, opts ...JSONLOption) *JSONL {
	j := &JSONL{path: path, maxBytes: defaultMaxBytes, bufLen: defaultBufferLen}
	for _, opt := range opts {
		opt(j)
	}
	return j
}

// Write appends the given finding to the JSONL file.
func (r *JSONL) Write(f findings.Finding) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := f.Validate(); err != nil {
		return fmt.Errorf("invalid finding: %w", err)
	}

	if err := r.ensureWriter(); err != nil {
		return err
	}

	payload, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("encode finding: %w", err)
	}
	payload = append(payload, '\n')

	if err := r.rotateIfNeeded(int64(len(payload))); err != nil {
		return err
	}

	if _, err := r.writer.Write(payload); err != nil {
		return fmt.Errorf("write finding: %w", err)
	}
	if err := r.writer.Flush(); err != nil {
		return fmt.Errorf("flush finding: %w", err)
	}
	if syncWritesEnabled() && r.file != nil {
		if err := r.file.Sync(); err != nil {
			return fmt.Errorf("sync finding: %w", err)
		}
	}
	if r.file != nil {
		r.written += int64(len(payload))
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

func (r *JSONL) ensureWriter() error {
	if r.writer != nil {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(r.path), 0o755); err != nil {
		return fmt.Errorf("create findings directory: %w", err)
	}

	file, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open findings file: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return fmt.Errorf("stat findings file: %w", err)
	}
	// Use bufio so we only hit the filesystem when necessary.
	writer := bufio.NewWriterSize(file, r.bufLen)

	r.file = file
	r.writer = writer
	r.written = info.Size()
	return nil
}

func (r *JSONL) rotateIfNeeded(next int64) error {
	if r.maxBytes <= 0 {
		return nil
	}
	if r.written+next <= r.maxBytes {
		return nil
	}

	if r.writer != nil {
		if err := r.writer.Flush(); err != nil {
			return fmt.Errorf("flush during rotation: %w", err)
		}
	}
	if r.file != nil {
		if err := r.file.Close(); err != nil {
			return fmt.Errorf("close during rotation: %w", err)
		}
	}

	timestamp := time.Now().UTC().Format("20060102T150405Z")
	rotated := fmt.Sprintf("%s.%s", r.path, timestamp)
	if err := os.Rename(r.path, rotated); err != nil {
		return fmt.Errorf("rotate findings file: %w", err)
	}

	r.writer = nil
	r.file = nil
	r.written = 0
	return r.ensureWriter()
}

func syncWritesEnabled() bool {
	return os.Getenv("GLYPH_SYNC_WRITES") == "1"
}
