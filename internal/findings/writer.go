package findings

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	defaultOutputDir    = "/out"
	defaultFilename     = "findings.jsonl"
	defaultMaxBytes     = 10 << 20
	defaultBufferSize   = 64 << 10
	defaultMaxRotations = 5
)

// DefaultFindingsPath is the canonical location for persisted findings.
var DefaultFindingsPath = filepath.Join(defaultOutputDir, defaultFilename)

func init() {
	if custom := strings.TrimSpace(os.Getenv("GLYPH_OUT")); custom != "" {
		DefaultFindingsPath = filepath.Join(custom, defaultFilename)
	}
}

// WriterOption configures the writer behaviour.
type WriterOption func(*Writer)

// WithMaxBytes overrides the rotation threshold. Values <= 0 disable rotation.
func WithMaxBytes(limit int64) WriterOption {
	return func(w *Writer) {
		w.maxBytes = limit
	}
}

// WithBufferSize overrides the buffered writer size.
func WithBufferSize(size int) WriterOption {
	return func(w *Writer) {
		if size > 0 {
			w.bufSize = size
		}
	}
}

// WithMaxRotations sets how many rotated files are retained. Values < 1 keep a
// single log file without rotation history.
func WithMaxRotations(count int) WriterOption {
	return func(w *Writer) {
		if count < 1 {
			count = 1
		}
		w.maxFiles = count
	}
}

// Writer persists findings to a JSON Lines file with size based rotation.
type Writer struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	bufSize  int
	maxFiles int
	file     *os.File
	buf      *bufio.Writer
	written  int64
}

// Path returns the file path currently used by the writer.
func (w *Writer) Path() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.path
}

// NewWriter constructs a writer targeting the provided path.
func NewWriter(path string, opts ...WriterOption) *Writer {
	if strings.TrimSpace(path) == "" {
		custom := strings.TrimSpace(os.Getenv("GLYPH_OUT"))
		if custom != "" {
			path = filepath.Join(custom, defaultFilename)
		} else {
			path = DefaultFindingsPath
		}
	}
	w := &Writer{path: path, maxBytes: defaultMaxBytes, bufSize: defaultBufferSize, maxFiles: defaultMaxRotations}
	for _, opt := range opts {
		opt(w)
	}
	if w.maxFiles < 1 {
		w.maxFiles = 1
	}
	return w
}

// Write validates and appends the finding to disk.
func (w *Writer) Write(f Finding) error {
	if strings.TrimSpace(f.Version) == "" {
		f.Version = SchemaVersion
	}
	if err := f.Validate(); err != nil {
		return fmt.Errorf("invalid finding: %w", err)
	}

	payload, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("encode finding: %w", err)
	}
	payload = append(payload, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.ensureWriter(); err != nil {
		return err
	}

	if err := w.rotateIfNeeded(int64(len(payload))); err != nil {
		return err
	}

	if _, err := w.buf.Write(payload); err != nil {
		return fmt.Errorf("write finding: %w", err)
	}
	if err := w.buf.Flush(); err != nil {
		return fmt.Errorf("flush finding: %w", err)
	}
	if syncWritesEnabled() && w.file != nil {
		if err := w.file.Sync(); err != nil {
			return fmt.Errorf("sync finding: %w", err)
		}
	}
	if w.file != nil {
		w.written += int64(len(payload))
	}
	return nil
}

// Close flushes and closes the underlying file handle.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	var firstErr error
	if w.buf != nil {
		if err := w.buf.Flush(); err != nil && !errors.Is(err, os.ErrClosed) {
			firstErr = err
		}
	}
	if w.file != nil {
		if err := w.file.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	w.buf = nil
	w.file = nil
	w.written = 0
	return firstErr
}

func (w *Writer) ensureWriter() error {
	if w.buf != nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(w.path), 0o755); err != nil {
		return fmt.Errorf("create findings directory: %w", err)
	}
	file, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open findings file: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("stat findings file: %w", err)
	}
	w.file = file
	w.buf = bufio.NewWriterSize(file, w.bufSize)
	w.written = info.Size()
	return nil
}

func (w *Writer) rotateIfNeeded(next int64) error {
	if w.maxBytes <= 0 {
		return nil
	}
	if w.written+next <= w.maxBytes {
		return nil
	}

	if w.buf != nil {
		if err := w.buf.Flush(); err != nil {
			return fmt.Errorf("flush during rotation: %w", err)
		}
	}
	if w.file != nil {
		if err := w.file.Close(); err != nil {
			return fmt.Errorf("close during rotation: %w", err)
		}
	}

	for i := w.maxFiles - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", w.path, i)
		dst := fmt.Sprintf("%s.%d", w.path, i+1)
		if _, err := os.Stat(src); err == nil {
			if i+1 > w.maxFiles {
				_ = os.Remove(src)
				continue
			}
			if err := os.Rename(src, dst); err != nil {
				return fmt.Errorf("rotate findings file: %w", err)
			}
		}
	}
	rotated := fmt.Sprintf("%s.%d", w.path, 1)
	if err := os.Rename(w.path, rotated); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("rotate findings file: %w", err)
		}
	}

	w.buf = nil
	w.file = nil
	w.written = 0
	return w.ensureWriter()
}

func syncWritesEnabled() bool {
	return os.Getenv("GLYPH_SYNC_WRITES") == "1"
}
