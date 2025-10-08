package proxy

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/RowanDark/Glyph/internal/flows"
)

type flowLogWriter struct {
	path string
	mu   sync.Mutex
	file *os.File
}

type flowLogEntry struct {
	ID                string `json:"id"`
	Sequence          uint64 `json:"sequence"`
	Type              string `json:"type"`
	TimestampUnix     int64  `json:"timestamp_unix"`
	SanitizedBase64   string `json:"sanitized_base64,omitempty"`
	RawBodyBytes      int    `json:"raw_body_bytes,omitempty"`
	RawBodyCaptured   int    `json:"raw_body_captured,omitempty"`
	SanitizedRedacted bool   `json:"sanitized_redacted,omitempty"`
}

func newFlowLogWriter(path string) (*flowLogWriter, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("flow log path must not be empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create flow log directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open flow log: %w", err)
	}
	return &flowLogWriter{path: path, file: file}, nil
}

func (w *flowLogWriter) Record(event flows.Event) error {
	if w == nil {
		return nil
	}
	if w.file == nil {
		return errors.New("flow log writer closed")
	}
	entry := flowLogEntry{
		ID:                strings.TrimSpace(event.ID),
		Sequence:          event.Sequence,
		Type:              event.Type.String(),
		TimestampUnix:     event.Timestamp.Unix(),
		RawBodyBytes:      event.RawBodySize,
		RawBodyCaptured:   event.RawBodyCaptured,
		SanitizedRedacted: event.SanitizedRedacted,
	}
	if len(event.Sanitized) > 0 {
		entry.SanitizedBase64 = base64.StdEncoding.EncodeToString(event.Sanitized)
	}

	payload, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encode flow log entry: %w", err)
	}
	payload = append(payload, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return errors.New("flow log writer closed")
	}
	if _, err := w.file.Write(payload); err != nil {
		return fmt.Errorf("write flow log entry: %w", err)
	}
	return nil
}

func (w *flowLogWriter) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

func (w *flowLogWriter) Path() string {
	if w == nil {
		return ""
	}
	return w.path
}
