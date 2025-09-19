package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// HistoryEntry captures a single request/response pair intercepted by the proxy.
type HistoryEntry struct {
	Timestamp       time.Time           `json:"timestamp"`
	ClientIP        string              `json:"client_ip"`
	Protocol        string              `json:"protocol"`
	Method          string              `json:"method"`
	URL             string              `json:"url"`
	StatusCode      int                 `json:"status_code"`
	LatencyMillis   int64               `json:"latency_ms"`
	RequestSize     int                 `json:"request_size_bytes"`
	ResponseSize    int                 `json:"response_size_bytes"`
	RequestHeaders  map[string][]string `json:"request_headers"`
	ResponseHeaders map[string][]string `json:"response_headers"`
	MatchedRules    []string            `json:"matched_rules,omitempty"`
}

// historyWriter persists intercepted flow history to disk as JSONL.
type historyWriter struct {
	path string
	mu   sync.Mutex
	file *os.File
}

func newHistoryWriter(path string) (*historyWriter, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("history path must not be empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create history directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open history file: %w", err)
	}
	return &historyWriter{path: path, file: file}, nil
}

// Close flushes and closes the history file handle.
func (h *historyWriter) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.file == nil {
		return nil
	}
	err := h.file.Close()
	h.file = nil
	return err
}

// Path reports the backing file path for persisted history entries.
func (h *historyWriter) Path() string {
	return h.path
}

// Write appends an entry to the history file.
func (h *historyWriter) Write(entry HistoryEntry) error {
	payload, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encode history entry: %w", err)
	}
	payload = append(payload, '\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.file == nil {
		return errors.New("history writer closed")
	}
	if _, err := h.file.Write(payload); err != nil {
		return fmt.Errorf("write history entry: %w", err)
	}
	return nil
}
