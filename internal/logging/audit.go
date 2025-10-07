package logging

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/RowanDark/Glyph/internal/redact"
)

type EventType string

const (
	EventPluginLoad         EventType = "plugin_load"
	EventPluginDisconnect   EventType = "plugin_disconnect"
	EventCapabilityGrant    EventType = "capability_grant"
	EventCapabilityDenied   EventType = "capability_denied"
	EventRPCCall            EventType = "rpc_call"
	EventRPCDenied          EventType = "rpc_denied"
	EventScopeViolation     EventType = "scope_violation"
	EventFindingReceived    EventType = "finding_received"
	EventFindingRejected    EventType = "finding_rejected"
	EventProxyLifecycle     EventType = "proxy_lifecycle"
	EventReporter           EventType = "reporter_event"
	EventSecretsToken       EventType = "secrets_token_issue"
	EventSecretsAccess      EventType = "secrets_access"
	EventSecretsDenied      EventType = "secrets_denied"
	EventSecretsTokenRev    EventType = "secrets_token_revoked"
	EventSecretsTokenExpiry EventType = "secrets_token_expired"
	EventNetworkDenied      EventType = "network_denied"
)

type Decision string

const (
	DecisionInfo  Decision = "info"
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
)

type AuditEvent struct {
	Timestamp time.Time      `json:"timestamp"`
	Component string         `json:"component"`
	PluginID  string         `json:"plugin_id,omitempty"`
	EventType EventType      `json:"event_type"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	Decision  Decision       `json:"decision,omitempty"`
	Reason    string         `json:"reason,omitempty"`
}

type Option func(*config) error

type config struct {
	writers          []io.Writer
	closers          []io.Closer
	useDefaultWriter bool
}

func defaultConfig() *config {
	return &config{writers: []io.Writer{os.Stdout}, useDefaultWriter: true}
}

func WithWriter(w io.Writer) Option {
	return func(cfg *config) error {
		if w == nil {
			return errors.New("writer cannot be nil")
		}
		cfg.writers = append(cfg.writers, w)
		return nil
	}
}

func WithFile(path string) Option {
	return func(cfg *config) error {
		if strings.TrimSpace(path) == "" {
			return errors.New("file path cannot be empty")
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		cfg.writers = append(cfg.writers, f)
		cfg.closers = append(cfg.closers, f)
		return nil
	}
}

func WithoutStdout() Option {
	return func(cfg *config) error {
		cfg.useDefaultWriter = false
		filtered := cfg.writers[:0]
		for _, w := range cfg.writers {
			if w == os.Stdout {
				continue
			}
			filtered = append(filtered, w)
		}
		cfg.writers = filtered
		return nil
	}
}

type auditCore struct {
	mu      sync.Mutex
	encoder *json.Encoder
	closers []io.Closer
}

type AuditLogger struct {
	component   string
	core        *auditCore
	ownsClosers bool
}

func NewAuditLogger(component string, opts ...Option) (*AuditLogger, error) {
	cfg := defaultConfig()
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			for _, closer := range cfg.closers {
				_ = closer.Close()
			}
			return nil, err
		}
	}
	if !cfg.useDefaultWriter && len(cfg.writers) == 0 {
		return nil, errors.New("no writers configured for audit logger")
	}
	writer := io.MultiWriter(cfg.writers...)
	enc := json.NewEncoder(writer)
	enc.SetEscapeHTML(false)
	return &AuditLogger{
		component:   component,
		core:        &auditCore{encoder: enc, closers: cfg.closers},
		ownsClosers: true,
	}, nil
}

func MustNewAuditLogger(component string, opts ...Option) *AuditLogger {
	logger, err := NewAuditLogger(component, opts...)
	if err != nil {
		panic(err)
	}
	return logger
}

func (l *AuditLogger) Close() error {
	if l == nil || !l.ownsClosers || l.core == nil {
		return nil
	}
	l.core.mu.Lock()
	defer l.core.mu.Unlock()
	var firstErr error
	for _, closer := range l.core.closers {
		if err := closer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	l.core.closers = nil
	return firstErr
}

func (l *AuditLogger) Emit(event AuditEvent) error {
	if l == nil {
		return errors.New("nil audit logger")
	}
	if l.core == nil {
		return errors.New("nil audit logger core")
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	} else {
		event.Timestamp = event.Timestamp.UTC()
	}
	if event.Component == "" {
		event.Component = l.component
	}
	event.Reason = redact.String(event.Reason)
	if len(event.Metadata) > 0 {
		event.Metadata = redact.Map(event.Metadata)
	}
	l.core.mu.Lock()
	defer l.core.mu.Unlock()
	return l.core.encoder.Encode(event)
}

func (l *AuditLogger) WithComponent(component string) *AuditLogger {
	if l == nil || l.core == nil {
		return nil
	}
	return &AuditLogger{
		component:   component,
		core:        l.core,
		ownsClosers: false,
	}
}
