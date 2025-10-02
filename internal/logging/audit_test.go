package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestAuditLoggerEmit(t *testing.T) {
	buf := &bytes.Buffer{}
	logger, err := NewAuditLogger("test", WithoutStdout(), WithWriter(buf))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	event := AuditEvent{EventType: EventPluginLoad, Decision: DecisionAllow}
	if err := logger.Emit(event); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	var decoded AuditEvent
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if decoded.Component != "test" {
		t.Fatalf("expected component 'test', got %q", decoded.Component)
	}
	if decoded.EventType != EventPluginLoad {
		t.Fatalf("expected event type %q, got %q", EventPluginLoad, decoded.EventType)
	}
	if decoded.Decision != DecisionAllow {
		t.Fatalf("expected decision %q, got %q", DecisionAllow, decoded.Decision)
	}
	if decoded.Timestamp.IsZero() {
		t.Fatalf("expected timestamp to be set")
	}
}

func TestAuditLoggerWithComponent(t *testing.T) {
	buf := &bytes.Buffer{}
	base, err := NewAuditLogger("base", WithoutStdout(), WithWriter(buf))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	child := base.WithComponent("child")
	if child == nil {
		t.Fatalf("expected child logger")
	}

	if err := base.Emit(AuditEvent{EventType: EventPluginLoad}); err != nil {
		t.Fatalf("base Emit: %v", err)
	}
	if err := child.Emit(AuditEvent{EventType: EventRPCDenied}); err != nil {
		t.Fatalf("child Emit: %v", err)
	}

	child.Close()
	if err := base.Close(); err != nil {
		t.Fatalf("base Close: %v", err)
	}

	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("expected 2 audit events, got %d", len(lines))
	}

	var first, second AuditEvent
	if err := json.Unmarshal(lines[0], &first); err != nil {
		t.Fatalf("unmarshal first: %v", err)
	}
	if err := json.Unmarshal(lines[1], &second); err != nil {
		t.Fatalf("unmarshal second: %v", err)
	}

	if first.Component != "base" {
		t.Fatalf("expected first component 'base', got %q", first.Component)
	}
	if second.Component != "child" {
		t.Fatalf("expected second component 'child', got %q", second.Component)
	}
}

func TestAuditLoggerRedactsSensitiveValues(t *testing.T) {
	buf := &bytes.Buffer{}
	logger, err := NewAuditLogger("test", WithoutStdout(), WithWriter(buf))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	event := AuditEvent{
		EventType: EventRPCCall,
		Decision:  DecisionInfo,
		Reason:    "API_TOKEN=AKIA123456789012345678901234",
		Metadata: map[string]any{
			"token":   "Bearer AKIA123456789012345678901234",
			"contact": "alice@example.com",
			"details": []any{"secret=supersecretvalue123456"},
		},
	}
	if err := logger.Emit(event); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	reason, _ := decoded["reason"].(string)
	if !strings.Contains(reason, "[REDACTED_SECRET]") {
		t.Fatalf("expected secret redaction in reason, got %q", reason)
	}
	metadata, ok := decoded["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("expected metadata object, got %T", decoded["metadata"])
	}
	if token, _ := metadata["token"].(string); !strings.Contains(token, "[REDACTED_SECRET]") {
		t.Fatalf("expected token redaction, got %q", token)
	}
	if contact, _ := metadata["contact"].(string); contact != "[REDACTED_EMAIL]" {
		t.Fatalf("expected email redaction, got %q", contact)
	}
	details, _ := metadata["details"].([]any)
	if len(details) != 1 {
		t.Fatalf("expected redacted details slice, got %#v", metadata["details"])
	}
	if detail, _ := details[0].(string); !strings.Contains(detail, "[REDACTED_SECRET]") {
		t.Fatalf("expected redacted detail, got %q", detail)
	}
}
