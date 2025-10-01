package logging

import (
	"bytes"
	"encoding/json"
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
