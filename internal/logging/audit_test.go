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
