package secrets

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/RowanDark/0xgen/internal/logging"
)

func newTestAuditLogger(t *testing.T) (*logging.AuditLogger, *bytes.Buffer) {
	t.Helper()
	buf := &bytes.Buffer{}
	logger, err := logging.NewAuditLogger("test", logging.WithoutStdout(), logging.WithWriter(buf))
	if err != nil {
		t.Fatalf("create audit logger: %v", err)
	}
	return logger, buf
}

func decodeAuditEvents(t *testing.T, data []byte) []logging.AuditEvent {
	t.Helper()
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	var events []logging.AuditEvent
	for _, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var event logging.AuditEvent
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatalf("decode audit event: %v", err)
		}
		events = append(events, event)
	}
	return events
}

func containsEvent(events []logging.AuditEvent, eventType logging.EventType) bool {
	for _, event := range events {
		if event.EventType == eventType {
			return true
		}
	}
	return false
}
