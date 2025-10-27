package cases

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/RowanDark/0xgen/internal/logging"
)

func TestEditorUpdateSummaryEmitsAudit(t *testing.T) {
	var buf bytes.Buffer
	logger, err := logging.NewAuditLogger("cases", logging.WithWriter(&buf))
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	editor := NewEditor(logger)
	c := &Case{ID: "case-1", Summary: "old"}
	editor.UpdateSummary("user-1", c, "new summary")
	if c.Summary != "new summary" {
		t.Fatalf("expected summary to update, got %q", c.Summary)
	}
	events := decodeCaseEvents(t, buf.Bytes())
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	evt := events[0]
	if evt["event_type"] != string(logging.EventCaseEdited) {
		t.Fatalf("unexpected event type: %v", evt["event_type"])
	}
	if evt["metadata"].(map[string]any)["field"] != "summary" {
		t.Fatalf("expected summary field, got %+v", evt["metadata"])
	}
}

func TestEditorLabelOperations(t *testing.T) {
	var buf bytes.Buffer
	logger, err := logging.NewAuditLogger("cases", logging.WithWriter(&buf))
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	editor := NewEditor(logger)
	c := &Case{ID: "case-2", Labels: map[string]string{"severity": "high"}}
	editor.SetLabel("user-1", c, "severity", "critical")
	editor.RemoveLabel("user-1", c, "severity")
	events := decodeCaseEvents(t, buf.Bytes())
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if _, ok := c.Labels["severity"]; ok {
		t.Fatal("label should be removed")
	}
}

func decodeCaseEvents(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	var events []map[string]any
	for {
		var entry map[string]any
		if err := dec.Decode(&entry); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("decode audit log entry: %v", err)
		}
		events = append(events, entry)
	}
	return events
}
