package cases

import (
	"strings"
	"time"

	"github.com/RowanDark/0xgen/internal/logging"
)

// Editor applies safe mutations to cases while emitting audit events.
type Editor struct {
	logger *logging.AuditLogger
}

// NewEditor constructs a case editor using the provided audit logger.
func NewEditor(logger *logging.AuditLogger) *Editor {
	return &Editor{logger: logger}
}

// UpdateSummary replaces the case summary and records the change.
func (e *Editor) UpdateSummary(actorID string, c *Case, summary string) {
	if c == nil {
		return
	}
	actorID = strings.TrimSpace(actorID)
	if actorID == "" {
		actorID = "unknown"
	}
	summary = strings.TrimSpace(summary)
	old := c.Summary
	c.Summary = summary
	e.emit(c.ID, actorID, map[string]any{
		"field":     "summary",
		"old_value": old,
		"new_value": summary,
	})
}

// SetLabel mutates a label key, emitting an audit event when the value changes.
func (e *Editor) SetLabel(actorID string, c *Case, key, value string) {
	if c == nil {
		return
	}
	actorID = strings.TrimSpace(actorID)
	if actorID == "" {
		actorID = "unknown"
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return
	}
	if c.Labels == nil {
		c.Labels = make(map[string]string)
	}
	old := c.Labels[key]
	value = strings.TrimSpace(value)
	if old == value {
		return
	}
	c.Labels[key] = value
	e.emit(c.ID, actorID, map[string]any{
		"field":     "label",
		"label_key": key,
		"old_value": old,
		"new_value": value,
	})
}

// RemoveLabel deletes a label and records the edit.
func (e *Editor) RemoveLabel(actorID string, c *Case, key string) {
	if c == nil || len(c.Labels) == 0 {
		return
	}
	actorID = strings.TrimSpace(actorID)
	if actorID == "" {
		actorID = "unknown"
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return
	}
	old, ok := c.Labels[key]
	if !ok {
		return
	}
	delete(c.Labels, key)
	e.emit(c.ID, actorID, map[string]any{
		"field":     "label",
		"label_key": key,
		"old_value": old,
		"new_value": "",
	})
}

func (e *Editor) emit(caseID, actorID string, metadata map[string]any) {
	if e == nil || e.logger == nil {
		return
	}
	metadata["case_id"] = caseID
	metadata["actor_id"] = actorID
	_ = e.logger.Emit(logging.AuditEvent{
		EventType: logging.EventCaseEdited,
		Decision:  logging.DecisionAllow,
		Timestamp: time.Now().UTC(),
		Metadata:  metadata,
	})
}
