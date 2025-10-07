package tracing

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Span represents an in-flight trace span.
type Span interface {
	Context() SpanContext
	End()
	EndWithStatus(status SpanStatus, description string)
	SetAttribute(key string, value any)
	AddEvent(name string, attributes map[string]any)
	RecordError(err error)
}

type span struct {
	tracer      *Tracer
	context     SpanContext
	parent      SpanContext
	name        string
	kind        SpanKind
	attributes  map[string]any
	events      []spanEvent
	status      SpanStatus
	statusMsg   string
	startTime   time.Time
	endTime     time.Time
	ended       bool
	mu          sync.Mutex
	serviceName string
}

type spanEvent struct {
	Name       string         `json:"name"`
	Time       time.Time      `json:"time"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// SpanStatus represents the outcome of a span.
type SpanStatus string

const (
	StatusUnset SpanStatus = "unset"
	StatusOK    SpanStatus = "ok"
	StatusError SpanStatus = "error"
)

func (s *span) Context() SpanContext {
	if s == nil {
		return SpanContext{}
	}
	return s.context
}

func (s *span) End() { s.EndWithStatus(s.status, s.statusMsg) }

func (s *span) EndWithStatus(status SpanStatus, description string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return
	}
	s.ended = true
	s.endTime = time.Now()
	if status != "" {
		s.status = status
		s.statusMsg = description
	}
	snapshot := s.snapshotLocked()
	s.mu.Unlock()
	if snapshot != nil && s.tracer != nil && s.tracer.exporters != nil {
		s.tracer.exporters.export(snapshot)
	}
}

func (s *span) SetAttribute(key string, value any) {
	if s == nil || key == "" {
		return
	}
	s.mu.Lock()
	if s.attributes == nil {
		s.attributes = make(map[string]any)
	}
	s.attributes[key] = value
	s.mu.Unlock()
}

func (s *span) AddEvent(name string, attributes map[string]any) {
	if s == nil || name == "" {
		return
	}
	s.mu.Lock()
	evt := spanEvent{Name: name, Time: time.Now()}
	if len(attributes) > 0 {
		evt.Attributes = cloneAttributes(attributes)
	}
	s.events = append(s.events, evt)
	s.mu.Unlock()
}

func (s *span) RecordError(err error) {
	if s == nil || err == nil {
		return
	}
	msg := err.Error()
	s.AddEvent("error", map[string]any{"message": msg})
	s.mu.Lock()
	s.status = StatusError
	s.statusMsg = msg
	s.mu.Unlock()
}

func (s *span) snapshotLocked() *SpanSnapshot {
	if s == nil {
		return nil
	}
	attrs := cloneAttributes(s.attributes)
	events := make([]spanEvent, len(s.events))
	copy(events, s.events)
	return &SpanSnapshot{
		TraceID:      s.context.TraceID,
		SpanID:       s.context.SpanID,
		ParentSpanID: s.parent.SpanID,
		Name:         s.name,
		Kind:         s.kind,
		Attributes:   attrs,
		Events:       events,
		Status:       s.status,
		StatusMsg:    s.statusMsg,
		StartTime:    s.startTime,
		EndTime:      s.endTime,
		ServiceName:  s.serviceName,
	}
}

type noopSpan struct {
	ctx SpanContext
}

func (n noopSpan) Context() SpanContext           { return n.ctx }
func (noopSpan) End()                             {}
func (noopSpan) EndWithStatus(SpanStatus, string) {}
func (noopSpan) SetAttribute(string, any)         {}
func (noopSpan) AddEvent(string, map[string]any)  {}
func (noopSpan) RecordError(error)                {}

// SpanSnapshot captures the immutable span data exported to sinks.
type SpanSnapshot struct {
	TraceID      string         `json:"trace_id"`
	SpanID       string         `json:"span_id"`
	ParentSpanID string         `json:"parent_span_id,omitempty"`
	Name         string         `json:"name"`
	Kind         SpanKind       `json:"kind"`
	Attributes   map[string]any `json:"attributes,omitempty"`
	Events       []spanEvent    `json:"events,omitempty"`
	Status       SpanStatus     `json:"status"`
	StatusMsg    string         `json:"status_message,omitempty"`
	StartTime    time.Time      `json:"start_time"`
	EndTime      time.Time      `json:"end_time"`
	ServiceName  string         `json:"service_name,omitempty"`
}

// Duration returns the elapsed time recorded by the span.
func (s *SpanSnapshot) Duration() time.Duration {
	if s == nil {
		return 0
	}
	if s.EndTime.IsZero() || s.StartTime.IsZero() {
		return 0
	}
	return s.EndTime.Sub(s.StartTime)
}

func (s *SpanSnapshot) MarshalJSON() ([]byte, error) {
	type alias SpanSnapshot
	out := &struct {
		*alias
		Start int64 `json:"start_time_unix_nano"`
		End   int64 `json:"end_time_unix_nano"`
	}{alias: (*alias)(s)}
	out.Start = s.StartTime.UnixNano()
	out.End = s.EndTime.UnixNano()
	return json.Marshal(out)
}

// ErrSpanEnded indicates operations were attempted on an already completed span.
var ErrSpanEnded = errors.New("span already ended")

func (s *span) ensureActive() error {
	if s == nil {
		return errors.New("nil span")
	}
	if s.ended {
		return ErrSpanEnded
	}
	return nil
}

func (s *span) String() string {
	if s == nil {
		return "<nil span>"
	}
	return fmt.Sprintf("span %s/%s", s.context.TraceID, s.context.SpanID)
}
