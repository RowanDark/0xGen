package tracing

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
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

// SpanContext holds distributed tracing identity information.
type SpanContext struct {
	TraceID string
	SpanID  string
	Sampled bool
}

// Valid returns true when the context contains identifiers.
func (sc SpanContext) Valid() bool {
	return len(sc.TraceID) == 32 && len(sc.SpanID) == 16
}

type spanContextKey struct{}
type activeSpanKey struct{}

type spanConfig struct {
	kind       SpanKind
	attributes map[string]any
}

// SpanStartOption configures start behaviour for spans.
type SpanStartOption interface{ apply(*spanConfig) }

type spanStartOptionFunc func(*spanConfig)

func (fn spanStartOptionFunc) apply(cfg *spanConfig) { fn(cfg) }

// WithSpanKind sets the span kind.
func WithSpanKind(kind SpanKind) SpanStartOption {
	return spanStartOptionFunc(func(cfg *spanConfig) {
		cfg.kind = kind
	})
}

// WithAttributes attaches attributes to the span on start.
func WithAttributes(attrs map[string]any) SpanStartOption {
	return spanStartOptionFunc(func(cfg *spanConfig) {
		if len(attrs) == 0 {
			return
		}
		if cfg.attributes == nil {
			cfg.attributes = make(map[string]any, len(attrs))
		}
		for k, v := range attrs {
			cfg.attributes[k] = v
		}
	})
}

// StartSpan begins a new span derived from ctx.
func StartSpan(ctx context.Context, name string, opts ...SpanStartOption) (context.Context, Span) {
	tracer := CurrentTracer()
	cfg := spanConfig{kind: SpanKindInternal}
	for _, opt := range opts {
		opt.apply(&cfg)
	}
	if tracer == nil || tracer.tracer == nil {
		sc := SpanContextFromContext(ctx)
		if sc.Valid() {
			ctx = context.WithValue(ctx, spanContextKey{}, sc)
		}
		return ctx, noopSpan{ctx: sc}
	}

	options := []trace.SpanStartOption{trace.WithSpanKind(toOTELSpanKind(cfg.kind))}
	if len(cfg.attributes) > 0 {
		options = append(options, trace.WithAttributes(mapToAttributes(cfg.attributes)...))
	}

	ctx, otelSpan := tracer.tracer.Start(ctx, name, options...)
	wrapper := &otelSpanWrapper{span: otelSpan}
	sc := fromOTELSpanContext(otelSpan.SpanContext())
	if sc.Valid() {
		ctx = context.WithValue(ctx, spanContextKey{}, sc)
	}
	ctx = context.WithValue(ctx, activeSpanKey{}, wrapper)
	return ctx, wrapper
}

// SpanFromContext retrieves the active span, returning a noop span if none exists.
func SpanFromContext(ctx context.Context) Span {
	if ctx == nil {
		return noopSpan{}
	}
	if sp, ok := ctx.Value(activeSpanKey{}).(Span); ok && sp != nil {
		return sp
	}
	if otelSpan := trace.SpanFromContext(ctx); otelSpan != nil {
		if otelSpan.SpanContext().IsValid() {
			return &otelSpanWrapper{span: otelSpan}
		}
	}
	return noopSpan{ctx: SpanContextFromContext(ctx)}
}

// SpanContextFromContext returns the span context stored on ctx.
func SpanContextFromContext(ctx context.Context) SpanContext {
	if ctx == nil {
		return SpanContext{}
	}
	if sc, ok := ctx.Value(spanContextKey{}).(SpanContext); ok && sc.Valid() {
		return sc
	}
	return fromOTELSpanContext(trace.SpanContextFromContext(ctx))
}

// TraceIDFromContext extracts the trace identifier, or "" when unavailable.
func TraceIDFromContext(ctx context.Context) string {
	sc := SpanContextFromContext(ctx)
	if !sc.Valid() {
		return ""
	}
	return sc.TraceID
}

// WithSpanContext returns a new context containing sc.
func WithSpanContext(ctx context.Context, sc SpanContext) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if !sc.Valid() {
		return ctx
	}
	otelCtx, err := toOTELSpanContext(sc)
	if err == nil {
		ctx = trace.ContextWithRemoteSpanContext(ctx, otelCtx)
	}
	return context.WithValue(ctx, spanContextKey{}, sc)
}

func fromOTELSpanContext(sc trace.SpanContext) SpanContext {
	if !sc.IsValid() {
		return SpanContext{}
	}
	return SpanContext{
		TraceID: sc.TraceID().String(),
		SpanID:  sc.SpanID().String(),
		Sampled: sc.IsSampled(),
	}
}

func toOTELSpanContext(sc SpanContext) (trace.SpanContext, error) {
	if !sc.Valid() {
		return trace.SpanContext{}, fmt.Errorf("invalid span context")
	}
	traceID, err := trace.TraceIDFromHex(sc.TraceID)
	if err != nil {
		return trace.SpanContext{}, fmt.Errorf("parse trace id: %w", err)
	}
	spanID, err := trace.SpanIDFromHex(sc.SpanID)
	if err != nil {
		return trace.SpanContext{}, fmt.Errorf("parse span id: %w", err)
	}
	config := trace.SpanContextConfig{
		TraceID: traceID,
		SpanID:  spanID,
	}
	if sc.Sampled {
		config.TraceFlags = trace.FlagsSampled
	}
	return trace.NewSpanContext(config), nil
}

type otelSpanWrapper struct {
	span trace.Span
}

func (s *otelSpanWrapper) Context() SpanContext {
	if s == nil || s.span == nil {
		return SpanContext{}
	}
	return fromOTELSpanContext(s.span.SpanContext())
}

func (s *otelSpanWrapper) End() {
	if s == nil || s.span == nil {
		return
	}
	s.span.End()
}

func (s *otelSpanWrapper) EndWithStatus(status SpanStatus, description string) {
	if s == nil || s.span == nil {
		return
	}
	switch status {
	case StatusError:
		s.span.SetStatus(codes.Error, description)
	case StatusOK:
		s.span.SetStatus(codes.Ok, description)
	default:
		if description != "" {
			s.span.SetStatus(codes.Unset, description)
		}
	}
	s.span.End()
}

func (s *otelSpanWrapper) SetAttribute(key string, value any) {
	if s == nil || s.span == nil {
		return
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return
	}
	s.span.SetAttributes(attribute.KeyValue{Key: attribute.Key(key), Value: attributeValue(value)})
}

func (s *otelSpanWrapper) AddEvent(name string, attributes map[string]any) {
	if s == nil || s.span == nil {
		return
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	if len(attributes) == 0 {
		s.span.AddEvent(name)
		return
	}
	s.span.AddEvent(name, trace.WithAttributes(mapToAttributes(attributes)...))
}

func (s *otelSpanWrapper) RecordError(err error) {
	if s == nil || s.span == nil || err == nil {
		return
	}
	s.span.RecordError(err)
	s.span.SetStatus(codes.Error, err.Error())
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

// SpanStatus represents the outcome of a span.
type SpanStatus string

const (
	StatusUnset SpanStatus = "unset"
	StatusOK    SpanStatus = "ok"
	StatusError SpanStatus = "error"
)

type spanEvent struct {
	Name       string         `json:"name"`
	Time       time.Time      `json:"time"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

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

func spanSnapshotFromReadOnly(span sdktrace.ReadOnlySpan) *SpanSnapshot {
	if span == nil {
		return nil
	}
	sc := span.SpanContext()
	if !sc.IsValid() {
		return nil
	}

	attrs := make(map[string]any)
	for _, attr := range span.Attributes() {
		attrs[string(attr.Key)] = attributeValueFromKeyValue(attr)
	}

	events := make([]spanEvent, 0, len(span.Events()))
	for _, event := range span.Events() {
		eventAttrs := make(map[string]any)
		for _, attr := range event.Attributes {
			eventAttrs[string(attr.Key)] = attributeValueFromKeyValue(attr)
		}
		events = append(events, spanEvent{Name: event.Name, Time: event.Time, Attributes: eventAttrs})
	}

	status := StatusUnset
	statusMsg := span.Status().Description
	switch span.Status().Code {
	case codes.Ok:
		status = StatusOK
	case codes.Error:
		status = StatusError
	}

	parentID := ""
	if parent := span.Parent(); parent.IsValid() {
		parentID = parent.SpanID().String()
	}

	serviceName := ""
	if resource := span.Resource(); resource != nil {
		for _, attr := range resource.Attributes() {
			if attr.Key == semconv.ServiceNameKey {
				serviceName = attr.Value.AsString()
				break
			}
		}
	}

	return &SpanSnapshot{
		TraceID:      sc.TraceID().String(),
		SpanID:       sc.SpanID().String(),
		ParentSpanID: parentID,
		Name:         span.Name(),
		Kind:         fromOTELSpanKind(span.SpanKind()),
		Attributes:   attrs,
		Events:       events,
		Status:       status,
		StatusMsg:    statusMsg,
		StartTime:    span.StartTime(),
		EndTime:      span.EndTime(),
		ServiceName:  serviceName,
	}
}

func mapToAttributes(attrs map[string]any) []attribute.KeyValue {
	if len(attrs) == 0 {
		return nil
	}
	kvs := make([]attribute.KeyValue, 0, len(attrs))
	for k, v := range attrs {
		kvs = append(kvs, attribute.KeyValue{Key: attribute.Key(k), Value: attributeValue(v)})
	}
	return kvs
}

func attributeValue(value any) attribute.Value {
	switch v := value.(type) {
	case string:
		return attribute.StringValue(v)
	case bool:
		return attribute.BoolValue(v)
	case int:
		return attribute.IntValue(v)
	case int64:
		return attribute.Int64Value(v)
	case uint:
		return attribute.Int64Value(int64(v))
	case uint64:
		return attribute.Int64Value(int64(v))
	case float32:
		return attribute.Float64Value(float64(v))
	case float64:
		return attribute.Float64Value(v)
	case fmt.Stringer:
		return attribute.StringValue(v.String())
	default:
		return attribute.StringValue(fmt.Sprintf("%v", v))
	}
}

func attributeValueFromKeyValue(kv attribute.KeyValue) any {
	switch kv.Value.Type() {
	case attribute.BOOL:
		return kv.Value.AsBool()
	case attribute.INT64:
		return kv.Value.AsInt64()
	case attribute.FLOAT64:
		return kv.Value.AsFloat64()
	case attribute.STRING:
		return kv.Value.AsString()
	case attribute.BOOLSLICE:
		return kv.Value.AsBoolSlice()
	case attribute.INT64SLICE:
		return kv.Value.AsInt64Slice()
	case attribute.FLOAT64SLICE:
		return kv.Value.AsFloat64Slice()
	case attribute.STRINGSLICE:
		return kv.Value.AsStringSlice()
	default:
		return fmt.Sprintf("%v", kv.Value)
	}
}

// SpanKind describes the role of the span relative to external systems.
type SpanKind string

const (
	SpanKindInternal SpanKind = "internal"
	SpanKindServer   SpanKind = "server"
	SpanKindClient   SpanKind = "client"
)

func toOTELSpanKind(kind SpanKind) trace.SpanKind {
	switch kind {
	case SpanKindServer:
		return trace.SpanKindServer
	case SpanKindClient:
		return trace.SpanKindClient
	default:
		return trace.SpanKindInternal
	}
}

func fromOTELSpanKind(kind trace.SpanKind) SpanKind {
	switch kind {
	case trace.SpanKindServer:
		return SpanKindServer
	case trace.SpanKindClient:
		return SpanKindClient
	default:
		return SpanKindInternal
	}
}
