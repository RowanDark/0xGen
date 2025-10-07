package tracing

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"strings"
	"sync"
	"time"
)

// Config controls how tracing is initialised for the process.
type Config struct {
	// Endpoint is the optional OTLP/HTTP collector endpoint (e.g. http://collector:4318/v1/traces).
	Endpoint string
	// Headers are optional headers that should be included with OTLP requests.
	Headers map[string]string
	// SkipTLSVerify disables TLS verification when communicating with the collector.
	SkipTLSVerify bool
	// ServiceName is recorded on exported spans to identify the emitting service.
	ServiceName string
	// SampleRatio controls probabilistic sampling for root spans. Values outside the range
	// (0,1] are clamped. A value of 0 disables tracing, whereas 1 samples all spans.
	SampleRatio float64
	// FilePath controls the location where a JSONL copy of spans is written. When empty,
	// spans are not persisted locally.
	FilePath string
}

var (
	globalMu     sync.RWMutex
	globalTracer *Tracer
)

// Setup configures the global tracer. The returned shutdown function must be invoked when
// the process exits to ensure spans are flushed.
func Setup(ctx context.Context, cfg Config) (func(context.Context) error, error) {
	tracer, err := newTracer(cfg)
	if err != nil {
		return nil, err
	}
	if tracer == nil {
		return func(context.Context) error { return nil }, nil
	}

	globalMu.Lock()
	if globalTracer != nil {
		_ = globalTracer.Shutdown(ctx)
	}
	globalTracer = tracer
	globalMu.Unlock()

	return tracer.Shutdown, nil
}

// CurrentTracer returns the active tracer, or nil if tracing is disabled.
func CurrentTracer() *Tracer {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalTracer
}

// Tracer represents the process level tracing configuration.
type Tracer struct {
	exporters   *exportManager
	sampleRatio float64
	serviceName string
	rngMu       sync.Mutex
	rng         *rand.Rand
}

func newTracer(cfg Config) (*Tracer, error) {
	ratio := math.Max(0, math.Min(1, cfg.SampleRatio))
	if ratio == 0 {
		return nil, nil
	}
	exporters, err := newExportManager(cfg)
	if err != nil {
		return nil, err
	}
	seed, err := randInt64()
	if err != nil {
		return nil, err
	}
	tracer := &Tracer{
		exporters:   exporters,
		sampleRatio: ratio,
		serviceName: strings.TrimSpace(cfg.ServiceName),
		rng:         rand.New(rand.NewSource(seed)),
	}
	return tracer, nil
}

func randInt64() (int64, error) {
	n, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return 0, err
	}
	return n.Int64(), nil
}

// Shutdown flushes exporters and releases resources.
func (t *Tracer) Shutdown(ctx context.Context) error {
	if t == nil {
		return nil
	}
	if t.exporters == nil {
		return nil
	}
	return t.exporters.shutdown(ctx)
}

// sampledRoot determines whether a new root span should be sampled.
func (t *Tracer) sampledRoot() bool {
	if t == nil {
		return false
	}
	t.rngMu.Lock()
	defer t.rngMu.Unlock()
	return t.rng.Float64() < t.sampleRatio
}

// StartSpan begins a new span derived from ctx.
func StartSpan(ctx context.Context, name string, opts ...SpanStartOption) (context.Context, Span) {
	tracer := CurrentTracer()
	if tracer == nil {
		return ctx, noopSpan{}
	}
	cfg := spanConfig{kind: SpanKindInternal}
	for _, opt := range opts {
		opt.apply(&cfg)
	}
	parent := SpanContextFromContext(ctx)
	spanVal, spanCtx := tracer.startSpan(parent, name, cfg)
	combined := context.WithValue(ctx, spanContextKey{}, spanCtx)
	if realSpan, ok := spanVal.(*span); ok {
		combined = context.WithValue(combined, activeSpanKey{}, realSpan)
	}
	return combined, spanVal
}

// SpanFromContext retrieves the active span, returning a noop span if none exists.
func SpanFromContext(ctx context.Context) Span {
	if ctx == nil {
		return noopSpan{}
	}
	if sp, ok := ctx.Value(activeSpanKey{}).(Span); ok && sp != nil {
		return sp
	}
	return noopSpan{ctx: SpanContextFromContext(ctx)}
}

// SpanContextFromContext returns the span context stored on ctx.
func SpanContextFromContext(ctx context.Context) SpanContext {
	if ctx == nil {
		return SpanContext{}
	}
	if sc, ok := ctx.Value(spanContextKey{}).(SpanContext); ok {
		return sc
	}
	return SpanContext{}
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
	return context.WithValue(ctx, spanContextKey{}, sc)
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

func newTraceID() string {
	b := make([]byte, 16)
	if _, err := crand.Read(b); err != nil {
		panic(fmt.Errorf("generate trace id: %w", err))
	}
	return hex.EncodeToString(b)
}

func newSpanID() string {
	b := make([]byte, 8)
	if _, err := crand.Read(b); err != nil {
		panic(fmt.Errorf("generate span id: %w", err))
	}
	return hex.EncodeToString(b)
}

// SpanKind describes the role of the span relative to external systems.
type SpanKind string

const (
	SpanKindInternal SpanKind = "internal"
	SpanKindServer   SpanKind = "server"
	SpanKindClient   SpanKind = "client"
)

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

func cloneAttributes(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (t *Tracer) startSpan(parent SpanContext, name string, cfg spanConfig) (Span, SpanContext) {
	if t == nil {
		return noopSpan{}, SpanContext{}
	}
	traceID := parent.TraceID
	sampled := parent.Sampled
	if !parent.Valid() {
		sampled = t.sampledRoot()
		traceID = newTraceID()
	}
	spanID := newSpanID()
	sc := SpanContext{TraceID: traceID, SpanID: spanID, Sampled: sampled}
	if !sampled {
		return noopSpan{ctx: sc}, sc
	}
	s := &span{
		tracer:      t,
		context:     sc,
		parent:      parent,
		name:        name,
		kind:        cfg.kind,
		attributes:  cloneAttributes(cfg.attributes),
		startTime:   time.Now(),
		serviceName: t.serviceName,
	}
	return s, sc
}
