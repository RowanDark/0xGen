package tracing

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
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
	tracer, err := newTracer(ctx, cfg)
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

	otel.SetTracerProvider(tracer.provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

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
	provider    *sdktrace.TracerProvider
	tracer      trace.Tracer
	serviceName string
}

func newTracer(ctx context.Context, cfg Config) (*Tracer, error) {
	ratio := math.Max(0, math.Min(1, cfg.SampleRatio))
	if ratio == 0 {
		return nil, nil
	}

	serviceName := strings.TrimSpace(cfg.ServiceName)
	if serviceName == "" {
		serviceName = "0xgen"
	}

	exporters, err := newExporters(ctx, cfg)
	if err != nil {
		return nil, err
	}

	resource, err := sdkresource.New(ctx,
		sdkresource.WithTelemetrySDK(),
		sdkresource.WithProcess(),
		sdkresource.WithAttributes(semconv.ServiceName(serviceName)),
	)
	if err != nil {
		return nil, fmt.Errorf("build trace resource: %w", err)
	}

	providerOpts := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(resource),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))),
	}

	if len(exporters) > 0 {
		providerOpts = append(providerOpts, sdktrace.WithSpanProcessor(
			sdktrace.NewBatchSpanProcessor(newCompositeExporter(exporters...)),
		))
	}

	provider := sdktrace.NewTracerProvider(providerOpts...)
	tracer := provider.Tracer("github.com/RowanDark/0xgen")

	return &Tracer{provider: provider, tracer: tracer, serviceName: serviceName}, nil
}

// Shutdown flushes exporters and releases resources.
func (t *Tracer) Shutdown(ctx context.Context) error {
	if t == nil || t.provider == nil {
		return nil
	}
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return t.provider.Shutdown(shutdownCtx)
}

// ServiceName returns the configured service name.
func (t *Tracer) ServiceName() string {
	if t == nil {
		return ""
	}
	return t.serviceName
}
