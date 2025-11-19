package tracing

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"os"
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
	// Deprecated: Use DevelopmentMode instead. This field is only honored when DevelopmentMode is true.
	SkipTLSVerify bool
	// DevelopmentMode enables development-only settings like skipping TLS verification.
	// WARNING: Never enable this in production - it allows man-in-the-middle attacks!
	// This can also be controlled via the 0XGEN_DEV_MODE environment variable.
	DevelopmentMode bool
	// ServiceName is recorded on exported spans to identify the emitting service.
	ServiceName string
	// SampleRatio controls probabilistic sampling for root spans. Values outside the range
	// (0,1] are clamped. A value of 0 disables tracing, whereas 1 samples all spans.
	SampleRatio float64
	// FilePath controls the location where a JSONL copy of spans is written. When empty,
	// spans are not persisted locally.
	FilePath string
}

// IsDevelopmentMode returns true if the configuration is set for development mode.
// It checks both the DevelopmentMode field and the 0XGEN_DEV_MODE environment variable.
func (c *Config) IsDevelopmentMode() bool {
	if c.DevelopmentMode {
		return true
	}
	// Check environment variable
	envVal := strings.ToLower(strings.TrimSpace(os.Getenv("0XGEN_DEV_MODE")))
	return envVal == "true" || envVal == "1" || envVal == "yes"
}

// GetTLSConfig returns the appropriate TLS configuration based on the environment.
// In development mode, TLS verification may be skipped (if SkipTLSVerify is also true).
// In production mode, TLS certificates are always verified with a minimum of TLS 1.2.
//
// WARNING: Skipping TLS verification is dangerous and should only be used in development
// environments. It enables man-in-the-middle attacks that can expose sensitive telemetry data.
func (c *Config) GetTLSConfig() *tls.Config {
	if c.IsDevelopmentMode() && c.SkipTLSVerify {
		return &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
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
