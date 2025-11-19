package tracing

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func newExporters(ctx context.Context, cfg Config) ([]sdktrace.SpanExporter, error) {
	exporters := make([]sdktrace.SpanExporter, 0, 2)
	if path := strings.TrimSpace(cfg.FilePath); path != "" {
		fileExporter, err := newFileSpanExporter(path)
		if err != nil {
			return nil, err
		}
		exporters = append(exporters, fileExporter)
	}
	if endpoint := strings.TrimSpace(cfg.Endpoint); endpoint != "" {
		otlpExporter, err := newOTLPHTTPExporter(ctx, endpoint, cfg.Headers, cfg.GetTLSConfig())
		if err != nil {
			return nil, err
		}
		exporters = append(exporters, otlpExporter)
	}
	return exporters, nil
}

func newCompositeExporter(exporters ...sdktrace.SpanExporter) sdktrace.SpanExporter {
	filtered := make([]sdktrace.SpanExporter, 0, len(exporters))
	for _, exp := range exporters {
		if exp != nil {
			filtered = append(filtered, exp)
		}
	}
	if len(filtered) == 1 {
		return filtered[0]
	}
	return &compositeExporter{exporters: filtered}
}

type compositeExporter struct {
	exporters []sdktrace.SpanExporter
}

func (c *compositeExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	var firstErr error
	for _, exporter := range c.exporters {
		if err := exporter.ExportSpans(ctx, spans); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (c *compositeExporter) Shutdown(ctx context.Context) error {
	var firstErr error
	for _, exporter := range c.exporters {
		if err := exporter.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

type fileSpanExporter struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
}

func newFileSpanExporter(path string) (sdktrace.SpanExporter, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &fileSpanExporter{file: f, enc: json.NewEncoder(f)}, nil
}

func (f *fileSpanExporter) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	if f == nil || len(spans) == 0 {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, span := range spans {
		snapshot := spanSnapshotFromReadOnly(span)
		if snapshot == nil {
			continue
		}
		if err := f.enc.Encode(snapshot); err != nil {
			return err
		}
	}
	return nil
}

func (f *fileSpanExporter) Shutdown(context.Context) error {
	if f == nil || f.file == nil {
		return nil
	}
	return f.file.Close()
}

func newOTLPHTTPExporter(ctx context.Context, endpoint string, headers map[string]string, tlsConfig *tls.Config) (sdktrace.SpanExporter, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil {
		return nil, fmt.Errorf("parse trace endpoint: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("trace endpoint must include scheme and host")
	}

	opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(parsed.Host)}
	if parsed.Path != "" && parsed.Path != "/" {
		path := parsed.Path
		if parsed.RawQuery != "" {
			path = fmt.Sprintf("%s?%s", path, parsed.RawQuery)
		}
		opts = append(opts, otlptracehttp.WithURLPath(path))
	}
	if len(headers) > 0 {
		trimmed := make(map[string]string, len(headers))
		for k, v := range headers {
			key := strings.TrimSpace(k)
			if key == "" {
				continue
			}
			trimmed[key] = strings.TrimSpace(v)
		}
		if len(trimmed) > 0 {
			opts = append(opts, otlptracehttp.WithHeaders(trimmed))
		}
	}
	if parsed.Scheme == "http" {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	if tlsConfig != nil {
		opts = append(opts, otlptracehttp.WithTLSClientConfig(tlsConfig))
	}

	client := otlptracehttp.NewClient(opts...)
	return otlptrace.New(ctx, client)
}
