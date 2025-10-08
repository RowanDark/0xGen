package tracing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type exporter interface {
	Export(ctx context.Context, span *SpanSnapshot) error
	Shutdown(ctx context.Context) error
}

type exportManager struct {
	exporters []exporter
	ch        chan *SpanSnapshot
	wg        sync.WaitGroup
	mu        sync.RWMutex
	closed    bool
}

func newExportManager(cfg Config) (*exportManager, error) {
	exps := make([]exporter, 0, 2)
	if path := strings.TrimSpace(cfg.FilePath); path != "" {
		fileExp, err := newFileExporter(path)
		if err != nil {
			return nil, err
		}
		exps = append(exps, fileExp)
	}
	if endpoint := strings.TrimSpace(cfg.Endpoint); endpoint != "" {
		otlp, err := newOTLPExporter(endpoint, cfg.Headers, cfg.SkipTLSVerify, cfg.ServiceName)
		if err != nil {
			return nil, err
		}
		exps = append(exps, otlp)
	}
	mgr := &exportManager{
		exporters: exps,
		ch:        make(chan *SpanSnapshot, 128),
	}
	if len(exps) > 0 {
		mgr.wg.Add(1)
		go mgr.run()
	}
	return mgr, nil
}

func (m *exportManager) run() {
	defer m.wg.Done()
	for span := range m.ch {
		for _, exp := range m.exporters {
			if err := exp.Export(context.Background(), span); err != nil {
				fmt.Fprintf(os.Stderr, "trace export error: %v\n", err)
			}
		}
	}
}

func (m *exportManager) export(span *SpanSnapshot) {
	if m == nil || len(m.exporters) == 0 || span == nil {
		return
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return
	}
	select {
	case m.ch <- span:
	default:
		// Drop spans when the exporter is overwhelmed to avoid blocking the pipeline.
		fmt.Fprintln(os.Stderr, "trace export queue full; dropping span")
	}
}

func (m *exportManager) shutdown(ctx context.Context) error {
	if m == nil || len(m.exporters) == 0 {
		return nil
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	close(m.ch)
	m.mu.Unlock()
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
	var firstErr error
	for _, exp := range m.exporters {
		if err := exp.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

type fileExporter struct {
	mu  sync.Mutex
	fw  *os.File
	enc *json.Encoder
}

func newFileExporter(path string) (*fileExporter, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	enc := json.NewEncoder(f)
	return &fileExporter{fw: f, enc: enc}, nil
}

func (f *fileExporter) Export(_ context.Context, span *SpanSnapshot) error {
	if f == nil || span == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.enc.Encode(span)
}

func (f *fileExporter) Shutdown(context.Context) error {
	if f == nil || f.fw == nil {
		return nil
	}
	return f.fw.Close()
}

type otlpExporter struct {
	client      *http.Client
	endpoint    string
	headers     map[string]string
	serviceName string
}

func newOTLPExporter(endpoint string, headers map[string]string, skipTLS bool, service string) (*otlpExporter, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Do not disable TLS certificate verification in production code.
	client := &http.Client{Timeout: 10 * time.Second, Transport: transport}
	hdrs := make(map[string]string, len(headers))
	for k, v := range headers {
		hdrs[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return &otlpExporter{client: client, endpoint: endpoint, headers: hdrs, serviceName: service}, nil
}

func (o *otlpExporter) Export(ctx context.Context, span *SpanSnapshot) error {
	if o == nil || span == nil {
		return nil
	}
	payload := o.buildPayload(span)
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range o.headers {
		if k == "" {
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("otlp export failed: %s", resp.Status)
	}
	return nil
}

func (o *otlpExporter) buildPayload(span *SpanSnapshot) map[string]any {
	attrs := make([]map[string]any, 0, len(span.Attributes))
	for k, v := range span.Attributes {
		attrs = append(attrs, otlpKeyValue(k, v))
	}
	events := make([]map[string]any, 0, len(span.Events))
	for _, evt := range span.Events {
		evtAttrs := make([]map[string]any, 0, len(evt.Attributes))
		for k, v := range evt.Attributes {
			evtAttrs = append(evtAttrs, otlpKeyValue(k, v))
		}
		events = append(events, map[string]any{
			"name":         evt.Name,
			"timeUnixNano": strconv.FormatInt(evt.Time.UnixNano(), 10),
			"attributes":   evtAttrs,
		})
	}
	status := map[string]any{}
	switch span.Status {
	case StatusOK:
		status["code"] = 1
	case StatusError:
		status["code"] = 2
	default:
		status["code"] = 0
	}
	if span.StatusMsg != "" {
		status["message"] = span.StatusMsg
	}
	resAttrs := []map[string]any{}
	if o.serviceName != "" {
		resAttrs = append(resAttrs, otlpKeyValue("service.name", o.serviceName))
	}
	payload := map[string]any{
		"resourceSpans": []map[string]any{
			{
				"resource": map[string]any{
					"attributes": resAttrs,
				},
				"scopeSpans": []map[string]any{
					{
						"scope": map[string]any{"name": "glyph"},
						"spans": []map[string]any{
							{
								"traceId":           span.TraceID,
								"spanId":            span.SpanID,
								"parentSpanId":      span.ParentSpanID,
								"name":              span.Name,
								"kind":              otlpSpanKind(span.Kind),
								"startTimeUnixNano": strconv.FormatInt(span.StartTime.UnixNano(), 10),
								"endTimeUnixNano":   strconv.FormatInt(span.EndTime.UnixNano(), 10),
								"attributes":        attrs,
								"events":            events,
								"status":            status,
							},
						},
					},
				},
			},
		},
	}
	return payload
}

func (o *otlpExporter) Shutdown(context.Context) error { return nil }

func otlpSpanKind(kind SpanKind) int {
	switch kind {
	case SpanKindServer:
		return 2
	case SpanKindClient:
		return 3
	case SpanKindInternal:
		fallthrough
	default:
		return 1
	}
}

func otlpKeyValue(key string, value any) map[string]any {
	m := map[string]any{"key": key}
	switch v := value.(type) {
	case string:
		m["value"] = map[string]any{"stringValue": v}
	case fmt.Stringer:
		m["value"] = map[string]any{"stringValue": v.String()}
	case bool:
		m["value"] = map[string]any{"boolValue": v}
	case int:
		m["value"] = map[string]any{"intValue": strconv.FormatInt(int64(v), 10)}
	case int32:
		m["value"] = map[string]any{"intValue": strconv.FormatInt(int64(v), 10)}
	case int64:
		m["value"] = map[string]any{"intValue": strconv.FormatInt(v, 10)}
	case uint:
		m["value"] = map[string]any{"intValue": strconv.FormatUint(uint64(v), 10)}
	case uint32:
		m["value"] = map[string]any{"intValue": strconv.FormatUint(uint64(v), 10)}
	case uint64:
		m["value"] = map[string]any{"intValue": strconv.FormatUint(v, 10)}
	case float32:
		m["value"] = map[string]any{"doubleValue": float64(v)}
	case float64:
		m["value"] = map[string]any{"doubleValue": v}
	default:
		m["value"] = map[string]any{"stringValue": fmt.Sprint(v)}
	}
	return m
}
