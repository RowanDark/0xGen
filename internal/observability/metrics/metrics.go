package metrics

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RowanDark/0xgen/internal/observability/tracing"
)

type collector interface {
	write(sb *strings.Builder)
}

type counterVec struct {
	name   string
	help   string
	labels []string

	mu     sync.RWMutex
	values map[string]float64
}

type gaugeVec struct {
	name   string
	help   string
	labels []string

	mu     sync.RWMutex
	values map[string]float64
}

type histogramVec struct {
	name    string
	help    string
	labels  []string
	buckets []float64

	mu     sync.RWMutex
	values map[string]*histogramValue
}

type dualCounterVec struct {
	primary *counterVec
}

type dualGaugeVec struct {
	primary *gaugeVec
}

type dualHistogramVec struct {
	primary *histogramVec
}

type histogramValue struct {
	counts   []uint64
	sum      float64
	total    uint64
	exemplar *metricExemplar
}

type metricExemplar struct {
	traceID string
	value   float64
}

var (
	collectors []collector

	rpcRequests         = newDualCounterVec("oxg_rpc_requests_total", "Total number of RPC requests handled by OxG components.", []string{"component", "method"})
	rpcErrors           = newDualCounterVec("oxg_rpc_errors_total", "Total number of RPC errors emitted by OxG components.", []string{"component", "method", "code"})
	rpcLatency          = newDualHistogramVec("oxg_rpc_duration_seconds", "Latency of RPC handlers broken down by component and method.", []string{"component", "method", "code"})
	pluginEvent         = newDualHistogramVec("oxg_plugin_event_duration_seconds", "Duration OxG spends processing plugin events.", []string{"plugin", "event"})
	pluginQueue         = newDualGaugeVec("oxg_plugin_queue_length", "Current length of the outbound queue for a plugin.", []string{"plugin"})
	activePlugs         = newDualGaugeVec("oxg_active_plugins", "Number of active plugin connections registered with the bus.", nil)
	httpThrottle        = newDualCounterVec("oxg_http_throttle_total", "Number of outbound HTTP requests delayed due to throttling.", []string{"scope"})
	httpBackoff         = newDualCounterVec("oxg_http_backoff_total", "Number of outbound HTTP retry backoffs triggered by response status codes.", []string{"status"})
	httpLatency         = newDualHistogramVec("oxg_http_request_duration_seconds", "Latency of outbound HTTP requests executed on behalf of plugins.", []string{"plugin", "capability", "method", "status"})
	flowEvents          = newDualCounterVec("oxg_flow_events_total", "Number of flow events dispatched to plugins.", []string{"subscription", "variant"})
	flowDrops           = newDualCounterVec("oxg_flow_events_dropped_total", "Number of flow events dropped before reaching plugins.", []string{"subscription", "reason"})
	flowDispatchLatency = newDualHistogramVec("oxg_flow_dispatch_seconds", "Latency to broadcast flow events to subscribers.", []string{"subscription", "variant"})
	flowRedactions      = newDualCounterVec("oxg_flow_redactions_total", "Number of sanitisation or truncation actions applied to flow payloads.", []string{"kind"})

	totalRequests uint64
)

func init() {
	collectors = []collector{rpcRequests, rpcErrors, rpcLatency, pluginEvent, pluginQueue, activePlugs, httpThrottle, httpBackoff, httpLatency, flowEvents, flowDrops, flowDispatchLatency, flowRedactions}
}

func newCounterVec(name, help string, labels []string) *counterVec {
	return &counterVec{name: name, help: help, labels: labels, values: make(map[string]float64)}
}

func newDualCounterVec(name, help string, labels []string) *dualCounterVec {
	return &dualCounterVec{
		primary: newCounterVec(name, help, labels),
	}
}

func newGaugeVec(name, help string, labels []string) *gaugeVec {
	return &gaugeVec{name: name, help: help, labels: labels, values: make(map[string]float64)}
}

func newDualGaugeVec(name, help string, labels []string) *dualGaugeVec {
	return &dualGaugeVec{
		primary: newGaugeVec(name, help, labels),
	}
}

func newHistogramVec(name, help string, labels []string) *histogramVec {
	buckets := []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
	return &histogramVec{
		name:    name,
		help:    help,
		labels:  labels,
		buckets: buckets,
		values:  make(map[string]*histogramValue),
	}
}

func newDualHistogramVec(name, help string, labels []string) *dualHistogramVec {
	return &dualHistogramVec{
		primary: newHistogramVec(name, help, labels),
	}
}

func (cv *counterVec) add(delta float64, values ...string) {
	if len(values) != len(cv.labels) {
		panic(fmt.Sprintf("expected %d labels, got %d", len(cv.labels), len(values)))
	}
	key := strings.Join(values, ",")
	cv.mu.Lock()
	cv.values[key] += delta
	cv.mu.Unlock()
}

func (cv *counterVec) IncWith(values ...string) {
	cv.add(1, values...)
}

func (cv *counterVec) AddWith(delta float64, values ...string) {
	cv.add(delta, values...)
}

func (dcv *dualCounterVec) IncWith(values ...string) {
	dcv.primary.IncWith(values...)
}

func (dcv *dualCounterVec) AddWith(delta float64, values ...string) {
	dcv.primary.AddWith(delta, values...)
}

func (dcv *dualCounterVec) write(sb *strings.Builder) {
	dcv.primary.write(sb)
}

func (cv *counterVec) write(sb *strings.Builder) {
	writeHeader(sb, cv.name, cv.help, "counter")
	cv.mu.RLock()
	keys := make([]string, 0, len(cv.values))
	for k := range cv.values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := cv.values[key]
		sb.WriteString(cv.name)
		if len(cv.labels) > 0 {
			sb.WriteString("{")
			parts := strings.Split(key, ",")
			for i, label := range cv.labels {
				sb.WriteString(label)
				sb.WriteString("=\"")
				sb.WriteString(escapeLabel(parts[i]))
				sb.WriteString("\"")
				if i < len(cv.labels)-1 {
					sb.WriteString(",")
				}
			}
			sb.WriteString("}")
		}
		sb.WriteString(fmt.Sprintf(" %g\n", value))
	}
	cv.mu.RUnlock()
}

func (gv *gaugeVec) Set(values []string, v float64) {
	if len(values) != len(gv.labels) {
		panic(fmt.Sprintf("expected %d labels, got %d", len(gv.labels), len(values)))
	}
	key := strings.Join(values, ",")
	gv.mu.Lock()
	gv.values[key] = v
	gv.mu.Unlock()
}

func (gv *gaugeVec) Delete(values ...string) {
	if len(values) != len(gv.labels) {
		panic(fmt.Sprintf("expected %d labels, got %d", len(gv.labels), len(values)))
	}
	key := strings.Join(values, ",")
	gv.mu.Lock()
	delete(gv.values, key)
	gv.mu.Unlock()
}

func (dgv *dualGaugeVec) Set(values []string, v float64) {
	dgv.primary.Set(values, v)
}

func (dgv *dualGaugeVec) Delete(values ...string) {
	dgv.primary.Delete(values...)
}

func (dgv *dualGaugeVec) write(sb *strings.Builder) {
	dgv.primary.write(sb)
}

func (gv *gaugeVec) write(sb *strings.Builder) {
	writeHeader(sb, gv.name, gv.help, "gauge")
	gv.mu.RLock()
	keys := make([]string, 0, len(gv.values))
	for k := range gv.values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		v := gv.values[key]
		sb.WriteString(gv.name)
		if len(gv.labels) > 0 {
			sb.WriteString("{")
			parts := strings.Split(key, ",")
			for i, label := range gv.labels {
				sb.WriteString(label)
				sb.WriteString("=\"")
				sb.WriteString(escapeLabel(parts[i]))
				sb.WriteString("\"")
				if i < len(gv.labels)-1 {
					sb.WriteString(",")
				}
			}
			sb.WriteString("}")
		}
		sb.WriteString(fmt.Sprintf(" %g\n", v))
	}
	gv.mu.RUnlock()
}

func (hv *histogramVec) Observe(values []string, sample float64) {
	hv.observe(values, sample, nil)
}

func (hv *histogramVec) ObserveWithContext(ctx context.Context, values []string, sample float64) {
	hv.observe(values, sample, exemplarFromContext(ctx, sample))
}

func (hv *histogramVec) observe(values []string, sample float64, ex *metricExemplar) {
	if len(values) != len(hv.labels) {
		panic(fmt.Sprintf("expected %d labels, got %d", len(hv.labels), len(values)))
	}
	key := strings.Join(values, ",")
	hv.mu.Lock()
	defer hv.mu.Unlock()
	entry, ok := hv.values[key]
	if !ok {
		entry = &histogramValue{counts: make([]uint64, len(hv.buckets)+1)}
		hv.values[key] = entry
	}
	entry.sum += sample
	entry.total++
	placed := false
	for i, bucket := range hv.buckets {
		if sample <= bucket {
			entry.counts[i]++
			placed = true
			break
		}
	}
	if !placed {
		entry.counts[len(hv.buckets)]++
	}
	if ex != nil {
		entry.exemplar = ex
	}
}

func (hv *histogramVec) write(sb *strings.Builder) {
	writeHeader(sb, hv.name, hv.help, "histogram")
	hv.mu.RLock()
	keys := make([]string, 0, len(hv.values))
	for k := range hv.values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		entry := hv.values[key]
		parts := strings.Split(key, ",")
		cumulative := uint64(0)
		for i, upper := range hv.buckets {
			cumulative += entry.counts[i]
			sb.WriteString(hv.name)
			sb.WriteString("_bucket{")
			for j, label := range hv.labels {
				sb.WriteString(label)
				sb.WriteString("=\"")
				sb.WriteString(escapeLabel(parts[j]))
				sb.WriteString("\"")
				sb.WriteString(",")
			}
			sb.WriteString(fmt.Sprintf("le=\"%g\"} %d\n", upper, cumulative))
		}
		cumulative += entry.counts[len(hv.buckets)]
		sb.WriteString(hv.name)
		sb.WriteString("_bucket{")
		for j, label := range hv.labels {
			sb.WriteString(label)
			sb.WriteString("=\"")
			sb.WriteString(escapeLabel(parts[j]))
			sb.WriteString("\"")
			sb.WriteString(",")
		}
		sb.WriteString("le=\"+Inf\"} ")
		sb.WriteString(fmt.Sprintf("%d\n", cumulative))

		sb.WriteString(hv.name)
		sb.WriteString("_sum")
		if len(hv.labels) > 0 {
			sb.WriteString("{")
			for j, label := range hv.labels {
				sb.WriteString(label)
				sb.WriteString("=\"")
				sb.WriteString(escapeLabel(parts[j]))
				sb.WriteString("\"")
				if j < len(hv.labels)-1 {
					sb.WriteString(",")
				}
			}
			sb.WriteString("}")
		}
		sb.WriteString(fmt.Sprintf(" %g", entry.sum))
		if entry.exemplar != nil && entry.exemplar.traceID != "" {
			sb.WriteString(" # {trace_id=\"")
			sb.WriteString(escapeLabel(entry.exemplar.traceID))
			sb.WriteString("\"} ")
			sb.WriteString(fmt.Sprintf("%g", entry.exemplar.value))
		}
		sb.WriteString("\n")
		sb.WriteString(hv.name)
		sb.WriteString("_count")
		if len(hv.labels) > 0 {
			sb.WriteString("{")
			for j, label := range hv.labels {
				sb.WriteString(label)
				sb.WriteString("=\"")
				sb.WriteString(escapeLabel(parts[j]))
				sb.WriteString("\"")
				if j < len(hv.labels)-1 {
					sb.WriteString(",")
				}
			}
			sb.WriteString("}")
		}
		sb.WriteString(fmt.Sprintf(" %d\n", entry.total))
	}
	hv.mu.RUnlock()
}

func (dhv *dualHistogramVec) Observe(values []string, sample float64) {
	dhv.primary.Observe(values, sample)
}

func (dhv *dualHistogramVec) ObserveWithContext(ctx context.Context, values []string, sample float64) {
	dhv.primary.ObserveWithContext(ctx, values, sample)
}

func (dhv *dualHistogramVec) write(sb *strings.Builder) {
	dhv.primary.write(sb)
}

func writeHeader(sb *strings.Builder, name, help, metricType string) {
	sb.WriteString("# HELP ")
	sb.WriteString(name)
	sb.WriteString(" ")
	sb.WriteString(help)
	sb.WriteString("\n# TYPE ")
	sb.WriteString(name)
	sb.WriteString(" ")
	sb.WriteString(metricType)
	sb.WriteString("\n")
}

func exemplarFromContext(ctx context.Context, sample float64) *metricExemplar {
	if ctx == nil {
		return nil
	}
	traceID := tracing.TraceIDFromContext(ctx)
	if traceID == "" {
		return nil
	}
	return &metricExemplar{traceID: traceID, value: sample}
}

func escapeLabel(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	return value
}

// Handler exposes the metrics registry as an http.Handler compatible with Prometheus.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var sb strings.Builder
		for _, collector := range collectors {
			collector.write(&sb)
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(sb.String()))
	})
}

// RecordRPCRequest increments the request counter for a component and method.
func RecordRPCRequest(component, method string) {
	rpcRequests.IncWith(component, method)
	atomic.AddUint64(&totalRequests, 1)
}

// RecordRPCError increments the error counter for a component, method, and error code.
func RecordRPCError(component, method, code string) {
	rpcErrors.IncWith(component, method, code)
}

// ObserveRPCLatency records the duration spent serving an RPC method and tags it by status code.
func ObserveRPCLatency(ctx context.Context, component, method, code string, dur time.Duration) {
	rpcLatency.ObserveWithContext(ctx, []string{component, method, code}, dur.Seconds())
}

// RecordHTTPThrottle increments the counter for HTTP throttle events at the provided scope.
func RecordHTTPThrottle(scope string) {
	httpThrottle.IncWith(scope)
}

// RecordHTTPBackoff increments the counter for HTTP backoff events keyed by status code.
func RecordHTTPBackoff(status int) {
	httpBackoff.IncWith(strconv.Itoa(status))
}

// ObservePluginEventDuration records the latency for handling a plugin event.
func ObservePluginEventDuration(pluginID, event string, dur time.Duration) {
	pluginEvent.Observe([]string{pluginID, event}, dur.Seconds())
}

// SetPluginQueueLength sets the outbound queue length gauge for a plugin.
func SetPluginQueueLength(pluginID string, length int) {
	pluginQueue.Set([]string{pluginID}, float64(length))
}

// RemovePlugin removes gauges associated with a plugin when it disconnects.
func RemovePlugin(pluginID string) {
	pluginQueue.Delete(pluginID)
}

// SetActivePlugins updates the gauge representing the number of active plugin connections.
func SetActivePlugins(count int) {
	activePlugs.Set(nil, float64(count))
}

// RecordFlowEvent increments the counter tracking dispatched flow events by subscription and variant.
func RecordFlowEvent(subscription, variant string, count int) {
	if count <= 0 {
		return
	}
	flowEvents.AddWith(float64(count), subscription, variant)
}

// RecordFlowDrop increments the counter for flow events dropped before delivery.
func RecordFlowDrop(subscription, reason string, count int) {
	if count <= 0 {
		return
	}
	flowDrops.AddWith(float64(count), subscription, reason)
}

// ObserveFlowDispatchLatency records the time spent dispatching a flow event to subscribers.
func ObserveFlowDispatchLatency(ctx context.Context, subscription, variant string, dur time.Duration) {
	flowDispatchLatency.ObserveWithContext(ctx, []string{subscription, variant}, dur.Seconds())
}

// RecordFlowRedaction counts sanitisation or truncation operations applied to flow payloads.
func RecordFlowRedaction(kind string) {
	kind = strings.TrimSpace(strings.ToLower(kind))
	if kind == "" {
		kind = "unspecified"
	}
	flowRedactions.IncWith(kind)
}

// ObserveHTTPClientDuration records the latency for an outbound HTTP request executed by the gate.
func ObserveHTTPClientDuration(pluginID, capability, method, status string, dur time.Duration) {
	pluginID = strings.TrimSpace(pluginID)
	if pluginID == "" {
		pluginID = "unknown"
	}
	capability = strings.TrimSpace(capability)
	if capability == "" {
		capability = "unspecified"
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "UNKNOWN"
	}
	status = strings.TrimSpace(status)
	if status == "" {
		status = "unknown"
	}
	httpLatency.Observe([]string{pluginID, capability, method, status}, dur.Seconds())
}

// TotalRequests returns the total number of RPC requests served since process start.
func TotalRequests() uint64 {
	return atomic.LoadUint64(&totalRequests)
}
