package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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

type histogramValue struct {
	counts []uint64
	sum    float64
	total  uint64
}

var (
	collectors []collector

	rpcRequests = newCounterVec("glyph_rpc_requests_total", "Total number of RPC requests handled by Glyph components.", []string{"component", "method"})
	rpcErrors   = newCounterVec("glyph_rpc_errors_total", "Total number of RPC errors emitted by Glyph components.", []string{"component", "method", "code"})
	pluginEvent = newHistogramVec("glyph_plugin_event_duration_seconds", "Duration Glyph spends processing plugin events.", []string{"plugin", "event"})
	pluginQueue = newGaugeVec("glyph_plugin_queue_length", "Current length of the outbound queue for a plugin.", []string{"plugin"})
	activePlugs = newGaugeVec("glyph_active_plugins", "Number of active plugin connections registered with the bus.", nil)

	totalRequests uint64
)

func init() {
	collectors = []collector{rpcRequests, rpcErrors, pluginEvent, pluginQueue, activePlugs}
}

func newCounterVec(name, help string, labels []string) *counterVec {
	return &counterVec{name: name, help: help, labels: labels, values: make(map[string]float64)}
}

func newGaugeVec(name, help string, labels []string) *gaugeVec {
	return &gaugeVec{name: name, help: help, labels: labels, values: make(map[string]float64)}
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

func (cv *counterVec) IncWith(values ...string) {
	if len(values) != len(cv.labels) {
		panic(fmt.Sprintf("expected %d labels, got %d", len(cv.labels), len(values)))
	}
	key := strings.Join(values, ",")
	cv.mu.Lock()
	defer cv.mu.Unlock()
	cv.values[key]++
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
		sb.WriteString(fmt.Sprintf(" %g\n", entry.sum))
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

// TotalRequests returns the total number of RPC requests served since process start.
func TotalRequests() uint64 {
	return atomic.LoadUint64(&totalRequests)
}
