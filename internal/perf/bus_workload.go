package perf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"math/rand"
	"runtime"
	"runtime/metrics"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RowanDark/Glyph/internal/findings"
)

// BusWorkloadConfig configures the synthetic pipeline exercised when benchmarking
// the findings bus.
type BusWorkloadConfig struct {
	Name         string  `json:"name"`
	FanOut       int     `json:"fan_out"`
	Depth        int     `json:"depth"`
	Concurrency  int     `json:"concurrency"`
	Events       int     `json:"events"`
	PayloadBytes int     `json:"payload_bytes"`
	FailureRate  float64 `json:"failure_rate"`
	Seed         int64   `json:"seed"`
	DynamicWork  int     `json:"dynamic_work"`
}

// Validate ensures the workload configuration is well formed.
func (cfg BusWorkloadConfig) Validate() error {
	if strings.TrimSpace(cfg.Name) == "" {
		return errors.New("name is required")
	}
	if cfg.FanOut <= 0 {
		return fmt.Errorf("fan_out must be positive (got %d)", cfg.FanOut)
	}
	if cfg.Depth < 0 {
		return fmt.Errorf("depth cannot be negative (got %d)", cfg.Depth)
	}
	if cfg.Concurrency <= 0 {
		return fmt.Errorf("concurrency must be positive (got %d)", cfg.Concurrency)
	}
	if cfg.Events <= 0 {
		return fmt.Errorf("events must be positive (got %d)", cfg.Events)
	}
	if cfg.PayloadBytes < 0 {
		return fmt.Errorf("payload_bytes cannot be negative (got %d)", cfg.PayloadBytes)
	}
	if cfg.FailureRate < 0 || cfg.FailureRate >= 1 {
		return fmt.Errorf("failure_rate must be in [0,1) (got %f)", cfg.FailureRate)
	}
	if cfg.DynamicWork < 0 {
		return fmt.Errorf("dynamic_work cannot be negative (got %d)", cfg.DynamicWork)
	}
	return nil
}

// BusWorkloadMetrics captures the aggregated statistics observed for a
// BusWorkloadConfig execution.
type BusWorkloadMetrics struct {
	Name       string            `json:"name"`
	Config     BusWorkloadConfig `json:"config"`
	Duration   time.Duration     `json:"duration"`
	Successes  int               `json:"successes"`
	Errors     int               `json:"errors"`
	Throughput float64           `json:"throughput_eps"`
	ErrorRate  float64           `json:"error_rate"`
	Latency    LatencyMetrics    `json:"latency"`
	Memory     MemoryMetrics     `json:"memory"`
	CPUSeconds float64           `json:"cpu_seconds"`
}

// LatencyMetrics exposes percentile data in milliseconds.
type LatencyMetrics struct {
	P50 float64 `json:"p50_ms"`
	P95 float64 `json:"p95_ms"`
	P99 float64 `json:"p99_ms"`
	Max float64 `json:"max_ms"`
}

// MemoryMetrics captures allocation statistics for the workload.
type MemoryMetrics struct {
	BytesTotal         uint64  `json:"bytes_total"`
	BytesPerEvent      float64 `json:"bytes_per_event"`
	PeakGoroutines     int     `json:"peak_goroutines"`
	BaselineGoroutines int     `json:"baseline_goroutines"`
}

var workAccumulator atomic.Uint64

type eventResult struct {
	latency time.Duration
	err     error
}

// RunBusWorkload executes the configured synthetic workload and returns the
// aggregated metrics.
func RunBusWorkload(ctx context.Context, cfg BusWorkloadConfig) (BusWorkloadMetrics, error) {
	if err := cfg.Validate(); err != nil {
		return BusWorkloadMetrics{}, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	totalEvents := cfg.Events
	rootBus := findings.NewBus()

	type stage struct {
		bus    *findings.Bus
		wg     *sync.WaitGroup
		cancel []context.CancelFunc
	}

	stages := make([]*stage, 0, cfg.Depth+1)
	stages = append(stages, &stage{bus: rootBus, wg: &sync.WaitGroup{}})

	// Build intermediate processing stages to simulate fan-out/depth.
	prevBus := rootBus
	for level := 0; level < cfg.Depth; level++ {
		nextBus := findings.NewBus()
		st := &stage{bus: nextBus, wg: &sync.WaitGroup{}}
		subCtx, subCancel := context.WithCancel(runCtx)
		st.cancel = append(st.cancel, subCancel)
		sub := prevBus.Subscribe(subCtx)
		for worker := 0; worker < cfg.FanOut; worker++ {
			st.wg.Add(1)
			go runIntermediateStage(subCtx, st.wg, level, worker, cfg, sub, nextBus)
		}
		stages = append(stages, st)
		prevBus = nextBus
	}

	// Final sink stage that records metrics.
	results := make(chan eventResult, totalEvents)
	finalWG := &sync.WaitGroup{}
	var startTimes sync.Map
	lastStage := stages[len(stages)-1]
	subCtx, subCancel := context.WithCancel(runCtx)
	lastStage.cancel = append(lastStage.cancel, subCancel)
	sub := prevBus.Subscribe(subCtx)
	for worker := 0; worker < cfg.FanOut; worker++ {
		finalWG.Add(1)
		go runFinalStage(subCtx, finalWG, cfg, worker, sub, results, &startTimes)
	}

	runtime.GC()
	before := runtime.MemStats{}
	runtime.ReadMemStats(&before)
	cpuStart := readCPUSeconds()
	baselineG := runtime.NumGoroutine()

	emitWG := &sync.WaitGroup{}
	emitWG.Add(cfg.Concurrency)

	start := time.Now()
	for worker := 0; worker < cfg.Concurrency; worker++ {
		count := totalEvents / cfg.Concurrency
		if worker == cfg.Concurrency-1 {
			count += totalEvents % cfg.Concurrency
		}
		go func(workerID int, count int) {
			defer emitWG.Done()
			rng := rand.New(rand.NewSource(cfg.Seed + int64(workerID)*97))
			payload := strings.Repeat("x", cfg.PayloadBytes)
			baseFinding := findings.Finding{
				Version:    findings.SchemaVersion,
				Plugin:     "perfbench",
				Type:       fmt.Sprintf("fanout_%d_depth_%d", cfg.FanOut, cfg.Depth),
				Message:    fmt.Sprintf("synthetic payload %d", cfg.PayloadBytes),
				Severity:   findings.SeverityLow,
				DetectedAt: findings.NewTimestamp(time.Now()),
			}
			for i := 0; i < count; i++ {
				id := findings.NewID()
				f := baseFinding
				f.ID = id
				metadata := map[string]string{
					"payload": payload,
				}
				if cfg.PayloadBytes > 0 {
					metadata["nonce"] = fmt.Sprintf("%d", rng.Int63())
				}
				f.Metadata = metadata
				startTimes.Store(id, time.Now())
				rootBus.Emit(f)
			}
		}(worker, count)
	}

	go func() {
		finalWG.Wait()
		close(results)
	}()

	metrics := BusWorkloadMetrics{
		Name:   cfg.Name,
		Config: cfg,
	}

	latencies := make([]time.Duration, 0, totalEvents)
	var maxLatency time.Duration
	processed := 0
	success := 0
	errorsCount := 0
	cancelOnce := sync.Once{}
	peakG := baselineG

	for res := range results {
		processed++
		if res.err != nil {
			errorsCount++
		} else {
			success++
			latencies = append(latencies, res.latency)
			if res.latency > maxLatency {
				maxLatency = res.latency
			}
		}
		if g := runtime.NumGoroutine(); g > peakG {
			peakG = g
		}
		if processed >= totalEvents {
			cancelOnce.Do(cancel)
		}
	}

	cancelOnce.Do(cancel)
	emitWG.Wait()
	finalWG.Wait()
	for _, st := range stages {
		st.wg.Wait()
		for _, c := range st.cancel {
			c()
		}
	}

	duration := time.Since(start)
	runtime.GC()
	after := runtime.MemStats{}
	runtime.ReadMemStats(&after)
	cpuEnd := readCPUSeconds()

	metrics.Duration = duration
	metrics.Successes = success
	metrics.Errors = errorsCount
	if duration > 0 {
		metrics.Throughput = float64(success) / duration.Seconds()
	}
	if processed > 0 {
		metrics.ErrorRate = float64(errorsCount) / float64(processed)
	}
	metrics.Latency = summariseLatencies(latencies, maxLatency)

	allocBytes := after.TotalAlloc - before.TotalAlloc
	metrics.Memory = MemoryMetrics{
		BytesTotal:         allocBytes,
		BytesPerEvent:      safeDivideFloat(float64(allocBytes), float64(processed)),
		PeakGoroutines:     peakG,
		BaselineGoroutines: baselineG,
	}
	metrics.CPUSeconds = safeDifference(cpuEnd, cpuStart)

	return metrics, nil
}

func runIntermediateStage(ctx context.Context, wg *sync.WaitGroup, level int, workerID int, cfg BusWorkloadConfig, sub <-chan findings.Finding, next *findings.Bus) {
	defer wg.Done()
	payload := make([]byte, cfg.PayloadBytes)
	for i := range payload {
		payload[i] = byte((i + level + workerID) % 251)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case f, ok := <-sub:
			if !ok {
				return
			}
			simulateWork(level, workerID, payload, f.ID, cfg.DynamicWork)
			next.Emit(f)
		}
	}
}

func runFinalStage(ctx context.Context, wg *sync.WaitGroup, cfg BusWorkloadConfig, workerID int, sub <-chan findings.Finding, results chan<- eventResult, startTimes *sync.Map) {
	defer wg.Done()
	payload := make([]byte, cfg.PayloadBytes)
	for i := range payload {
		payload[i] = byte((i + workerID*3) % 251)
	}
	rng := rand.New(rand.NewSource(cfg.Seed + int64(workerID)*131 + 17))
	for {
		select {
		case <-ctx.Done():
			return
		case f, ok := <-sub:
			if !ok {
				return
			}
			simulateWork(cfg.Depth, workerID, payload, f.ID, cfg.DynamicWork)
			startTime, ok := startTimes.LoadAndDelete(f.ID)
			if !ok {
				results <- eventResult{err: errors.New("missing start timestamp")}
				continue
			}
			latency := time.Since(startTime.(time.Time))
			if cfg.FailureRate > 0 && rng.Float64() < cfg.FailureRate {
				results <- eventResult{latency: latency, err: errors.New("simulated failure")}
				continue
			}
			results <- eventResult{latency: latency}
		}
	}
}

func simulateWork(level int, workerID int, payload []byte, id string, dynamic int) {
	hasher := fnv.New64a()
	_, _ = hasher.Write(payload)
	_, _ = hasher.Write([]byte(id))
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(level+workerID))
	_, _ = hasher.Write(buf[:])
	sum := hasher.Sum64()
	workAccumulator.Add(sum)
	if dynamic > 0 {
		simulateDynamicWork(dynamic, sum)
	}
}

func simulateDynamicWork(dynamic int, seed uint64) {
	// Busy loop using a simple linear congruential generator to emulate the
	// CPU burn of dynamic JavaScript execution without relying on sleeps.
	// The accumulator prevents the compiler from optimising the loop away.
	iterations := dynamic * 256
	if iterations <= 0 {
		return
	}
	var acc uint64 = seed | 1
	for i := 0; i < iterations; i++ {
		acc = acc*6364136223846793005 + 1442695040888963407
	}
	workAccumulator.Add(acc)
}

func summariseLatencies(latencies []time.Duration, max time.Duration) LatencyMetrics {
	if len(latencies) == 0 {
		return LatencyMetrics{}
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	return LatencyMetrics{
		P50: durationToMillis(percentile(latencies, 0.50)),
		P95: durationToMillis(percentile(latencies, 0.95)),
		P99: durationToMillis(percentile(latencies, 0.99)),
		Max: durationToMillis(max),
	}
}

func percentile(values []time.Duration, p float64) time.Duration {
	if len(values) == 0 {
		return 0
	}
	if p <= 0 {
		return values[0]
	}
	if p >= 1 {
		return values[len(values)-1]
	}
	rank := p * float64(len(values)-1)
	lower := int(math.Floor(rank))
	upper := int(math.Ceil(rank))
	if lower == upper {
		return values[lower]
	}
	weight := rank - float64(lower)
	low := float64(values[lower])
	high := float64(values[upper])
	interpolated := low + (high-low)*weight
	return time.Duration(interpolated)
}

func durationToMillis(d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(d) / float64(time.Millisecond)
}

func safeDivideFloat(num, denom float64) float64 {
	if denom == 0 {
		return 0
	}
	return num / denom
}

func safeDifference(end, start float64) float64 {
	if end <= 0 {
		return 0
	}
	if start <= 0 {
		return end
	}
	if end < start {
		return 0
	}
	return end - start
}

func readCPUSeconds() float64 {
	names := []string{"/process/cpu-seconds", "/cpu/classes/total:cpu-seconds"}
	samples := make([]metrics.Sample, len(names))
	for i, name := range names {
		samples[i].Name = name
	}
	metrics.Read(samples)
	for _, sample := range samples {
		if sample.Value.Kind() != metrics.KindFloat64 {
			continue
		}
		if v := sample.Value.Float64(); v > 0 {
			return v
		}
	}
	return 0
}
