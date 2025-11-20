package atlas

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestPerformanceMonitor_RecordRequest(t *testing.T) {
	pm := NewPerformanceMonitor()

	// Record a successful request
	pm.RecordRequest(100*time.Millisecond, 2, nil)

	metrics := pm.GetMetrics()

	if metrics.TotalRequests != 1 {
		t.Errorf("Expected 1 request, got %d", metrics.TotalRequests)
	}

	if metrics.FindingsFound != 2 {
		t.Errorf("Expected 2 findings, got %d", metrics.FindingsFound)
	}

	if metrics.ErrorsEncountered != 0 {
		t.Errorf("Expected 0 errors, got %d", metrics.ErrorsEncountered)
	}

	if metrics.AvgRequestTime != 100*time.Millisecond {
		t.Errorf("Expected avg 100ms, got %v", metrics.AvgRequestTime)
	}

	if metrics.MinRequestTime != 100*time.Millisecond {
		t.Errorf("Expected min 100ms, got %v", metrics.MinRequestTime)
	}

	if metrics.MaxRequestTime != 100*time.Millisecond {
		t.Errorf("Expected max 100ms, got %v", metrics.MaxRequestTime)
	}
}

func TestPerformanceMonitor_MultipleRequests(t *testing.T) {
	pm := NewPerformanceMonitor()

	// Record multiple requests with different timings
	pm.RecordRequest(50*time.Millisecond, 1, nil)
	pm.RecordRequest(100*time.Millisecond, 2, nil)
	pm.RecordRequest(200*time.Millisecond, 0, nil)

	metrics := pm.GetMetrics()

	if metrics.TotalRequests != 3 {
		t.Errorf("Expected 3 requests, got %d", metrics.TotalRequests)
	}

	if metrics.FindingsFound != 3 {
		t.Errorf("Expected 3 findings total, got %d", metrics.FindingsFound)
	}

	// Average should be (50 + 100 + 200) / 3 = 116.666ms
	expectedAvg := 116 * time.Millisecond
	if metrics.AvgRequestTime < expectedAvg || metrics.AvgRequestTime > expectedAvg+20*time.Millisecond {
		t.Errorf("Expected avg ~116ms, got %v", metrics.AvgRequestTime)
	}

	if metrics.MinRequestTime != 50*time.Millisecond {
		t.Errorf("Expected min 50ms, got %v", metrics.MinRequestTime)
	}

	if metrics.MaxRequestTime != 200*time.Millisecond {
		t.Errorf("Expected max 200ms, got %v", metrics.MaxRequestTime)
	}
}

func TestPerformanceMonitor_ErrorTracking(t *testing.T) {
	pm := NewPerformanceMonitor()

	// Record requests with errors
	pm.RecordRequest(100*time.Millisecond, 1, nil)
	pm.RecordRequest(100*time.Millisecond, 0, fmt.Errorf("scan failed"))
	pm.RecordRequest(100*time.Millisecond, 0, fmt.Errorf("scan failed"))

	metrics := pm.GetMetrics()

	if metrics.TotalRequests != 3 {
		t.Errorf("Expected 3 requests, got %d", metrics.TotalRequests)
	}

	if metrics.ErrorsEncountered != 2 {
		t.Errorf("Expected 2 errors, got %d", metrics.ErrorsEncountered)
	}
}

func TestPerformanceMonitor_RequestsPerSecond(t *testing.T) {
	pm := NewPerformanceMonitor()

	// Record some requests
	for i := 0; i < 10; i++ {
		pm.RecordRequest(10*time.Millisecond, 0, nil)
	}

	// Wait a bit to get meaningful RPS
	time.Sleep(100 * time.Millisecond)

	metrics := pm.GetMetrics()

	if metrics.RequestsPerSecond <= 0 {
		t.Error("RequestsPerSecond should be positive")
	}

	// Should be roughly 10 requests / 0.1 seconds = 100 RPS
	// Allow wide range due to timing variations
	if metrics.RequestsPerSecond < 50 || metrics.RequestsPerSecond > 200 {
		t.Errorf("Expected RPS ~100, got %.2f", metrics.RequestsPerSecond)
	}
}

func TestPerformanceMonitor_Reset(t *testing.T) {
	pm := NewPerformanceMonitor()

	// Record some data
	pm.RecordRequest(100*time.Millisecond, 5, nil)
	pm.RecordRequest(200*time.Millisecond, 3, fmt.Errorf("scan failed"))

	// Verify data exists
	metrics := pm.GetMetrics()
	if metrics.TotalRequests != 2 {
		t.Errorf("Expected 2 requests before reset, got %d", metrics.TotalRequests)
	}

	// Reset
	pm.Reset()

	// Verify data cleared
	metrics = pm.GetMetrics()
	if metrics.TotalRequests != 0 {
		t.Errorf("Expected 0 requests after reset, got %d", metrics.TotalRequests)
	}

	if metrics.FindingsFound != 0 {
		t.Errorf("Expected 0 findings after reset, got %d", metrics.FindingsFound)
	}

	if metrics.ErrorsEncountered != 0 {
		t.Errorf("Expected 0 errors after reset, got %d", metrics.ErrorsEncountered)
	}

	if metrics.TotalDuration < 0 {
		t.Errorf("Duration should be >= 0 after reset, got %v", metrics.TotalDuration)
	}
}

func TestPerformanceMonitor_ConcurrentAccess(t *testing.T) {
	pm := NewPerformanceMonitor()

	var wg sync.WaitGroup
	workerCount := 10
	requestsPerWorker := 100

	// Spawn concurrent workers
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < requestsPerWorker; j++ {
				pm.RecordRequest(10*time.Millisecond, 1, nil)
			}
		}()
	}

	wg.Wait()

	metrics := pm.GetMetrics()

	expectedRequests := int64(workerCount * requestsPerWorker)
	if metrics.TotalRequests != expectedRequests {
		t.Errorf("Expected %d requests, got %d", expectedRequests, metrics.TotalRequests)
	}

	if metrics.FindingsFound != expectedRequests {
		t.Errorf("Expected %d findings, got %d", expectedRequests, metrics.FindingsFound)
	}
}

func TestPerformanceMonitor_TimingAccuracy(t *testing.T) {
	pm := NewPerformanceMonitor()

	durations := []time.Duration{
		10 * time.Millisecond,
		50 * time.Millisecond,
		100 * time.Millisecond,
		200 * time.Millisecond,
		500 * time.Millisecond,
	}

	for _, duration := range durations {
		pm.RecordRequest(duration, 0, nil)
	}

	metrics := pm.GetMetrics()

	if metrics.MinRequestTime != 10*time.Millisecond {
		t.Errorf("Expected min 10ms, got %v", metrics.MinRequestTime)
	}

	if metrics.MaxRequestTime != 500*time.Millisecond {
		t.Errorf("Expected max 500ms, got %v", metrics.MaxRequestTime)
	}

	// Average: (10 + 50 + 100 + 200 + 500) / 5 = 172ms
	expectedAvg := 172 * time.Millisecond
	if metrics.AvgRequestTime != expectedAvg {
		t.Errorf("Expected avg 172ms, got %v", metrics.AvgRequestTime)
	}
}

func TestPerformanceMonitor_ZeroRequests(t *testing.T) {
	pm := NewPerformanceMonitor()

	metrics := pm.GetMetrics()

	if metrics.TotalRequests != 0 {
		t.Errorf("Expected 0 requests, got %d", metrics.TotalRequests)
	}

	if metrics.AvgRequestTime != 0 {
		t.Errorf("Expected avg 0, got %v", metrics.AvgRequestTime)
	}

	if metrics.RequestsPerSecond != 0 {
		t.Errorf("Expected 0 RPS, got %.2f", metrics.RequestsPerSecond)
	}
}

func TestPerformanceMonitor_TotalDuration(t *testing.T) {
	pm := NewPerformanceMonitor()

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	metrics := pm.GetMetrics()

	if metrics.TotalDuration < 100*time.Millisecond {
		t.Errorf("Total duration should be >= 100ms, got %v", metrics.TotalDuration)
	}

	if metrics.TotalDuration > 200*time.Millisecond {
		t.Errorf("Total duration should be < 200ms, got %v", metrics.TotalDuration)
	}
}

func BenchmarkPerformanceMonitor_RecordRequest(b *testing.B) {
	pm := NewPerformanceMonitor()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pm.RecordRequest(10*time.Millisecond, 1, nil)
	}
}

func BenchmarkPerformanceMonitor_GetMetrics(b *testing.B) {
	pm := NewPerformanceMonitor()

	// Record some data
	for i := 0; i < 1000; i++ {
		pm.RecordRequest(10*time.Millisecond, 1, nil)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pm.GetMetrics()
	}
}

func BenchmarkPerformanceMonitor_Concurrent(b *testing.B) {
	pm := NewPerformanceMonitor()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pm.RecordRequest(10*time.Millisecond, 1, nil)
		}
	})
}
