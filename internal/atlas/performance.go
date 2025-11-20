package atlas

import (
	"sync"
	"sync/atomic"
	"time"
)

// PerformanceMonitor tracks performance metrics during scans.
type PerformanceMonitor struct {
	startTime time.Time

	// Counters (using atomic for lock-free increments)
	requestsSent      int64
	findingsFound     int64
	errorsEncountered int64

	// Timing (protected by mutex)
	totalRequestTime time.Duration
	minRequestTime   time.Duration
	maxRequestTime   time.Duration

	mu sync.RWMutex
}

// NewPerformanceMonitor creates a new performance monitor.
func NewPerformanceMonitor() *PerformanceMonitor {
	return &PerformanceMonitor{
		startTime:      time.Now(),
		minRequestTime: time.Hour, // Start high
	}
}

// RecordRequest records a request with its timing and results.
func (pm *PerformanceMonitor) RecordRequest(duration time.Duration, foundFindings int, err error) {
	// Update counters atomically
	atomic.AddInt64(&pm.requestsSent, 1)
	atomic.AddInt64(&pm.findingsFound, int64(foundFindings))

	if err != nil {
		atomic.AddInt64(&pm.errorsEncountered, 1)
	}

	// Update timing with lock
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.totalRequestTime += duration

	if duration < pm.minRequestTime {
		pm.minRequestTime = duration
	}
	if duration > pm.maxRequestTime {
		pm.maxRequestTime = duration
	}
}

// GetMetrics returns current performance metrics.
func (pm *PerformanceMonitor) GetMetrics() PerformanceMetrics {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Load atomic counters
	requests := atomic.LoadInt64(&pm.requestsSent)
	findings := atomic.LoadInt64(&pm.findingsFound)
	errors := atomic.LoadInt64(&pm.errorsEncountered)

	elapsed := time.Since(pm.startTime)

	var avgRequestTime time.Duration
	var requestsPerSecond float64

	if requests > 0 {
		avgRequestTime = pm.totalRequestTime / time.Duration(requests)
		requestsPerSecond = float64(requests) / elapsed.Seconds()
	}

	return PerformanceMetrics{
		TotalRequests:     requests,
		FindingsFound:     findings,
		ErrorsEncountered: errors,
		TotalDuration:     elapsed,
		AvgRequestTime:    avgRequestTime,
		MinRequestTime:    pm.minRequestTime,
		MaxRequestTime:    pm.maxRequestTime,
		RequestsPerSecond: requestsPerSecond,
	}
}

// Reset resets all performance metrics.
func (pm *PerformanceMonitor) Reset() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.startTime = time.Now()
	atomic.StoreInt64(&pm.requestsSent, 0)
	atomic.StoreInt64(&pm.findingsFound, 0)
	atomic.StoreInt64(&pm.errorsEncountered, 0)
	pm.totalRequestTime = 0
	pm.minRequestTime = time.Hour
	pm.maxRequestTime = 0
}

// PerformanceMetrics contains performance statistics.
type PerformanceMetrics struct {
	TotalRequests     int64
	FindingsFound     int64
	ErrorsEncountered int64
	TotalDuration     time.Duration
	AvgRequestTime    time.Duration
	MinRequestTime    time.Duration
	MaxRequestTime    time.Duration
	RequestsPerSecond float64
}
