package atlas

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestWorkerPool_Basic(t *testing.T) {
	config := ScanConfig{
		Timeout:   10 * time.Second,
		VerifySSL: false,
	}

	rl := NewRateLimiter(1000, 100, false)
	logger := &testLogger{}
	requester := NewRequester(config, rl, logger)

	pool := NewWorkerPool(5, requester)
	pool.Start()
	defer pool.Stop()

	module := &testModule{
		findings: []*Finding{
			{Type: "Test Finding"},
		},
	}

	// Submit job
	err := pool.Submit(Job{
		ID:     "job-1",
		Target: &ScanTarget{URL: "http://test.com"},
		Module: module,
	})

	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	// Get result
	select {
	case result := <-pool.Results():
		if result.JobID != "job-1" {
			t.Errorf("Expected job-1, got %s", result.JobID)
		}
		if result.Error != nil {
			t.Errorf("Unexpected error: %v", result.Error)
		}
		if len(result.Findings) != 1 {
			t.Errorf("Expected 1 finding, got %d", len(result.Findings))
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for result")
	}
}

func TestWorkerPool_MultipleJobs(t *testing.T) {
	config := ScanConfig{
		Timeout:   10 * time.Second,
		VerifySSL: false,
	}

	rl := NewRateLimiter(1000, 100, false)
	logger := &testLogger{}
	requester := NewRequester(config, rl, logger)

	pool := NewWorkerPool(3, requester)
	pool.Start()
	defer pool.Stop()

	module := &testModule{
		findings: []*Finding{
			{Type: "Test Finding"},
		},
	}

	jobCount := 10

	// Submit multiple jobs
	for i := 0; i < jobCount; i++ {
		err := pool.Submit(Job{
			ID:     fmt.Sprintf("job-%d", i),
			Target: &ScanTarget{URL: "http://test.com"},
			Module: module,
		})
		if err != nil {
			t.Fatalf("Submit failed: %v", err)
		}
	}

	// Collect results
	results := make(map[string]bool)
	for i := 0; i < jobCount; i++ {
		select {
		case result := <-pool.Results():
			results[result.JobID] = true
			if result.Error != nil {
				t.Errorf("Job %s failed: %v", result.JobID, result.Error)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("Timeout waiting for result %d", i)
		}
	}

	if len(results) != jobCount {
		t.Errorf("Expected %d results, got %d", jobCount, len(results))
	}
}

func TestWorkerPool_ModuleError(t *testing.T) {
	config := ScanConfig{
		Timeout:   10 * time.Second,
		VerifySSL: false,
	}

	rl := NewRateLimiter(1000, 100, false)
	logger := &testLogger{}
	requester := NewRequester(config, rl, logger)

	pool := NewWorkerPool(2, requester)
	pool.Start()
	defer pool.Stop()

	module := &testModule{
		err: fmt.Errorf("scan failed"),
	}

	err := pool.Submit(Job{
		ID:     "job-error",
		Target: &ScanTarget{URL: "http://test.com"},
		Module: module,
	})

	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	select {
	case result := <-pool.Results():
		if result.Error == nil {
			t.Error("Expected error from module")
		}
		if result.Error.Error() != "scan failed" {
			t.Errorf("Expected 'scan failed', got: %v", result.Error)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for result")
	}
}

func TestWorkerPool_Cancel(t *testing.T) {
	config := ScanConfig{
		Timeout:   10 * time.Second,
		VerifySSL: false,
	}

	rl := NewRateLimiter(1000, 100, false)
	logger := &testLogger{}
	requester := NewRequester(config, rl, logger)

	pool := NewWorkerPool(2, requester)
	pool.Start()

	module := &testModule{
		delay: 100 * time.Millisecond,
		findings: []*Finding{
			{Type: "Test Finding"},
		},
	}

	// Submit jobs
	for i := 0; i < 5; i++ {
		pool.Submit(Job{
			ID:     fmt.Sprintf("job-%d", i),
			Target: &ScanTarget{URL: "http://test.com"},
			Module: module,
		})
	}

	// Cancel immediately
	pool.Cancel()

	// Should not hang
	time.Sleep(200 * time.Millisecond)
}

func TestWorkerPool_Stop(t *testing.T) {
	config := ScanConfig{
		Timeout:   10 * time.Second,
		VerifySSL: false,
	}

	rl := NewRateLimiter(1000, 100, false)
	logger := &testLogger{}
	requester := NewRequester(config, rl, logger)

	pool := NewWorkerPool(2, requester)
	pool.Start()

	module := &testModule{
		findings: []*Finding{
			{Type: "Test Finding"},
		},
	}

	// Submit a few jobs
	for i := 0; i < 3; i++ {
		pool.Submit(Job{
			ID:     fmt.Sprintf("job-%d", i),
			Target: &ScanTarget{URL: "http://test.com"},
			Module: module,
		})
	}

	// Drain results
	for i := 0; i < 3; i++ {
		<-pool.Results()
	}

	// Stop should complete gracefully
	pool.Stop()

	// Results channel should be closed
	_, ok := <-pool.Results()
	if ok {
		t.Error("Results channel should be closed after Stop")
	}
}

func TestWorkerPool_Concurrency(t *testing.T) {
	config := ScanConfig{
		Timeout:   10 * time.Second,
		VerifySSL: false,
	}

	rl := NewRateLimiter(1000, 100, false)
	logger := &testLogger{}
	requester := NewRequester(config, rl, logger)

	workerCount := 5
	pool := NewWorkerPool(workerCount, requester)
	pool.Start()
	defer pool.Stop()

	var concurrentCount int32
	var maxConcurrent int32

	module := &mockConcurrentModule{
		concurrentCount: &concurrentCount,
		maxConcurrent:   &maxConcurrent,
		delay:           50 * time.Millisecond,
	}

	jobCount := 20

	// Submit jobs
	for i := 0; i < jobCount; i++ {
		pool.Submit(Job{
			ID:     fmt.Sprintf("job-%d", i),
			Target: &ScanTarget{URL: "http://test.com"},
			Module: module,
		})
	}

	// Collect results
	for i := 0; i < jobCount; i++ {
		<-pool.Results()
	}

	// Check that we achieved expected concurrency
	max := atomic.LoadInt32(&maxConcurrent)
	if max < int32(workerCount) {
		t.Errorf("Expected max concurrency >= %d, got %d", workerCount, max)
	}
}

func BenchmarkWorkerPool(b *testing.B) {
	config := ScanConfig{
		Timeout:   10 * time.Second,
		VerifySSL: false,
	}

	rl := NewRateLimiter(10000, 1000, false)
	logger := &testLogger{}
	requester := NewRequester(config, rl, logger)

	pool := NewWorkerPool(10, requester)
	pool.Start()
	defer pool.Stop()

	module := &testModule{
		findings: []*Finding{
			{Type: "Test Finding"},
		},
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pool.Submit(Job{
			ID:     fmt.Sprintf("job-%d", i),
			Target: &ScanTarget{URL: "http://test.com"},
			Module: module,
		})
	}

	// Drain results
	for i := 0; i < b.N; i++ {
		<-pool.Results()
	}
}

// testModule implements Module interface for testing
type testModule struct {
	findings []*Finding
	err      error
	delay    time.Duration
}

func (m *testModule) Name() string {
	return "test"
}

func (m *testModule) Description() string {
	return "Test module for worker pool"
}

func (m *testModule) Scan(ctx context.Context, target *ScanTarget) ([]*Finding, error) {
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if m.err != nil {
		return nil, m.err
	}

	return m.findings, nil
}

func (m *testModule) SupportsTarget(target *ScanTarget) bool {
	return true
}

// mockConcurrentModule tracks concurrent executions
type mockConcurrentModule struct {
	concurrentCount *int32
	maxConcurrent   *int32
	delay           time.Duration
}

func (m *mockConcurrentModule) Name() string {
	return "concurrent-mock"
}

func (m *mockConcurrentModule) Description() string {
	return "Mock module for testing concurrency"
}

func (m *mockConcurrentModule) Scan(ctx context.Context, target *ScanTarget) ([]*Finding, error) {
	current := atomic.AddInt32(m.concurrentCount, 1)
	defer atomic.AddInt32(m.concurrentCount, -1)

	// Update max
	for {
		max := atomic.LoadInt32(m.maxConcurrent)
		if current <= max {
			break
		}
		if atomic.CompareAndSwapInt32(m.maxConcurrent, max, current) {
			break
		}
	}

	select {
	case <-time.After(m.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	return []*Finding{{Type: "Test"}}, nil
}

func (m *mockConcurrentModule) SupportsTarget(target *ScanTarget) bool {
	return true
}
