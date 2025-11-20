package atlas

import (
	"context"
	"testing"
	"time"
)

func TestRateLimiter_Basic(t *testing.T) {
	rl := NewRateLimiter(10, 10, false) // 10 req/sec, burst of 10

	start := time.Now()

	// Acquire 10 tokens (should be instant - burst)
	for i := 0; i < 10; i++ {
		err := rl.Wait(context.Background(), "test.com")
		if err != nil {
			t.Fatalf("Wait failed: %v", err)
		}
	}

	burstTime := time.Since(start)
	if burstTime > 100*time.Millisecond {
		t.Errorf("Burst should be instant, took %v", burstTime)
	}

	// 11th token should wait
	start = time.Now()
	err := rl.Wait(context.Background(), "test.com")
	if err != nil {
		t.Fatalf("Wait failed: %v", err)
	}

	waitTime := time.Since(start)
	if waitTime < 50*time.Millisecond {
		t.Errorf("Should have waited for token refill, only waited %v", waitTime)
	}
}

func TestRateLimiter_PerHostLimiting(t *testing.T) {
	rl := NewRateLimiter(20, 10, false) // 20 req/sec global, 10 per host

	// Exhaust burst for host1
	for i := 0; i < 10; i++ {
		err := rl.Wait(context.Background(), "host1.com")
		if err != nil {
			t.Fatalf("Wait failed: %v", err)
		}
	}

	// host1 should now be rate limited
	start := time.Now()
	err := rl.Wait(context.Background(), "host1.com")
	if err != nil {
		t.Fatalf("Wait failed: %v", err)
	}
	waitTime := time.Since(start)

	if waitTime < 50*time.Millisecond {
		t.Errorf("host1 should be rate limited, only waited %v", waitTime)
	}

	// host2 should still have burst available
	start = time.Now()
	err = rl.Wait(context.Background(), "host2.com")
	if err != nil {
		t.Fatalf("Wait failed: %v", err)
	}
	burstTime := time.Since(start)

	if burstTime > 50*time.Millisecond {
		t.Errorf("host2 should have burst available, took %v", burstTime)
	}
}

func TestRateLimiter_Adaptive(t *testing.T) {
	rl := NewRateLimiter(100, 10, true)

	initialRate := rl.GetCurrentRate()
	if initialRate != 100 {
		t.Errorf("Initial rate should be 100, got %d", initialRate)
	}

	// Simulate rate limit errors
	for i := 0; i < 5; i++ {
		rl.RecordError(429)
	}

	reducedRate := rl.GetCurrentRate()
	if reducedRate >= initialRate {
		t.Errorf("Rate should be reduced after 429 errors, got %d", reducedRate)
	}

	// Simulate successful requests
	for i := 0; i < 100; i++ {
		rl.RecordSuccess()
	}

	increasedRate := rl.GetCurrentRate()
	if increasedRate <= reducedRate {
		t.Errorf("Rate should increase after successes, got %d", increasedRate)
	}
}

func TestRateLimiter_AdaptiveRateLimitDetection(t *testing.T) {
	rl := NewRateLimiter(50, 10, true)

	// Test different rate limit status codes
	testCases := []int{429, 503, 509}

	for _, statusCode := range testCases {
		initialRate := rl.GetCurrentRate()
		rl.RecordError(statusCode)
		newRate := rl.GetCurrentRate()

		if newRate >= initialRate {
			t.Errorf("Status %d should reduce rate, initial=%d, new=%d",
				statusCode, initialRate, newRate)
		}
	}

	// Non-rate-limit errors shouldn't affect rate
	currentRate := rl.GetCurrentRate()
	rl.RecordError(500)
	afterErrorRate := rl.GetCurrentRate()

	if afterErrorRate != currentRate {
		t.Errorf("500 error shouldn't change rate, before=%d, after=%d",
			currentRate, afterErrorRate)
	}
}

func TestRateLimiter_GetStats(t *testing.T) {
	rl := NewRateLimiter(10, 5, true)

	// Initial stats
	stats := rl.GetStats()
	if stats.CurrentRate != 10 {
		t.Errorf("Initial rate should be 10, got %d", stats.CurrentRate)
	}
	if stats.SuccessCount != 0 {
		t.Errorf("Initial success count should be 0, got %d", stats.SuccessCount)
	}
	if stats.ErrorCount != 0 {
		t.Errorf("Initial error count should be 0, got %d", stats.ErrorCount)
	}

	// Record some activity
	rl.RecordSuccess()
	rl.RecordSuccess()
	rl.RecordError(429)

	// Use different hosts to track
	rl.Wait(context.Background(), "host1.com")
	rl.Wait(context.Background(), "host2.com")

	stats = rl.GetStats()
	if stats.SuccessCount != 2 {
		t.Errorf("Success count should be 2, got %d", stats.SuccessCount)
	}
	if stats.ErrorCount != 1 {
		t.Errorf("Error count should be 1, got %d", stats.ErrorCount)
	}
	if stats.ActiveHosts != 2 {
		t.Errorf("Active hosts should be 2, got %d", stats.ActiveHosts)
	}
}

func TestRateLimiter_ContextCancellation(t *testing.T) {
	rl := NewRateLimiter(1, 1, false) // Very slow rate

	// Exhaust token
	rl.Wait(context.Background(), "test.com")

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Should return immediately with error
	err := rl.Wait(ctx, "test.com")
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled, got %v", err)
	}
}

func TestRateLimiter_ContextTimeout(t *testing.T) {
	rl := NewRateLimiter(1, 1, false)

	// Exhaust token
	rl.Wait(context.Background(), "test.com")

	// Create context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Should timeout
	err := rl.Wait(ctx, "test.com")
	if err != context.DeadlineExceeded {
		t.Errorf("Expected context.DeadlineExceeded, got %v", err)
	}
}

func TestRateLimiter_MaxRate(t *testing.T) {
	rl := NewRateLimiter(10, 5, true)

	// Try to increase rate beyond max (200)
	for i := 0; i < 2000; i++ {
		rl.RecordSuccess()
	}

	finalRate := rl.GetCurrentRate()
	if finalRate > 200 {
		t.Errorf("Rate should be capped at 200, got %d", finalRate)
	}
}

func TestRateLimiter_MinRate(t *testing.T) {
	rl := NewRateLimiter(10, 5, true)

	// Try to reduce rate to zero with many errors
	for i := 0; i < 20; i++ {
		rl.RecordError(429)
	}

	finalRate := rl.GetCurrentRate()
	if finalRate < 1 {
		t.Errorf("Rate should be at least 1, got %d", finalRate)
	}
}

func BenchmarkRateLimiter_Wait(b *testing.B) {
	rl := NewRateLimiter(10000, 100, false) // High rate for benchmarking

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.Wait(context.Background(), "test.com")
	}
}

func BenchmarkRateLimiter_MultiHost(b *testing.B) {
	rl := NewRateLimiter(10000, 100, false)

	hosts := []string{"host1.com", "host2.com", "host3.com", "host4.com"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		host := hosts[i%len(hosts)]
		rl.Wait(context.Background(), host)
	}
}
