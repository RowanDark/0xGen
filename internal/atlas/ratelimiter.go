package atlas

import (
	"context"
	"sync"
	"time"
)

// RateLimiter implements token bucket rate limiting with adaptive capabilities.
type RateLimiter struct {
	// Token bucket algorithm
	rate       int       // Requests per second
	burst      int       // Max burst size
	tokens     float64   // Current token count
	lastRefill time.Time
	mu         sync.Mutex

	// Per-host rate limiting
	hostLimiters map[string]*hostLimiter
	hostMu       sync.RWMutex

	// Adaptive rate limiting
	adaptive     bool
	errorCount   int
	successCount int
	adaptMu      sync.RWMutex
}

type hostLimiter struct {
	tokens     float64
	lastRefill time.Time
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(rate, burst int, adaptive bool) *RateLimiter {
	return &RateLimiter{
		rate:         rate,
		burst:        burst,
		tokens:       float64(burst),
		lastRefill:   time.Now(),
		adaptive:     adaptive,
		hostLimiters: make(map[string]*hostLimiter),
	}
}

// Wait blocks until a token is available.
func (rl *RateLimiter) Wait(ctx context.Context, host string) error {
	for {
		if rl.tryAcquire(host) {
			return nil
		}

		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
			// Try again
		}
	}
}

func (rl *RateLimiter) tryAcquire(host string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Refill tokens based on time elapsed
	now := time.Now()
	elapsed := now.Sub(rl.lastRefill)
	rl.tokens += elapsed.Seconds() * float64(rl.rate)

	// Cap at burst size
	if rl.tokens > float64(rl.burst) {
		rl.tokens = float64(rl.burst)
	}

	rl.lastRefill = now

	// Check if token available
	if rl.tokens >= 1.0 {
		rl.tokens -= 1.0

		// Also check per-host limit
		if !rl.tryAcquireHost(host) {
			// Return token if host limit reached
			rl.tokens += 1.0
			return false
		}

		return true
	}

	return false
}

func (rl *RateLimiter) tryAcquireHost(host string) bool {
	rl.hostMu.Lock()
	defer rl.hostMu.Unlock()

	limiter, exists := rl.hostLimiters[host]
	if !exists {
		limiter = &hostLimiter{
			tokens:     float64(rl.burst),
			lastRefill: time.Now(),
		}
		rl.hostLimiters[host] = limiter
	}

	// Refill host tokens (half the global rate per host)
	now := time.Now()
	elapsed := now.Sub(limiter.lastRefill)
	limiter.tokens += elapsed.Seconds() * float64(rl.rate/2)

	if limiter.tokens > float64(rl.burst) {
		limiter.tokens = float64(rl.burst)
	}

	limiter.lastRefill = now

	if limiter.tokens >= 1.0 {
		limiter.tokens -= 1.0
		return true
	}

	return false
}

// RecordSuccess updates adaptive rate limiter on successful request.
func (rl *RateLimiter) RecordSuccess() {
	if !rl.adaptive {
		return
	}

	rl.adaptMu.Lock()
	defer rl.adaptMu.Unlock()

	rl.successCount++

	// Every 100 successful requests, try increasing rate
	if rl.successCount%100 == 0 {
		rl.mu.Lock()
		if rl.rate < 200 { // Max 200 req/sec
			rl.rate += 10
		}
		rl.mu.Unlock()
	}
}

// RecordError updates adaptive rate limiter on failed request.
func (rl *RateLimiter) RecordError(statusCode int) {
	if !rl.adaptive {
		return
	}

	// Certain status codes indicate rate limiting
	isRateLimit := statusCode == 429 || // Too Many Requests
		statusCode == 503 || // Service Unavailable
		statusCode == 509 // Bandwidth Limit Exceeded

	if !isRateLimit {
		return
	}

	rl.adaptMu.Lock()
	defer rl.adaptMu.Unlock()

	rl.errorCount++

	// On rate limit error, reduce rate immediately
	rl.mu.Lock()
	rl.rate = int(float64(rl.rate) * 0.5) // Reduce by 50%
	if rl.rate < 1 {
		rl.rate = 1 // Minimum 1 req/sec
	}
	rl.mu.Unlock()
}

// GetCurrentRate returns the current rate limit.
func (rl *RateLimiter) GetCurrentRate() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.rate
}

// GetStats returns rate limiter statistics.
func (rl *RateLimiter) GetStats() RateLimiterStats {
	rl.adaptMu.RLock()
	defer rl.adaptMu.RUnlock()

	rl.hostMu.RLock()
	activeHosts := len(rl.hostLimiters)
	rl.hostMu.RUnlock()

	return RateLimiterStats{
		CurrentRate:  rl.GetCurrentRate(),
		SuccessCount: rl.successCount,
		ErrorCount:   rl.errorCount,
		ActiveHosts:  activeHosts,
	}
}

// RateLimiterStats contains rate limiter statistics.
type RateLimiterStats struct {
	CurrentRate  int
	SuccessCount int
	ErrorCount   int
	ActiveHosts  int
}
