package atlas

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// Requester handles HTTP requests with connection pooling and rate limiting.
type Requester struct {
	client      *http.Client
	rateLimiter *RateLimiter
	logger      Logger

	// Statistics
	requestCount  int
	errorCount    int
	totalDuration time.Duration
	mu            sync.RWMutex
}

// NewRequester creates a new HTTP requester.
func NewRequester(config ScanConfig, rateLimiter *RateLimiter, logger Logger) *Requester {
	// Custom transport for connection pooling
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,

		// Connection pooling
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,

		// TLS config
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !config.VerifySSL,
		},

		// Timeouts
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !config.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	return &Requester{
		client:      client,
		rateLimiter: rateLimiter,
		logger:      logger,
	}
}

// Send sends HTTP request with rate limiting and retries.
func (r *Requester) Send(ctx context.Context, req *http.Request) (*http.Response, error) {
	// Extract host for per-host rate limiting
	host := req.URL.Hostname()

	// Wait for rate limiter
	if err := r.rateLimiter.Wait(ctx, host); err != nil {
		return nil, fmt.Errorf("rate limit wait: %w", err)
	}

	// Send request with timing
	start := time.Now()
	resp, err := r.client.Do(req.WithContext(ctx))
	duration := time.Since(start)

	// Update statistics
	r.mu.Lock()
	r.requestCount++
	r.totalDuration += duration
	if err != nil {
		r.errorCount++
	}
	r.mu.Unlock()

	// Update rate limiter
	if err != nil {
		r.rateLimiter.RecordError(0)
		return nil, err
	}

	// Record rate limiting status codes
	if resp.StatusCode == 429 || resp.StatusCode == 503 || resp.StatusCode == 509 || resp.StatusCode >= 500 {
		r.rateLimiter.RecordError(resp.StatusCode)
	} else {
		r.rateLimiter.RecordSuccess()
	}

	return resp, nil
}

// SendWithRetry sends request with automatic retry on transient errors.
func (r *Requester) SendWithRetry(ctx context.Context, req *http.Request, maxRetries int) (*http.Response, error) {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		resp, err := r.Send(ctx, req)
		if err == nil {
			// Success
			if resp.StatusCode < 500 {
				return resp, nil
			}

			// 5xx error - might be transient
			lastErr = fmt.Errorf("server error: %d", resp.StatusCode)
			resp.Body.Close()
			continue
		}

		// Check if error is retryable
		if !isRetryableError(err) {
			return nil, err
		}

		lastErr = err
	}

	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

func isRetryableError(err error) bool {
	// Network errors are retryable
	if netErr, ok := err.(net.Error); ok {
		return netErr.Temporary() || netErr.Timeout()
	}
	return false
}

// GetStats returns request statistics.
func (r *Requester) GetStats() RequesterStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var avgDuration time.Duration
	var errorRate float64
	if r.requestCount > 0 {
		avgDuration = r.totalDuration / time.Duration(r.requestCount)
		errorRate = float64(r.errorCount) / float64(r.requestCount)
	}

	return RequesterStats{
		TotalRequests:   r.requestCount,
		ErrorCount:      r.errorCount,
		AverageDuration: avgDuration,
		ErrorRate:       errorRate,
	}
}

// RequesterStats contains request statistics.
type RequesterStats struct {
	TotalRequests   int
	ErrorCount      int
	AverageDuration time.Duration
	ErrorRate       float64
}
