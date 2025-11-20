package atlas

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRequester_Send(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	}))
	defer server.Close()

	config := ScanConfig{
		Timeout:         10 * time.Second,
		FollowRedirects: true,
		VerifySSL:       false,
	}

	rl := NewRateLimiter(100, 10, false)
	logger := &testLogger{}
	requester := NewRequester(config, rl, logger)

	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := requester.Send(context.Background(), req)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "test response" {
		t.Errorf("Unexpected response body: %s", body)
	}

	// Check stats
	stats := requester.GetStats()
	if stats.TotalRequests != 1 {
		t.Errorf("Expected 1 request, got %d", stats.TotalRequests)
	}
}

func TestRequester_SendWithRateLimit(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := ScanConfig{
		Timeout:   10 * time.Second,
		VerifySSL: false,
	}

	// Very low rate limit
	rl := NewRateLimiter(5, 5, false)
	logger := &testLogger{}
	requester := NewRequester(config, rl, logger)

	start := time.Now()

	// Send 10 requests
	for i := 0; i < 10; i++ {
		req, _ := http.NewRequest("GET", server.URL, nil)
		resp, err := requester.Send(context.Background(), req)
		if err != nil {
			t.Fatalf("Send failed: %v", err)
		}
		resp.Body.Close()
	}

	elapsed := time.Since(start)

	// First 5 should be instant (burst), next 5 should be rate limited
	// Should take at least 1 second for next 5 requests at 5 req/sec
	if elapsed < 500*time.Millisecond {
		t.Errorf("Rate limiting should have delayed requests, took %v", elapsed)
	}

	if callCount != 10 {
		t.Errorf("Expected 10 calls to server, got %d", callCount)
	}
}

func TestRequester_SendWithRetry_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := ScanConfig{
		Timeout:   10 * time.Second,
		VerifySSL: false,
	}

	rl := NewRateLimiter(100, 10, false)
	logger := &testLogger{}
	requester := NewRequester(config, rl, logger)

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := requester.SendWithRetry(context.Background(), req, 3)
	if err != nil {
		t.Fatalf("SendWithRetry failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestRequester_SendWithRetry_ServerError(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	config := ScanConfig{
		Timeout:   10 * time.Second,
		VerifySSL: false,
	}

	rl := NewRateLimiter(100, 10, false)
	logger := &testLogger{}
	requester := NewRequester(config, rl, logger)

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := requester.SendWithRetry(context.Background(), req, 3)
	if err != nil {
		t.Fatalf("SendWithRetry failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 after retries, got %d", resp.StatusCode)
	}

	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}
}

func TestRequester_SendWithRetry_MaxRetriesExceeded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	config := ScanConfig{
		Timeout:   10 * time.Second,
		VerifySSL: false,
	}

	rl := NewRateLimiter(100, 10, false)
	logger := &testLogger{}
	requester := NewRequester(config, rl, logger)

	req, _ := http.NewRequest("GET", server.URL, nil)
	_, err := requester.SendWithRetry(context.Background(), req, 2)
	if err == nil {
		t.Error("Expected error after max retries, got nil")
	}

	if !strings.Contains(err.Error(), "max retries exceeded") {
		t.Errorf("Expected 'max retries exceeded' error, got: %v", err)
	}
}

func TestRequester_FollowRedirects(t *testing.T) {
	finalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("final"))
	}))
	defer finalServer.Close()

	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, finalServer.URL, http.StatusFound)
	}))
	defer redirectServer.Close()

	// Test with FollowRedirects = true
	config := ScanConfig{
		Timeout:         10 * time.Second,
		FollowRedirects: true,
		VerifySSL:       false,
	}

	rl := NewRateLimiter(100, 10, false)
	logger := &testLogger{}
	requester := NewRequester(config, rl, logger)

	req, _ := http.NewRequest("GET", redirectServer.URL, nil)
	resp, err := requester.Send(context.Background(), req)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "final" {
		t.Errorf("Should have followed redirect, got: %s", body)
	}

	// Test with FollowRedirects = false
	config.FollowRedirects = false
	requester = NewRequester(config, rl, logger)

	req, _ = http.NewRequest("GET", redirectServer.URL, nil)
	resp, err = requester.Send(context.Background(), req)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("Should not follow redirect, got status %d", resp.StatusCode)
	}
}

func TestRequester_GetStats(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := ScanConfig{
		Timeout:   10 * time.Second,
		VerifySSL: false,
	}

	rl := NewRateLimiter(100, 10, false)
	logger := &testLogger{}
	requester := NewRequester(config, rl, logger)

	// Initial stats
	stats := requester.GetStats()
	if stats.TotalRequests != 0 {
		t.Errorf("Initial requests should be 0, got %d", stats.TotalRequests)
	}

	// Send some requests
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest("GET", server.URL, nil)
		resp, _ := requester.Send(context.Background(), req)
		resp.Body.Close()
	}

	stats = requester.GetStats()
	if stats.TotalRequests != 5 {
		t.Errorf("Expected 5 requests, got %d", stats.TotalRequests)
	}

	if stats.AverageDuration == 0 {
		t.Error("Average duration should be non-zero")
	}

	if stats.ErrorRate != 0 {
		t.Errorf("Error rate should be 0, got %.2f", stats.ErrorRate)
	}
}

func TestRequester_AdaptiveRateLimiting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	config := ScanConfig{
		Timeout:   10 * time.Second,
		VerifySSL: false,
	}

	rl := NewRateLimiter(100, 10, true) // Adaptive
	logger := &testLogger{}
	requester := NewRequester(config, rl, logger)

	initialRate := rl.GetCurrentRate()

	// Send request that returns 429
	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, _ := requester.Send(context.Background(), req)
	resp.Body.Close()

	reducedRate := rl.GetCurrentRate()
	if reducedRate >= initialRate {
		t.Errorf("Rate should be reduced after 429, initial=%d, reduced=%d",
			initialRate, reducedRate)
	}
}

func TestRequester_ContextCancellation(t *testing.T) {
	// Server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := ScanConfig{
		Timeout:   10 * time.Second,
		VerifySSL: false,
	}

	rl := NewRateLimiter(100, 10, false)
	logger := &testLogger{}
	requester := NewRequester(config, rl, logger)

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	req, _ := http.NewRequest("GET", server.URL, nil)
	_, err := requester.Send(ctx, req)

	if err == nil {
		t.Error("Expected error due to cancelled context")
	}
}

// testLogger implements Logger interface for testing
type testLogger struct{}

func (l *testLogger) Debug(msg string, args ...interface{}) {}
func (l *testLogger) Info(msg string, args ...interface{})  {}
func (l *testLogger) Warn(msg string, args ...interface{})  {}
func (l *testLogger) Error(msg string, args ...interface{}) {}
