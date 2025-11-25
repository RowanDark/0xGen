package oast

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/logging"
	"github.com/RowanDark/0xgen/internal/oast/local"
)

// Integration tests for end-to-end OAST functionality

func integrationLogger() *logging.AuditLogger {
	return logging.MustNewAuditLogger("oast-integration", logging.WithWriter(io.Discard))
}

func setupTestOAST(ctx context.Context, t *testing.T) *Client {
	cfg := Config{
		Mode:    ModeLocal,
		Port:    0,
		Host:    "localhost",
		Timeout: 5,
	}

	client, err := NewClient(cfg, &testEventBus{}, integrationLogger())
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Start client in background
	go func() {
		client.Start(ctx)
	}()

	// Wait for server to be ready
	time.Sleep(100 * time.Millisecond)

	return client
}

func TestOAST_EndToEnd(t *testing.T) {
	// Start OAST server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := setupTestOAST(ctx, t)

	// Generate callback
	callback, err := client.GenerateCallback(ctx, "e2e-test")
	if err != nil {
		t.Fatalf("failed to generate callback: %v", err)
	}

	// Make HTTP request to callback URL
	resp, err := http.Get(callback.URL)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// Wait briefly for processing
	time.Sleep(100 * time.Millisecond)

	// Check interaction was recorded
	interactions, err := client.CheckInteractions(ctx, callback.ID)
	if err != nil {
		t.Fatalf("failed to check interactions: %v", err)
	}

	if len(interactions) != 1 {
		t.Errorf("expected 1 interaction, got %d", len(interactions))
	}

	if len(interactions) > 0 && interactions[0].Method != "GET" {
		t.Errorf("expected method GET, got %s", interactions[0].Method)
	}
}

func TestOAST_MultipleCallbacks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := setupTestOAST(ctx, t)

	// Generate multiple callbacks
	numCallbacks := 10
	callbacks := make([]*Callback, numCallbacks)
	for i := 0; i < numCallbacks; i++ {
		cb, err := client.GenerateCallback(ctx, fmt.Sprintf("multi-test-%d", i))
		if err != nil {
			t.Fatalf("failed to generate callback %d: %v", i, err)
		}
		callbacks[i] = cb
	}

	// Make requests to all callbacks
	for _, cb := range callbacks {
		resp, err := http.Get(cb.URL)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		resp.Body.Close()
	}

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	// Verify all interactions recorded
	for i, cb := range callbacks {
		interactions, err := client.CheckInteractions(ctx, cb.ID)
		if err != nil {
			t.Fatalf("failed to check interactions for callback %d: %v", i, err)
		}
		if len(interactions) != 1 {
			t.Errorf("callback %d: expected 1 interaction, got %d", i, len(interactions))
		}
	}

	// Check stats
	stats, err := client.GetStats()
	if err != nil {
		t.Fatalf("failed to get stats: %v", err)
	}
	if stats.TotalInteractions != numCallbacks {
		t.Errorf("expected %d total interactions, got %d", numCallbacks, stats.TotalInteractions)
	}
}

func TestOAST_ConcurrentCallbacks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := setupTestOAST(ctx, t)

	// Send concurrent callbacks
	numCallbacks := 50
	var wg sync.WaitGroup

	for i := 0; i < numCallbacks; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()

			cb, err := client.GenerateCallback(ctx, fmt.Sprintf("concurrent-test-%d", n))
			if err != nil {
				t.Errorf("failed to generate callback %d: %v", n, err)
				return
			}

			resp, err := http.Get(cb.URL)
			if err != nil {
				t.Errorf("failed to make request %d: %v", n, err)
				return
			}
			resp.Body.Close()
		}(i)
	}

	wg.Wait()

	// Wait for all to process
	time.Sleep(200 * time.Millisecond)

	// Verify stats
	stats, err := client.GetStats()
	if err != nil {
		t.Fatalf("failed to get stats: %v", err)
	}
	if stats.TotalInteractions < numCallbacks {
		t.Errorf("expected at least %d total interactions, got %d", numCallbacks, stats.TotalInteractions)
	}
}

func TestOAST_DifferentHTTPMethods(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := setupTestOAST(ctx, t)

	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			cb, err := client.GenerateCallback(ctx, fmt.Sprintf("method-test-%s", method))
			if err != nil {
				t.Fatalf("failed to generate callback: %v", err)
			}

			req, err := http.NewRequest(method, cb.URL, nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("failed to make request: %v", err)
			}
			resp.Body.Close()

			// Wait for processing
			time.Sleep(50 * time.Millisecond)

			// Check interaction
			interactions, err := client.CheckInteractions(ctx, cb.ID)
			if err != nil {
				t.Fatalf("failed to check interactions: %v", err)
			}

			if len(interactions) != 1 {
				t.Fatalf("expected 1 interaction, got %d", len(interactions))
			}

			if interactions[0].Method != method {
				t.Errorf("expected method %s, got %s", method, interactions[0].Method)
			}
		})
	}
}

func TestOAST_WithHeaders(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := setupTestOAST(ctx, t)

	cb, err := client.GenerateCallback(ctx, "header-test")
	if err != nil {
		t.Fatalf("failed to generate callback: %v", err)
	}

	req, err := http.NewRequest("GET", cb.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	req.Header.Set("X-Custom-Header", "test-value")
	req.Header.Set("User-Agent", "Integration-Test/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	resp.Body.Close()

	// Wait for processing
	time.Sleep(50 * time.Millisecond)

	// Check interaction
	interactions, err := client.CheckInteractions(ctx, cb.ID)
	if err != nil {
		t.Fatalf("failed to check interactions: %v", err)
	}

	if len(interactions) != 1 {
		t.Fatalf("expected 1 interaction, got %d", len(interactions))
	}

	// Verify headers were captured
	if interactions[0].Headers == nil {
		t.Error("expected headers to be captured")
	} else {
		if _, ok := interactions[0].Headers["X-Custom-Header"]; !ok {
			t.Error("expected X-Custom-Header to be captured")
		}
	}
}

func TestOAST_WithQueryParams(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := setupTestOAST(ctx, t)

	cb, err := client.GenerateCallback(ctx, "query-test")
	if err != nil {
		t.Fatalf("failed to generate callback: %v", err)
	}

	url := cb.URL + "?param1=value1&param2=value2"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	resp.Body.Close()

	// Wait for processing
	time.Sleep(50 * time.Millisecond)

	// Check interaction
	interactions, err := client.CheckInteractions(ctx, cb.ID)
	if err != nil {
		t.Fatalf("failed to check interactions: %v", err)
	}

	if len(interactions) != 1 {
		t.Fatalf("expected 1 interaction, got %d", len(interactions))
	}

	// Verify query was captured
	if interactions[0].Query == "" {
		t.Error("expected query to be captured")
	}
}

func TestOAST_GetByTestID(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := setupTestOAST(ctx, t)

	testID := "grouped-test-123"

	// Generate multiple callbacks with same test ID
	for i := 0; i < 3; i++ {
		cb, err := client.GenerateCallback(ctx, testID)
		if err != nil {
			t.Fatalf("failed to generate callback: %v", err)
		}

		resp, err := http.Get(cb.URL)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		resp.Body.Close()
	}

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	// Get by test ID
	interactions, err := client.GetInteractionsByTestID(ctx, testID)
	if err != nil {
		t.Fatalf("failed to get by test ID: %v", err)
	}

	if len(interactions) != 3 {
		t.Errorf("expected 3 interactions, got %d", len(interactions))
	}
}

func TestOAST_WaitForInteraction(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := setupTestOAST(ctx, t)

	cb, err := client.GenerateCallback(ctx, "wait-test")
	if err != nil {
		t.Fatalf("failed to generate callback: %v", err)
	}

	// Make request in background after short delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		resp, err := http.Get(cb.URL)
		if err != nil {
			t.Errorf("background request failed: %v", err)
			return
		}
		resp.Body.Close()
	}()

	// Wait for interaction
	interaction, err := client.WaitForInteraction(ctx, cb.ID, 2*time.Second)
	if err != nil {
		t.Fatalf("failed to wait for interaction: %v", err)
	}

	if interaction == nil {
		t.Error("expected interaction, got nil")
	}

	if interaction != nil && interaction.Method != "GET" {
		t.Errorf("expected method GET, got %s", interaction.Method)
	}
}

func TestOAST_BlindVulnerabilityFlow(t *testing.T) {
	// Simulates a blind vulnerability detection flow
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := setupTestOAST(ctx, t)

	// Setup a "vulnerable" server that makes callbacks
	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate SSRF: make request to callback URL from query param
		callbackURL := r.URL.Query().Get("url")
		if callbackURL != "" {
			resp, err := http.Get(callbackURL)
			if err == nil {
				resp.Body.Close()
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer vulnServer.Close()

	// Generate callback
	cb, err := client.GenerateCallback(ctx, "ssrf-test")
	if err != nil {
		t.Fatalf("failed to generate callback: %v", err)
	}

	// Trigger the "vulnerable" endpoint
	resp, err := http.Get(vulnServer.URL + "?url=" + cb.URL)
	if err != nil {
		t.Fatalf("failed to trigger vulnerable endpoint: %v", err)
	}
	resp.Body.Close()

	// Wait for callback
	interaction, err := client.WaitForInteraction(ctx, cb.ID, 2*time.Second)
	if err != nil {
		t.Fatalf("failed to wait for interaction: %v", err)
	}

	// Vulnerability confirmed by callback
	if interaction == nil {
		t.Error("expected interaction (vulnerability confirmed), got nil")
	}
}

func TestOAST_StorageCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := setupTestOAST(ctx, t)

	// Generate and trigger callback
	cb, err := client.GenerateCallback(ctx, "cleanup-test")
	if err != nil {
		t.Fatalf("failed to generate callback: %v", err)
	}

	resp, err := http.Get(cb.URL)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	resp.Body.Close()

	// Wait for processing
	time.Sleep(50 * time.Millisecond)

	// Verify interaction exists
	interactions, err := client.CheckInteractions(ctx, cb.ID)
	if err != nil {
		t.Fatalf("failed to check interactions: %v", err)
	}
	if len(interactions) != 1 {
		t.Errorf("expected 1 interaction before cleanup, got %d", len(interactions))
	}

	// Clear the storage (remove all interactions)
	storage := client.GetStorage()
	storage.Clear()

	// Verify interactions are cleared
	interactions, err = client.CheckInteractions(ctx, cb.ID)
	if err != nil {
		t.Fatalf("failed to check interactions after clear: %v", err)
	}
	if len(interactions) != 0 {
		t.Errorf("expected 0 interactions after clear, got %d", len(interactions))
	}
}

func TestOAST_TesterIntegration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := setupTestOAST(ctx, t)
	tester := NewTester(client, integrationLogger())
	tester.SetTimeout(500 * time.Millisecond)

	// Setup a server that doesn't make callbacks (no vulnerability)
	safeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer safeServer.Close()

	req := httptest.NewRequest("GET", safeServer.URL, nil)

	// Test should return nil (no vulnerability detected)
	finding, err := tester.TestBlindSSRF(ctx, req, "tester-integration")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if finding != nil {
		t.Error("expected nil finding for non-vulnerable endpoint")
	}
}

func TestOAST_URLBuilderIntegration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := setupTestOAST(ctx, t)

	builder := client.GetURLBuilder()
	if builder == nil {
		t.Fatal("expected URL builder to be available")
	}

	// Generate URL with custom path
	result := builder.GenerateWithPath("/ssrf-test")
	if result.ID == "" {
		t.Error("expected ID to be generated")
	}
	if result.URL == "" {
		t.Error("expected URL to be generated")
	}

	// Make request using generated URL
	resp, err := http.Get(result.URL)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	resp.Body.Close()

	// Wait and check
	time.Sleep(50 * time.Millisecond)

	storage := client.GetStorage()
	interactions := storage.GetByID(result.ID)
	if len(interactions) != 1 {
		t.Errorf("expected 1 interaction, got %d", len(interactions))
	}
}

// Benchmark tests

func BenchmarkOAST_GenerateCallback(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := Config{
		Mode: ModeLocal,
		Port: 0,
		Host: "localhost",
	}
	client, _ := NewClient(cfg, &testEventBus{}, integrationLogger())
	go client.Start(ctx)
	time.Sleep(100 * time.Millisecond)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = client.GenerateCallback(ctx, "bench")
	}
}

func BenchmarkOAST_ConcurrentCallbacks(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := Config{
		Mode: ModeLocal,
		Port: 0,
		Host: "localhost",
	}
	client, _ := NewClient(cfg, &testEventBus{}, integrationLogger())
	go client.Start(ctx)
	time.Sleep(100 * time.Millisecond)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			callback, _ := client.GenerateCallback(ctx, "bench")
			resp, err := http.Get(callback.URL)
			if err == nil {
				resp.Body.Close()
			}
		}
	})
}

func BenchmarkOAST_StoreLookup(b *testing.B) {
	storage := local.NewStorage()

	// Pre-populate with interactions
	for i := 0; i < 1000; i++ {
		interaction := &local.Interaction{
			ID:        fmt.Sprintf("bench-%d", i),
			Timestamp: time.Now(),
			Method:    "GET",
			Path:      "/callback/bench",
			ClientIP:  "127.0.0.1",
		}
		storage.Store(interaction)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = storage.GetByID(fmt.Sprintf("bench-%d", i%1000))
	}
}

func TestOAST_HighLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping high load test in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := setupTestOAST(ctx, t)

	// Send 100 concurrent callbacks (reduced from 1000 for faster tests)
	numCallbacks := 100
	var wg sync.WaitGroup

	for i := 0; i < numCallbacks; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			callback, err := client.GenerateCallback(ctx, fmt.Sprintf("load-test-%d", n))
			if err != nil {
				return
			}
			resp, err := http.Get(callback.URL)
			if err == nil {
				resp.Body.Close()
			}
		}(i)
	}

	wg.Wait()

	// Wait for all to process
	time.Sleep(500 * time.Millisecond)

	// Verify all recorded
	stats, err := client.GetStats()
	if err != nil {
		t.Fatalf("failed to get stats: %v", err)
	}

	if stats.TotalInteractions < numCallbacks {
		t.Errorf("expected at least %d interactions, got %d", numCallbacks, stats.TotalInteractions)
	}
}
