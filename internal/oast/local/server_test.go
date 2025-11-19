package local

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/logging"
)

// testLogger creates an audit logger suitable for testing
func testLogger() *logging.AuditLogger {
	return logging.MustNewAuditLogger("oast-test", logging.WithWriter(io.Discard))
}

// mockEventBus is a test implementation of EventBus
type mockEventBus struct {
	mu     sync.Mutex
	events []struct {
		Type string
		Data interface{}
	}
}

func (m *mockEventBus) Publish(eventType string, data interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, struct {
		Type string
		Data interface{}
	}{eventType, data})
}

func (m *mockEventBus) GetEvents() []struct {
	Type string
	Data interface{}
} {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]struct {
		Type string
		Data interface{}
	}, len(m.events))
	copy(result, m.events)
	return result
}

// setupTestServer creates a test server with proper configuration
func setupTestServer(t *testing.T) (*Server, context.CancelFunc) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	eventBus := &mockEventBus{}
	logger := testLogger()

	server := New(Config{Port: 0}, eventBus, logger)

	// Start server in background
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start(ctx)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Return cleanup function
	cleanup := func() {
		cancel()
		select {
		case err := <-errChan:
			if err != nil {
				t.Errorf("server error: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("server did not shut down in time")
		}
	}

	return server, cleanup
}

func TestServer_Start(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eventBus := &mockEventBus{}
	logger := testLogger()

	server := New(Config{Port: 0}, eventBus, logger)

	// Start server in background
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start(ctx)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Verify port was assigned
	if server.GetPort() == 0 {
		t.Fatal("expected non-zero port")
	}

	// Test health check
	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/health", server.GetPort()))
	if err != nil {
		t.Fatalf("health check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %d", resp.StatusCode)
	}

	// Verify response body
	var health map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatalf("failed to decode health response: %v", err)
	}

	if health["status"] != "ok" {
		t.Errorf("expected status ok, got %v", health["status"])
	}

	// Stop server
	cancel()

	// Wait for server to shut down
	select {
	case err := <-errChan:
		if err != nil {
			t.Errorf("server error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shut down in time")
	}
}

func TestServer_Callback(t *testing.T) {
	t.Parallel()

	server, cleanup := setupTestServer(t)
	defer cleanup()

	// Send callback
	callbackID := "test123"
	body := strings.NewReader("test payload")
	resp, err := http.Post(
		fmt.Sprintf("http://localhost:%d/callback/%s", server.GetPort(), callbackID),
		"application/json",
		body,
	)
	if err != nil {
		t.Fatalf("callback request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %d", resp.StatusCode)
	}

	// Check X-OAST-ID header
	if got := resp.Header.Get("X-OAST-ID"); got != callbackID {
		t.Errorf("expected X-OAST-ID %s, got %s", callbackID, got)
	}

	// Verify interaction stored
	interactions := server.storage.GetByID(callbackID)
	if len(interactions) != 1 {
		t.Fatalf("expected 1 interaction, got %d", len(interactions))
	}

	interaction := interactions[0]
	if interaction.ID != callbackID {
		t.Errorf("expected ID %s, got %s", callbackID, interaction.ID)
	}
	if interaction.Method != "POST" {
		t.Errorf("expected method POST, got %s", interaction.Method)
	}
	if interaction.Body != "test payload" {
		t.Errorf("expected body 'test payload', got %s", interaction.Body)
	}
	if interaction.Type != "http" {
		t.Errorf("expected type http, got %s", interaction.Type)
	}
}

func TestServer_CallbackWithExtraPath(t *testing.T) {
	t.Parallel()

	server, cleanup := setupTestServer(t)
	defer cleanup()

	callbackID := "abc123"
	resp, err := http.Get(
		fmt.Sprintf("http://localhost:%d/callback/%s/extra/path", server.GetPort(), callbackID),
	)
	if err != nil {
		t.Fatalf("callback request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %d", resp.StatusCode)
	}

	// Verify interaction stored with correct ID
	interactions := server.storage.GetByID(callbackID)
	if len(interactions) != 1 {
		t.Fatalf("expected 1 interaction, got %d", len(interactions))
	}

	if interactions[0].Path != "/callback/abc123/extra/path" {
		t.Errorf("expected full path stored, got %s", interactions[0].Path)
	}
}

func TestServer_CallbackMissingID(t *testing.T) {
	t.Parallel()

	server, cleanup := setupTestServer(t)
	defer cleanup()

	resp, err := http.Get(
		fmt.Sprintf("http://localhost:%d/callback/", server.GetPort()),
	)
	if err != nil {
		t.Fatalf("callback request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status BadRequest, got %d", resp.StatusCode)
	}
}

func TestServer_CallbackWithHeaders(t *testing.T) {
	t.Parallel()

	server, cleanup := setupTestServer(t)
	defer cleanup()

	callbackID := "headers-test"
	req, err := http.NewRequest("GET",
		fmt.Sprintf("http://localhost:%d/callback/%s", server.GetPort(), callbackID),
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	req.Header.Set("X-Custom-Header", "custom-value")
	req.Header.Set("User-Agent", "test-agent/1.0")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("callback request failed: %v", err)
	}
	defer resp.Body.Close()

	interactions := server.storage.GetByID(callbackID)
	if len(interactions) != 1 {
		t.Fatalf("expected 1 interaction, got %d", len(interactions))
	}

	interaction := interactions[0]

	// Check headers are stored
	if got := interaction.Headers["X-Custom-Header"]; len(got) == 0 || got[0] != "custom-value" {
		t.Errorf("expected X-Custom-Header to be 'custom-value', got %v", got)
	}

	if interaction.UserAgent != "test-agent/1.0" {
		t.Errorf("expected UserAgent 'test-agent/1.0', got %s", interaction.UserAgent)
	}
}

func TestServer_CallbackWithQuery(t *testing.T) {
	t.Parallel()

	server, cleanup := setupTestServer(t)
	defer cleanup()

	callbackID := "query-test"
	resp, err := http.Get(
		fmt.Sprintf("http://localhost:%d/callback/%s?foo=bar&baz=qux", server.GetPort(), callbackID),
	)
	if err != nil {
		t.Fatalf("callback request failed: %v", err)
	}
	defer resp.Body.Close()

	interactions := server.storage.GetByID(callbackID)
	if len(interactions) != 1 {
		t.Fatalf("expected 1 interaction, got %d", len(interactions))
	}

	if interactions[0].Query != "foo=bar&baz=qux" {
		t.Errorf("expected query 'foo=bar&baz=qux', got %s", interactions[0].Query)
	}
}

func TestServer_AdminInteractions(t *testing.T) {
	t.Parallel()

	server, cleanup := setupTestServer(t)
	defer cleanup()

	// First create some interactions
	callbackID := "admin-test"
	for i := 0; i < 3; i++ {
		resp, err := http.Post(
			fmt.Sprintf("http://localhost:%d/callback/%s", server.GetPort(), callbackID),
			"text/plain",
			strings.NewReader(fmt.Sprintf("payload-%d", i)),
		)
		if err != nil {
			t.Fatalf("callback request %d failed: %v", i, err)
		}
		resp.Body.Close()
	}

	// Query admin endpoint
	resp, err := http.Get(
		fmt.Sprintf("http://localhost:%d/admin/interactions?id=%s", server.GetPort(), callbackID),
	)
	if err != nil {
		t.Fatalf("admin request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result["id"] != callbackID {
		t.Errorf("expected id %s, got %v", callbackID, result["id"])
	}

	if count := result["count"].(float64); count != 3 {
		t.Errorf("expected count 3, got %v", count)
	}

	interactions := result["interactions"].([]interface{})
	if len(interactions) != 3 {
		t.Errorf("expected 3 interactions, got %d", len(interactions))
	}
}

func TestServer_AdminInteractionsMissingID(t *testing.T) {
	t.Parallel()

	server, cleanup := setupTestServer(t)
	defer cleanup()

	resp, err := http.Get(
		fmt.Sprintf("http://localhost:%d/admin/interactions", server.GetPort()),
	)
	if err != nil {
		t.Fatalf("admin request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status BadRequest, got %d", resp.StatusCode)
	}
}

func TestServer_HealthDuringShutdown(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	eventBus := &mockEventBus{}
	logger := testLogger()

	server := New(Config{Port: 0}, eventBus, logger)

	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	// Mark server as shutting down
	server.mu.Lock()
	server.shuttingDown = true
	server.mu.Unlock()

	// Health check should return 503
	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/health", server.GetPort()))
	if err != nil {
		t.Fatalf("health check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected status ServiceUnavailable, got %d", resp.StatusCode)
	}

	cancel()
	<-errChan
}

func TestServer_GetBaseURL(t *testing.T) {
	t.Parallel()

	eventBus := &mockEventBus{}
	logger := testLogger()

	server := New(Config{Port: 8080, Host: "127.0.0.1", BasePath: "/oast"}, eventBus, logger)

	expected := "http://127.0.0.1:8080/oast"
	if got := server.GetBaseURL(); got != expected {
		t.Errorf("expected %s, got %s", expected, got)
	}
}

func TestServer_ConfigDefaults(t *testing.T) {
	t.Parallel()

	eventBus := &mockEventBus{}
	logger := testLogger()

	server := New(Config{}, eventBus, logger)

	if server.host != "localhost" {
		t.Errorf("expected default host 'localhost', got %s", server.host)
	}

	if server.basePath != "/callback" {
		t.Errorf("expected default basePath '/callback', got %s", server.basePath)
	}

	// Port should be assigned a free port (non-zero)
	if server.port == 0 {
		t.Error("expected non-zero port")
	}
}

func TestServer_EventBusPublish(t *testing.T) {
	t.Parallel()

	server, cleanup := setupTestServer(t)
	defer cleanup()

	callbackID := "event-test"
	resp, err := http.Post(
		fmt.Sprintf("http://localhost:%d/callback/%s", server.GetPort(), callbackID),
		"text/plain",
		strings.NewReader("event payload"),
	)
	if err != nil {
		t.Fatalf("callback request failed: %v", err)
	}
	resp.Body.Close()

	// Get the event bus and check events
	eventBus := server.eventBus.(*mockEventBus)
	events := eventBus.GetEvents()

	// Should have at least one oast.interaction event
	found := false
	for _, event := range events {
		if event.Type == "oast.interaction" {
			found = true
			interaction := event.Data.(*Interaction)
			if interaction.ID != callbackID {
				t.Errorf("expected event ID %s, got %s", callbackID, interaction.ID)
			}
			break
		}
	}

	if !found {
		t.Error("expected oast.interaction event to be published")
	}
}

func TestServer_LargeBody(t *testing.T) {
	t.Parallel()

	server, cleanup := setupTestServer(t)
	defer cleanup()

	// Create a body larger than 1MB
	largeBody := strings.Repeat("x", 2*1024*1024)

	callbackID := "large-body-test"
	resp, err := http.Post(
		fmt.Sprintf("http://localhost:%d/callback/%s", server.GetPort(), callbackID),
		"text/plain",
		strings.NewReader(largeBody),
	)
	if err != nil {
		t.Fatalf("callback request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %d", resp.StatusCode)
	}

	// Verify body was truncated to 1MB
	interactions := server.storage.GetByID(callbackID)
	if len(interactions) != 1 {
		t.Fatalf("expected 1 interaction, got %d", len(interactions))
	}

	if len(interactions[0].Body) != 1024*1024 {
		t.Errorf("expected body to be truncated to 1MB, got %d bytes", len(interactions[0].Body))
	}
}

func TestServer_MultipleCallbacksSameID(t *testing.T) {
	t.Parallel()

	server, cleanup := setupTestServer(t)
	defer cleanup()

	callbackID := "multi-test"
	for i := 0; i < 5; i++ {
		resp, err := http.Post(
			fmt.Sprintf("http://localhost:%d/callback/%s", server.GetPort(), callbackID),
			"text/plain",
			strings.NewReader(fmt.Sprintf("payload-%d", i)),
		)
		if err != nil {
			t.Fatalf("callback request %d failed: %v", i, err)
		}
		resp.Body.Close()
	}

	interactions := server.storage.GetByID(callbackID)
	if len(interactions) != 5 {
		t.Errorf("expected 5 interactions, got %d", len(interactions))
	}

	// Verify each payload
	for i, interaction := range interactions {
		expected := fmt.Sprintf("payload-%d", i)
		if interaction.Body != expected {
			t.Errorf("interaction %d: expected body %s, got %s", i, expected, interaction.Body)
		}
	}
}

func TestExtractIDFromPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path     string
		basePath string
		expected string
	}{
		{"/callback/abc123", "/callback", "abc123"},
		{"/callback/abc123/", "/callback", "abc123"},
		{"/callback/abc123/extra/path", "/callback", "abc123"},
		{"/callback/", "/callback", ""},
		{"/callback", "/callback", ""},
		{"/other/abc123", "/callback", ""},
		{"/oast/abc123", "/oast", "abc123"},
		{"/oast/test-id-123/foo/bar", "/oast", "test-id-123"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := extractIDFromPath(tt.path, tt.basePath)
			if result != tt.expected {
				t.Errorf("extractIDFromPath(%q, %q) = %q, expected %q",
					tt.path, tt.basePath, result, tt.expected)
			}
		})
	}
}

func TestExtractClientIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		expected   string
	}{
		{
			name:       "RemoteAddr only",
			remoteAddr: "192.168.1.1:12345",
			expected:   "192.168.1.1",
		},
		{
			name:       "X-Forwarded-For single",
			remoteAddr: "127.0.0.1:12345",
			headers:    map[string]string{"X-Forwarded-For": "10.0.0.1"},
			expected:   "10.0.0.1",
		},
		{
			name:       "X-Forwarded-For multiple",
			remoteAddr: "127.0.0.1:12345",
			headers:    map[string]string{"X-Forwarded-For": "10.0.0.1, 10.0.0.2, 10.0.0.3"},
			expected:   "10.0.0.1",
		},
		{
			name:       "X-Real-IP",
			remoteAddr: "127.0.0.1:12345",
			headers:    map[string]string{"X-Real-IP": "172.16.0.1"},
			expected:   "172.16.0.1",
		},
		{
			name:       "X-Forwarded-For takes precedence",
			remoteAddr: "127.0.0.1:12345",
			headers: map[string]string{
				"X-Forwarded-For": "10.0.0.1",
				"X-Real-IP":       "172.16.0.1",
			},
			expected: "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://localhost/test", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			result := extractClientIP(req)
			if result != tt.expected {
				t.Errorf("extractClientIP() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestStorage_Basic(t *testing.T) {
	t.Parallel()

	storage := NewStorage()

	// Store interaction
	interaction := &Interaction{
		ID:        "test-id",
		Type:      "http",
		Timestamp: time.Now(),
		Method:    "GET",
		Path:      "/test",
	}

	if err := storage.Store(interaction); err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	// Retrieve by ID
	retrieved := storage.GetByID("test-id")
	if len(retrieved) != 1 {
		t.Fatalf("expected 1 interaction, got %d", len(retrieved))
	}

	if retrieved[0].ID != "test-id" {
		t.Errorf("expected ID 'test-id', got %s", retrieved[0].ID)
	}

	// Get all
	all := storage.GetAll()
	if len(all) != 1 {
		t.Errorf("expected 1 interaction in GetAll, got %d", len(all))
	}

	// Get count
	if storage.GetCount() != 1 {
		t.Errorf("expected count 1, got %d", storage.GetCount())
	}
}

func TestStorage_MultipleIDs(t *testing.T) {
	t.Parallel()

	storage := NewStorage()

	// Store interactions with different IDs
	for i := 0; i < 10; i++ {
		storage.Store(&Interaction{
			ID:        fmt.Sprintf("id-%d", i%3), // 3 unique IDs
			Type:      "http",
			Timestamp: time.Now(),
		})
	}

	// Check counts
	if storage.GetCount() != 10 {
		t.Errorf("expected total count 10, got %d", storage.GetCount())
	}

	if storage.GetCountByID("id-0") != 4 {
		t.Errorf("expected count for id-0: 4, got %d", storage.GetCountByID("id-0"))
	}

	if storage.GetCountByID("id-1") != 3 {
		t.Errorf("expected count for id-1: 3, got %d", storage.GetCountByID("id-1"))
	}

	if storage.GetCountByID("id-2") != 3 {
		t.Errorf("expected count for id-2: 3, got %d", storage.GetCountByID("id-2"))
	}
}

func TestStorage_Clear(t *testing.T) {
	t.Parallel()

	storage := NewStorage()

	for i := 0; i < 5; i++ {
		storage.Store(&Interaction{ID: "test", Type: "http", Timestamp: time.Now()})
	}

	if storage.GetCount() != 5 {
		t.Errorf("expected count 5, got %d", storage.GetCount())
	}

	storage.Clear()

	if storage.GetCount() != 0 {
		t.Errorf("expected count 0 after clear, got %d", storage.GetCount())
	}
}

func TestStorage_DeleteByID(t *testing.T) {
	t.Parallel()

	storage := NewStorage()

	storage.Store(&Interaction{ID: "keep", Type: "http", Timestamp: time.Now()})
	storage.Store(&Interaction{ID: "delete", Type: "http", Timestamp: time.Now()})
	storage.Store(&Interaction{ID: "delete", Type: "http", Timestamp: time.Now()})
	storage.Store(&Interaction{ID: "keep", Type: "http", Timestamp: time.Now()})

	deleted := storage.DeleteByID("delete")
	if deleted != 2 {
		t.Errorf("expected 2 deleted, got %d", deleted)
	}

	if storage.GetCount() != 2 {
		t.Errorf("expected count 2, got %d", storage.GetCount())
	}

	if storage.HasInteraction("delete") {
		t.Error("expected 'delete' ID to be removed")
	}

	if !storage.HasInteraction("keep") {
		t.Error("expected 'keep' ID to still exist")
	}
}

func TestStorage_GetSince(t *testing.T) {
	t.Parallel()

	storage := NewStorage()

	now := time.Now()

	storage.Store(&Interaction{ID: "old", Type: "http", Timestamp: now.Add(-time.Hour)})
	storage.Store(&Interaction{ID: "new", Type: "http", Timestamp: now.Add(time.Hour)})
	storage.Store(&Interaction{ID: "newer", Type: "http", Timestamp: now.Add(2 * time.Hour)})

	since := storage.GetSince(now)
	if len(since) != 2 {
		t.Errorf("expected 2 interactions since now, got %d", len(since))
	}
}

func TestStorage_GetIDs(t *testing.T) {
	t.Parallel()

	storage := NewStorage()

	storage.Store(&Interaction{ID: "id-a", Type: "http", Timestamp: time.Now()})
	storage.Store(&Interaction{ID: "id-b", Type: "http", Timestamp: time.Now()})
	storage.Store(&Interaction{ID: "id-a", Type: "http", Timestamp: time.Now()})

	ids := storage.GetIDs()
	if len(ids) != 2 {
		t.Errorf("expected 2 unique IDs, got %d", len(ids))
	}

	// Check both IDs are present
	idSet := make(map[string]bool)
	for _, id := range ids {
		idSet[id] = true
	}

	if !idSet["id-a"] || !idSet["id-b"] {
		t.Error("expected both id-a and id-b to be in the result")
	}
}

func TestStorage_Concurrency(t *testing.T) {
	t.Parallel()

	storage := NewStorage()
	var wg sync.WaitGroup

	// Concurrent writes
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			storage.Store(&Interaction{
				ID:        fmt.Sprintf("id-%d", idx%10),
				Type:      "http",
				Timestamp: time.Now(),
			})
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			storage.GetByID(fmt.Sprintf("id-%d", idx%10))
			storage.GetAll()
			storage.GetCount()
		}(i)
	}

	wg.Wait()

	if storage.GetCount() != 100 {
		t.Errorf("expected count 100, got %d", storage.GetCount())
	}
}

func TestServer_NilEventBus(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := testLogger()

	// Server with nil event bus should not panic
	server := New(Config{Port: 0}, nil, logger)

	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	// Send callback - should not panic
	resp, err := http.Post(
		fmt.Sprintf("http://localhost:%d/callback/test", server.GetPort()),
		"text/plain",
		strings.NewReader("test"),
	)
	if err != nil {
		t.Fatalf("callback request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %d", resp.StatusCode)
	}

	cancel()
	<-errChan
}

func TestServer_DifferentHTTPMethods(t *testing.T) {
	t.Parallel()

	server, cleanup := setupTestServer(t)
	defer cleanup()

	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			callbackID := fmt.Sprintf("method-%s", method)
			req, err := http.NewRequest(method,
				fmt.Sprintf("http://localhost:%d/callback/%s", server.GetPort(), callbackID),
				nil,
			)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("expected status OK, got %d", resp.StatusCode)
			}

			interactions := server.storage.GetByID(callbackID)
			if len(interactions) != 1 {
				t.Fatalf("expected 1 interaction, got %d", len(interactions))
			}

			if interactions[0].Method != method {
				t.Errorf("expected method %s, got %s", method, interactions[0].Method)
			}
		})
	}
}

func TestServer_ResponseBody(t *testing.T) {
	t.Parallel()

	server, cleanup := setupTestServer(t)
	defer cleanup()

	resp, err := http.Get(
		fmt.Sprintf("http://localhost:%d/callback/test-response", server.GetPort()),
	)
	if err != nil {
		t.Fatalf("callback request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	expected := "Interaction logged"
	if string(body) != expected {
		t.Errorf("expected body %q, got %q", expected, string(body))
	}

	if ct := resp.Header.Get("Content-Type"); ct != "text/plain" {
		t.Errorf("expected Content-Type text/plain, got %s", ct)
	}
}
