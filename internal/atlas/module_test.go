package atlas

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDefaultModuleConfig(t *testing.T) {
	config := DefaultModuleConfig()

	if config.Intensity != 3 {
		t.Errorf("expected default intensity 3, got %d", config.Intensity)
	}

	if config.Timeout != 10*time.Second {
		t.Errorf("expected default timeout 10s, got %v", config.Timeout)
	}

	if !config.EnableOAST {
		t.Error("expected EnableOAST to be true by default")
	}

	if config.CustomPayloads != nil {
		t.Error("expected CustomPayloads to be nil by default")
	}
}

func TestNewBaseModule(t *testing.T) {
	logger := NewNopLogger()
	base := NewBaseModule("test", "Test Module", "injection", SeverityHigh, logger, nil)

	if base.Name() != "test" {
		t.Errorf("expected name 'test', got '%s'", base.Name())
	}

	if base.Description() != "Test Module" {
		t.Errorf("expected description 'Test Module', got '%s'", base.Description())
	}

	if base.Category() != "injection" {
		t.Errorf("expected category 'injection', got '%s'", base.Category())
	}

	if base.severity != SeverityHigh {
		t.Errorf("expected severity High, got %s", base.severity)
	}

	if base.httpClient == nil {
		t.Fatal("expected httpClient to be initialized")
	}

	if base.httpClient.Timeout != 10*time.Second {
		t.Errorf("expected default httpClient timeout 10s, got %v", base.httpClient.Timeout)
	}

	if base.config.Intensity != 3 {
		t.Errorf("expected default config intensity 3, got %d", base.config.Intensity)
	}
}

func TestBaseModule_Configure(t *testing.T) {
	logger := NewNopLogger()
	base := NewBaseModule("test", "Test Module", "injection", SeverityHigh, logger, nil)

	customConfig := ModuleConfig{
		Intensity:      5,
		Timeout:        30 * time.Second,
		CustomPayloads: []string{"payload1", "payload2"},
		EnableOAST:     false,
	}

	err := base.Configure(customConfig)
	if err != nil {
		t.Fatalf("Configure failed: %v", err)
	}

	if base.config.Intensity != 5 {
		t.Errorf("expected intensity 5, got %d", base.config.Intensity)
	}

	if base.config.Timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", base.config.Timeout)
	}

	if base.httpClient.Timeout != 30*time.Second {
		t.Errorf("expected httpClient timeout updated to 30s, got %v", base.httpClient.Timeout)
	}

	if base.config.EnableOAST {
		t.Error("expected EnableOAST to be false")
	}

	if len(base.config.CustomPayloads) != 2 {
		t.Errorf("expected 2 custom payloads, got %d", len(base.config.CustomPayloads))
	}
}

func TestBaseModule_OASTClient(t *testing.T) {
	logger := NewNopLogger()
	mockOAST := &mockOASTClient{hasInteractions: true}
	base := NewBaseModule("test", "Test Module", "injection", SeverityHigh, logger, mockOAST)

	client := base.OASTClient()
	if client == nil {
		t.Fatal("expected OAST client to be returned")
	}

	if client != mockOAST {
		t.Error("expected same OAST client instance")
	}
}

func TestBaseModule_SendRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello World"))
	}))
	defer server.Close()

	logger := NewNopLogger()
	base := NewBaseModule("test", "Test Module", "injection", SeverityHigh, logger, nil)

	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := base.SendRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("SendRequest failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, err := base.ReadBody(resp)
	if err != nil {
		t.Fatalf("ReadBody failed: %v", err)
	}

	if body != "Hello World" {
		t.Errorf("expected body 'Hello World', got '%s'", body)
	}
}

func TestBaseModule_SendRequest_WithContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	logger := NewNopLogger()
	base := NewBaseModule("test", "Test Module", "injection", SeverityHigh, logger, nil)

	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = base.SendRequest(ctx, req)
	if err == nil {
		t.Error("expected timeout error")
	}
}

func TestBaseModule_SendRequest_InvalidURL(t *testing.T) {
	logger := NewNopLogger()
	base := NewBaseModule("test", "Test Module", "injection", SeverityHigh, logger, nil)

	req, err := http.NewRequest("GET", "http://localhost:99999", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	_, err = base.SendRequest(context.Background(), req)
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestBaseModule_ReadBody(t *testing.T) {
	testBody := "This is test response body"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(testBody))
	}))
	defer server.Close()

	logger := NewNopLogger()
	base := NewBaseModule("test", "Test Module", "injection", SeverityHigh, logger, nil)

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := base.SendRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("SendRequest failed: %v", err)
	}

	body, err := base.ReadBody(resp)
	if err != nil {
		t.Fatalf("ReadBody failed: %v", err)
	}

	if body != testBody {
		t.Errorf("expected body '%s', got '%s'", testBody, body)
	}
}

func TestBaseModule_ReadBody_SizeLimit(t *testing.T) {
	// Create a large response (2MB, but limit is 1MB)
	largeBody := strings.Repeat("X", 2*1024*1024)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(largeBody))
	}))
	defer server.Close()

	logger := NewNopLogger()
	base := NewBaseModule("test", "Test Module", "injection", SeverityHigh, logger, nil)

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := base.SendRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("SendRequest failed: %v", err)
	}

	body, err := base.ReadBody(resp)
	if err != nil {
		t.Fatalf("ReadBody failed: %v", err)
	}

	// Should be limited to 1MB
	if len(body) != 1024*1024 {
		t.Errorf("expected body size 1MB, got %d bytes", len(body))
	}
}

func TestBaseModule_CreateFinding(t *testing.T) {
	logger := NewNopLogger()
	base := NewBaseModule("test-module", "Test Module", "injection", SeverityHigh, logger, nil)

	target := &ScanTarget{
		URL:    "http://example.com/test",
		Method: "GET",
	}

	evidence := Evidence{
		Parameter: "id",
		Location:  ParamLocationQuery,
		Request:   "GET http://example.com/test?id=1",
		Response:  "Error: SQL syntax",
		Payload:   "1' OR '1'='1",
		Proof:     "SQL error detected",
	}

	finding := base.CreateFinding(target, "SQL Injection", ConfidenceConfirmed, evidence)

	if finding.Type != "SQL Injection" {
		t.Errorf("expected type 'SQL Injection', got '%s'", finding.Type)
	}

	if finding.Severity != SeverityHigh {
		t.Errorf("expected severity High, got %s", finding.Severity)
	}

	if finding.Confidence != ConfidenceConfirmed {
		t.Errorf("expected confidence Confirmed, got %s", finding.Confidence)
	}

	if finding.URL != "http://example.com/test" {
		t.Errorf("expected URL 'http://example.com/test', got '%s'", finding.URL)
	}

	if finding.Method != "GET" {
		t.Errorf("expected method 'GET', got '%s'", finding.Method)
	}

	if finding.Parameter != "id" {
		t.Errorf("expected parameter 'id', got '%s'", finding.Parameter)
	}

	if finding.Location != ParamLocationQuery {
		t.Errorf("expected location Query, got %s", finding.Location)
	}

	if finding.Payload != "1' OR '1'='1" {
		t.Errorf("expected payload \"1' OR '1'='1\", got '%s'", finding.Payload)
	}

	if finding.Proof != "SQL error detected" {
		t.Errorf("expected proof 'SQL error detected', got '%s'", finding.Proof)
	}

	if finding.DetectedBy != "test-module" {
		t.Errorf("expected DetectedBy 'test-module', got '%s'", finding.DetectedBy)
	}

	if !strings.Contains(finding.Title, "SQL Injection") {
		t.Errorf("expected title to contain 'SQL Injection', got '%s'", finding.Title)
	}

	if !strings.Contains(finding.Description, "SQL Injection") {
		t.Errorf("expected description to contain 'SQL Injection', got '%s'", finding.Description)
	}

	if finding.ID == "" {
		t.Error("expected finding ID to be set")
	}
}

func TestGenerateFindingID(t *testing.T) {
	id1 := GenerateFindingID()
	time.Sleep(1 * time.Millisecond)
	id2 := GenerateFindingID()

	if id1 == "" {
		t.Error("expected non-empty finding ID")
	}

	if id2 == "" {
		t.Error("expected non-empty finding ID")
	}

	if id1 == id2 {
		t.Error("expected unique finding IDs")
	}

	if !strings.HasPrefix(id1, "finding-") {
		t.Errorf("expected ID to start with 'finding-', got '%s'", id1)
	}
}

func TestFormatRequest(t *testing.T) {
	tests := []struct {
		name     string
		req      *http.Request
		expected string
	}{
		{
			name:     "GET request",
			req:      httptest.NewRequest("GET", "http://example.com/api", nil),
			expected: "GET http://example.com/api",
		},
		{
			name:     "POST request with path",
			req:      httptest.NewRequest("POST", "http://example.com/api/users", nil),
			expected: "POST http://example.com/api/users",
		},
		{
			name:     "Request with query string",
			req:      httptest.NewRequest("GET", "http://example.com/api?id=1&name=test", nil),
			expected: "GET http://example.com/api?id=1&name=test",
		},
		{
			name:     "Nil request",
			req:      nil,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatRequest(tt.req)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestTruncateBody(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		maxLen   int
		expected string
	}{
		{
			name:     "Short body - no truncation",
			body:     "Hello World",
			maxLen:   100,
			expected: "Hello World",
		},
		{
			name:     "Exact length - no truncation",
			body:     "Hello",
			maxLen:   5,
			expected: "Hello",
		},
		{
			name:     "Long body - truncated",
			body:     "This is a very long response body that should be truncated",
			maxLen:   20,
			expected: "This is a very long ... (truncated)",
		},
		{
			name:     "Empty body",
			body:     "",
			maxLen:   100,
			expected: "",
		},
		{
			name:     "Single character over limit",
			body:     "Hello World",
			maxLen:   10,
			expected: "Hello Worl... (truncated)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TruncateBody(tt.body, tt.maxLen)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestBaseModule_RedirectHandling(t *testing.T) {
	redirectCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectCount++
		if redirectCount <= 11 {
			http.Redirect(w, r, "/redirect", http.StatusFound)
		} else {
			w.Write([]byte("Final destination"))
		}
	}))
	defer server.Close()

	logger := NewNopLogger()
	base := NewBaseModule("test", "Test Module", "injection", SeverityHigh, logger, nil)

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := base.SendRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("SendRequest failed: %v", err)
	}

	// Should stop following redirects after 10
	if redirectCount > 11 {
		t.Errorf("expected max 11 redirects, got %d", redirectCount)
	}

	if resp.StatusCode != http.StatusFound {
		t.Logf("Status code: %d (redirect limit reached)", resp.StatusCode)
	}
}

// Mock OAST client for testing
type mockOASTClient struct {
	hasInteractions bool
	payload         string
}

func (m *mockOASTClient) GeneratePayload(ctx context.Context, testID string) (string, error) {
	m.payload = fmt.Sprintf("%s.oast.test", testID)
	return m.payload, nil
}

func (m *mockOASTClient) CheckInteractions(ctx context.Context, testID string) ([]OASTInteraction, error) {
	if m.hasInteractions {
		return []OASTInteraction{
			{
				ID:        testID,
				TestID:    testID,
				Type:      "http",
				Timestamp: time.Now(),
			},
		}, nil
	}
	return nil, nil
}

func TestBaseModule_ReadBody_Error(t *testing.T) {
	// Create a response with a body that will error on read
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(&errorReader{}),
	}

	logger := NewNopLogger()
	base := NewBaseModule("test", "Test Module", "injection", SeverityHigh, logger, nil)

	_, err := base.ReadBody(resp)
	if err == nil {
		t.Error("expected error reading body")
	}
}

// errorReader always returns an error
type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, fmt.Errorf("simulated read error")
}
