package modules

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/atlas"
)

func TestSSRFModule_CloudMetadata_AWS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Query().Get("url")
		// Simulate SSRF fetching AWS metadata
		if strings.Contains(url, "169.254.169.254") {
			w.Write([]byte("ami-id\ninstance-id\nhostname\nami-12345"))
		} else {
			w.Write([]byte("Normal response"))
		}
	}))
	defer server.Close()

	module := NewSSRFModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?url=http://example.com",
		Method:     "GET",
		Parameters: map[string]string{"url": "http://example.com"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected to detect AWS metadata SSRF")
	}

	if findings[0].Type != "Server-Side Request Forgery (Cloud Metadata)" {
		t.Errorf("expected type 'Server-Side Request Forgery (Cloud Metadata)', got '%s'", findings[0].Type)
	}

	if findings[0].Confidence != atlas.ConfidenceConfirmed {
		t.Errorf("expected confidence Confirmed, got %s", findings[0].Confidence)
	}
}

func TestSSRFModule_CloudMetadata_GCP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Query().Get("url")
		if strings.Contains(url, "metadata.google.internal") || strings.Contains(url, "computemetadata") {
			w.Write([]byte("computeMetadata instance-id hostname"))
		} else {
			w.Write([]byte("Normal response"))
		}
	}))
	defer server.Close()

	module := NewSSRFModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?url=http://example.com",
		Method:     "GET",
		Parameters: map[string]string{"url": "http://example.com"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected to detect GCP metadata SSRF")
	}
}

func TestSSRFModule_LocalFile_EtcPasswd(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Query().Get("url")
		if strings.Contains(url, "/etc/passwd") {
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"))
		} else {
			w.Write([]byte("Normal response"))
		}
	}))
	defer server.Close()

	module := NewSSRFModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?url=http://example.com",
		Method:     "GET",
		Parameters: map[string]string{"url": "http://example.com"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected to detect local file SSRF")
	}

	if findings[0].Type != "Server-Side Request Forgery (Local File)" {
		t.Errorf("expected type 'Server-Side Request Forgery (Local File)', got '%s'", findings[0].Type)
	}
}

func TestSSRFModule_LocalFile_WinIni(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Query().Get("url")
		if strings.Contains(url, "win.ini") {
			w.Write([]byte("[fonts]\n[extensions]\n[files]\n"))
		} else {
			w.Write([]byte("Normal response"))
		}
	}))
	defer server.Close()

	module := NewSSRFModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?url=http://example.com",
		Method:     "GET",
		Parameters: map[string]string{"url": "http://example.com"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected to detect Windows file SSRF")
	}
}

func TestSSRFModule_LocalFile_Environ(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Query().Get("url")
		if strings.Contains(url, "environ") {
			w.Write([]byte("PATH=/usr/bin:/bin\nHOME=/root\nUSER=root"))
		} else {
			w.Write([]byte("Normal response"))
		}
	}))
	defer server.Close()

	module := NewSSRFModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?url=http://example.com",
		Method:     "GET",
		Parameters: map[string]string{"url": "http://example.com"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected to detect environment file SSRF")
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

func (m *mockOASTClient) CheckInteractions(ctx context.Context, testID string) ([]atlas.OASTInteraction, error) {
	if m.hasInteractions {
		return []atlas.OASTInteraction{
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

func TestSSRFModule_BlindWithOAST(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Server makes request but doesn't reflect in response (blind SSRF)
		w.Write([]byte("Request processed"))
	}))
	defer server.Close()

	mockOAST := &mockOASTClient{hasInteractions: true}
	module := NewSSRFModule(atlas.NewNopLogger(), mockOAST)

	target := &atlas.ScanTarget{
		URL:        server.URL + "?url=http://example.com",
		Method:     "GET",
		Parameters: map[string]string{"url": "http://example.com"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected to detect blind SSRF via OAST")
	}

	if findings[0].Type != "Server-Side Request Forgery (Blind)" {
		t.Errorf("expected type 'Server-Side Request Forgery (Blind)', got '%s'", findings[0].Type)
	}
}

func TestSSRFModule_NoOASTInteraction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Normal response"))
	}))
	defer server.Close()

	mockOAST := &mockOASTClient{hasInteractions: false}
	module := NewSSRFModule(atlas.NewNopLogger(), mockOAST)

	target := &atlas.ScanTarget{
		URL:        server.URL + "?url=http://example.com",
		Method:     "GET",
		Parameters: map[string]string{"url": "http://example.com"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should not detect SSRF without interaction
	for _, f := range findings {
		if f.Type == "Server-Side Request Forgery (Blind)" {
			t.Error("false positive: detected blind SSRF without OAST interaction")
		}
	}
}

func TestSSRFModule_IsMetadataResponse(t *testing.T) {
	module := NewSSRFModule(atlas.NewNopLogger(), nil)

	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{
			name:     "AWS metadata",
			body:     "ami-id: ami-12345\ninstance-id: i-abcdef",
			expected: true,
		},
		{
			name:     "GCP metadata",
			body:     "computeMetadata: true\nhostname: instance-1",
			expected: true,
		},
		{
			name:     "Azure metadata",
			body:     "instanceId: vm-12345\nmeta-data: ...",
			expected: true,
		},
		{
			name:     "Normal response",
			body:     "This is a normal webpage content",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := module.isMetadataResponse(tt.body)
			if result != tt.expected {
				t.Errorf("expected %v, got %v for body: %s", tt.expected, result, tt.body)
			}
		})
	}
}

func TestSSRFModule_IsFileContent(t *testing.T) {
	module := NewSSRFModule(atlas.NewNopLogger(), nil)

	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{
			name:     "etc/passwd content",
			body:     "root:x:0:0:root:/root:/bin/bash",
			expected: true,
		},
		{
			name:     "win.ini content",
			body:     "[fonts]\n[extensions]\n[mci extensions]",
			expected: true,
		},
		{
			name:     "environ content",
			body:     "PATH=/usr/bin:/bin\nHOME=/root",
			expected: true,
		},
		{
			name:     "Normal response",
			body:     "This is a normal webpage",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := module.isFileContent(tt.body)
			if result != tt.expected {
				t.Errorf("expected %v, got %v for body: %s", tt.expected, result, tt.body)
			}
		})
	}
}

func TestSSRFModule_SupportsTarget(t *testing.T) {
	module := NewSSRFModule(atlas.NewNopLogger(), nil)

	// SSRF should support all targets
	target := &atlas.ScanTarget{
		URL:    "http://example.com",
		Method: "GET",
	}

	if !module.SupportsTarget(target) {
		t.Error("SSRF module should support all targets")
	}
}

func TestSSRFModule_ExtractParameters(t *testing.T) {
	module := NewSSRFModule(atlas.NewNopLogger(), nil)

	target := &atlas.ScanTarget{
		URL:        "http://example.com?url=http://test.com&callback=http://cb.com",
		Method:     "GET",
		Parameters: map[string]string{"redirect": "http://redir.com"},
	}

	params := module.extractParameters(target)

	if len(params) != 3 {
		t.Errorf("expected 3 parameters, got %d", len(params))
	}

	if params["url"] != "http://test.com" {
		t.Errorf("expected url=http://test.com, got %s", params["url"])
	}

	if params["callback"] != "http://cb.com" {
		t.Errorf("expected callback=http://cb.com, got %s", params["callback"])
	}

	if params["redirect"] != "http://redir.com" {
		t.Errorf("expected redirect=http://redir.com, got %s", params["redirect"])
	}
}

func TestSSRFModule_GetParamLocation(t *testing.T) {
	module := NewSSRFModule(atlas.NewNopLogger(), nil)

	tests := []struct {
		name     string
		target   *atlas.ScanTarget
		param    string
		expected atlas.ParamLocation
	}{
		{
			name: "Query parameter",
			target: &atlas.ScanTarget{
				URL:    "http://test.com?url=http://example.com",
				Method: "GET",
			},
			param:    "url",
			expected: atlas.ParamLocationQuery,
		},
		{
			name: "POST body parameter",
			target: &atlas.ScanTarget{
				URL:    "http://test.com",
				Method: "POST",
			},
			param:    "redirect",
			expected: atlas.ParamLocationBody,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := module.getParamLocation(tt.target, tt.param)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestSSRFModule_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	module := NewSSRFModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?url=http://example.com",
		Method:     "GET",
		Parameters: map[string]string{"url": "http://example.com"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	findings, err := module.Scan(ctx, target)

	if err == nil {
		t.Error("expected context cancellation error")
	}

	if len(findings) > 0 {
		t.Errorf("expected 0 findings after cancellation, got %d", len(findings))
	}
}

func TestSSRFModule_MultipleParameters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Query().Get("url")
		callback := r.URL.Query().Get("callback")

		if strings.Contains(url, "169.254.169.254") {
			w.Write([]byte("ami-id instance-id"))
		} else if strings.Contains(callback, "/etc/passwd") {
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
		} else {
			w.Write([]byte("Normal response"))
		}
	}))
	defer server.Close()

	module := NewSSRFModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?url=http://test.com&callback=http://cb.com",
		Method:     "GET",
		Parameters: map[string]string{"url": "http://test.com", "callback": "http://cb.com"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should detect SSRF in both parameters
	if len(findings) != 2 {
		t.Errorf("expected 2 findings (one per parameter), got %d", len(findings))
	}
}

func TestSSRFModule_NoFalsePositive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("This is a normal webpage with no sensitive content"))
	}))
	defer server.Close()

	module := NewSSRFModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?url=http://example.com",
		Method:     "GET",
		Parameters: map[string]string{"url": "http://example.com"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("false positive detected: got %d findings for non-vulnerable endpoint", len(findings))
	}
}

func TestSSRFModule_NoParameters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Static page"))
	}))
	defer server.Close()

	module := NewSSRFModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:    server.URL,
		Method: "GET",
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for page without parameters, got %d", len(findings))
	}
}
