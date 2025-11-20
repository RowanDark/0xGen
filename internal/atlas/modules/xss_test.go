package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/RowanDark/0xgen/internal/atlas"
)

func TestXSSModule_Reflected(t *testing.T) {
	// Setup vulnerable test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Search: " + query + "</body></html>"))
	}))
	defer server.Close()

	module := NewXSSModule(atlas.NewNopLogger(), nil)

	target := &atlas.ScanTarget{
		URL:        server.URL + "?q=test",
		Method:     "GET",
		Parameters: map[string]string{"q": "test"},
	}

	findings, err := module.Scan(context.Background(), target)

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Type != "Cross-Site Scripting (Reflected)" {
		t.Errorf("expected type 'Cross-Site Scripting (Reflected)', got '%s'", findings[0].Type)
	}

	if findings[0].Confidence != atlas.ConfidenceConfirmed {
		t.Errorf("expected confidence Confirmed, got %s", findings[0].Confidence)
	}

	if findings[0].Severity != atlas.SeverityHigh {
		t.Errorf("expected severity High, got %s", findings[0].Severity)
	}
}

func TestXSSModule_NoReflection(t *testing.T) {
	// Setup non-vulnerable server (sanitizes input)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Search: sanitized</body></html>"))
	}))
	defer server.Close()

	module := NewXSSModule(atlas.NewNopLogger(), nil)

	target := &atlas.ScanTarget{
		URL:        server.URL + "?q=test",
		Method:     "GET",
		Parameters: map[string]string{"q": "test"},
	}

	findings, err := module.Scan(context.Background(), target)

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-vulnerable server, got %d", len(findings))
	}
}

func TestXSSModule_DetectContext(t *testing.T) {
	module := NewXSSModule(atlas.NewNopLogger(), nil)

	tests := []struct {
		name     string
		body     string
		marker   string
		expected string
	}{
		{
			name:     "JavaScript context",
			body:     "<script>var x = 'xss123';</script>",
			marker:   "xss123",
			expected: "JavaScript",
		},
		{
			name:     "HTML attribute context",
			body:     "<input value=\"xss123\">",
			marker:   "xss123",
			expected: "HTML attribute",
		},
		{
			name:     "HTML context",
			body:     "<div>xss123</div>",
			marker:   "xss123",
			expected: "HTML",
		},
		{
			name:     "Text context",
			body:     "Some text xss123 here",
			marker:   "xss123",
			expected: "text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := module.detectContext(tt.body, tt.marker, "")
			if result != tt.expected {
				t.Errorf("expected context %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestXSSModule_SupportsTarget(t *testing.T) {
	module := NewXSSModule(atlas.NewNopLogger(), nil)

	// XSS should support all targets
	target := &atlas.ScanTarget{
		URL:    "http://example.com",
		Method: "GET",
	}

	if !module.SupportsTarget(target) {
		t.Error("XSS module should support all targets")
	}
}
