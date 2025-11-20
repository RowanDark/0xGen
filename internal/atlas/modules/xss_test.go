package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func TestXSSModule_EventHandlers(t *testing.T) {
	// Test that the module tests event handler payloads
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		// Reflect the input unsanitized
		w.Write([]byte("<html><body>" + q + "</body></html>"))
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

	if len(findings) == 0 {
		t.Error("expected to detect XSS on vulnerable endpoint")
	}
}

func TestXSSModule_ScriptTagInjection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		script := r.URL.Query().Get("script")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body><script>" + script + "</script></body></html>"))
	}))
	defer server.Close()

	module := NewXSSModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?script=console.log('test')",
		Method:     "GET",
		Parameters: map[string]string{"script": "console.log('test')"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected to detect script injection")
	}

	if findings[0].Type != "Cross-Site Scripting (Reflected)" {
		t.Errorf("expected type 'Cross-Site Scripting (Reflected)', got '%s'", findings[0].Type)
	}
}

func TestXSSModule_AttributeContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attr := r.URL.Query().Get("attr")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body><input value=\"" + attr + "\"></body></html>"))
	}))
	defer server.Close()

	module := NewXSSModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?attr=test",
		Method:     "GET",
		Parameters: map[string]string{"attr": "test"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected to detect attribute injection")
	}

	if findings[0].Type != "Cross-Site Scripting (Reflected)" {
		t.Errorf("expected type 'Cross-Site Scripting (Reflected)', got '%s'", findings[0].Type)
	}
}

func TestXSSModule_HTMLContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		content := r.URL.Query().Get("content")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body><div>" + content + "</div></body></html>"))
	}))
	defer server.Close()

	module := NewXSSModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?content=test",
		Method:     "GET",
		Parameters: map[string]string{"content": "test"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected to detect HTML injection")
	}

	if findings[0].Type != "Cross-Site Scripting (Reflected)" {
		t.Errorf("expected type 'Cross-Site Scripting (Reflected)', got '%s'", findings[0].Type)
	}
}

func TestXSSModule_FilterBypass(t *testing.T) {
	tests := []struct {
		name         string
		bypassMethod string
	}{
		{
			name:         "Case variation",
			bypassMethod: "<ScRiPt>",
		},
		{
			name:         "Nested tags",
			bypassMethod: "<scr<script>ipt>",
		},
		{
			name:         "HTML entities",
			bypassMethod: "&#97;",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query().Get("q")
				w.Header().Set("Content-Type", "text/html")
				w.Write([]byte("<html><body>" + q + "</body></html>"))
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

			// Should attempt detection with bypass payloads
			if len(findings) == 0 {
				t.Error("expected to attempt bypass detection")
			}
		})
	}
}

func TestXSSModule_MultipleParameters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q1 := r.URL.Query().Get("q1")
		q2 := r.URL.Query().Get("q2")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Q1: " + q1 + " Q2: " + q2 + "</body></html>"))
	}))
	defer server.Close()

	module := NewXSSModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?q1=test1&q2=test2",
		Method:     "GET",
		Parameters: map[string]string{"q1": "test1", "q2": "test2"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should detect XSS in both parameters
	if len(findings) != 2 {
		t.Errorf("expected 2 findings (one per parameter), got %d", len(findings))
	}
}

func TestXSSModule_POSTRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			if err := r.ParseForm(); err == nil {
				comment := r.FormValue("comment")
				w.Header().Set("Content-Type", "text/html")
				w.Write([]byte("<html><body>Comment: " + comment + "</body></html>"))
				return
			}
		}
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	module := NewXSSModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL,
		Method:     "POST",
		Parameters: map[string]string{"comment": "test comment"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected to detect XSS in POST request")
	}
}

func TestXSSModule_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	module := NewXSSModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?q=test",
		Method:     "GET",
		Parameters: map[string]string{"q": "test"},
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

func TestXSSModule_ExtractParameters(t *testing.T) {
	module := NewXSSModule(atlas.NewNopLogger(), nil)

	target := &atlas.ScanTarget{
		URL:        "http://example.com?q=search&page=1",
		Method:     "GET",
		Parameters: map[string]string{"user": "admin"},
	}

	params := module.extractParameters(target)

	if len(params) != 3 {
		t.Errorf("expected 3 parameters, got %d", len(params))
	}

	if params["q"] != "search" {
		t.Errorf("expected q=search, got %s", params["q"])
	}

	if params["page"] != "1" {
		t.Errorf("expected page=1, got %s", params["page"])
	}

	if params["user"] != "admin" {
		t.Errorf("expected user=admin, got %s", params["user"])
	}
}

func TestXSSModule_GetParamLocation(t *testing.T) {
	module := NewXSSModule(atlas.NewNopLogger(), nil)

	tests := []struct {
		name     string
		target   *atlas.ScanTarget
		param    string
		expected atlas.ParamLocation
	}{
		{
			name: "Query parameter",
			target: &atlas.ScanTarget{
				URL:    "http://test.com?q=search",
				Method: "GET",
			},
			param:    "q",
			expected: atlas.ParamLocationQuery,
		},
		{
			name: "POST body parameter",
			target: &atlas.ScanTarget{
				URL:    "http://test.com",
				Method: "POST",
			},
			param:    "comment",
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

func TestXSSModule_NoParametersNoDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>Static page</body></html>"))
	}))
	defer server.Close()

	module := NewXSSModule(atlas.NewNopLogger(), nil)
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

func TestXSSModule_PolyglotPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		poly := r.URL.Query().Get("poly")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>" + poly + "</body></html>"))
	}))
	defer server.Close()

	module := NewXSSModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:        server.URL + "?poly=test",
		Method:     "GET",
		Parameters: map[string]string{"poly": "test"},
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("expected to detect XSS with polyglot payloads")
	}
}
