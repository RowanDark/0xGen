package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RowanDark/0xgen/internal/atlas"
)

func TestSQLiModule_ErrorBased(t *testing.T) {
	// Setup vulnerable test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "'") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("SQL syntax error near '" + id + "'"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	module := NewSQLiModule(atlas.NewNopLogger(), nil)

	target := &atlas.ScanTarget{
		URL:        server.URL + "?id=1",
		Method:     "GET",
		Parameters: map[string]string{"id": "1"},
	}

	findings, err := module.Scan(context.Background(), target)

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Type != "SQL Injection (Error-based)" {
		t.Errorf("expected type 'SQL Injection (Error-based)', got '%s'", findings[0].Type)
	}

	if findings[0].Confidence != atlas.ConfidenceConfirmed {
		t.Errorf("expected confidence Confirmed, got %s", findings[0].Confidence)
	}

	if findings[0].Severity != atlas.SeverityCritical {
		t.Errorf("expected severity Critical, got %s", findings[0].Severity)
	}
}

func TestSQLiModule_BooleanBased(t *testing.T) {
	// Setup vulnerable test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")

		// Simulate boolean-based SQLi
		if strings.Contains(id, "OR '1'='1") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Result 1\nResult 2\nResult 3\n"))
			return
		}
		if strings.Contains(id, "OR '1'='2") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(""))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Result 1"))
	}))
	defer server.Close()

	module := NewSQLiModule(atlas.NewNopLogger(), nil)

	target := &atlas.ScanTarget{
		URL:        server.URL + "?id=1",
		Method:     "GET",
		Parameters: map[string]string{"id": "1"},
	}

	findings, err := module.Scan(context.Background(), target)

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Type != "SQL Injection (Boolean-based)" {
		t.Errorf("expected type 'SQL Injection (Boolean-based)', got '%s'", findings[0].Type)
	}
}

func TestSQLiModule_NoVulnerability(t *testing.T) {
	// Setup non-vulnerable server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	module := NewSQLiModule(atlas.NewNopLogger(), nil)

	target := &atlas.ScanTarget{
		URL:        server.URL + "?id=1",
		Method:     "GET",
		Parameters: map[string]string{"id": "1"},
	}

	findings, err := module.Scan(context.Background(), target)

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-vulnerable server, got %d", len(findings))
	}
}

func TestSQLiModule_SupportsTarget(t *testing.T) {
	module := NewSQLiModule(atlas.NewNopLogger(), nil)

	tests := []struct {
		name     string
		target   *atlas.ScanTarget
		expected bool
	}{
		{
			name: "URL with query parameters",
			target: &atlas.ScanTarget{
				URL:    "http://example.com?id=1",
				Method: "GET",
			},
			expected: true,
		},
		{
			name: "Target with parameters",
			target: &atlas.ScanTarget{
				URL:        "http://example.com",
				Method:     "GET",
				Parameters: map[string]string{"id": "1"},
			},
			expected: true,
		},
		{
			name: "POST request",
			target: &atlas.ScanTarget{
				URL:    "http://example.com",
				Method: "POST",
			},
			expected: true,
		},
		{
			name: "No parameters",
			target: &atlas.ScanTarget{
				URL:    "http://example.com",
				Method: "GET",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := module.SupportsTarget(tt.target)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestSQLiModule_ExtractParameters(t *testing.T) {
	module := NewSQLiModule(atlas.NewNopLogger(), nil)

	target := &atlas.ScanTarget{
		URL:        "http://example.com?id=1&name=test",
		Method:     "GET",
		Parameters: map[string]string{"extra": "value"},
	}

	params := module.extractParameters(target)

	if len(params) != 3 {
		t.Errorf("expected 3 parameters, got %d", len(params))
	}

	if params["id"] != "1" {
		t.Errorf("expected id=1, got %s", params["id"])
	}

	if params["name"] != "test" {
		t.Errorf("expected name=test, got %s", params["name"])
	}

	if params["extra"] != "value" {
		t.Errorf("expected extra=value, got %s", params["extra"])
	}
}
