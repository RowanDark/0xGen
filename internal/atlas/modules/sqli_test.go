package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

func TestSQLiModule_TimeBased(t *testing.T) {
	// Setup vulnerable test server with delay
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")

		// Simulate time-based SQLi vulnerability
		if strings.Contains(id, "SLEEP(3)") ||
		   strings.Contains(id, "WAITFOR DELAY") ||
		   strings.Contains(id, "pg_sleep(3)") {
			time.Sleep(3 * time.Second)
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

	if findings[0].Type != "SQL Injection (Time-based)" {
		t.Errorf("expected type 'SQL Injection (Time-based)', got '%s'", findings[0].Type)
	}

	if findings[0].Confidence != atlas.ConfidenceConfirmed {
		t.Errorf("expected confidence Confirmed, got %s", findings[0].Confidence)
	}
}

func TestSQLiModule_ErrorPatterns(t *testing.T) {
	tests := []struct {
		name         string
		errorMessage string
		shouldDetect bool
	}{
		{
			name:         "MySQL syntax error",
			errorMessage: "You have an error in your SQL syntax",
			shouldDetect: true,
		},
		{
			name:         "PostgreSQL error",
			errorMessage: "ERROR: syntax error at or near",
			shouldDetect: true,
		},
		{
			name:         "Oracle error",
			errorMessage: "ORA-00933: SQL command not properly ended",
			shouldDetect: true,
		},
		{
			name:         "MSSQL error",
			errorMessage: "Unclosed quotation mark after the character string",
			shouldDetect: true,
		},
		{
			name:         "SQLite error",
			errorMessage: "sqlite3.OperationalError: near \"'\": syntax error",
			shouldDetect: true,
		},
		{
			name:         "Generic MySQL error",
			errorMessage: "Warning: mysql_fetch_array() expects parameter 1 to be resource",
			shouldDetect: true,
		},
		{
			name:         "ODBC error",
			errorMessage: "Microsoft OLE DB Provider for ODBC SQL Server",
			shouldDetect: true,
		},
		{
			name:         "Normal response",
			errorMessage: "User not found",
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				id := r.URL.Query().Get("id")
				if strings.Contains(id, "'") {
					w.Write([]byte(tt.errorMessage))
				} else {
					w.Write([]byte("OK"))
				}
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

			if tt.shouldDetect {
				if len(findings) == 0 {
					t.Errorf("expected to detect SQL injection for error: %s", tt.errorMessage)
				}
			} else {
				if len(findings) > 0 {
					t.Errorf("false positive detected for message: %s", tt.errorMessage)
				}
			}
		})
	}
}

func TestSQLiModule_POSTRequest(t *testing.T) {
	// Setup vulnerable test server for POST
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			// Simulate POST parameter injection
			if err := r.ParseForm(); err == nil {
				username := r.FormValue("username")
				if strings.Contains(username, "'") {
					w.Write([]byte("SQL syntax error near '" + username + "'"))
					return
				}
			}
		}
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	module := NewSQLiModule(atlas.NewNopLogger(), nil)

	target := &atlas.ScanTarget{
		URL:        server.URL,
		Method:     "POST",
		Parameters: map[string]string{"username": "admin"},
	}

	findings, err := module.Scan(context.Background(), target)

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for POST injection, got %d", len(findings))
	}
}

func TestSQLiModule_GetParamLocation(t *testing.T) {
	module := NewSQLiModule(atlas.NewNopLogger(), nil)

	tests := []struct {
		name     string
		target   *atlas.ScanTarget
		param    string
		expected atlas.ParamLocation
	}{
		{
			name: "Query parameter",
			target: &atlas.ScanTarget{
				URL:    "http://test.com?id=1",
				Method: "GET",
			},
			param:    "id",
			expected: atlas.ParamLocationQuery,
		},
		{
			name: "Query parameter with ampersand",
			target: &atlas.ScanTarget{
				URL:    "http://test.com?foo=bar&id=1",
				Method: "GET",
			},
			param:    "id",
			expected: atlas.ParamLocationQuery,
		},
		{
			name: "POST body parameter",
			target: &atlas.ScanTarget{
				URL:    "http://test.com",
				Method: "POST",
			},
			param:    "username",
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

func TestSQLiModule_ContextCancellation(t *testing.T) {
	// Setup slow server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	module := NewSQLiModule(atlas.NewNopLogger(), nil)

	target := &atlas.ScanTarget{
		URL:        server.URL + "?id=1",
		Method:     "GET",
		Parameters: map[string]string{"id": "1"},
	}

	// Cancel context immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	findings, err := module.Scan(ctx, target)

	// Should return with context error
	if err == nil {
		t.Error("expected context cancellation error")
	}

	if len(findings) > 0 {
		t.Errorf("expected 0 findings after cancellation, got %d", len(findings))
	}
}

func TestSQLiModule_MultipleParameters(t *testing.T) {
	// Setup vulnerable test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		name := r.URL.Query().Get("name")

		if strings.Contains(id, "'") {
			w.Write([]byte("SQL syntax error in id parameter"))
			return
		}
		if strings.Contains(name, "'") {
			w.Write([]byte("SQL syntax error in name parameter"))
			return
		}
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	module := NewSQLiModule(atlas.NewNopLogger(), nil)

	target := &atlas.ScanTarget{
		URL:        server.URL + "?id=1&name=test",
		Method:     "GET",
		Parameters: map[string]string{"id": "1", "name": "test"},
	}

	findings, err := module.Scan(context.Background(), target)

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should detect vulnerabilities in both parameters
	if len(findings) != 2 {
		t.Errorf("expected 2 findings (one per parameter), got %d", len(findings))
	}
}

func TestSQLiModule_BooleanDifferentResponses(t *testing.T) {
	// Setup server with different response sizes
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")

		// True condition returns more data
		if strings.Contains(id, "1'='1") {
			w.Write([]byte(strings.Repeat("Data ", 100))) // 500 bytes
		} else if strings.Contains(id, "1'='2") {
			w.Write([]byte("")) // 0 bytes
		} else {
			w.Write([]byte("Normal response"))
		}
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

	// Should detect boolean-based SQLi due to response size difference
	foundBoolean := false
	for _, f := range findings {
		if f.Type == "SQL Injection (Boolean-based)" {
			foundBoolean = true
			break
		}
	}

	if !foundBoolean {
		t.Error("expected to detect boolean-based SQL injection")
	}
}

func TestSQLiModule_NoFalsePositiveOnSimilarSizes(t *testing.T) {
	// Setup server with similar response sizes (within 10% threshold)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")

		// Responses are similar in size (within 10%)
		if strings.Contains(id, "1'='1") {
			w.Write([]byte(strings.Repeat("X", 100)))
		} else if strings.Contains(id, "1'='2") {
			w.Write([]byte(strings.Repeat("Y", 95))) // Only 5% difference
		} else {
			w.Write([]byte(strings.Repeat("Z", 100)))
		}
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

	// Should NOT detect boolean-based SQLi (responses too similar)
	for _, f := range findings {
		if f.Type == "SQL Injection (Boolean-based)" {
			t.Error("false positive: detected boolean-based SQLi when responses are similar")
		}
	}
}
