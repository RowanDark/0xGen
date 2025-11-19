package rewrite

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestSanitizeHeaderValue(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		wantErr     bool
		errContains string
		expected    string
	}{
		{
			name:     "valid simple value",
			value:    "application/json",
			wantErr:  false,
			expected: "application/json",
		},
		{
			name:     "valid with spaces",
			value:    "  text/html  ",
			wantErr:  false,
			expected: "text/html", // trimmed
		},
		{
			name:        "CRLF injection attempt",
			value:       "valid\r\nX-Injected: evil",
			wantErr:     true,
			errContains: "CRLF",
		},
		{
			name:        "CR only injection",
			value:       "valid\rX-Injected: evil",
			wantErr:     true,
			errContains: "CRLF",
		},
		{
			name:        "LF only injection",
			value:       "valid\nX-Injected: evil",
			wantErr:     true,
			errContains: "CRLF",
		},
		{
			name:        "null byte injection",
			value:       "valid\x00evil",
			wantErr:     true,
			errContains: "CRLF",
		},
		{
			name:        "non-printable character",
			value:       "valid\x01evil",
			wantErr:     true,
			errContains: "non-printable",
		},
		{
			name:        "control character",
			value:       "valid\x1Fevil",
			wantErr:     true,
			errContains: "non-printable",
		},
		{
			name:     "valid special characters",
			value:    "Bearer token123-_.",
			wantErr:  false,
			expected: "Bearer token123-_.",
		},
		{
			name:     "empty string",
			value:    "",
			wantErr:  false,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := sanitizeHeaderValue(tt.value)

			if tt.wantErr {
				if err == nil {
					t.Errorf("sanitizeHeaderValue() expected error containing %q, got nil", tt.errContains)
				} else if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("sanitizeHeaderValue() error = %v, should contain %q", err, tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("sanitizeHeaderValue() unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("sanitizeHeaderValue() = %q, want %q", result, tt.expected)
				}
			}
		})
	}
}

func TestSanitizeHeaderName(t *testing.T) {
	tests := []struct {
		name        string
		headerName  string
		wantErr     bool
		errContains string
		expected    string
	}{
		{
			name:       "valid simple name",
			headerName: "X-Custom-Header",
			wantErr:    false,
			expected:   "X-Custom-Header",
		},
		{
			name:       "valid with trim",
			headerName: "  Content-Type  ",
			wantErr:    false,
			expected:   "Content-Type",
		},
		{
			name:        "CRLF injection attempt",
			headerName:  "Valid\r\nX-Injected",
			wantErr:     true,
			errContains: "CRLF",
		},
		{
			name:        "colon in name",
			headerName:  "X:Invalid",
			wantErr:     true,
			errContains: "invalid character",
		},
		{
			name:        "space in name",
			headerName:  "X Invalid",
			wantErr:     true,
			errContains: "invalid character",
		},
		{
			name:        "null byte in name",
			headerName:  "X-Test\x00",
			wantErr:     true,
			errContains: "CRLF",
		},
		{
			name:       "valid hyphenated name",
			headerName: "X-Request-ID",
			wantErr:    false,
			expected:   "X-Request-ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := sanitizeHeaderName(tt.headerName)

			if tt.wantErr {
				if err == nil {
					t.Errorf("sanitizeHeaderName() expected error containing %q, got nil", tt.errContains)
				} else if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("sanitizeHeaderName() error = %v, should contain %q", err, tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("sanitizeHeaderName() unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("sanitizeHeaderName() = %q, want %q", result, tt.expected)
				}
			}
		})
	}
}

func TestExecutorAddHeader_CRLFInjection(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	variables := NewVariableStore()
	executor := NewExecutor(variables, logger)

	tests := []struct {
		name         string
		headerName   string
		headerValue  string
		wantErr      bool
		checkRequest func(*http.Request) bool
	}{
		{
			name:        "valid header",
			headerName:  "X-Custom",
			headerValue: "safe-value",
			wantErr:     false,
			checkRequest: func(req *http.Request) bool {
				return req.Header.Get("X-Custom") == "safe-value"
			},
		},
		{
			name:        "CRLF in value",
			headerName:  "X-Custom",
			headerValue: "value\r\nX-Injected: evil",
			wantErr:     true,
		},
		{
			name:        "CRLF in name",
			headerName:  "X-Custom\r\nX-Injected",
			headerValue: "value",
			wantErr:     true,
		},
		{
			name:        "null byte in value",
			headerName:  "X-Custom",
			headerValue: "value\x00evil",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/test", nil)

			action := Action{
				Type:     ActionAdd,
				Location: LocationHeader,
				Name:     tt.headerName,
				Value:    tt.headerValue,
			}

			err := executor.executeAdd(action, req, nil, tt.headerValue, false)

			if tt.wantErr {
				if err == nil {
					t.Error("executeAdd() expected error for CRLF injection, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("executeAdd() unexpected error: %v", err)
				}
				if tt.checkRequest != nil && !tt.checkRequest(req) {
					t.Error("executeAdd() request check failed")
				}
			}
		})
	}
}

func TestExecutorAddHeader_ResponseCRLFInjection(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	variables := NewVariableStore()
	executor := NewExecutor(variables, logger)

	// Test CRLF injection in response headers
	resp := &http.Response{
		Header: make(http.Header),
	}

	action := Action{
		Type:     ActionAdd,
		Location: LocationHeader,
		Name:     "X-Custom",
		Value:    "value\r\nX-Injected: evil",
	}

	err := executor.executeAdd(action, nil, resp, "value\r\nX-Injected: evil", true)
	if err == nil {
		t.Error("executeAdd() should reject CRLF injection in response header")
	}

	// Verify no header was set
	if resp.Header.Get("X-Custom") != "" {
		t.Error("executeAdd() should not set header when injection detected")
	}
}

func TestExecutorReplaceHeader_CRLFInjection(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	variables := NewVariableStore()
	executor := NewExecutor(variables, logger)

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("X-Custom", "original")

	// Try to inject via replacement value
	action := Action{
		Type:     ActionReplace,
		Location: LocationHeader,
		Name:     "X-Custom",
		Pattern:  "original",
		Value:    "replaced\r\nX-Injected: evil",
	}

	err := executor.executeReplace(action, req, nil, nil, "replaced\r\nX-Injected: evil", "test-id", false)
	if err == nil {
		t.Error("executeReplace() should reject CRLF injection")
	}

	// Header should still have original value since injection was blocked
	if req.Header.Get("X-Custom") != "original" {
		t.Errorf("executeReplace() should preserve original value when injection blocked, got %q", req.Header.Get("X-Custom"))
	}
}

func TestExecutorReplaceHeader_ValidReplacement(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	variables := NewVariableStore()
	executor := NewExecutor(variables, logger)

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("X-Custom", "original-value")

	action := Action{
		Type:     ActionReplace,
		Location: LocationHeader,
		Name:     "X-Custom",
		Pattern:  "original",
		Value:    "new",
	}

	err := executor.executeReplace(action, req, nil, nil, "new", "test-id", false)
	if err != nil {
		t.Errorf("executeReplace() unexpected error: %v", err)
	}

	expected := "new-value"
	if req.Header.Get("X-Custom") != expected {
		t.Errorf("executeReplace() = %q, want %q", req.Header.Get("X-Custom"), expected)
	}
}

func TestExecutorReplaceHeader_ResponseCRLFInjection(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	variables := NewVariableStore()
	executor := NewExecutor(variables, logger)

	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("X-Custom", "original")

	action := Action{
		Type:     ActionReplace,
		Location: LocationHeader,
		Name:     "X-Custom",
		Pattern:  "original",
		Value:    "replaced\nX-Injected: evil",
	}

	err := executor.executeReplace(action, nil, resp, nil, "replaced\nX-Injected: evil", "test-id", true)
	if err == nil {
		t.Error("executeReplace() should reject LF injection in response header")
	}
}

func TestExecutorRequestActions_HeaderInjection(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	variables := NewVariableStore()
	executor := NewExecutor(variables, logger)

	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	rule := &Rule{
		Name:    "injection-test",
		Enabled: true,
		Actions: []Action{
			{
				Type:     ActionAdd,
				Location: LocationHeader,
				Name:     "X-Malicious",
				Value:    "value\r\nSet-Cookie: session=hijacked",
			},
		},
	}

	// ExecuteRequestActions should continue but log the error
	err := executor.ExecuteRequestActions(rule, req, "test-id")
	if err != nil {
		t.Errorf("ExecuteRequestActions() should not return error (continues despite action failure): %v", err)
	}

	// The malicious header should not be set
	if req.Header.Get("X-Malicious") != "" {
		t.Error("ExecuteRequestActions() should not set header with CRLF injection")
	}
}

func TestExecutorResponseActions_HeaderInjection(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	variables := NewVariableStore()
	executor := NewExecutor(variables, logger)

	resp := &http.Response{
		Header: make(http.Header),
	}

	rule := &Rule{
		Name:    "injection-test",
		Enabled: true,
		Actions: []Action{
			{
				Type:     ActionAdd,
				Location: LocationHeader,
				Name:     "X-Malicious",
				Value:    "value\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK",
			},
		},
	}

	// ExecuteResponseActions should continue but log the error
	err := executor.ExecuteResponseActions(rule, resp, "test-id")
	if err != nil {
		t.Errorf("ExecuteResponseActions() should not return error: %v", err)
	}

	// The malicious header should not be set
	if resp.Header.Get("X-Malicious") != "" {
		t.Error("ExecuteResponseActions() should not set header with CRLF injection")
	}
}
