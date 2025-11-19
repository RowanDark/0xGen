package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RowanDark/0xgen/internal/team"
)

func TestCipherErrorStatusCodes(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	// Get a valid token for authenticated requests
	token := getTestToken(t, server, "test-workspace", team.RoleViewer)

	tests := []struct {
		name       string
		endpoint   string
		method     string
		payload    string
		wantStatus int
	}{
		{
			name:       "execute missing operation returns 400",
			endpoint:   "/api/v1/cipher/execute",
			method:     "POST",
			payload:    `{"input": "test"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "execute unknown operation returns 400",
			endpoint:   "/api/v1/cipher/execute",
			method:     "POST",
			payload:    `{"operation": "unknown-op", "input": "test"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "execute invalid base64 returns 422",
			endpoint:   "/api/v1/cipher/execute",
			method:     "POST",
			payload:    `{"operation": "base64-decode", "input": "not-valid-base64!!!"}`,
			wantStatus: http.StatusUnprocessableEntity,
		},
		{
			name:       "pipeline empty operations returns 400",
			endpoint:   "/api/v1/cipher/pipeline",
			method:     "POST",
			payload:    `{"input": "test", "operations": []}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "pipeline missing operations returns 400",
			endpoint:   "/api/v1/cipher/pipeline",
			method:     "POST",
			payload:    `{"input": "test"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "detect empty input returns 400",
			endpoint:   "/api/v1/cipher/detect",
			method:     "POST",
			payload:    `{"input": ""}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "smart-decode empty input returns 400",
			endpoint:   "/api/v1/cipher/smart-decode",
			method:     "POST",
			payload:    `{"input": ""}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "smart-decode random data returns 422",
			endpoint:   "/api/v1/cipher/smart-decode",
			method:     "POST",
			payload:    `{"input": "not encoded at all xyz123"}`,
			wantStatus: http.StatusUnprocessableEntity,
		},
		{
			name:       "execute invalid json returns 400",
			endpoint:   "/api/v1/cipher/execute",
			method:     "POST",
			payload:    `{invalid json`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "pipeline invalid json returns 400",
			endpoint:   "/api/v1/cipher/pipeline",
			method:     "POST",
			payload:    `{invalid json`,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.endpoint, strings.NewReader(tt.payload))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d for %s: %s", tt.wantStatus, rec.Code, tt.name, rec.Body.String())
			}
		})
	}
}

func TestCipherSuccessStatusCodes(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	// Get a valid token for authenticated requests
	token := getTestToken(t, server, "test-workspace", team.RoleViewer)

	tests := []struct {
		name       string
		endpoint   string
		method     string
		payload    string
		wantStatus int
	}{
		{
			name:       "execute base64 encode returns 200",
			endpoint:   "/api/v1/cipher/execute",
			method:     "POST",
			payload:    `{"operation": "base64-encode", "input": "hello"}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "execute base64 decode returns 200",
			endpoint:   "/api/v1/cipher/execute",
			method:     "POST",
			payload:    `{"operation": "base64-decode", "input": "aGVsbG8="}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "execute hex encode returns 200",
			endpoint:   "/api/v1/cipher/execute",
			method:     "POST",
			payload:    `{"operation": "hex-encode", "input": "hello"}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "detect valid input returns 200",
			endpoint:   "/api/v1/cipher/detect",
			method:     "POST",
			payload:    `{"input": "aGVsbG8="}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "list operations returns 200",
			endpoint:   "/api/v1/cipher/operations",
			method:     "GET",
			payload:    "",
			wantStatus: http.StatusOK,
		},
		{
			name:       "list recipes returns 200",
			endpoint:   "/api/v1/cipher/recipes/list",
			method:     "GET",
			payload:    "",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body *strings.Reader
			if tt.payload != "" {
				body = strings.NewReader(tt.payload)
			} else {
				body = strings.NewReader("")
			}

			req := httptest.NewRequest(tt.method, tt.endpoint, body)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d for %s: %s", tt.wantStatus, rec.Code, tt.name, rec.Body.String())
			}
		})
	}
}

func TestCipherMethodNotAllowed(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	token := getTestToken(t, server, "test-workspace", team.RoleViewer)

	tests := []struct {
		name     string
		endpoint string
		method   string
	}{
		{
			name:     "execute with GET",
			endpoint: "/api/v1/cipher/execute",
			method:   "GET",
		},
		{
			name:     "pipeline with GET",
			endpoint: "/api/v1/cipher/pipeline",
			method:   "GET",
		},
		{
			name:     "detect with GET",
			endpoint: "/api/v1/cipher/detect",
			method:   "GET",
		},
		{
			name:     "smart-decode with GET",
			endpoint: "/api/v1/cipher/smart-decode",
			method:   "GET",
		},
		{
			name:     "operations with POST",
			endpoint: "/api/v1/cipher/operations",
			method:   "POST",
		},
		{
			name:     "recipes/list with POST",
			endpoint: "/api/v1/cipher/recipes/list",
			method:   "POST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.endpoint, bytes.NewReader([]byte("{}")))
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
			}
		})
	}
}

func TestCipherRecipeOperations(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	token := getTestToken(t, server, "test-workspace", team.RoleViewer)

	// Test save recipe with valid data
	t.Run("save recipe returns 200", func(t *testing.T) {
		payload := `{
			"name": "test-recipe",
			"description": "Test recipe",
			"operations": [{"name": "base64-encode"}]
		}`

		req := httptest.NewRequest("POST", "/api/v1/cipher/recipes/save", strings.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
		}
	})

	// Test load recipe that doesn't exist
	t.Run("load nonexistent recipe returns 404", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/cipher/recipes/load?name=nonexistent", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("expected status %d, got %d: %s", http.StatusNotFound, rec.Code, rec.Body.String())
		}
	})

	// Test load recipe without name
	t.Run("load recipe without name returns 400", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/cipher/recipes/load", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d: %s", http.StatusBadRequest, rec.Code, rec.Body.String())
		}
	})

	// Test delete recipe without name
	t.Run("delete recipe without name returns 400", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/cipher/recipes/delete", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d: %s", http.StatusBadRequest, rec.Code, rec.Body.String())
		}
	})
}

func TestCipherNoSensitiveInfoInErrors(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	token := getTestToken(t, server, "test-workspace", team.RoleViewer)

	// Test that error messages don't contain sensitive information
	t.Run("error messages are safe", func(t *testing.T) {
		payload := `{"operation": "base64-decode", "input": "not-valid!!!"}`

		req := httptest.NewRequest("POST", "/api/v1/cipher/execute", strings.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		body := rec.Body.String()

		// Check that response doesn't contain stack traces or internal paths
		sensitivePatterns := []string{
			"/home/",
			"/usr/",
			"panic:",
			"goroutine",
			".go:",
		}

		for _, pattern := range sensitivePatterns {
			if strings.Contains(body, pattern) {
				t.Errorf("error response contains sensitive info pattern %q: %s", pattern, body)
			}
		}
	})
}
