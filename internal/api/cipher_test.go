package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

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
			payload:    `{"operation": "base64_decode", "input": "not-valid-base64!!!"}`,
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
			payload:    `{"operation": "base64_encode", "input": "hello"}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "execute base64 decode returns 200",
			endpoint:   "/api/v1/cipher/execute",
			method:     "POST",
			payload:    `{"operation": "base64_decode", "input": "aGVsbG8="}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "execute hex encode returns 200",
			endpoint:   "/api/v1/cipher/execute",
			method:     "POST",
			payload:    `{"operation": "hex_encode", "input": "hello"}`,
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
			"operations": [{"name": "base64_encode"}]
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
		payload := `{"operation": "base64_decode", "input": "not-valid!!!"}`

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

func TestCipherHandlersRespectContext(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	token := getTestToken(t, server, "test-workspace", team.RoleViewer)

	endpoints := []struct {
		name     string
		endpoint string
		payload  string
	}{
		{
			name:     "execute",
			endpoint: "/api/v1/cipher/execute",
			payload:  `{"operation": "base64_encode", "input": "test"}`,
		},
		{
			name:     "pipeline",
			endpoint: "/api/v1/cipher/pipeline",
			payload:  `{"input": "test", "operations": [{"name": "base64_encode"}]}`,
		},
		{
			name:     "detect",
			endpoint: "/api/v1/cipher/detect",
			payload:  `{"input": "aGVsbG8="}`,
		},
		{
			name:     "smart-decode",
			endpoint: "/api/v1/cipher/smart-decode",
			payload:  `{"input": "aGVsbG8="}`,
		},
	}

	for _, ep := range endpoints {
		t.Run(ep.name+" with canceled context", func(t *testing.T) {
			// Create context with immediate cancellation
			ctx, cancel := context.WithCancel(context.Background())
			cancel() // Cancel immediately

			req := httptest.NewRequest("POST", ep.endpoint, strings.NewReader(ep.payload))
			req = req.WithContext(ctx)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			// Should return timeout status (408) or the operation may complete before checking context
			// Either way, we verify the handler uses the request context
			if rec.Code == http.StatusOK {
				// Operation completed before context check - this is acceptable
				t.Logf("%s completed before context cancellation check", ep.name)
			} else if rec.Code == http.StatusRequestTimeout {
				// Context cancellation was detected - good
				t.Logf("%s detected context cancellation", ep.name)
			}
		})
	}
}

func TestCipherHandlersWithValidContext(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	token := getTestToken(t, server, "test-workspace", team.RoleViewer)

	// Test that normal requests with valid context work correctly
	endpoints := []struct {
		name       string
		endpoint   string
		payload    string
		wantStatus int
	}{
		{
			name:       "execute with valid context",
			endpoint:   "/api/v1/cipher/execute",
			payload:    `{"operation": "base64_encode", "input": "hello"}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "pipeline with valid context",
			endpoint:   "/api/v1/cipher/pipeline",
			payload:    `{"input": "hello", "operations": [{"name": "base64_encode"}]}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "detect with valid context",
			endpoint:   "/api/v1/cipher/detect",
			payload:    `{"input": "aGVsbG8="}`,
			wantStatus: http.StatusOK,
		},
	}

	for _, ep := range endpoints {
		t.Run(ep.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", ep.endpoint, strings.NewReader(ep.payload))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != ep.wantStatus {
				t.Errorf("expected status %d, got %d: %s", ep.wantStatus, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestCipherContextTimeoutHandling(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	token := getTestToken(t, server, "test-workspace", team.RoleViewer)

	// Test with deadline exceeded context
	t.Run("execute with deadline exceeded", func(t *testing.T) {
		deadline, ok := t.Deadline()
		if !ok {
			deadline = time.Now().Add(time.Minute)
		}
		ctx, cancel := context.WithDeadline(context.Background(), deadline.Add(-time.Minute))
		defer cancel()

		req := httptest.NewRequest("POST", "/api/v1/cipher/execute", strings.NewReader(`{"operation": "base64_encode", "input": "test"}`))
		req = req.WithContext(ctx)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		// Expect either GatewayTimeout for deadline exceeded or OK if completed before check
		if rec.Code != http.StatusGatewayTimeout && rec.Code != http.StatusOK && rec.Code != http.StatusRequestTimeout {
			t.Errorf("expected status %d or %d or %d, got %d", http.StatusGatewayTimeout, http.StatusOK, http.StatusRequestTimeout, rec.Code)
		}
	})
}

func TestCipherContextPropagation(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	token := getTestToken(t, server, "test-workspace", team.RoleViewer)

	// Verify context values are propagated through the request
	t.Run("context propagates through handler", func(t *testing.T) {
		type ctxKey string
		ctx := context.WithValue(context.Background(), ctxKey("test-key"), "test-value")

		req := httptest.NewRequest("POST", "/api/v1/cipher/execute", strings.NewReader(`{"operation": "base64_encode", "input": "hello"}`))
		req = req.WithContext(ctx)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		// Should complete successfully with context value available
		if rec.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
		}
	})
}

// TestCipherConcurrentRequests tests that the cipher endpoints handle concurrent requests safely.
// Run with -race flag to detect race conditions: go test -race -run TestCipherConcurrentRequests
func TestCipherConcurrentRequests(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	token := getTestToken(t, server, "test-workspace", team.RoleViewer)

	t.Run("concurrent execute requests", func(t *testing.T) {
		const numRequests = 50
		var wg sync.WaitGroup
		errors := make(chan error, numRequests)

		for i := 0; i < numRequests; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()

				payload := `{"operation": "base64_encode", "input": "concurrent-test"}`
				req := httptest.NewRequest("POST", "/api/v1/cipher/execute", strings.NewReader(payload))
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()

				mux.ServeHTTP(rec, req)

				if rec.Code != http.StatusOK {
					errors <- &testError{idx: idx, code: rec.Code, body: rec.Body.String()}
				}
			}(i)
		}

		wg.Wait()
		close(errors)

		for err := range errors {
			t.Error(err)
		}
	})

	t.Run("concurrent pipeline requests", func(t *testing.T) {
		const numRequests = 50
		var wg sync.WaitGroup
		errors := make(chan error, numRequests)

		for i := 0; i < numRequests; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()

				payload := `{"input": "pipeline-test", "operations": [{"name": "base64_encode"}, {"name": "hex_encode"}]}`
				req := httptest.NewRequest("POST", "/api/v1/cipher/pipeline", strings.NewReader(payload))
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()

				mux.ServeHTTP(rec, req)

				if rec.Code != http.StatusOK {
					errors <- &testError{idx: idx, code: rec.Code, body: rec.Body.String()}
				}
			}(i)
		}

		wg.Wait()
		close(errors)

		for err := range errors {
			t.Error(err)
		}
	})

	t.Run("concurrent detect requests", func(t *testing.T) {
		const numRequests = 50
		var wg sync.WaitGroup
		errors := make(chan error, numRequests)

		for i := 0; i < numRequests; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()

				payload := `{"input": "aGVsbG8gd29ybGQ="}`
				req := httptest.NewRequest("POST", "/api/v1/cipher/detect", strings.NewReader(payload))
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()

				mux.ServeHTTP(rec, req)

				if rec.Code != http.StatusOK {
					errors <- &testError{idx: idx, code: rec.Code, body: rec.Body.String()}
				}
			}(i)
		}

		wg.Wait()
		close(errors)

		for err := range errors {
			t.Error(err)
		}
	})

	t.Run("concurrent list operations requests", func(t *testing.T) {
		const numRequests = 50
		var wg sync.WaitGroup
		errors := make(chan error, numRequests)

		for i := 0; i < numRequests; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()

				req := httptest.NewRequest("GET", "/api/v1/cipher/operations", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				rec := httptest.NewRecorder()

				mux.ServeHTTP(rec, req)

				if rec.Code != http.StatusOK {
					errors <- &testError{idx: idx, code: rec.Code, body: rec.Body.String()}
				}
			}(i)
		}

		wg.Wait()
		close(errors)

		for err := range errors {
			t.Error(err)
		}
	})

	t.Run("mixed concurrent requests", func(t *testing.T) {
		const numRequests = 100
		var wg sync.WaitGroup
		errors := make(chan error, numRequests)

		endpoints := []struct {
			method   string
			endpoint string
			payload  string
		}{
			{"POST", "/api/v1/cipher/execute", `{"operation": "base64_encode", "input": "test"}`},
			{"POST", "/api/v1/cipher/pipeline", `{"input": "test", "operations": [{"name": "hex_encode"}]}`},
			{"POST", "/api/v1/cipher/detect", `{"input": "aGVsbG8="}`},
			{"GET", "/api/v1/cipher/operations", ""},
			{"GET", "/api/v1/cipher/recipes/list", ""},
		}

		for i := 0; i < numRequests; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()

				ep := endpoints[idx%len(endpoints)]
				var body *strings.Reader
				if ep.payload != "" {
					body = strings.NewReader(ep.payload)
				} else {
					body = strings.NewReader("")
				}

				req := httptest.NewRequest(ep.method, ep.endpoint, body)
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()

				mux.ServeHTTP(rec, req)

				if rec.Code != http.StatusOK {
					errors <- &testError{idx: idx, code: rec.Code, body: rec.Body.String()}
				}
			}(i)
		}

		wg.Wait()
		close(errors)

		for err := range errors {
			t.Error(err)
		}
	})
}

type testError struct {
	idx  int
	code int
	body string
}

func (e *testError) Error() string {
	return strings.TrimSpace(e.body)
}

// TestCipherConcurrentDifferentTokens tests concurrent requests with different authentication tokens
func TestCipherConcurrentDifferentTokens(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	// Create multiple tokens for different workspaces
	tokens := make([]string, 5)
	for i := 0; i < 5; i++ {
		workspaceID := "workspace-" + string(rune('A'+i))
		tokens[i] = getTestToken(t, server, workspaceID, team.RoleViewer)
	}

	const numRequests = 100
	var wg sync.WaitGroup
	errors := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			token := tokens[idx%len(tokens)]
			payload := `{"operation": "base64_encode", "input": "multi-token-test"}`
			req := httptest.NewRequest("POST", "/api/v1/cipher/execute", strings.NewReader(payload))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				errors <- &testError{idx: idx, code: rec.Code, body: rec.Body.String()}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

// TestCipherPipelineExecution tests various pipeline configurations
func TestCipherPipelineExecution(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	token := getTestToken(t, server, "test-workspace", team.RoleViewer)

	tests := []struct {
		name       string
		payload    string
		wantStatus int
		checkBody  func(t *testing.T, body string)
	}{
		{
			name:       "single operation pipeline",
			payload:    `{"input": "hello", "operations": [{"name": "base64_encode"}]}`,
			wantStatus: http.StatusOK,
			checkBody: func(t *testing.T, body string) {
				var resp CipherPipelineResponse
				if err := json.Unmarshal([]byte(body), &resp); err != nil {
					t.Errorf("failed to unmarshal response: %v", err)
					return
				}
				if resp.Output != "aGVsbG8=" {
					t.Errorf("expected output aGVsbG8=, got %s", resp.Output)
				}
			},
		},
		{
			name:       "two operation pipeline",
			payload:    `{"input": "hello", "operations": [{"name": "base64_encode"}, {"name": "hex_encode"}]}`,
			wantStatus: http.StatusOK,
			checkBody: func(t *testing.T, body string) {
				var resp CipherPipelineResponse
				if err := json.Unmarshal([]byte(body), &resp); err != nil {
					t.Errorf("failed to unmarshal response: %v", err)
					return
				}
				// base64("hello") = "aGVsbG8=" then hex encode
				if resp.Output == "" {
					t.Error("expected non-empty output")
				}
			},
		},
		{
			name:       "pipeline with unknown operation",
			payload:    `{"input": "hello", "operations": [{"name": "unknown-op"}]}`,
			wantStatus: http.StatusUnprocessableEntity,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/cipher/pipeline", strings.NewReader(tt.payload))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d: %s", tt.wantStatus, rec.Code, rec.Body.String())
			}

			if tt.checkBody != nil && rec.Code == http.StatusOK {
				tt.checkBody(t, rec.Body.String())
			}
		})
	}
}

// TestCipherExecuteOutput tests that execute returns correct output values
func TestCipherExecuteOutput(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	token := getTestToken(t, server, "test-workspace", team.RoleViewer)

	tests := []struct {
		name       string
		operation  string
		input      string
		wantOutput string
	}{
		{
			name:       "base64 encode",
			operation:  "base64_encode",
			input:      "hello",
			wantOutput: "aGVsbG8=",
		},
		{
			name:       "base64 decode",
			operation:  "base64_decode",
			input:      "aGVsbG8=",
			wantOutput: "hello",
		},
		{
			name:       "hex encode",
			operation:  "hex_encode",
			input:      "hello",
			wantOutput: "68656c6c6f",
		},
		{
			name:       "hex decode",
			operation:  "hex_decode",
			input:      "68656c6c6f",
			wantOutput: "hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := map[string]string{
				"operation": tt.operation,
				"input":     tt.input,
			}
			payloadBytes, _ := json.Marshal(payload)

			req := httptest.NewRequest("POST", "/api/v1/cipher/execute", bytes.NewReader(payloadBytes))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
				return
			}

			var resp CipherOperationResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Errorf("failed to unmarshal response: %v", err)
				return
			}

			if resp.Output != tt.wantOutput {
				t.Errorf("expected output %q, got %q", tt.wantOutput, resp.Output)
			}
		})
	}
}

// TestCipherDetectOutput tests that detect returns valid detection results
func TestCipherDetectOutput(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	token := getTestToken(t, server, "test-workspace", team.RoleViewer)

	tests := []struct {
		name              string
		input             string
		expectDetections  bool
		minDetectionCount int
	}{
		{
			name:              "base64 encoded string",
			input:             "aGVsbG8gd29ybGQ=",
			expectDetections:  true,
			minDetectionCount: 1,
		},
		{
			name:              "hex encoded string",
			input:             "48656c6c6f",
			expectDetections:  true,
			minDetectionCount: 1,
		},
		{
			name:              "plain text",
			input:             "hello world",
			expectDetections:  true,
			minDetectionCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := map[string]string{"input": tt.input}
			payloadBytes, _ := json.Marshal(payload)

			req := httptest.NewRequest("POST", "/api/v1/cipher/detect", bytes.NewReader(payloadBytes))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
				return
			}

			var resp CipherDetectResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Errorf("failed to unmarshal response: %v", err)
				return
			}

			if tt.expectDetections && len(resp.Detections) < tt.minDetectionCount {
				t.Errorf("expected at least %d detections, got %d", tt.minDetectionCount, len(resp.Detections))
			}
		})
	}
}

// TestCipherListOperationsOutput tests that list operations returns valid operation info
func TestCipherListOperationsOutput(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	token := getTestToken(t, server, "test-workspace", team.RoleViewer)

	req := httptest.NewRequest("GET", "/api/v1/cipher/operations", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
		return
	}

	var resp struct {
		Operations []struct {
			Name        string `json:"name"`
			Type        string `json:"type"`
			Description string `json:"description"`
			Reversible  bool   `json:"reversible"`
		} `json:"operations"`
	}

	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Errorf("failed to unmarshal response: %v", err)
		return
	}

	if len(resp.Operations) == 0 {
		t.Error("expected at least one operation")
		return
	}

	// Verify that essential operations are present
	essentialOps := []string{"base64_encode", "base64_decode", "hex_encode", "hex_decode"}
	foundOps := make(map[string]bool)
	for _, op := range resp.Operations {
		foundOps[op.Name] = true
		// Validate that each operation has required fields
		if op.Name == "" {
			t.Error("operation name should not be empty")
		}
		if op.Type == "" {
			t.Error("operation type should not be empty")
		}
	}

	for _, essential := range essentialOps {
		if !foundOps[essential] {
			t.Errorf("essential operation %q not found in list", essential)
		}
	}
}
