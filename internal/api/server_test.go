package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/findings"
	"github.com/RowanDark/0xgen/internal/team"
)

// setupTestServer creates a test server with minimal configuration
func setupTestServer(t *testing.T) *Server {
	t.Helper()

	// Create temporary directories for test
	tempDir := t.TempDir()
	recipesDir := tempDir + "/recipes"
	if err := os.MkdirAll(recipesDir, 0755); err != nil {
		t.Fatalf("Failed to create recipes dir: %v", err)
	}

	// Create a minimal signing key file for testing
	signingKeyPath := tempDir + "/signing.key"
	if err := os.WriteFile(signingKeyPath, []byte("test-signing-key-content"), 0600); err != nil {
		t.Fatalf("Failed to create signing key: %v", err)
	}

	// Create workspace store
	store := team.NewStore(nil)

	cfg := Config{
		Addr:            ":0",
		StaticToken:     "test-static-token",
		JWTSecret:       []byte("test-jwt-secret-key-12345"),
		JWTIssuer:       "test-issuer",
		DefaultTokenTTL: time.Hour,
		SigningKeyPath:  signingKeyPath,
		FindingsBus:     findings.NewBus(),
		WorkspaceStore:  store,
		RecipesDir:      recipesDir,
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	return server
}

// getTestToken creates a valid token for testing authenticated requests
func getTestToken(t *testing.T, server *Server, workspaceID string, role team.Role) string {
	t.Helper()

	// Add user to workspace with role
	_, err := server.teams.UpsertMembership(workspaceID, "test-user", role)
	if err != nil {
		t.Fatalf("UpsertMembership failed: %v", err)
	}

	token, _, err := server.authenticator.MintWithOptions("test-user", TokenOptions{
		Audience:    "test",
		WorkspaceID: workspaceID,
		Role:        string(role),
	})
	if err != nil {
		t.Fatalf("MintWithOptions failed: %v", err)
	}

	return token
}

// createTestMux creates the HTTP mux with routes for testing
func createTestMux(t *testing.T, server *Server) *http.ServeMux {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/api/v1/api-tokens", http.HandlerFunc(server.handleTokenIssue))
	mux.Handle("/api/v1/plugins", server.requireRole(team.RoleViewer, http.HandlerFunc(server.handleListPlugins)))
	mux.Handle("/api/v1/scans", server.requireRole(team.RoleAnalyst, http.HandlerFunc(server.handleScans)))
	mux.Handle("/api/v1/scans/", server.requireRole(team.RoleViewer, http.HandlerFunc(server.handleScanByID)))

	// Cipher endpoints - require at least Viewer role
	mux.Handle("/api/v1/cipher/execute", server.requireRole(team.RoleViewer, http.HandlerFunc(server.handleCipherExecute)))
	mux.Handle("/api/v1/cipher/pipeline", server.requireRole(team.RoleViewer, http.HandlerFunc(server.handleCipherPipeline)))
	mux.Handle("/api/v1/cipher/detect", server.requireRole(team.RoleViewer, http.HandlerFunc(server.handleCipherDetect)))
	mux.Handle("/api/v1/cipher/smart-decode", server.requireRole(team.RoleViewer, http.HandlerFunc(server.handleCipherSmartDecode)))
	mux.Handle("/api/v1/cipher/operations", server.requireRole(team.RoleViewer, http.HandlerFunc(server.handleCipherListOperations)))
	mux.Handle("/api/v1/cipher/recipes/save", server.requireRole(team.RoleViewer, http.HandlerFunc(server.handleRecipeSave)))
	mux.Handle("/api/v1/cipher/recipes/list", server.requireRole(team.RoleViewer, http.HandlerFunc(server.handleRecipeList)))
	mux.Handle("/api/v1/cipher/recipes/load", server.requireRole(team.RoleViewer, http.HandlerFunc(server.handleRecipeLoad)))
	mux.Handle("/api/v1/cipher/recipes/delete", server.requireRole(team.RoleViewer, http.HandlerFunc(server.handleRecipeDelete)))

	return mux
}

func TestCipherEndpointsRequireAuth(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	endpoints := []string{
		"/api/v1/cipher/execute",
		"/api/v1/cipher/pipeline",
		"/api/v1/cipher/detect",
		"/api/v1/cipher/smart-decode",
		"/api/v1/cipher/operations",
		"/api/v1/cipher/recipes/save",
		"/api/v1/cipher/recipes/list",
		"/api/v1/cipher/recipes/load",
		"/api/v1/cipher/recipes/delete",
	}

	for _, endpoint := range endpoints {
		t.Run(endpoint, func(t *testing.T) {
			// Request without auth
			req := httptest.NewRequest("POST", endpoint, bytes.NewReader([]byte("{}")))
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("expected status %d, got %d for %s", http.StatusUnauthorized, rec.Code, endpoint)
			}
		})
	}
}

func TestCipherEndpointsWithValidAuth(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	// Get a valid token with Viewer role
	token := getTestToken(t, server, "test-workspace", team.RoleViewer)

	// Test that authenticated requests are allowed (may fail for other reasons but not auth)
	endpoints := []string{
		"/api/v1/cipher/operations",
		"/api/v1/cipher/recipes/list",
	}

	for _, endpoint := range endpoints {
		t.Run(endpoint, func(t *testing.T) {
			req := httptest.NewRequest("POST", endpoint, bytes.NewReader([]byte("{}")))
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			// Should NOT be unauthorized - may be other error but not 401
			if rec.Code == http.StatusUnauthorized {
				t.Errorf("got unexpected 401 Unauthorized for %s with valid token", endpoint)
			}
		})
	}
}

func TestCipherEndpointsWithInvalidToken(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	endpoints := []string{
		"/api/v1/cipher/execute",
		"/api/v1/cipher/pipeline",
		"/api/v1/cipher/detect",
	}

	for _, endpoint := range endpoints {
		t.Run(endpoint, func(t *testing.T) {
			req := httptest.NewRequest("POST", endpoint, bytes.NewReader([]byte("{}")))
			req.Header.Set("Authorization", "Bearer invalid-token")
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("expected status %d, got %d for %s with invalid token", http.StatusUnauthorized, rec.Code, endpoint)
			}
		})
	}
}

func TestCipherEndpointsWithMissingBearerPrefix(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	token := getTestToken(t, server, "test-workspace", team.RoleViewer)

	req := httptest.NewRequest("POST", "/api/v1/cipher/execute", bytes.NewReader([]byte("{}")))
	req.Header.Set("Authorization", token) // Missing "Bearer " prefix
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestCipherEndpointsWithInsufficientRole(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	// Create a token but don't add user to workspace
	token, _, err := server.authenticator.MintWithOptions("test-user-no-role", TokenOptions{
		Audience:    "test",
		WorkspaceID: "test-workspace",
		Role:        string(team.RoleViewer),
	})
	if err != nil {
		t.Fatalf("MintWithOptions failed: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/v1/cipher/execute", bytes.NewReader([]byte("{}")))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, rec.Code)
	}
}

func TestCipherEndpointsWithMissingWorkspaceClaim(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	// Create a token without workspace
	token, _, err := server.authenticator.MintWithOptions("test-user", TokenOptions{
		Audience: "test",
		// No WorkspaceID
	})
	if err != nil {
		t.Fatalf("MintWithOptions failed: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/v1/cipher/execute", bytes.NewReader([]byte("{}")))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, rec.Code)
	}
}

func TestHealthzEndpointNoAuth(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestCipherEndpointAllRolesCanAccess(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	roles := []team.Role{
		team.RoleViewer,
		team.RoleAnalyst,
		team.RoleAdmin,
	}

	for _, role := range roles {
		t.Run(string(role), func(t *testing.T) {
			workspaceID := "workspace-" + string(role)
			token := getTestToken(t, server, workspaceID, role)

			req := httptest.NewRequest("POST", "/api/v1/cipher/operations", bytes.NewReader([]byte("{}")))
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			// Should not be unauthorized or forbidden
			if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
				t.Errorf("role %s should have access, got status %d", role, rec.Code)
			}
		})
	}
}

func TestServerRunAndShutdown(t *testing.T) {
	server := setupTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Run(ctx)
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Cancel context to trigger shutdown
	cancel()

	// Wait for server to stop
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Server did not shut down in time")
	}
}

func TestTokenIssueEndpoint(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	// Test without static token
	t.Run("missing static token", func(t *testing.T) {
		body := map[string]interface{}{
			"subject":  "user1",
			"audience": "test",
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest("POST", "/api/v1/api-tokens", bytes.NewReader(bodyBytes))
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
		}
	})

	// Test with valid static token
	t.Run("valid static token", func(t *testing.T) {
		body := map[string]interface{}{
			"subject":      "user1",
			"audience":     "test",
			"workspace_id": "ws1",
			"role":         "viewer",
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest("POST", "/api/v1/api-tokens", bytes.NewReader(bodyBytes))
		req.Header.Set("X-0xgen-Token", "test-static-token")
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		if _, ok := resp["token"]; !ok {
			t.Error("response should contain token")
		}
		if _, ok := resp["expires_at"]; !ok {
			t.Error("response should contain expires_at")
		}
	})
}

// TestScansEndpointAuth tests authentication requirements for scan endpoints
func TestScansEndpointAuth(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	endpoints := []struct {
		name   string
		method string
		path   string
	}{
		{"POST /api/v1/scans", "POST", "/api/v1/scans"},
		{"GET /api/v1/scans/123", "GET", "/api/v1/scans/123"},
		{"GET /api/v1/scans/123/results", "GET", "/api/v1/scans/123/results"},
	}

	for _, ep := range endpoints {
		t.Run(ep.name+" without auth", func(t *testing.T) {
			req := httptest.NewRequest(ep.method, ep.path, bytes.NewReader([]byte("{}")))
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
			}
		})
	}
}

// TestScansEndpointRoleRequirements tests that scan endpoints require appropriate roles
func TestScansEndpointRoleRequirements(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	// Viewer can read scan status but not create scans
	viewerToken := getTestToken(t, server, "test-workspace", team.RoleViewer)
	analystToken := getTestToken(t, server, "test-workspace-2", team.RoleAnalyst)

	t.Run("viewer cannot create scans", func(t *testing.T) {
		body := `{"plugin": "test-plugin"}`
		req := httptest.NewRequest("POST", "/api/v1/scans", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+viewerToken)
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("expected status %d, got %d", http.StatusForbidden, rec.Code)
		}
	})

	t.Run("analyst can create scans", func(t *testing.T) {
		body := `{"plugin": "test-plugin"}`
		req := httptest.NewRequest("POST", "/api/v1/scans", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+analystToken)
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		// May fail for other reasons (no plugin) but not 401/403
		if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
			t.Errorf("expected access allowed, got status %d", rec.Code)
		}
	})

	t.Run("viewer can read scan status", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/scans/nonexistent-scan", nil)
		req.Header.Set("Authorization", "Bearer "+viewerToken)
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		// Should be 404 (not found) not 401/403
		if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
			t.Errorf("expected access allowed, got status %d", rec.Code)
		}
	})
}

// TestPluginsEndpointAuth tests authentication for plugins endpoint
func TestPluginsEndpointAuth(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	t.Run("without auth", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/plugins", nil)
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
		}
	})

	t.Run("with valid auth", func(t *testing.T) {
		token := getTestToken(t, server, "test-workspace", team.RoleViewer)
		req := httptest.NewRequest("GET", "/api/v1/plugins", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		// May fail for other reasons but not auth
		if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
			t.Errorf("expected access allowed, got status %d", rec.Code)
		}
	})
}

// TestAuthorizationHeaderFormats tests various authorization header formats
func TestAuthorizationHeaderFormats(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	token := getTestToken(t, server, "test-workspace", team.RoleViewer)

	tests := []struct {
		name       string
		authHeader string
		wantAuth   bool
	}{
		{
			name:       "valid Bearer format",
			authHeader: "Bearer " + token,
			wantAuth:   true,
		},
		{
			name:       "lowercase bearer",
			authHeader: "bearer " + token,
			wantAuth:   true,
		},
		{
			name:       "missing Bearer prefix",
			authHeader: token,
			wantAuth:   false,
		},
		{
			name:       "Basic auth instead of Bearer",
			authHeader: "Basic dXNlcjpwYXNz",
			wantAuth:   false,
		},
		{
			name:       "empty header",
			authHeader: "",
			wantAuth:   false,
		},
		{
			name:       "Bearer with extra spaces",
			authHeader: "Bearer   " + token,
			wantAuth:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/cipher/operations", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if tt.wantAuth {
				if rec.Code == http.StatusUnauthorized {
					t.Errorf("expected auth to succeed, got 401")
				}
			} else {
				if rec.Code != http.StatusUnauthorized {
					t.Errorf("expected auth to fail with 401, got %d", rec.Code)
				}
			}
		})
	}
}

// TestTokenExpiration tests that expired tokens are rejected
func TestTokenExpiration(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	// Create a token with a very short TTL that will expire immediately
	// Note: We can't easily test this without mocking time, so we test the structure
	_, err := server.teams.UpsertMembership("test-workspace", "expiry-user", team.RoleViewer)
	if err != nil {
		t.Fatalf("UpsertMembership failed: %v", err)
	}

	// Create token with 1 second TTL
	token, _, err := server.authenticator.MintWithOptions("expiry-user", TokenOptions{
		Audience:    "test",
		WorkspaceID: "test-workspace",
		Role:        string(team.RoleViewer),
		TTL:         time.Second,
	})
	if err != nil {
		t.Fatalf("MintWithOptions failed: %v", err)
	}

	// Token should work immediately
	req := httptest.NewRequest("GET", "/api/v1/cipher/operations", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code == http.StatusUnauthorized {
		t.Errorf("fresh token should be valid, got %d", rec.Code)
	}

	// Wait for token to expire
	time.Sleep(2 * time.Second)

	// Token should now be expired
	req = httptest.NewRequest("GET", "/api/v1/cipher/operations", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expired token should return 401, got %d", rec.Code)
	}
}

// TestConcurrentAuthRequests tests concurrent authentication handling
func TestConcurrentAuthRequests(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	// Create tokens for different workspaces
	tokens := make([]string, 10)
	for i := 0; i < 10; i++ {
		workspaceID := "workspace-" + string(rune('0'+i))
		tokens[i] = getTestToken(t, server, workspaceID, team.RoleViewer)
	}

	const numRequests = 200
	var wg sync.WaitGroup
	errors := make(chan string, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			token := tokens[idx%len(tokens)]
			req := httptest.NewRequest("GET", "/api/v1/cipher/operations", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				errors <- rec.Body.String()
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent auth request failed: %s", err)
	}
}

// TestTokenIssueWithDifferentRoles tests token issuance for all roles
func TestTokenIssueWithDifferentRoles(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	roles := []string{"viewer", "analyst", "admin"}

	for _, role := range roles {
		t.Run("role_"+role, func(t *testing.T) {
			body := map[string]interface{}{
				"subject":      "user-" + role,
				"audience":     "test",
				"workspace_id": "ws-" + role,
				"role":         role,
			}
			bodyBytes, _ := json.Marshal(body)

			req := httptest.NewRequest("POST", "/api/v1/api-tokens", bytes.NewReader(bodyBytes))
			req.Header.Set("X-0xgen-Token", "test-static-token")
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestTokenIssueWithInvalidRole tests that invalid roles are rejected
func TestTokenIssueWithInvalidRole(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	body := map[string]interface{}{
		"subject":      "user1",
		"audience":     "test",
		"workspace_id": "ws1",
		"role":         "superadmin", // Invalid role
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/api-tokens", bytes.NewReader(bodyBytes))
	req.Header.Set("X-0xgen-Token", "test-static-token")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d: %s", http.StatusBadRequest, rec.Code, rec.Body.String())
	}
}

// TestTokenIssueMethodValidation tests method validation for token endpoint
func TestTokenIssueMethodValidation(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	methods := []string{"GET", "PUT", "DELETE", "PATCH"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/v1/api-tokens", nil)
			req.Header.Set("X-0xgen-Token", "test-static-token")
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
			}
		})
	}
}

// TestWriteJSONResponse tests JSON response writing
func TestWriteJSONResponse(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	token := getTestToken(t, server, "test-workspace", team.RoleViewer)

	req := httptest.NewRequest("GET", "/api/v1/cipher/operations", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	// Check Content-Type header
	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", contentType)
	}

	// Verify response is valid JSON
	var resp interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Errorf("response is not valid JSON: %v", err)
	}
}

// TestServerConfigValidation tests server configuration validation
func TestServerConfigValidation(t *testing.T) {
	tempDir := t.TempDir()

	// Create signing key
	signingKeyPath := tempDir + "/signing.key"
	if err := os.WriteFile(signingKeyPath, []byte("test-signing-key"), 0600); err != nil {
		t.Fatalf("Failed to create signing key: %v", err)
	}

	tests := []struct {
		name      string
		cfg       Config
		wantError bool
	}{
		{
			name: "valid config",
			cfg: Config{
				Addr:            ":8080",
				StaticToken:     "token",
				JWTSecret:       []byte("secret"),
				JWTIssuer:       "issuer",
				DefaultTokenTTL: time.Hour,
				SigningKeyPath:  signingKeyPath,
				FindingsBus:     findings.NewBus(),
			},
			wantError: false,
		},
		{
			name: "missing address",
			cfg: Config{
				Addr:            "",
				StaticToken:     "token",
				JWTSecret:       []byte("secret"),
				JWTIssuer:       "issuer",
				DefaultTokenTTL: time.Hour,
				SigningKeyPath:  signingKeyPath,
				FindingsBus:     findings.NewBus(),
			},
			wantError: true,
		},
		{
			name: "missing static token",
			cfg: Config{
				Addr:            ":8080",
				StaticToken:     "",
				JWTSecret:       []byte("secret"),
				JWTIssuer:       "issuer",
				DefaultTokenTTL: time.Hour,
				SigningKeyPath:  signingKeyPath,
				FindingsBus:     findings.NewBus(),
			},
			wantError: true,
		},
		{
			name: "missing findings bus",
			cfg: Config{
				Addr:            ":8080",
				StaticToken:     "token",
				JWTSecret:       []byte("secret"),
				JWTIssuer:       "issuer",
				DefaultTokenTTL: time.Hour,
				SigningKeyPath:  signingKeyPath,
				FindingsBus:     nil,
			},
			wantError: true,
		},
		{
			name: "missing signing key path",
			cfg: Config{
				Addr:            ":8080",
				StaticToken:     "token",
				JWTSecret:       []byte("secret"),
				JWTIssuer:       "issuer",
				DefaultTokenTTL: time.Hour,
				SigningKeyPath:  "",
				FindingsBus:     findings.NewBus(),
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewServer(tt.cfg)
			if tt.wantError && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("expected no error but got: %v", err)
			}
		})
	}
}

// TestHealthzNoAuth verifies healthz doesn't require auth
func TestHealthzNoAuth(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	if rec.Body.String() != "ok" {
		t.Errorf("expected body 'ok', got %q", rec.Body.String())
	}
}

// TestScanNotFound tests scan status for non-existent scan
func TestScanNotFound(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	token := getTestToken(t, server, "test-workspace", team.RoleViewer)

	req := httptest.NewRequest("GET", "/api/v1/scans/nonexistent-scan-id", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, rec.Code)
	}
}

// TestScanResultsNotComplete tests getting results for incomplete scan
func TestScanResultsNotComplete(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	token := getTestToken(t, server, "test-workspace", team.RoleViewer)

	// First, the scan should not exist
	req := httptest.NewRequest("GET", "/api/v1/scans/fake-scan/results", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	// Should be 404 since scan doesn't exist
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, rec.Code)
	}
}

// TestScanMethodValidation tests HTTP method validation for scan endpoints
func TestScanMethodValidation(t *testing.T) {
	server := setupTestServer(t)
	mux := createTestMux(t, server)

	token := getTestToken(t, server, "test-workspace", team.RoleAnalyst)

	tests := []struct {
		name     string
		method   string
		path     string
		wantCode int
	}{
		{
			name:     "scans endpoint with GET",
			method:   "GET",
			path:     "/api/v1/scans",
			wantCode: http.StatusMethodNotAllowed,
		},
		{
			name:     "scan status with POST",
			method:   "POST",
			path:     "/api/v1/scans/123",
			wantCode: http.StatusMethodNotAllowed,
		},
		{
			name:     "scan results with POST",
			method:   "POST",
			path:     "/api/v1/scans/123/results",
			wantCode: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, bytes.NewReader([]byte("{}")))
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != tt.wantCode {
				t.Errorf("expected status %d, got %d", tt.wantCode, rec.Code)
			}
		})
	}
}
