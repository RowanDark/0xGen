package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
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
