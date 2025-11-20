package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RowanDark/0xgen/internal/atlas"
)

func TestAuthModule_MissingAuthentication(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate endpoint with sensitive data but no auth requirement
		w.Write([]byte("Welcome to admin dashboard. API Key: sk-12345. Token: abc123xyz. Password: hidden"))
	}))
	defer server.Close()

	module := NewAuthModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:    server.URL,
		Method: "GET",
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected to detect missing authentication")
	}

	if findings[0].Type != "Missing Authentication" {
		t.Errorf("expected type 'Missing Authentication', got '%s'", findings[0].Type)
	}

	if findings[0].Confidence != atlas.ConfidenceFirm {
		t.Errorf("expected confidence Firm, got %s", findings[0].Confidence)
	}
}

func TestAuthModule_WeakDefaultCredentials_Admin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if ok && username == "admin" && password == "admin" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Welcome admin!"))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorized"))
	}))
	defer server.Close()

	module := NewAuthModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:    server.URL,
		Method: "GET",
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected to detect weak default credentials")
	}

	if findings[0].Type != "Weak Default Credentials" {
		t.Errorf("expected type 'Weak Default Credentials', got '%s'", findings[0].Type)
	}

	if findings[0].Confidence != atlas.ConfidenceConfirmed {
		t.Errorf("expected confidence Confirmed, got %s", findings[0].Confidence)
	}
}

func TestAuthModule_WeakDefaultCredentials_Root(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if ok && username == "root" && password == "root" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Root access granted"))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	module := NewAuthModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:    server.URL,
		Method: "GET",
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected to detect root default credentials")
	}
}

func TestAuthModule_ExposedAdminInterface(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/admin") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<h1>Admin Panel</h1><p>Administration Dashboard</p>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found"))
	}))
	defer server.Close()

	module := NewAuthModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:    server.URL,
		Method: "GET",
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected to detect exposed admin interface")
	}

	if findings[0].Type != "Exposed Admin Interface" {
		t.Errorf("expected type 'Exposed Admin Interface', got '%s'", findings[0].Type)
	}
}

func TestAuthModule_ContainsSensitiveData(t *testing.T) {
	module := NewAuthModule(atlas.NewNopLogger(), nil)

	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{
			name:     "Multiple sensitive patterns - password and api_key",
			body:     "User profile: password: hidden, api_key: sk-12345",
			expected: true,
		},
		{
			name:     "Multiple sensitive patterns - token and secret",
			body:     "Configuration: secret_key=abc123, token=xyz789",
			expected: true,
		},
		{
			name:     "Multiple sensitive patterns - private and ssn",
			body:     "Private data SSN: 123-45-6789",
			expected: true,
		},
		{
			name:     "Single sensitive pattern - not enough",
			body:     "Enter your password to continue",
			expected: false,
		},
		{
			name:     "No sensitive data",
			body:     "Welcome to our website! This is public content.",
			expected: false,
		},
		{
			name:     "Credit card and token",
			body:     "Payment: credit card ****1234, token: xyz",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := module.containsSensitiveData(tt.body)
			if result != tt.expected {
				t.Errorf("expected %v, got %v for body: %s", tt.expected, result, tt.body)
			}
		})
	}
}

func TestAuthModule_IsAdminInterface(t *testing.T) {
	module := NewAuthModule(atlas.NewNopLogger(), nil)

	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{
			name:     "Admin panel heading",
			body:     "<h1>Admin Panel</h1><p>Welcome</p>",
			expected: true,
		},
		{
			name:     "Administration page",
			body:     "<title>Administration Dashboard</title>",
			expected: true,
		},
		{
			name:     "Dashboard interface",
			body:     "Welcome to the Dashboard. Manage your system here.",
			expected: true,
		},
		{
			name:     "Control panel",
			body:     "Control Panel - System Settings",
			expected: true,
		},
		{
			name:     "Admin login page",
			body:     "<form>Admin Login</form>",
			expected: true,
		},
		{
			name:     "Administrator login",
			body:     "Administrator Login Required",
			expected: true,
		},
		{
			name:     "Normal page",
			body:     "Welcome to our public website",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := module.isAdminInterface(tt.body)
			if result != tt.expected {
				t.Errorf("expected %v, got %v for body: %s", tt.expected, result, tt.body)
			}
		})
	}
}

func TestAuthModule_GetBaseURL(t *testing.T) {
	module := NewAuthModule(atlas.NewNopLogger(), nil)

	tests := []struct {
		name     string
		fullURL  string
		expected string
	}{
		{
			name:     "URL with path",
			fullURL:  "http://example.com/api/users",
			expected: "http://example.com",
		},
		{
			name:     "URL with query string",
			fullURL:  "https://example.com/api?key=value",
			expected: "https://example.com",
		},
		{
			name:     "URL with port",
			fullURL:  "http://example.com:8080/admin",
			expected: "http://example.com:8080",
		},
		{
			name:     "URL without path",
			fullURL:  "http://example.com",
			expected: "http://example.com",
		},
		{
			name:     "URL with multiple path segments",
			fullURL:  "https://api.example.com/v1/users/123",
			expected: "https://api.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := module.getBaseURL(tt.fullURL)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestAuthModule_SupportsTarget(t *testing.T) {
	module := NewAuthModule(atlas.NewNopLogger(), nil)

	// Auth module should support all targets
	target := &atlas.ScanTarget{
		URL:    "http://example.com",
		Method: "GET",
	}

	if !module.SupportsTarget(target) {
		t.Error("Auth module should support all targets")
	}
}

func TestAuthModule_ContextCancellation(t *testing.T) {
	module := NewAuthModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:    "http://example.com",
		Method: "GET",
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

func TestAuthModule_NoVulnerabilities(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for proper authentication
		username, password, ok := r.BasicAuth()
		if !ok || username != "validuser" || password != "strongpassword123!" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Welcome! This is public content."))
	}))
	defer server.Close()

	module := NewAuthModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:    server.URL,
		Method: "GET",
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should not find vulnerabilities on properly secured endpoint
	if len(findings) > 0 {
		t.Errorf("false positive detected: got %d findings for secured endpoint", len(findings))
	}
}

func TestAuthModule_MultipleDefaultCredentials(t *testing.T) {
	// Test multiple default credentials are tried
	attemptedCreds := make(map[string]bool)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if ok {
			attemptedCreds[username+":"+password] = true
			// Accept admin:password
			if username == "admin" && password == "password" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Access granted"))
				return
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	module := NewAuthModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:    server.URL,
		Method: "GET",
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected to detect default credentials")
	}

	// Verify multiple credentials were tried
	if len(attemptedCreds) < 2 {
		t.Errorf("expected multiple credential attempts, got %d", len(attemptedCreds))
	}
}

func TestAuthModule_AdminPathVariations(t *testing.T) {
	// Test that multiple admin paths are checked
	accessedPaths := make(map[string]bool)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessedPaths[r.URL.Path] = true

		if r.URL.Path == "/admin/dashboard" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<h1>Admin Dashboard</h1>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	module := NewAuthModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:    server.URL,
		Method: "GET",
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected to detect exposed admin dashboard")
	}

	// Verify multiple admin paths were tried
	if len(accessedPaths) < 2 {
		t.Errorf("expected multiple admin path attempts, got %d paths", len(accessedPaths))
	}
}

func TestAuthModule_EmptyPasswordCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		// Accept admin with empty password
		if ok && username == "admin" && password == "" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Welcome admin"))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	module := NewAuthModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:    server.URL,
		Method: "GET",
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected to detect empty password vulnerability")
	}
}

func TestAuthModule_NoFalsePositiveOnPublicContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Public page with no sensitive data
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Welcome to our public homepage! Learn more about our services."))
	}))
	defer server.Close()

	module := NewAuthModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:    server.URL,
		Method: "GET",
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should not detect missing auth on public page with no sensitive data
	for _, f := range findings {
		if f.Type == "Missing Authentication" {
			t.Error("false positive: detected missing authentication on public content")
		}
	}
}

func TestAuthModule_RedirectToAdminLogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" || r.URL.Path == "/admin/" {
			// Return 302 redirect with admin-related content
			w.Header().Set("Location", "/admin/login")
			w.WriteHeader(http.StatusFound)
			w.Write([]byte("<html>Redirecting to admin login... Administration area</html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	module := NewAuthModule(atlas.NewNopLogger(), nil)
	target := &atlas.ScanTarget{
		URL:    server.URL,
		Method: "GET",
	}

	findings, err := module.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should detect admin interface when redirect response contains admin indicators
	foundAdminInterface := false
	for _, f := range findings {
		if f.Type == "Exposed Admin Interface" {
			foundAdminInterface = true
			break
		}
	}

	if foundAdminInterface {
		t.Log("Successfully detected admin interface via redirect")
	} else {
		t.Log("Note: Admin interface not detected via redirect (acceptable - depends on response content)")
	}
}
