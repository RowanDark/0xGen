package modules

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/RowanDark/0xgen/internal/atlas"
)

// AuthModule detects authentication and access control issues.
type AuthModule struct {
	*atlas.BaseModule
}

// NewAuthModule creates a new authentication detection module.
func NewAuthModule(logger atlas.Logger, oastClient atlas.OASTClient) *AuthModule {
	base := atlas.NewBaseModule(
		"auth",
		"Authentication & Access Control Detection",
		"auth",
		atlas.SeverityHigh,
		logger,
		oastClient,
	)

	return &AuthModule{
		BaseModule: base,
	}
}

// SupportsTarget checks if this module can scan the target.
func (m *AuthModule) SupportsTarget(target *atlas.ScanTarget) bool {
	return true
}

// Scan performs authentication detection on the target.
func (m *AuthModule) Scan(ctx context.Context, target *atlas.ScanTarget) ([]*atlas.Finding, error) {
	var findings []*atlas.Finding

	// Check context cancellation
	select {
	case <-ctx.Done():
		return findings, ctx.Err()
	default:
	}

	// Test for missing authentication
	if finding := m.testMissingAuth(ctx, target); finding != nil {
		findings = append(findings, finding)
	}

	// Test for weak HTTP authentication
	if finding := m.testWeakHTTPAuth(ctx, target); finding != nil {
		findings = append(findings, finding)
	}

	// Test for exposed admin paths
	if finding := m.testExposedAdminPaths(ctx, target); finding != nil {
		findings = append(findings, finding)
	}

	return findings, nil
}

func (m *AuthModule) testMissingAuth(ctx context.Context, target *atlas.ScanTarget) *atlas.Finding {
	// Create request without authentication
	req, err := http.NewRequestWithContext(ctx, target.Method, target.URL, nil)
	if err != nil {
		return nil
	}

	resp, err := m.SendRequest(ctx, req)
	if err != nil {
		return nil
	}

	body, err := m.ReadBody(resp)
	if err != nil {
		return nil
	}

	// Check if got successful response without auth
	if resp.StatusCode == http.StatusOK {
		// Look for sensitive data patterns
		if m.containsSensitiveData(body) {
			return m.CreateFinding(target, "Missing Authentication", atlas.ConfidenceFirm, atlas.Evidence{
				Location: atlas.ParamLocationPath,
				Request:  atlas.FormatRequest(req),
				Response: atlas.TruncateBody(body, 1000),
				Proof:    "Endpoint accessible without authentication and contains sensitive data",
			})
		}
	}

	return nil
}

func (m *AuthModule) testWeakHTTPAuth(ctx context.Context, target *atlas.ScanTarget) *atlas.Finding {
	// Common default credentials
	defaultCreds := []struct {
		username string
		password string
	}{
		{"admin", "admin"},
		{"admin", "password"},
		{"admin", ""},
		{"root", "root"},
		{"administrator", "password"},
		{"user", "user"},
	}

	for _, cred := range defaultCreds {
		req, err := http.NewRequestWithContext(ctx, target.Method, target.URL, nil)
		if err != nil {
			continue
		}

		// Add basic auth
		req.SetBasicAuth(cred.username, cred.password)

		resp, err := m.SendRequest(ctx, req)
		if err != nil {
			continue
		}

		// Check if authentication succeeded
		if resp.StatusCode == http.StatusOK {
			body, _ := m.ReadBody(resp)
			return m.CreateFinding(target, "Weak Default Credentials", atlas.ConfidenceConfirmed, atlas.Evidence{
				Location: atlas.ParamLocationHeader,
				Request:  atlas.FormatRequest(req),
				Response: atlas.TruncateBody(body, 1000),
				Proof:    fmt.Sprintf("Default credentials accepted: %s:%s", cred.username, cred.password),
			})
		}
	}

	return nil
}

func (m *AuthModule) testExposedAdminPaths(ctx context.Context, target *atlas.ScanTarget) *atlas.Finding {
	// Common admin paths
	adminPaths := []string{
		"/admin",
		"/admin/",
		"/administrator",
		"/admin/login",
		"/admin/dashboard",
		"/wp-admin/",
		"/phpmyadmin/",
		"/cpanel/",
	}

	baseURL := m.getBaseURL(target.URL)

	for _, path := range adminPaths {
		testURL := baseURL + path

		req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
		if err != nil {
			continue
		}

		resp, err := m.SendRequest(ctx, req)
		if err != nil {
			continue
		}

		// Check if admin path is accessible
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound {
			body, _ := m.ReadBody(resp)
			if m.isAdminInterface(body) {
				return m.CreateFinding(target, "Exposed Admin Interface", atlas.ConfidenceFirm, atlas.Evidence{
					Location: atlas.ParamLocationPath,
					Request:  atlas.FormatRequest(req),
					Response: atlas.TruncateBody(body, 1000),
					Proof:    fmt.Sprintf("Admin interface accessible at %s", path),
				})
			}
		}
	}

	return nil
}

func (m *AuthModule) containsSensitiveData(body string) bool {
	bodyLower := strings.ToLower(body)
	patterns := []string{
		"password",
		"api_key",
		"apikey",
		"secret",
		"token",
		"private",
		"credit card",
		"ssn",
		"social security",
	}

	// Check for at least 2 sensitive patterns
	count := 0
	for _, pattern := range patterns {
		if strings.Contains(bodyLower, pattern) {
			count++
			if count >= 2 {
				return true
			}
		}
	}

	return false
}

func (m *AuthModule) isAdminInterface(body string) bool {
	bodyLower := strings.ToLower(body)
	patterns := []string{
		"admin panel",
		"administration",
		"dashboard",
		"control panel",
		"admin login",
		"administrator login",
	}

	for _, pattern := range patterns {
		if strings.Contains(bodyLower, pattern) {
			return true
		}
	}

	return false
}

func (m *AuthModule) getBaseURL(fullURL string) string {
	// Extract base URL (protocol + host + port)
	if idx := strings.Index(fullURL, "://"); idx != -1 {
		remaining := fullURL[idx+3:]
		if pathIdx := strings.Index(remaining, "/"); pathIdx != -1 {
			return fullURL[:idx+3+pathIdx]
		}
		return fullURL
	}
	return fullURL
}
