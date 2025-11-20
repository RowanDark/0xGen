package modules

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/RowanDark/0xgen/internal/atlas"
)

// SSRFModule detects Server-Side Request Forgery vulnerabilities.
type SSRFModule struct {
	*atlas.BaseModule
}

// NewSSRFModule creates a new SSRF detection module.
func NewSSRFModule(logger atlas.Logger, oastClient atlas.OASTClient) *SSRFModule {
	base := atlas.NewBaseModule(
		"ssrf",
		"Server-Side Request Forgery Detection",
		"injection",
		atlas.SeverityHigh,
		logger,
		oastClient,
	)

	return &SSRFModule{
		BaseModule: base,
	}
}

// SupportsTarget checks if this module can scan the target.
func (m *SSRFModule) SupportsTarget(target *atlas.ScanTarget) bool {
	// SSRF typically affects endpoints with URL parameters
	return true
}

// Scan performs SSRF detection on the target.
func (m *SSRFModule) Scan(ctx context.Context, target *atlas.ScanTarget) ([]*atlas.Finding, error) {
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

		// Test with cloud metadata endpoints
		if finding := m.testCloudMetadata(ctx, target, paramName); finding != nil {
			findings = append(findings, finding)
			continue
		}

		// Test with local file access
		if finding := m.testLocalFiles(ctx, target, paramName); finding != nil {
			findings = append(findings, finding)
			continue
		}

		// Test with OAST callback
		if finding := m.testWithOAST(ctx, target, paramName); finding != nil {
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

func (m *SSRFModule) testCloudMetadata(ctx context.Context, target *atlas.ScanTarget, param string) *atlas.Finding {
	metadataURLs := []string{
		"http://169.254.169.254/latest/meta-data/",           // AWS
		"http://metadata.google.internal/computeMetadata/v1/", // GCP
		"http://169.254.169.254/metadata/instance?api-version=2021-02-01", // Azure
	}

	for _, metadataURL := range metadataURLs {
		resp, err := m.sendTestRequest(ctx, target, param, metadataURL)
		if err != nil {
			continue
		}

		body, err := m.ReadBody(resp)
		if err != nil {
			continue
		}

		// Check for metadata response patterns
		if m.isMetadataResponse(body) {
			return m.CreateFinding(target, "Server-Side Request Forgery (Cloud Metadata)", atlas.ConfidenceConfirmed, atlas.Evidence{
				Parameter: param,
				Location:  m.getParamLocation(target, param),
				Request:   atlas.FormatRequest(resp.Request),
				Response:  atlas.TruncateBody(body, 1000),
				Payload:   metadataURL,
				Proof:     "Cloud metadata endpoint accessible",
			})
		}
	}

	return nil
}

func (m *SSRFModule) testLocalFiles(ctx context.Context, target *atlas.ScanTarget, param string) *atlas.Finding {
	fileURLs := []string{
		"file:///etc/passwd",
		"file:///c:/windows/win.ini",
		"file:///proc/self/environ",
	}

	for _, fileURL := range fileURLs {
		resp, err := m.sendTestRequest(ctx, target, param, fileURL)
		if err != nil {
			continue
		}

		body, err := m.ReadBody(resp)
		if err != nil {
			continue
		}

		// Check for file content patterns
		if m.isFileContent(body) {
			return m.CreateFinding(target, "Server-Side Request Forgery (Local File)", atlas.ConfidenceConfirmed, atlas.Evidence{
				Parameter: param,
				Location:  m.getParamLocation(target, param),
				Request:   atlas.FormatRequest(resp.Request),
				Response:  atlas.TruncateBody(body, 1000),
				Payload:   fileURL,
				Proof:     "Local file content retrieved",
			})
		}
	}

	return nil
}

func (m *SSRFModule) testWithOAST(ctx context.Context, target *atlas.ScanTarget, param string) *atlas.Finding {
	if m.BaseModule == nil || m.BaseModule.OASTClient() == nil {
		return nil
	}

	// Generate OAST callback
	callback, err := m.BaseModule.OASTClient().GeneratePayload(ctx, fmt.Sprintf("ssrf-%s", param))
	if err != nil {
		return nil
	}

	// Test with HTTP callback
	resp, err := m.sendTestRequest(ctx, target, param, "http://"+callback)
	if err != nil {
		return nil
	}

	// Wait for callback
	time.Sleep(2 * time.Second)

	// Check for interactions
	interactions, err := m.BaseModule.OASTClient().CheckInteractions(ctx, fmt.Sprintf("ssrf-%s", param))
	if err != nil || len(interactions) == 0 {
		return nil
	}

	body, _ := m.ReadBody(resp)
	return m.CreateFinding(target, "Server-Side Request Forgery (Blind)", atlas.ConfidenceConfirmed, atlas.Evidence{
		Parameter: param,
		Location:  m.getParamLocation(target, param),
		Request:   atlas.FormatRequest(resp.Request),
		Response:  atlas.TruncateBody(body, 1000),
		Payload:   "http://" + callback,
		Proof:     fmt.Sprintf("Out-of-band callback received (%d interactions)", len(interactions)),
	})
}

func (m *SSRFModule) isMetadataResponse(body string) bool {
	bodyLower := strings.ToLower(body)
	patterns := []string{
		"ami-id",
		"instance-id",
		"hostname",
		"computemetadata",
		"meta-data",
		"instanceid",
	}

	for _, pattern := range patterns {
		if strings.Contains(bodyLower, pattern) {
			return true
		}
	}
	return false
}

func (m *SSRFModule) isFileContent(body string) bool {
	patterns := []string{
		"root:x:",     // /etc/passwd
		"[extensions]", // win.ini
		"PATH=",       // environ
	}

	for _, pattern := range patterns {
		if strings.Contains(body, pattern) {
			return true
		}
	}
	return false
}

func (m *SSRFModule) sendTestRequest(ctx context.Context, target *atlas.ScanTarget, param, payload string) (*http.Response, error) {
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

func (m *SSRFModule) extractParameters(target *atlas.ScanTarget) map[string]string {
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

func (m *SSRFModule) getParamLocation(target *atlas.ScanTarget, param string) atlas.ParamLocation {
	if strings.Contains(target.URL, "?"+param+"=") || strings.Contains(target.URL, "&"+param+"=") {
		return atlas.ParamLocationQuery
	}
	if target.Method == "POST" {
		return atlas.ParamLocationBody
	}
	return atlas.ParamLocationQuery
}
