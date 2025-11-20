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

// SQLiModule detects SQL injection vulnerabilities.
type SQLiModule struct {
	*atlas.BaseModule
	payloads []string
}

// NewSQLiModule creates a new SQL injection detection module.
func NewSQLiModule(logger atlas.Logger, oastClient atlas.OASTClient) *SQLiModule {
	base := atlas.NewBaseModule(
		"sqli",
		"SQL Injection Detection",
		"injection",
		atlas.SeverityCritical,
		logger,
		oastClient,
	)

	return &SQLiModule{
		BaseModule: base,
		payloads:   defaultSQLiPayloads,
	}
}

var defaultSQLiPayloads = []string{
	// Error-based
	"'",
	"''",
	"'\"",
	"' OR '1'='1",
	"' OR '1'='1' --",
	"' OR '1'='1' /*",
	"\" OR \"1\"=\"1",
	"' OR 1=1 --",
	"admin' --",
	"admin' #",
	"admin'/*",

	// Union-based
	"' UNION SELECT NULL--",
	"' UNION SELECT NULL,NULL--",
	"' UNION SELECT NULL,NULL,NULL--",

	// Boolean-based
	"' AND '1'='1",
	"' AND '1'='2",
	"1' AND '1'='1",
	"1' AND '1'='2",

	// Time-based
	"' AND SLEEP(5)--",
	"'; WAITFOR DELAY '00:00:05'--",
	"' AND pg_sleep(5)--",

	// Stacked queries
	"'; DROP TABLE users--",
	"'; SELECT SLEEP(5)--",
}

// SupportsTarget checks if this module can scan the target.
func (m *SQLiModule) SupportsTarget(target *atlas.ScanTarget) bool {
	// SQLi can affect any endpoint with parameters
	return len(target.Parameters) > 0 ||
		strings.Contains(target.URL, "?") ||
		target.Method == "POST"
}

// Scan performs SQL injection detection on the target.
func (m *SQLiModule) Scan(ctx context.Context, target *atlas.ScanTarget) ([]*atlas.Finding, error) {
	var findings []*atlas.Finding

	// Extract parameters from URL
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

		// Test error-based SQLi
		if finding := m.testErrorBased(ctx, target, paramName); finding != nil {
			findings = append(findings, finding)
			continue // Skip other tests if confirmed
		}

		// Test boolean-based SQLi
		if finding := m.testBooleanBased(ctx, target, paramName); finding != nil {
			findings = append(findings, finding)
			continue
		}

		// Test time-based SQLi
		if finding := m.testTimeBased(ctx, target, paramName); finding != nil {
			findings = append(findings, finding)
			continue
		}
	}

	return findings, nil
}

func (m *SQLiModule) testErrorBased(ctx context.Context, target *atlas.ScanTarget, param string) *atlas.Finding {
	errorPatterns := []string{
		"sql syntax",
		"mysql_fetch",
		"ora-",
		"postgresql",
		"sqlite3",
		"microsoft sql",
		"odbc sql",
		"syntax error",
		"unclosed quotation mark",
		"unterminated string",
		"mysql error",
		"pg_query()",
		"warning: mysql",
	}

	// Try error-inducing payloads
	for _, payload := range []string{"'", "''", "'\"", "\""} {
		resp, err := m.sendTestRequest(ctx, target, param, payload)
		if err != nil {
			continue
		}

		body, err := m.ReadBody(resp)
		if err != nil {
			continue
		}

		// Check for SQL error messages
		bodyLower := strings.ToLower(body)
		for _, pattern := range errorPatterns {
			if strings.Contains(bodyLower, pattern) {
				return m.CreateFinding(target, "SQL Injection (Error-based)", atlas.ConfidenceConfirmed, atlas.Evidence{
					Parameter: param,
					Location:  m.getParamLocation(target, param),
					Request:   atlas.FormatRequest(resp.Request),
					Response:  atlas.TruncateBody(body, 1000),
					Payload:   payload,
					Proof:     fmt.Sprintf("SQL error message detected: %s", pattern),
				})
			}
		}
	}

	return nil
}

func (m *SQLiModule) testBooleanBased(ctx context.Context, target *atlas.ScanTarget, param string) *atlas.Finding {
	// Send true condition
	trueResp, err := m.sendTestRequest(ctx, target, param, "' OR '1'='1")
	if err != nil {
		return nil
	}
	trueBody, err := m.ReadBody(trueResp)
	if err != nil {
		return nil
	}

	// Send false condition
	falseResp, err := m.sendTestRequest(ctx, target, param, "' OR '1'='2")
	if err != nil {
		return nil
	}
	falseBody, err := m.ReadBody(falseResp)
	if err != nil {
		return nil
	}

	// Compare responses - look for significant differences
	trueLenght := len(trueBody)
	falseLength := len(falseBody)

	// Responses must differ significantly (more than 10%)
	if trueLenght != falseLength {
		maxLen := max(trueLenght, falseLength)
		if maxLen > 0 {
			diff := float64(abs(trueLenght-falseLength)) / float64(maxLen)
			if diff > 0.1 {
				return m.CreateFinding(target, "SQL Injection (Boolean-based)", atlas.ConfidenceFirm, atlas.Evidence{
					Parameter: param,
					Location:  m.getParamLocation(target, param),
					Request:   atlas.FormatRequest(trueResp.Request),
					Response:  atlas.TruncateBody(trueBody, 1000),
					Payload:   "' OR '1'='1",
					Proof:     fmt.Sprintf("Response length differs significantly: true=%d, false=%d (%.1f%% diff)", trueLenght, falseLength, diff*100),
				})
			}
		}
	}

	return nil
}

func (m *SQLiModule) testTimeBased(ctx context.Context, target *atlas.ScanTarget, param string) *atlas.Finding {
	delays := []struct {
		payload string
		delay   time.Duration
	}{
		{"' AND SLEEP(3)--", 3 * time.Second},
		{"'; WAITFOR DELAY '00:00:03'--", 3 * time.Second},
		{"' AND pg_sleep(3)--", 3 * time.Second},
	}

	for _, d := range delays {
		start := time.Now()
		resp, err := m.sendTestRequest(ctx, target, param, d.payload)
		elapsed := time.Since(start)

		if err != nil {
			continue
		}

		// If response took longer than expected (within 20% tolerance), likely vulnerable
		if elapsed >= d.delay && elapsed < d.delay*2 {
			body, _ := m.ReadBody(resp)
			return m.CreateFinding(target, "SQL Injection (Time-based)", atlas.ConfidenceConfirmed, atlas.Evidence{
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

func (m *SQLiModule) sendTestRequest(ctx context.Context, target *atlas.ScanTarget, param, payload string) (*http.Response, error) {
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

func (m *SQLiModule) extractParameters(target *atlas.ScanTarget) map[string]string {
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

func (m *SQLiModule) getParamLocation(target *atlas.ScanTarget, param string) atlas.ParamLocation {
	if strings.Contains(target.URL, "?"+param+"=") || strings.Contains(target.URL, "&"+param+"=") {
		return atlas.ParamLocationQuery
	}
	if target.Method == "POST" {
		return atlas.ParamLocationBody
	}
	return atlas.ParamLocationQuery
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
