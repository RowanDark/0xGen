package main

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	pluginsdk "github.com/RowanDark/0xgen/sdk/plugin-sdk"
)

func TestHydraDetectsCoreVulnerabilities(t *testing.T) {
	hooks := newHydraHooks(func() time.Time { return time.Date(2024, time.April, 12, 10, 0, 0, 0, time.UTC) })

	events := []pluginsdk.HTTPPassiveEvent{
		// XSS
		{
			Response: &pluginsdk.HTTPResponse{
				StatusLine: "HTTP/1.1 200 OK",
				Headers: http.Header{
					"X-Request-Url": []string{"https://app.example/xss?input=%3Cscript%3Ealert(1)%3C/script%3E"},
					"Content-Type":  []string{"text/html"},
				},
				Body: []byte(`<html><body><script>alert('xss')</script></body></html>`),
			},
		},
		// SQL injection
		{
			Response: &pluginsdk.HTTPResponse{
				StatusLine: "HTTP/1.1 500 Internal Server Error",
				Headers: http.Header{
					"X-Request-Url": []string{"https://api.example/users?id=1'"},
				},
				Body: []byte("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"),
			},
		},
		// SSRF
		{
			Response: &pluginsdk.HTTPResponse{
				StatusLine: "HTTP/1.1 200 OK",
				Headers: http.Header{
					"X-Request-Url": []string{"https://api.example/metadata"},
				},
				Body: []byte("Instance metadata: http://169.254.169.254/latest/meta-data/iam/security-credentials"),
			},
		},
		// Command Injection
		{
			Response: &pluginsdk.HTTPResponse{
				StatusLine: "HTTP/1.1 200 OK",
				Headers: http.Header{
					"X-Request-Url": []string{"https://app.example/admin/ping"},
				},
				Body: []byte("uid=0(root) gid=0(root) groups=0(root)\nsh: warning: command not found"),
			},
		},
		// Open Redirect
		{
			Response: &pluginsdk.HTTPResponse{
				StatusLine: "HTTP/1.1 302 Found",
				Headers: http.Header{
					"X-Request-Url": []string{"https://app.example/start"},
					"Location":      []string{"https://evil.example/phish?next=%2Fdashboard"},
				},
			},
		},
	}

	cfg := pluginsdk.LocalRunConfig{
		PluginName:    "hydra",
		Capabilities:  []pluginsdk.Capability{pluginsdk.CapabilityEmitFindings, pluginsdk.CapabilityHTTPPassive, pluginsdk.CapabilityFlowInspect, pluginsdk.CapabilityAIAnalysis},
		Hooks:         hooks,
		PassiveEvents: events,
	}

	result, err := pluginsdk.RunLocal(context.Background(), cfg)
	if err != nil {
		t.Fatalf("RunLocal: %v", err)
	}
	if len(result.Findings) != 5 {
		t.Fatalf("expected 5 findings, got %d", len(result.Findings))
	}

	findingsByType := make(map[string]pluginsdk.Finding, len(result.Findings))
	for _, finding := range result.Findings {
		findingsByType[finding.Type] = finding
		if finding.Metadata["analysis_engine"] != "hydra" {
			t.Fatalf("expected analysis_engine hydra for %s", finding.Type)
		}
		if _, err := strconv.ParseFloat(finding.Metadata["analysis_confidence"], 64); err != nil {
			t.Fatalf("analysis_confidence missing or invalid for %s", finding.Type)
		}
		if finding.Metadata["asset_kind"] != "web" {
			t.Fatalf("expected asset_kind web for %s", finding.Type)
		}
		if finding.Metadata["signal_source"] == "" {
			t.Fatalf("signal_source missing for %s", finding.Type)
		}
		if finding.Metadata["vector"] != "web_passive_flow" {
			t.Fatalf("unexpected vector for %s: %s", finding.Type, finding.Metadata["vector"])
		}
		if finding.Message == "" {
			t.Fatalf("message missing for %s", finding.Type)
		}
	}

	mustHave := []string{"hydra.xss.reflection", "hydra.sqli.error", "hydra.ssrf.exfil", "hydra.command.exec", "hydra.redirect.open"}
	for _, typ := range mustHave {
		finding, ok := findingsByType[typ]
		if !ok {
			t.Fatalf("expected finding type %s", typ)
		}
		if finding.Severity == pluginsdk.SeverityInfo {
			t.Fatalf("unexpected informational severity for %s", typ)
		}
	}
}
