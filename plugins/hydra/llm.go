package main

import (
	"fmt"
	"strings"

	pluginsdk "github.com/RowanDark/0xgen/sdk/plugin-sdk"
)

type llmPolicy struct {
	name              string
	minConfidence     float64
	escalateThreshold float64
	baseSeverity      pluginsdk.Severity
	escalatedSeverity pluginsdk.Severity
	summaryBuilder    func(analysisCandidate) string
	rationaleBuilder  func(analysisCandidate, float64) string
}

type llmConsensus struct {
	policies map[string]llmPolicy
}

func newLLMConsensus() aiEvaluator {
	policies := map[string]llmPolicy{
		"xss": {
			name:              "xss-reflection",
			minConfidence:     0.55,
			escalateThreshold: 0.75,
			baseSeverity:      pluginsdk.SeverityMedium,
			escalatedSeverity: pluginsdk.SeverityHigh,
			summaryBuilder: func(c analysisCandidate) string {
				return fmt.Sprintf("Possible cross-site scripting detected on %s", describeHost(c))
			},
			rationaleBuilder: func(c analysisCandidate, confidence float64) string {
				return fmt.Sprintf("Reflected script markers observed (%s) with %.0f%% confidence", c.Metadata["matched_pattern"], confidence*100)
			},
		},
		"sqli": {
			name:              "sql-error",
			minConfidence:     0.5,
			escalateThreshold: 0.7,
			baseSeverity:      pluginsdk.SeverityHigh,
			escalatedSeverity: pluginsdk.SeverityHigh,
			summaryBuilder: func(c analysisCandidate) string {
				return fmt.Sprintf("Database error signature indicates injection on %s", describeHost(c))
			},
			rationaleBuilder: func(c analysisCandidate, confidence float64) string {
				return fmt.Sprintf("Structured SQL error patterns matched (%s)", c.Metadata["matched_pattern"])
			},
		},
		"ssrf": {
			name:              "ssrf-metadata",
			minConfidence:     0.55,
			escalateThreshold: 0.75,
			baseSeverity:      pluginsdk.SeverityHigh,
			escalatedSeverity: pluginsdk.SeverityCritical,
			summaryBuilder: func(c analysisCandidate) string {
				return fmt.Sprintf("Server-side request forgery likely exposed metadata on %s", describeHost(c))
			},
			rationaleBuilder: func(c analysisCandidate, confidence float64) string {
				return fmt.Sprintf("Metadata endpoints observed (%s)", c.Metadata["matched_pattern"])
			},
		},
		"cmdi": {
			name:              "command-exec",
			minConfidence:     0.55,
			escalateThreshold: 0.75,
			baseSeverity:      pluginsdk.SeverityHigh,
			escalatedSeverity: pluginsdk.SeverityCritical,
			summaryBuilder: func(c analysisCandidate) string {
				return fmt.Sprintf("Command execution output returned by %s", describeHost(c))
			},
			rationaleBuilder: func(c analysisCandidate, confidence float64) string {
				return fmt.Sprintf("Shell output fragments detected (%s)", c.Metadata["matched_pattern"])
			},
		},
		"redirect": {
			name:              "open-redirect",
			minConfidence:     0.45,
			escalateThreshold: 0.65,
			baseSeverity:      pluginsdk.SeverityLow,
			escalatedSeverity: pluginsdk.SeverityMedium,
			summaryBuilder: func(c analysisCandidate) string {
				dest := c.Metadata["redirect_host"]
				if dest == "" {
					dest = "external destination"
				}
				return fmt.Sprintf("Application redirects users to %s", dest)
			},
			rationaleBuilder: func(c analysisCandidate, confidence float64) string {
				return fmt.Sprintf("Redirect to %s accepted with %.0f%% confidence", c.Metadata["redirect_location"], confidence*100)
			},
		},
	}
	return llmConsensus{policies: policies}
}

func (c llmConsensus) Decide(candidate *analysisCandidate) (analysisDecision, bool) {
	if candidate == nil {
		return analysisDecision{}, false
	}
	policy, ok := c.policies[candidate.Category]
	if !ok {
		policy = llmPolicy{
			name:              "generic",
			minConfidence:     0.6,
			escalateThreshold: 0.8,
			baseSeverity:      pluginsdk.SeverityMedium,
			escalatedSeverity: pluginsdk.SeverityHigh,
			summaryBuilder: func(ac analysisCandidate) string {
				return fmt.Sprintf("Potential issue detected on %s", describeHost(ac))
			},
			rationaleBuilder: func(ac analysisCandidate, confidence float64) string {
				return fmt.Sprintf("AI consensus accepted signal with %.0f%% confidence", confidence*100)
			},
		}
	}
	confidence := candidate.Confidence
	if confidence < policy.minConfidence {
		return analysisDecision{}, false
	}
	severity := maxSeverity(candidate.Severity, policy.baseSeverity)
	if confidence >= policy.escalateThreshold {
		severity = maxSeverity(severity, policy.escalatedSeverity)
	}
	summary := candidate.Summary
	if policy.summaryBuilder != nil {
		if built := strings.TrimSpace(policy.summaryBuilder(*candidate)); built != "" {
			summary = built
		}
	}
	rationale := fmt.Sprintf("Policy %s accepted signal", policy.name)
	if policy.rationaleBuilder != nil {
		if detail := strings.TrimSpace(policy.rationaleBuilder(*candidate, confidence)); detail != "" {
			rationale = detail
		}
	}
	return analysisDecision{
		Message:   summary,
		Severity:  severity,
		Rationale: rationale,
		Policy:    policy.name,
	}, true
}

func describeHost(c analysisCandidate) string {
	if c.Host != "" {
		return c.Host
	}
	if c.TargetURL != "" {
		return c.TargetURL
	}
	return "target"
}

func maxSeverity(a, b pluginsdk.Severity) pluginsdk.Severity {
	order := map[pluginsdk.Severity]int{
		pluginsdk.SeverityInfo:     1,
		pluginsdk.SeverityLow:      2,
		pluginsdk.SeverityMedium:   3,
		pluginsdk.SeverityHigh:     4,
		pluginsdk.SeverityCritical: 5,
	}
	if order[a] >= order[b] {
		return a
	}
	return b
}
