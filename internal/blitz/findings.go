package blitz

import (
	"fmt"
	"strings"

	"github.com/RowanDark/0xgen/internal/findings"
)

// FindingsCorrelator converts Blitz fuzzing results into 0xGen findings.
type FindingsCorrelator struct {
	classifier *AIClassifier
	sessionID  string
}

// VulnerabilityInfo contains detailed vulnerability information.
type VulnerabilityInfo struct {
	Type        string
	Title       string
	Description string
	CWE         string
	OWASP       string
	Severity    findings.Severity
	Remediation string
	References  []string
}

// NewFindingsCorrelator creates a new findings correlator.
func NewFindingsCorrelator(sessionID string) *FindingsCorrelator {
	return &FindingsCorrelator{
		classifier: NewAIClassifier(),
		sessionID:  sessionID,
	}
}

// CorrelateResult analyzes a fuzzing result and generates findings if vulnerabilities are detected.
func (fc *FindingsCorrelator) CorrelateResult(result *FuzzResult) []*findings.Finding {
	var resultFindings []*findings.Finding

	// Only process interesting anomalies
	if result.Anomaly == nil || !result.Anomaly.IsInteresting {
		return resultFindings
	}

	// Classify the response with AI
	classifications := fc.classifier.ClassifyWithContext(result, result.Payload)

	// Generate findings for each classification
	for _, class := range classifications {
		finding := fc.createFinding(result, class)
		if finding != nil {
			resultFindings = append(resultFindings, finding)
		}
	}

	// If no specific vulnerability detected, create a generic anomaly finding
	if len(resultFindings) == 0 && result.Error == "" {
		finding := fc.createAnomalyFinding(result)
		if finding != nil {
			resultFindings = append(resultFindings, finding)
		}
	}

	return resultFindings
}

// createFinding creates a 0xGen finding from a classification.
func (fc *FindingsCorrelator) createFinding(result *FuzzResult, class Classification) *findings.Finding {
	vulnInfo := fc.getVulnerabilityInfo(class.Category, class.CWE, class.OWASP)

	// Create PoC request
	poc := fc.generatePoC(result)

	metadata := map[string]string{
		"blitz_session":      fc.sessionID,
		"blitz_result_id":    fmt.Sprintf("%d", result.ID),
		"position":           result.PositionName,
		"payload":            truncate(result.Payload, 200),
		"status_code":        fmt.Sprintf("%d", result.StatusCode),
		"response_time_ms":   fmt.Sprintf("%d", result.Duration),
		"content_length":     fmt.Sprintf("%d", result.ContentLen),
		"classification":     string(class.Category),
		"confidence":         fmt.Sprintf("%.2f", class.Confidence),
		"cwe":                class.CWE,
		"owasp":              class.OWASP,
		"vulnerability_type": vulnInfo.Type,
		"poc_request":        poc,
		"remediation":        vulnInfo.Remediation,
	}

	// Add anomaly details
	if result.Anomaly != nil {
		if result.Anomaly.StatusCodeAnomaly {
			metadata["anomaly_status_code"] = "true"
		}
		if result.Anomaly.ContentLengthDelta != 0 {
			metadata["anomaly_content_delta"] = fmt.Sprintf("%d", result.Anomaly.ContentLengthDelta)
		}
		if result.Anomaly.ResponseTimeFactor != 0 {
			metadata["anomaly_time_factor"] = fmt.Sprintf("%.2f", result.Anomaly.ResponseTimeFactor)
		}
	}

	// Map classification severity to findings severity
	severity := fc.mapSeverity(class.Severity)

	return &findings.Finding{
		Version:    findings.SchemaVersion,
		ID:         findings.NewID(),
		Plugin:     "blitz",
		Type:       fmt.Sprintf("blitz.%s", class.Category),
		Message:    class.Message,
		Target:     result.Request.URL,
		Evidence:   fc.buildEvidence(result, class),
		Severity:   severity,
		DetectedAt: findings.NewTimestamp(result.Timestamp),
		Metadata:   metadata,
	}
}

// createAnomalyFinding creates a generic anomaly finding when no specific vulnerability is detected.
func (fc *FindingsCorrelator) createAnomalyFinding(result *FuzzResult) *findings.Finding {
	// Build description of the anomaly
	anomalyDesc := fc.describeAnomaly(result.Anomaly)

	metadata := map[string]string{
		"blitz_session":    fc.sessionID,
		"blitz_result_id":  fmt.Sprintf("%d", result.ID),
		"position":         result.PositionName,
		"payload":          truncate(result.Payload, 200),
		"status_code":      fmt.Sprintf("%d", result.StatusCode),
		"response_time_ms": fmt.Sprintf("%d", result.Duration),
		"content_length":   fmt.Sprintf("%d", result.ContentLen),
		"anomaly_type":     anomalyDesc,
	}

	poc := fc.generatePoC(result)
	if poc != "" {
		metadata["poc_request"] = poc
	}

	return &findings.Finding{
		Version:    findings.SchemaVersion,
		ID:         findings.NewID(),
		Plugin:     "blitz",
		Type:       "blitz.anomaly.generic",
		Message:    fmt.Sprintf("Anomalous response detected: %s", anomalyDesc),
		Target:     result.Request.URL,
		Evidence:   truncate(result.Response.Body, 500),
		Severity:   findings.SeverityLow,
		DetectedAt: findings.NewTimestamp(result.Timestamp),
		Metadata:   metadata,
	}
}

// generatePoC creates a proof-of-concept request string.
func (fc *FindingsCorrelator) generatePoC(result *FuzzResult) string {
	var poc strings.Builder

	poc.WriteString(fmt.Sprintf("%s %s\n", result.Request.Method, result.Request.URL))

	// Add significant headers
	for key, value := range result.Request.Headers {
		if strings.EqualFold(key, "host") ||
			strings.EqualFold(key, "content-type") ||
			strings.EqualFold(key, "cookie") {
			poc.WriteString(fmt.Sprintf("%s: %s\n", key, value))
		}
	}

	if result.Request.Body != "" {
		poc.WriteString("\n")
		poc.WriteString(truncate(result.Request.Body, 500))
	}

	return poc.String()
}

// buildEvidence creates evidence string from result and classification.
func (fc *FindingsCorrelator) buildEvidence(result *FuzzResult, class Classification) string {
	var evidence strings.Builder

	evidence.WriteString(fmt.Sprintf("Payload: %s\n\n", truncate(result.Payload, 200)))

	if class.Evidence != "" {
		evidence.WriteString(fmt.Sprintf("Matched Pattern: %s\n\n", class.Evidence))
	}

	evidence.WriteString(fmt.Sprintf("Response Preview:\n%s", truncate(result.Response.Body, 300)))

	return evidence.String()
}

// describeAnomaly generates a human-readable description of the anomaly.
func (fc *FindingsCorrelator) describeAnomaly(anomaly *AnomalyIndicator) string {
	if anomaly == nil {
		return "unknown anomaly"
	}

	var parts []string

	if anomaly.StatusCodeAnomaly {
		parts = append(parts, "unexpected status code")
	}

	if anomaly.ContentLengthDelta != 0 {
		parts = append(parts, fmt.Sprintf("content length deviation (%+d bytes)", anomaly.ContentLengthDelta))
	}

	if anomaly.ResponseTimeFactor > 1.5 || anomaly.ResponseTimeFactor < 0.5 {
		parts = append(parts, fmt.Sprintf("response time anomaly (%.2fx)", anomaly.ResponseTimeFactor))
	}

	if anomaly.PatternAnomalies > 0 {
		parts = append(parts, fmt.Sprintf("%d pattern matches", anomaly.PatternAnomalies))
	}

	if len(parts) == 0 {
		return "general anomaly detected"
	}

	return strings.Join(parts, ", ")
}

// mapSeverity maps classification severity to findings severity.
func (fc *FindingsCorrelator) mapSeverity(severity string) findings.Severity {
	switch strings.ToLower(severity) {
	case "critical":
		return findings.SeverityCritical
	case "high":
		return findings.SeverityHigh
	case "medium", "med":
		return findings.SeverityMedium
	case "low":
		return findings.SeverityLow
	default:
		return findings.SeverityInfo
	}
}

// getVulnerabilityInfo returns detailed vulnerability information.
func (fc *FindingsCorrelator) getVulnerabilityInfo(category ClassificationCategory, cwe, owasp string) VulnerabilityInfo {
	vulnDatabase := map[ClassificationCategory]VulnerabilityInfo{
		ClassCategorySQLError: {
			Type:        "SQL Injection",
			Title:       "SQL Injection Vulnerability",
			Description: "The application is vulnerable to SQL injection, allowing attackers to manipulate database queries.",
			CWE:         "CWE-89",
			OWASP:       "A03:2021-Injection",
			Severity:    findings.SeverityHigh,
			Remediation: "Use parameterized queries or prepared statements. Validate and sanitize all user inputs.",
			References: []string{
				"https://owasp.org/www-community/attacks/SQL_Injection",
				"https://cwe.mitre.org/data/definitions/89.html",
			},
		},
		ClassCategoryXSSReflection: {
			Type:        "Cross-Site Scripting (XSS)",
			Title:       "Reflected Cross-Site Scripting",
			Description: "The application reflects user input without proper encoding, allowing script injection.",
			CWE:         "CWE-79",
			OWASP:       "A03:2021-Injection",
			Severity:    findings.SeverityMedium,
			Remediation: "Encode all user-supplied data before rendering in HTML. Use Content-Security-Policy headers.",
			References: []string{
				"https://owasp.org/www-community/attacks/xss/",
				"https://cwe.mitre.org/data/definitions/79.html",
			},
		},
		ClassCategoryCmdExecution: {
			Type:        "Command Injection",
			Title:       "OS Command Injection",
			Description: "The application executes system commands with user-supplied input, allowing arbitrary command execution.",
			CWE:         "CWE-78",
			OWASP:       "A03:2021-Injection",
			Severity:    findings.SeverityCritical,
			Remediation: "Avoid executing system commands with user input. Use API calls instead. If necessary, use strict allow-lists.",
			References: []string{
				"https://owasp.org/www-community/attacks/Command_Injection",
				"https://cwe.mitre.org/data/definitions/78.html",
			},
		},
		ClassCategoryPathTraversal: {
			Type:        "Path Traversal",
			Title:       "Directory Traversal / Path Traversal",
			Description: "The application allows access to files outside the intended directory through path manipulation.",
			CWE:         "CWE-22",
			OWASP:       "A01:2021-Broken Access Control",
			Severity:    findings.SeverityHigh,
			Remediation: "Validate file paths against an allow-list. Use Path.normalize() and check the canonical path.",
			References: []string{
				"https://owasp.org/www-community/attacks/Path_Traversal",
				"https://cwe.mitre.org/data/definitions/22.html",
			},
		},
		ClassCategoryErrorMessage: {
			Type:        "Information Disclosure",
			Title:       "Sensitive Information in Error Messages",
			Description: "The application exposes sensitive information through error messages.",
			CWE:         "CWE-209",
			OWASP:       "A04:2021-Insecure Design",
			Severity:    findings.SeverityLow,
			Remediation: "Use generic error messages. Log detailed errors server-side only. Implement custom error pages.",
			References: []string{
				"https://owasp.org/www-community/Improper_Error_Handling",
				"https://cwe.mitre.org/data/definitions/209.html",
			},
		},
		ClassCategoryStackTrace: {
			Type:        "Information Disclosure",
			Title:       "Stack Trace Disclosure",
			Description: "The application exposes stack traces in responses, revealing implementation details.",
			CWE:         "CWE-209",
			OWASP:       "A04:2021-Insecure Design",
			Severity:    findings.SeverityMedium,
			Remediation: "Disable debug mode in production. Implement proper error handling with generic messages.",
			References: []string{
				"https://cwe.mitre.org/data/definitions/209.html",
			},
		},
		ClassCategoryDebugInfo: {
			Type:        "Security Misconfiguration",
			Title:       "Debug Information Exposed",
			Description: "The application is running with debug mode enabled, exposing sensitive information.",
			CWE:         "CWE-489",
			OWASP:       "A05:2021-Security Misconfiguration",
			Severity:    findings.SeverityLow,
			Remediation: "Disable debug mode in production environments. Remove debug endpoints and verbose logging.",
			References: []string{
				"https://cwe.mitre.org/data/definitions/489.html",
			},
		},
		ClassCategorySensitiveData: {
			Type:        "Sensitive Data Exposure",
			Title:       "Sensitive Data in Response",
			Description: "The application exposes sensitive data such as credentials, PII, or secrets.",
			CWE:         "CWE-200",
			OWASP:       "A01:2021-Broken Access Control",
			Severity:    findings.SeverityHigh,
			Remediation: "Implement proper access controls. Encrypt sensitive data. Use data classification policies.",
			References: []string{
				"https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
				"https://cwe.mitre.org/data/definitions/200.html",
			},
		},
		ClassCategoryAuth: {
			Type:        "Authentication Bypass",
			Title:       "Authentication / Authorization Bypass",
			Description: "The application's authentication or authorization mechanism can be bypassed.",
			CWE:         "CWE-287",
			OWASP:       "A07:2021-Identification and Authentication Failures",
			Severity:    findings.SeverityCritical,
			Remediation: "Implement proper authentication checks. Use framework authentication. Apply principle of least privilege.",
			References: []string{
				"https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
				"https://cwe.mitre.org/data/definitions/287.html",
			},
		},
	}

	info, ok := vulnDatabase[category]
	if !ok {
		// Default info
		info = VulnerabilityInfo{
			Type:        string(category),
			Title:       fmt.Sprintf("Security Issue: %s", category),
			Description: "A security issue was detected during fuzzing.",
			CWE:         cwe,
			OWASP:       owasp,
			Severity:    findings.SeverityMedium,
			Remediation: "Review the finding details and implement appropriate security controls.",
		}
	}

	// Override CWE/OWASP if provided
	if cwe != "" {
		info.CWE = cwe
	}
	if owasp != "" {
		info.OWASP = owasp
	}

	return info
}

// BatchCorrelate processes multiple results and returns all findings.
func (fc *FindingsCorrelator) BatchCorrelate(results []*FuzzResult) []*findings.Finding {
	var allFindings []*findings.Finding

	for _, result := range results {
		resultFindings := fc.CorrelateResult(result)
		allFindings = append(allFindings, resultFindings...)
	}

	return fc.deduplicateFindings(allFindings)
}

// deduplicateFindings removes duplicate findings based on type and target.
func (fc *FindingsCorrelator) deduplicateFindings(findingsList []*findings.Finding) []*findings.Finding {
	seen := make(map[string]bool)
	unique := make([]*findings.Finding, 0, len(findingsList))

	for _, finding := range findingsList {
		key := fmt.Sprintf("%s:%s", finding.Type, finding.Target)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, finding)
		}
	}

	return unique
}

// GetVulnerabilityStats returns statistics about detected vulnerabilities.
func (fc *FindingsCorrelator) GetVulnerabilityStats(findingsList []*findings.Finding) map[string]int {
	stats := make(map[string]int)

	for _, finding := range findingsList {
		// Count by type
		stats[finding.Type]++

		// Count by severity
		severityKey := fmt.Sprintf("severity_%s", finding.Severity)
		stats[severityKey]++

		// Count by CWE if present
		if cwe, ok := finding.Metadata["cwe"]; ok && cwe != "" {
			stats[cwe]++
		}
	}

	stats["total"] = len(findingsList)

	return stats
}
