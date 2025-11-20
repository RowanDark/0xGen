package atlas

import (
	"math"
	"strings"
)

// CVSSCalculator computes CVSS 3.1 scores and enriches findings.
type CVSSCalculator struct{}

// NewCVSSCalculator creates a new CVSS calculator.
func NewCVSSCalculator() *CVSSCalculator {
	return &CVSSCalculator{}
}

// CalculateCVSS computes CVSS 3.1 base score for finding.
func (c *CVSSCalculator) CalculateCVSS(f *Finding) float64 {
	// Base metrics
	av := c.getAttackVector(f)
	ac := c.getAttackComplexity(f)
	pr := c.getPrivilegesRequired(f)
	ui := c.getUserInteraction(f)
	s := c.getScope(f)
	conf := c.getConfidentialityImpact(f)
	integ := c.getIntegrityImpact(f)
	avail := c.getAvailabilityImpact(f)

	// Impact Sub Score (ISS)
	iss := 1 - ((1 - conf) * (1 - integ) * (1 - avail))

	// Impact score
	var impact float64
	if s == 0 { // Unchanged
		impact = 6.42 * iss
	} else { // Changed
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}

	// Exploitability score
	exploitability := 8.22 * av * ac * pr * ui

	// Base score
	var baseScore float64
	if impact <= 0 {
		baseScore = 0
	} else if s == 0 {
		baseScore = math.Min(impact+exploitability, 10)
	} else {
		baseScore = math.Min(1.08*(impact+exploitability), 10)
	}

	return math.Round(baseScore*10) / 10
}

func (c *CVSSCalculator) getAttackVector(f *Finding) float64 {
	// Network: 0.85, Adjacent: 0.62, Local: 0.55, Physical: 0.2
	return 0.85 // Most web vulns are network-based
}

func (c *CVSSCalculator) getAttackComplexity(f *Finding) float64 {
	// Low: 0.77, High: 0.44
	switch f.Type {
	case "Cross-Site Scripting (Stored/Blind)":
		return 0.44 // High complexity (requires victim interaction + storage)
	case "CSRF":
		return 0.44 // High complexity
	default:
		return 0.77 // Low complexity
	}
}

func (c *CVSSCalculator) getPrivilegesRequired(f *Finding) float64 {
	// None: 0.85, Low: 0.62 (scope unchanged), 0.68 (scope changed), High: 0.27, 0.50
	desc := strings.ToLower(f.Description)
	if strings.Contains(desc, "authenticated") || strings.Contains(f.Type, "Authentication") {
		return 0.62 // Low privileges required
	}
	return 0.85 // None required
}

func (c *CVSSCalculator) getUserInteraction(f *Finding) float64 {
	// None: 0.85, Required: 0.62
	switch {
	case strings.Contains(f.Type, "Cross-Site Scripting"):
		return 0.62 // Requires user interaction
	case strings.Contains(f.Type, "CSRF"):
		return 0.62 // Requires user interaction
	default:
		return 0.85 // None required
	}
}

func (c *CVSSCalculator) getScope(f *Finding) float64 {
	// Unchanged: 0, Changed: 1
	switch {
	case strings.Contains(f.Type, "Cross-Site Scripting"):
		return 1 // Changed (executes in victim's context)
	case strings.Contains(f.Type, "SSRF"):
		return 1 // Changed (affects other systems)
	default:
		return 0 // Unchanged
	}
}

func (c *CVSSCalculator) getConfidentialityImpact(f *Finding) float64 {
	// None: 0, Low: 0.22, High: 0.56
	switch {
	case strings.Contains(f.Type, "SQL Injection"):
		return 0.56 // High (database access)
	case strings.Contains(f.Type, "Path Traversal"):
		return 0.56 // High (file access)
	case strings.Contains(f.Type, "XXE"):
		return 0.56 // High (file access)
	case strings.Contains(f.Type, "SSRF"):
		return 0.56 // High (internal network access)
	case strings.Contains(f.Type, "Cross-Site Scripting"):
		return 0.22 // Low (session hijacking possible)
	case strings.Contains(f.Type, "Command Injection"):
		return 0.56 // High (system access)
	default:
		return 0.22
	}
}

func (c *CVSSCalculator) getIntegrityImpact(f *Finding) float64 {
	// None: 0, Low: 0.22, High: 0.56
	switch {
	case strings.Contains(f.Type, "SQL Injection"):
		return 0.56 // High (data modification)
	case strings.Contains(f.Type, "Command Injection"):
		return 0.56 // High (system modification)
	case strings.Contains(f.Type, "Cross-Site Scripting"):
		return 0.22 // Low (DOM modification)
	case strings.Contains(f.Type, "Path Traversal"):
		return 0.22 // Low (potentially write files)
	default:
		return 0.22
	}
}

func (c *CVSSCalculator) getAvailabilityImpact(f *Finding) float64 {
	// None: 0, Low: 0.22, High: 0.56
	switch {
	case strings.Contains(f.Type, "SQL Injection"):
		return 0.22 // Low (possible DoS)
	case strings.Contains(f.Type, "Command Injection"):
		return 0.56 // High (system shutdown possible)
	case strings.Contains(f.Type, "XXE"):
		return 0.22 // Low (billion laughs attack)
	default:
		return 0 // None
	}
}

// EnrichFinding adds CVSS score, severity, CWE, and OWASP mappings.
func (c *CVSSCalculator) EnrichFinding(f *Finding) {
	// Calculate CVSS score
	f.CVSS = c.CalculateCVSS(f)

	// Map CVSS to severity if not set or lower
	calculatedSeverity := c.cvssToSeverity(f.CVSS)
	if f.Severity == "" || severityWeight(calculatedSeverity) > severityWeight(f.Severity) {
		f.Severity = calculatedSeverity
	}

	// Add CWE if not set
	if f.CWE == "" {
		f.CWE = c.typeToCWE(f.Type)
	}

	// Add OWASP mapping if not set
	if f.OWASP == "" {
		f.OWASP = c.typeToOWASP(f.Type)
	}

	// Add remediation if not set
	if f.Remediation == "" {
		f.Remediation = c.getRemediation(f.Type)
	}
}

func (c *CVSSCalculator) cvssToSeverity(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score >= 0.1:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

func (c *CVSSCalculator) typeToCWE(findingType string) string {
	cweMap := map[string]string{
		"SQL Injection (Error-based)":           "CWE-89",
		"SQL Injection (Boolean-based)":         "CWE-89",
		"SQL Injection (Time-based)":            "CWE-89",
		"Blind SQL Injection (OAST)":            "CWE-89",
		"Cross-Site Scripting (Reflected)":      "CWE-79",
		"Cross-Site Scripting (Stored/Blind)":   "CWE-79",
		"Server-Side Request Forgery":           "CWE-918",
		"Server-Side Request Forgery (Blind)":   "CWE-918",
		"Server-Side Request Forgery (Cloud Metadata)": "CWE-918",
		"Server-Side Request Forgery (Local File)":     "CWE-918",
		"XML External Entity":                   "CWE-611",
		"XML External Entity (File Disclosure)": "CWE-611",
		"XML External Entity (Blind)":           "CWE-611",
		"XML External Entity (Parameter Entity)": "CWE-611",
		"Command Injection":                     "CWE-78",
		"Command Injection (Blind)":             "CWE-78",
		"Command Injection (Time-based)":        "CWE-78",
		"Path Traversal":                        "CWE-22",
		"CSRF":                                  "CWE-352",
		"Missing Authentication":                "CWE-287",
		"Weak Default Credentials":              "CWE-798",
		"Exposed Admin Interface":               "CWE-425",
	}

	// Try exact match first
	if cwe, ok := cweMap[findingType]; ok {
		return cwe
	}

	// Try partial match
	for key, cwe := range cweMap {
		if strings.Contains(findingType, key) {
			return cwe
		}
	}

	return "CWE-Other"
}

func (c *CVSSCalculator) typeToOWASP(findingType string) string {
	owaspMap := map[string]string{
		"SQL Injection":              "A03:2021 - Injection",
		"Cross-Site Scripting":       "A03:2021 - Injection",
		"Server-Side Request Forgery": "A10:2021 - Server-Side Request Forgery",
		"Command Injection":          "A03:2021 - Injection",
		"XML External Entity":        "A05:2021 - Security Misconfiguration",
		"Path Traversal":             "A01:2021 - Broken Access Control",
		"CSRF":                       "A01:2021 - Broken Access Control",
		"Missing Authentication":     "A07:2021 - Identification and Authentication Failures",
		"Weak Default Credentials":   "A07:2021 - Identification and Authentication Failures",
		"Exposed Admin":              "A01:2021 - Broken Access Control",
	}

	// Try partial match
	for key, owasp := range owaspMap {
		if strings.Contains(findingType, key) {
			return owasp
		}
	}

	return "OWASP Top 10"
}

func (c *CVSSCalculator) getRemediation(findingType string) string {
	remediationMap := map[string]string{
		"SQL Injection": "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries. Implement input validation and use an ORM where possible.",
		"Cross-Site Scripting": "Sanitize and encode all user input before rendering in HTML. Use Content Security Policy (CSP) headers. Implement context-aware output encoding.",
		"Server-Side Request Forgery": "Validate and whitelist allowed URLs and IP addresses. Disable unnecessary protocols (file://, gopher://). Implement network segmentation.",
		"Command Injection": "Avoid executing system commands with user input. Use built-in library functions instead. If unavoidable, use strict input validation and escaping.",
		"XML External Entity": "Disable external entity processing in XML parsers. Use less complex data formats like JSON. Keep XML processors updated.",
		"Path Traversal": "Validate and sanitize file paths. Use a whitelist of allowed files. Implement proper access controls. Never concatenate user input into file paths.",
		"Missing Authentication": "Implement authentication for all sensitive endpoints. Use established authentication frameworks. Require strong passwords.",
		"Weak Default Credentials": "Remove or change default credentials. Enforce strong password policies. Implement account lockout mechanisms.",
		"Exposed Admin": "Restrict access to admin interfaces by IP address. Implement additional authentication layers. Use VPN for admin access.",
	}

	// Try partial match
	for key, remediation := range remediationMap {
		if strings.Contains(findingType, key) {
			return remediation
		}
	}

	return "Review and fix the vulnerability according to security best practices."
}
