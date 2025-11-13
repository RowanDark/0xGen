package blitz

import (
	"regexp"
	"strings"
)

// AIClassifier provides AI-powered response classification.
type AIClassifier struct {
	patterns map[ClassificationCategory][]classificationPattern
}

// ClassificationCategory represents types of interesting responses.
type ClassificationCategory string

const (
	ClassCategorySQLError     ClassificationCategory = "sql_error"
	ClassCategoryXSSReflection ClassificationCategory = "xss_reflection"
	ClassCategoryCmdExecution  ClassificationCategory = "command_execution"
	ClassCategoryPathTraversal ClassificationCategory = "path_traversal"
	ClassCategoryErrorMessage  ClassificationCategory = "error_message"
	ClassCategoryStackTrace    ClassificationCategory = "stack_trace"
	ClassCategoryDebugInfo     ClassificationCategory = "debug_info"
	ClassCategorySensitiveData ClassificationCategory = "sensitive_data"
	ClassCategoryAuth          ClassificationCategory = "auth_bypass"
)

// Classification represents an AI classification of a response.
type Classification struct {
	Category   ClassificationCategory
	Confidence float64
	Evidence   string
	Message    string
	Severity   string
	CWE        string
	OWASP      string
}

type classificationPattern struct {
	regex      *regexp.Regexp
	literal    string
	confidence float64
	message    string
	severity   string
	cwe        string
	owasp      string
}

// NewAIClassifier creates a new AI-powered response classifier.
func NewAIClassifier() *AIClassifier {
	c := &AIClassifier{
		patterns: make(map[ClassificationCategory][]classificationPattern),
	}

	c.initializePatterns()
	return c
}

// initializePatterns sets up classification patterns for each category.
func (c *AIClassifier) initializePatterns() {
	// SQL Error patterns
	c.patterns[ClassCategorySQLError] = []classificationPattern{
		{
			literal:    "you have an error in your sql syntax",
			confidence: 0.95,
			message:    "MySQL syntax error detected - likely SQL injection vulnerability",
			severity:   "high",
			cwe:        "CWE-89",
			owasp:      "A03:2021-Injection",
		},
		{
			literal:    "warning: mysql",
			confidence: 0.85,
			message:    "MySQL warning message exposed",
			severity:   "high",
			cwe:        "CWE-89",
			owasp:      "A03:2021-Injection",
		},
		{
			literal:    "unclosed quotation mark after the character string",
			confidence: 0.90,
			message:    "SQL Server error - SQL injection likely",
			severity:   "high",
			cwe:        "CWE-89",
			owasp:      "A03:2021-Injection",
		},
		{
			literal:    "pg_query",
			confidence: 0.80,
			message:    "PostgreSQL function call exposed",
			severity:   "high",
			cwe:        "CWE-89",
			owasp:      "A03:2021-Injection",
		},
		{
			literal:    "mysql_fetch",
			confidence: 0.85,
			message:    "MySQL fetch function exposed",
			severity:   "high",
			cwe:        "CWE-89",
			owasp:      "A03:2021-Injection",
		},
		{
			literal:    "ora-00933",
			confidence: 0.90,
			message:    "Oracle SQL command not properly ended",
			severity:   "high",
			cwe:        "CWE-89",
			owasp:      "A03:2021-Injection",
		},
		{
			regex:      regexp.MustCompile(`(?i)sqlstate\[\w+\]`),
			confidence: 0.85,
			message:    "SQL state error code exposed",
			severity:   "high",
			cwe:        "CWE-89",
			owasp:      "A03:2021-Injection",
		},
	}

	// XSS Reflection patterns
	c.patterns[ClassCategoryXSSReflection] = []classificationPattern{
		{
			regex:      regexp.MustCompile(`<script[^>]*>alert\(`),
			confidence: 0.95,
			message:    "XSS payload reflected in response - Cross-Site Scripting vulnerability",
			severity:   "medium",
			cwe:        "CWE-79",
			owasp:      "A03:2021-Injection",
		},
		{
			regex:      regexp.MustCompile(`onerror\s*=\s*alert`),
			confidence: 0.90,
			message:    "Event handler XSS payload reflected",
			severity:   "medium",
			cwe:        "CWE-79",
			owasp:      "A03:2021-Injection",
		},
		{
			literal:    "javascript:alert",
			confidence: 0.85,
			message:    "JavaScript protocol handler reflected",
			severity:   "medium",
			cwe:        "CWE-79",
			owasp:      "A03:2021-Injection",
		},
		{
			regex:      regexp.MustCompile(`<svg[^>]*onload`),
			confidence: 0.85,
			message:    "SVG-based XSS payload reflected",
			severity:   "medium",
			cwe:        "CWE-79",
			owasp:      "A03:2021-Injection",
		},
	}

	// Command Execution patterns
	c.patterns[ClassCategoryCmdExecution] = []classificationPattern{
		{
			regex:      regexp.MustCompile(`uid=\d+\([\w-]+\)\s+gid=\d+`),
			confidence: 0.95,
			message:    "Unix user information exposed - Command injection successful",
			severity:   "critical",
			cwe:        "CWE-78",
			owasp:      "A03:2021-Injection",
		},
		{
			literal:    "root:x:0:0",
			confidence: 0.95,
			message:    "/etc/passwd content exposed - Command injection or path traversal",
			severity:   "critical",
			cwe:        "CWE-78",
			owasp:      "A03:2021-Injection",
		},
		{
			literal:    "command not found",
			confidence: 0.75,
			message:    "Shell error message exposed - possible command injection",
			severity:   "high",
			cwe:        "CWE-78",
			owasp:      "A03:2021-Injection",
		},
		{
			regex:      regexp.MustCompile(`(?m)^\s*cpu\s+:\s+\d+`),
			confidence: 0.80,
			message:    "/proc/cpuinfo content exposed",
			severity:   "high",
			cwe:        "CWE-78",
			owasp:      "A03:2021-Injection",
		},
	}

	// Path Traversal patterns
	c.patterns[ClassCategoryPathTraversal] = []classificationPattern{
		{
			regex:      regexp.MustCompile(`root:.*:0:0:`),
			confidence: 0.90,
			message:    "/etc/passwd contents exposed - Path traversal vulnerability",
			severity:   "high",
			cwe:        "CWE-22",
			owasp:      "A01:2021-Broken Access Control",
		},
		{
			regex:      regexp.MustCompile(`\[extensions\]`),
			confidence: 0.85,
			message:    "Windows INI file exposed - Path traversal vulnerability",
			severity:   "high",
			cwe:        "CWE-22",
			owasp:      "A01:2021-Broken Access Control",
		},
	}

	// Error Message patterns
	c.patterns[ClassCategoryErrorMessage] = []classificationPattern{
		{
			regex:      regexp.MustCompile(`(?i)fatal\s+error`),
			confidence: 0.70,
			message:    "Fatal error message exposed",
			severity:   "low",
			cwe:        "CWE-209",
			owasp:      "A04:2021-Insecure Design",
		},
		{
			regex:      regexp.MustCompile(`(?i)exception\s+in`),
			confidence: 0.65,
			message:    "Exception details exposed",
			severity:   "low",
			cwe:        "CWE-209",
			owasp:      "A04:2021-Insecure Design",
		},
		{
			regex:      regexp.MustCompile(`(?i)warning:.*line\s+\d+`),
			confidence: 0.70,
			message:    "Warning with line number exposed",
			severity:   "low",
			cwe:        "CWE-209",
			owasp:      "A04:2021-Insecure Design",
		},
	}

	// Stack Trace patterns
	c.patterns[ClassCategoryStackTrace] = []classificationPattern{
		{
			regex:      regexp.MustCompile(`at\s+[\w.]+\([\w.]+:\d+:\d+\)`),
			confidence: 0.85,
			message:    "JavaScript stack trace exposed",
			severity:   "medium",
			cwe:        "CWE-209",
			owasp:      "A04:2021-Insecure Design",
		},
		{
			regex:      regexp.MustCompile(`(?m)^\s+at\s+.*\(.*\.java:\d+\)`),
			confidence: 0.90,
			message:    "Java stack trace exposed",
			severity:   "medium",
			cwe:        "CWE-209",
			owasp:      "A04:2021-Insecure Design",
		},
		{
			regex:      regexp.MustCompile(`Traceback\s+\(most\s+recent\s+call\s+last\):`),
			confidence: 0.95,
			message:    "Python traceback exposed",
			severity:   "medium",
			cwe:        "CWE-209",
			owasp:      "A04:2021-Insecure Design",
		},
	}

	// Debug Info patterns
	c.patterns[ClassCategoryDebugInfo] = []classificationPattern{
		{
			regex:      regexp.MustCompile(`(?i)debug\s+mode`),
			confidence: 0.75,
			message:    "Debug mode indicator exposed",
			severity:   "low",
			cwe:        "CWE-489",
			owasp:      "A05:2021-Security Misconfiguration",
		},
		{
			regex:      regexp.MustCompile(`(?i)var_dump\(`),
			confidence: 0.80,
			message:    "PHP debug output exposed",
			severity:   "low",
			cwe:        "CWE-489",
			owasp:      "A05:2021-Security Misconfiguration",
		},
	}

	// Sensitive Data patterns
	c.patterns[ClassCategorySensitiveData] = []classificationPattern{
		{
			regex:      regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}`),
			confidence: 0.60,
			message:    "Email address exposed in response",
			severity:   "low",
			cwe:        "CWE-200",
			owasp:      "A01:2021-Broken Access Control",
		},
		{
			regex:      regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			confidence: 0.85,
			message:    "Social Security Number pattern detected",
			severity:   "critical",
			cwe:        "CWE-359",
			owasp:      "A01:2021-Broken Access Control",
		},
		{
			regex:      regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b`),
			confidence: 0.75,
			message:    "Credit card number pattern detected",
			severity:   "critical",
			cwe:        "CWE-359",
			owasp:      "A01:2021-Broken Access Control",
		},
		{
			regex:      regexp.MustCompile(`(?i)api[_-]?key\s*[:=]\s*['""]?[\w-]{20,}`),
			confidence: 0.80,
			message:    "API key pattern detected",
			severity:   "high",
			cwe:        "CWE-798",
			owasp:      "A07:2021-Identification and Authentication Failures",
		},
	}

	// Auth Bypass patterns
	c.patterns[ClassCategoryAuth] = []classificationPattern{
		{
			regex:      regexp.MustCompile(`(?i)logged\s+in\s+as\s+admin`),
			confidence: 0.85,
			message:    "Admin access indication - possible authentication bypass",
			severity:   "critical",
			cwe:        "CWE-287",
			owasp:      "A07:2021-Identification and Authentication Failures",
		},
		{
			regex:      regexp.MustCompile(`(?i)access\s+granted`),
			confidence: 0.65,
			message:    "Access granted message - possible authorization bypass",
			severity:   "high",
			cwe:        "CWE-862",
			owasp:      "A01:2021-Broken Access Control",
		},
	}
}

// Classify analyzes a response and returns all matching classifications.
func (c *AIClassifier) Classify(response *FuzzResult) []Classification {
	classifications := make([]Classification, 0)

	body := strings.ToLower(response.Response.Body)

	// Check each category
	for category, patterns := range c.patterns {
		for _, pattern := range patterns {
			match, evidence := c.matchPattern(pattern, response.Response.Body, body)
			if match {
				classifications = append(classifications, Classification{
					Category:   category,
					Confidence: pattern.confidence,
					Evidence:   evidence,
					Message:    pattern.message,
					Severity:   pattern.severity,
					CWE:        pattern.cwe,
					OWASP:      pattern.owasp,
				})
			}
		}
	}

	return classifications
}

// ClassifyWithContext provides enhanced classification using request context.
func (c *AIClassifier) ClassifyWithContext(result *FuzzResult, payload string) []Classification {
	classifications := c.Classify(result)

	// Enhance classifications with payload context
	for i := range classifications {
		classifications[i] = c.enhanceClassification(classifications[i], result, payload)
	}

	return classifications
}

// matchPattern checks if a pattern matches the response.
func (c *AIClassifier) matchPattern(pattern classificationPattern, originalBody, lowerBody string) (bool, string) {
	if pattern.regex != nil {
		// Use regex on original body to preserve case
		matches := pattern.regex.FindString(originalBody)
		if matches != "" {
			return true, truncate(matches, 100)
		}
		return false, ""
	}

	if pattern.literal != "" {
		idx := strings.Index(lowerBody, strings.ToLower(pattern.literal))
		if idx != -1 {
			// Extract snippet from original body
			start := idx
			end := idx + len(pattern.literal)
			if end > len(originalBody) {
				end = len(originalBody)
			}
			snippet := originalBody[start:end]
			return true, truncate(snippet, 100)
		}
	}

	return false, ""
}

// enhanceClassification adds contextual information to a classification.
func (c *AIClassifier) enhanceClassification(class Classification, result *FuzzResult, payload string) Classification {
	// Increase confidence if payload is reflected in response
	if strings.Contains(strings.ToLower(result.Response.Body), strings.ToLower(payload)) {
		class.Confidence = min(class.Confidence+0.1, 1.0)
		class.Message += " (payload reflected)"
	}

	// Increase confidence for error status codes
	if result.StatusCode >= 500 {
		if class.Category == ClassCategorySQLError ||
			class.Category == ClassCategoryErrorMessage {
			class.Confidence = min(class.Confidence+0.05, 1.0)
		}
	}

	return class
}

// GetTopClassification returns the highest confidence classification.
func (c *AIClassifier) GetTopClassification(classifications []Classification) *Classification {
	if len(classifications) == 0 {
		return nil
	}

	top := classifications[0]
	for _, class := range classifications[1:] {
		if class.Confidence > top.Confidence {
			top = class
		}
	}

	return &top
}

// min returns the minimum of two float64 values.
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
