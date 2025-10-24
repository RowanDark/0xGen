package main

import (
	"net/url"
	"strconv"
	"strings"

	pluginsdk "github.com/RowanDark/0xgen/sdk/plugin-sdk"
)

type indicatorMatch struct {
	pattern string
	index   int
}

type analyzerFunc struct {
	id       string
	category string
	analyse  func(responseContext) *analysisCandidate
}

func (a analyzerFunc) ID() string { return a.id }

func (a analyzerFunc) Analyse(ctx responseContext) *analysisCandidate {
	return a.analyse(ctx)
}

func newXSSAnalyzer() analyzer {
	patterns := []string{"<script>alert", "onerror=alert", "javascript:alert", "document.cookie", "<svg/onload"}
	const analyzerID = "hydra.rules.xss"
	const category = "xss"
	return analyzerFunc{
		id:       analyzerID,
		category: category,
		analyse: func(ctx responseContext) *analysisCandidate {
			matches := findIndicators(ctx.BodyLower, patterns)
			if len(matches) == 0 {
				return nil
			}
			score := float64(len(matches))
			if strings.Contains(ctx.BodyLower, "alert(") {
				score += 0.5
			}
			confidence := clampConfidence(0.55 + 0.15*(score-1))
			snippet := snippetAround(ctx.BodyText, matches[0].index, len(matches[0].pattern))
			metadata := map[string]string{
				"matched_pattern": matches[0].pattern,
				"indicator_count": strconv.Itoa(len(matches)),
			}
			return &analysisCandidate{
				AnalyzerID: analyzerID,
				Category:   category,
				Type:       "hydra.xss.reflection",
				Summary:    "Reflected script payload detected",
				Evidence:   snippet,
				Confidence: confidence,
				Severity:   pluginsdk.SeverityMedium,
				TargetURL:  ctx.URL,
				Host:       ctx.Host,
				Vector:     "web_passive_flow",
				StatusCode: ctx.StatusCode,
				Metadata:   metadata,
			}
		},
	}
}

func newSQLiAnalyzer() analyzer {
	indicators := []indicatorMatch{
		{pattern: "you have an error in your sql syntax"},
		{pattern: "warning: mysql"},
		{pattern: "sqlstate["},
		{pattern: "unclosed quotation mark after the character string"},
		{pattern: "pg_query"},
		{pattern: "mysql_fetch"},
		{pattern: "ora-009"},
	}
	const analyzerID = "hydra.rules.sqli"
	const category = "sqli"
	return analyzerFunc{
		id:       analyzerID,
		category: category,
		analyse: func(ctx responseContext) *analysisCandidate {
			matches := scoreIndicators(ctx.BodyLower, indicators)
			if len(matches) == 0 {
				return nil
			}
			confidence := clampConfidence(0.5 + 0.18*float64(len(matches)-1))
			snippet := snippetAround(ctx.BodyText, matches[0].index, len(matches[0].pattern))
			metadata := map[string]string{
				"matched_pattern": matches[0].pattern,
				"indicator_count": strconv.Itoa(len(matches)),
			}
			return &analysisCandidate{
				AnalyzerID: analyzerID,
				Category:   category,
				Type:       "hydra.sqli.error",
				Summary:    "Database error signature suggests injection",
				Evidence:   snippet,
				Confidence: confidence,
				Severity:   pluginsdk.SeverityHigh,
				TargetURL:  ctx.URL,
				Host:       ctx.Host,
				Vector:     "web_passive_flow",
				StatusCode: ctx.StatusCode,
				Metadata:   metadata,
			}
		},
	}
}

func newSSRFAnalyzer() analyzer {
	signals := []string{"169.254.169.254", "metadata.google.internal", "latest/meta-data", "aws_access_key_id", "azure instance metadata"}
	const analyzerID = "hydra.rules.ssrf"
	const category = "ssrf"
	return analyzerFunc{
		id:       analyzerID,
		category: category,
		analyse: func(ctx responseContext) *analysisCandidate {
			matches := findIndicators(ctx.BodyLower, signals)
			if len(matches) == 0 {
				return nil
			}
			confidence := clampConfidence(0.6 + 0.2*float64(len(matches)-1))
			snippet := snippetAround(ctx.BodyText, matches[0].index, len(matches[0].pattern))
			metadata := map[string]string{
				"matched_pattern": matches[0].pattern,
				"indicator_count": strconv.Itoa(len(matches)),
			}
			return &analysisCandidate{
				AnalyzerID: analyzerID,
				Category:   category,
				Type:       "hydra.ssrf.exfil",
				Summary:    "Internal metadata response exposed to client",
				Evidence:   snippet,
				Confidence: confidence,
				Severity:   pluginsdk.SeverityHigh,
				TargetURL:  ctx.URL,
				Host:       ctx.Host,
				Vector:     "web_passive_flow",
				StatusCode: ctx.StatusCode,
				Metadata:   metadata,
			}
		},
	}
}

func newCommandInjectionAnalyzer() analyzer {
	signals := []string{"uid=", "gid=", "sh:", "command not found", "root:x:0:0", "\ncpu"}
	const analyzerID = "hydra.rules.command"
	const category = "cmdi"
	return analyzerFunc{
		id:       analyzerID,
		category: category,
		analyse: func(ctx responseContext) *analysisCandidate {
			matches := findIndicators(ctx.BodyLower, signals)
			if len(matches) == 0 {
				return nil
			}
			confidence := clampConfidence(0.6 + 0.22*float64(len(matches)-1))
			snippet := snippetAround(ctx.BodyText, matches[0].index, len(matches[0].pattern))
			metadata := map[string]string{
				"matched_pattern": matches[0].pattern,
				"indicator_count": strconv.Itoa(len(matches)),
			}
			return &analysisCandidate{
				AnalyzerID: analyzerID,
				Category:   category,
				Type:       "hydra.command.exec",
				Summary:    "Command execution output returned in response",
				Evidence:   snippet,
				Confidence: confidence,
				Severity:   pluginsdk.SeverityHigh,
				TargetURL:  ctx.URL,
				Host:       ctx.Host,
				Vector:     "web_passive_flow",
				StatusCode: ctx.StatusCode,
				Metadata:   metadata,
			}
		},
	}
}

func newOpenRedirectAnalyzer() analyzer {
	const analyzerID = "hydra.rules.redirect"
	const category = "redirect"
	return analyzerFunc{
		id:       analyzerID,
		category: category,
		analyse: func(ctx responseContext) *analysisCandidate {
			location := strings.TrimSpace(ctx.Headers.Get("Location"))
			if location == "" {
				return nil
			}
			parsed, err := url.Parse(location)
			if err != nil {
				return nil
			}
			destHost := strings.ToLower(parsed.Host)
			if destHost == "" {
				return nil
			}
			confidence := 0.45
			if ctx.Host != "" && !strings.EqualFold(ctx.Host, destHost) {
				confidence = 0.6
			}
			for _, key := range []string{"redirect", "next", "target", "url"} {
				if strings.Contains(strings.ToLower(location), key+"=") {
					confidence += 0.1
					break
				}
			}
			confidence = clampConfidence(confidence)
			metadata := map[string]string{
				"redirect_location": parsed.String(),
				"redirect_host":     destHost,
			}
			return &analysisCandidate{
				AnalyzerID: analyzerID,
				Category:   category,
				Type:       "hydra.redirect.open",
				Summary:    "External redirect issued by application",
				Evidence:   parsed.String(),
				Confidence: confidence,
				Severity:   pluginsdk.SeverityLow,
				TargetURL:  ctx.URL,
				Host:       ctx.Host,
				Vector:     "web_passive_flow",
				StatusCode: ctx.StatusCode,
				Metadata:   metadata,
			}
		},
	}
}

func findIndicators(body string, patterns []string) []indicatorMatch {
	matches := make([]indicatorMatch, 0, len(patterns))
	for _, pattern := range patterns {
		lower := strings.ToLower(pattern)
		if idx := strings.Index(body, lower); idx >= 0 {
			matches = append(matches, indicatorMatch{pattern: pattern, index: idx})
		}
	}
	return matches
}

func scoreIndicators(body string, indicators []indicatorMatch) []indicatorMatch {
	matches := make([]indicatorMatch, 0, len(indicators))
	for _, indicator := range indicators {
		lower := strings.ToLower(indicator.pattern)
		if idx := strings.Index(body, lower); idx >= 0 {
			matches = append(matches, indicatorMatch{pattern: indicator.pattern, index: idx})
		}
	}
	return matches
}
