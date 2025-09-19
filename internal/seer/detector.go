package seer

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/RowanDark/Glyph/internal/findings"
)

var (
	awsAccessKeyRe = regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA)[0-9A-Z]{16}\b`)
	slackTokenRe   = regexp.MustCompile(`\bxox(?:b|p|a|r|s)-[0-9A-Za-z-]{10,}\b`)
	genericKeyRe   = regexp.MustCompile(`(?i)(?:api|token|secret|key)[-_ ]*(?:id|key)?\s*[:=]\s*['\"]?([A-Za-z0-9-_]{16,})['\"]?`)
	emailRe        = regexp.MustCompile(`\b[\w.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
)

// Config controls how the detector scans text for potential secrets.
type Config struct {
	Allowlist []string
	Now       func() time.Time
}

// Scan analyses the provided content and returns structured findings.
func Scan(target, content string, cfg Config) []findings.Finding {
	allow := buildAllowlist(cfg.Allowlist)
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	type detection struct {
		match    string
		kind     string
		message  string
		severity findings.Severity
		metadata map[string]string
	}

	var detections []detection
	seen := make(map[string]struct{})

	add := func(match, kind, message string, severity findings.Severity, metadata map[string]string) {
		match = strings.TrimSpace(match)
		if match == "" {
			return
		}
		if shouldAllow(match, allow) {
			return
		}
		key := kind + "|" + strings.ToLower(match)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		meta := map[string]string{"pattern": kind, "match_length": strconv.Itoa(utf8.RuneCountInString(match))}
		for k, v := range metadata {
			meta[k] = v
		}
		redacted := redact(match)
		meta["redacted_match"] = redacted
		detections = append(detections, detection{
			match:    match,
			kind:     kind,
			message:  message,
			severity: severity,
			metadata: meta,
		})
	}

	for _, match := range awsAccessKeyRe.FindAllString(content, -1) {
		add(match, "seer.aws_access_key", "Potential AWS access key detected", findings.SeverityHigh, nil)
	}

	for _, match := range slackTokenRe.FindAllString(content, -1) {
		add(match, "seer.slack_token", "Potential Slack token detected", findings.SeverityHigh, nil)
	}

	for _, groups := range genericKeyRe.FindAllStringSubmatch(content, -1) {
		if len(groups) < 2 {
			continue
		}
		candidate := groups[1]
		if len(candidate) > 128 {
			continue
		}
		if awsAccessKeyRe.MatchString(candidate) || slackTokenRe.MatchString(candidate) {
			continue
		}
		entropy := shannonEntropy(candidate)
		if entropy < 3.5 {
			continue
		}
		add(candidate, "seer.generic_api_key", "High-entropy API key candidate detected", findings.SeverityMedium, map[string]string{
			"entropy": fmt.Sprintf("%.2f", entropy),
		})
	}

	for _, match := range emailRe.FindAllString(content, -1) {
		add(match, "seer.email_address", "Email address discovered", findings.SeverityLow, nil)
	}

	sort.SliceStable(detections, func(i, j int) bool {
		if detections[i].kind == detections[j].kind {
			return detections[i].match < detections[j].match
		}
		return detections[i].kind < detections[j].kind
	})

	findingsList := make([]findings.Finding, 0, len(detections))
	for _, det := range detections {
		findingsList = append(findingsList, findings.Finding{
			ID:         findings.NewID(),
			Plugin:     "seer",
			Type:       det.kind,
			Message:    det.message,
			Target:     target,
			Evidence:   det.metadata["redacted_match"],
			Severity:   det.severity,
			DetectedAt: findings.NewTimestamp(nowFn()),
			Metadata:   det.metadata,
		})
	}

	return findingsList
}

func buildAllowlist(entries []string) map[string]struct{} {
	if len(entries) == 0 {
		return nil
	}
	allow := make(map[string]struct{}, len(entries)*2)
	for _, entry := range entries {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}
		allow[trimmed] = struct{}{}
		allow[strings.ToLower(trimmed)] = struct{}{}
	}
	return allow
}

func shouldAllow(match string, allow map[string]struct{}) bool {
	if len(allow) == 0 {
		return false
	}
	if _, ok := allow[match]; ok {
		return true
	}
	if _, ok := allow[strings.ToLower(match)]; ok {
		return true
	}
	return false
}

func redact(value string) string {
	if value == "" {
		return ""
	}
	if strings.Contains(value, "@") {
		parts := strings.SplitN(value, "@", 2)
		local := []rune(parts[0])
		domain := parts[1]
		maskedLocal := maskRunes(local, 1, 1)
		if maskedLocal == "" {
			maskedLocal = "*"
		}
		return maskedLocal + "@" + domain
	}
	runes := []rune(value)
	return maskRunes(runes, 0, 4)
}

func maskRunes(runes []rune, preserveStart, preserveEnd int) string {
	n := len(runes)
	if n == 0 {
		return ""
	}
	if preserveStart < 0 {
		preserveStart = 0
	}
	if preserveEnd < 0 {
		preserveEnd = 0
	}
	if preserveStart+preserveEnd >= n {
		return strings.Repeat("*", n)
	}
	var b strings.Builder
	for i := 0; i < n; i++ {
		if i < preserveStart || i >= n-preserveEnd {
			b.WriteRune(runes[i])
		} else {
			b.WriteRune('*')
		}
	}
	return b.String()
}

func shannonEntropy(input string) float64 {
	runes := []rune(input)
	if len(runes) == 0 {
		return 0
	}
	counts := make(map[rune]int, len(runes))
	for _, r := range runes {
		counts[r]++
	}
	total := float64(len(runes))
	var entropy float64
	for _, count := range counts {
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}
