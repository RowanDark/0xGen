package redact

import (
	"fmt"
	"regexp"
	"strings"
)

type stringer interface {
	String() string
}

var (
	emailRe     = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	kvSecretRe  = regexp.MustCompile(`(?i)((?:api|token|secret|key|password)[-_ ]*(?:id|key|token)?\s*[:=]\s*)(['\"]?)([A-Za-z0-9+/=_\-]{8,})(['\"]?)`)
	bearerRe    = regexp.MustCompile(`(?i)\b(bearer|token)\s+([A-Za-z0-9._\-]{10,})`)
	longTokenRe = regexp.MustCompile(`\b[A-Za-z0-9]{32,}\b`)
)

// String redacts common secret patterns and PII from the provided string.
func String(in string) string {
	if strings.TrimSpace(in) == "" {
		return in
	}
	masked := emailRe.ReplaceAllStringFunc(in, func(_ string) string {
		return "[REDACTED_EMAIL]"
	})
	masked = kvSecretRe.ReplaceAllString(masked, `$1$2[REDACTED_SECRET]$4`)
	masked = bearerRe.ReplaceAllString(masked, `$1 [REDACTED_SECRET]`)
	masked = longTokenRe.ReplaceAllString(masked, "[REDACTED_SECRET]")
	return masked
}

// Interface redacts recognised sensitive values within nested structures.
func Interface(value any) any {
	switch v := value.(type) {
	case string:
		return String(v)
	case stringer:
		return String(v.String())
	case fmt.Stringer:
		return String(v.String())
	case []string:
		out := make([]string, len(v))
		for i, s := range v {
			out[i] = String(s)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, elem := range v {
			out[i] = Interface(elem)
		}
		return out
	case map[string]string:
		return MapString(v)
	case map[string]any:
		return Map(v)
	case []fmt.Stringer:
		out := make([]string, len(v))
		for i, s := range v {
			out[i] = String(s.String())
		}
		return out
	default:
		return value
	}
}

// Map redacts sensitive values within a map of arbitrary values.
func Map(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = Interface(v)
	}
	return out
}

// MapString redacts sensitive values within a string map.
func MapString(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = String(v)
	}
	return out
}

// Slice redacts sensitive values within a slice of strings.
func Slice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = String(v)
	}
	return out
}
