package redact

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	neverPersistKey = "never_persist"
	redactedSecret  = "[REDACTED_SECRET]"
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
	masked = longTokenRe.ReplaceAllString(masked, redactedSecret)
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
	masked := applyNeverPersistAny(in)
	out := make(map[string]any, len(masked))
	for k, v := range masked {
		out[k] = Interface(v)
	}
	return out
}

// MapString redacts sensitive values within a string map.
func MapString(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	masked := applyNeverPersistString(in)
	out := make(map[string]string, len(masked))
	for k, v := range masked {
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

func applyNeverPersistAny(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	var toMask []string
	for k, v := range in {
		if strings.EqualFold(k, neverPersistKey) {
			toMask = append(toMask, collectNeverPersist(v)...)
			continue
		}
		out[k] = v
	}
	if len(toMask) == 0 {
		return out
	}
	keys := normaliseNeverPersistKeys(toMask)
	for key := range keys {
		if _, ok := out[key]; ok {
			out[key] = redactedSecret
		}
	}
	return out
}

func applyNeverPersistString(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	var rawList []string
	for k, v := range in {
		if strings.EqualFold(k, neverPersistKey) {
			rawList = append(rawList, collectNeverPersistStrings(v)...)
			continue
		}
		out[k] = v
	}
	if len(rawList) == 0 {
		return out
	}
	keys := normaliseNeverPersistKeys(rawList)
	for key := range keys {
		if _, ok := out[key]; ok {
			out[key] = redactedSecret
		}
	}
	return out
}

func collectNeverPersist(value any) []string {
	switch v := value.(type) {
	case string:
		return collectNeverPersistStrings(v)
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, elem := range v {
			if s, ok := elem.(string); ok {
				out = append(out, s)
				continue
			}
			out = append(out, fmt.Sprint(elem))
		}
		return out
	default:
		return nil
	}
}

func collectNeverPersistStrings(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func normaliseNeverPersistKeys(keys []string) map[string]struct{} {
	if len(keys) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		out[trimmed] = struct{}{}
	}
	return out
}
