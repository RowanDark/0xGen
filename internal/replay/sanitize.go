package replay

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

var sensitiveHeaderNames = map[string]struct{}{
	"authorization":       {},
	"proxy-authorization": {},
	"cookie":              {},
	"set-cookie":          {},
}

var sensitiveBodyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(authorization|token|password|secret)(=|\":?)[^&\s\"']+`),
}

// SanitizeHeaders redacts sensitive header values.
func SanitizeHeaders(input map[string][]string) map[string][]string {
	if len(input) == 0 {
		return nil
	}
	cleaned := make(map[string][]string, len(input))
	for k, values := range input {
		lower := strings.ToLower(strings.TrimSpace(k))
		if _, sensitive := sensitiveHeaderNames[lower]; sensitive {
			cleaned[k] = []string{"[REDACTED]"}
			continue
		}
		dup := make([]string, len(values))
		copy(dup, values)
		cleaned[k] = dup
	}
	return cleaned
}

// SanitizeCookieValue hashes cookie values to avoid leaking secrets.
func SanitizeCookieValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return value
	}
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// SanitizeBody redacts common credential tokens from HTTP bodies.
func SanitizeBody(body []byte) []byte {
	if len(body) == 0 {
		return nil
	}
	sanitized := string(body)
	for _, re := range sensitiveBodyPatterns {
		sanitized = re.ReplaceAllStringFunc(sanitized, func(match string) string {
			idx := strings.Index(match, "=")
			if idx == -1 {
				idx = strings.Index(match, ":")
			}
			if idx == -1 {
				return match
			}
			prefix := strings.TrimSpace(match[:idx+1])
			return prefix + "[REDACTED]"
		})
	}
	return []byte(sanitized)
}
