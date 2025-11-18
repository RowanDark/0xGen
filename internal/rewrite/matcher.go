package rewrite

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/tidwall/gjson"
)

// Matcher handles rule condition evaluation.
type Matcher struct {
	variables *VariableStore
}

// NewMatcher creates a new matcher with the given variable store.
func NewMatcher(variables *VariableStore) *Matcher {
	return &Matcher{
		variables: variables,
	}
}

// MatchesScope checks if a request/response matches the rule's scope.
func (m *Matcher) MatchesScope(rule *Rule, req *http.Request, isResponse bool) bool {
	scope := rule.Scope

	// Check direction
	switch scope.Direction {
	case DirectionRequest:
		if isResponse {
			return false
		}
	case DirectionResponse:
		if !isResponse {
			return false
		}
	case DirectionBoth:
		// Always matches
	}

	// Check method (only for requests)
	if !isResponse && len(scope.Methods) > 0 {
		methodMatch := false
		for _, method := range scope.Methods {
			if strings.EqualFold(req.Method, method) {
				methodMatch = true
				break
			}
		}
		if !methodMatch {
			return false
		}
	}

	// Check URL pattern
	if scope.URLPattern != "" && scope.urlRegex != nil {
		url := req.URL.String()
		if !scope.urlRegex.MatchString(url) {
			return false
		}
	}

	// Check content type
	if scope.ContentType != "" && scope.contentTypeRegex != nil {
		ct := req.Header.Get("Content-Type")
		if ct == "" {
			return false
		}
		if !scope.contentTypeRegex.MatchString(ct) {
			return false
		}
	}

	return true
}

// EvaluateConditions checks if all conditions in a rule are met.
// Returns true if all conditions pass (AND logic).
func (m *Matcher) EvaluateConditions(rule *Rule, req *http.Request, respStatus int, respHeaders http.Header, body []byte, requestID string) bool {
	// If no conditions, rule always applies (after scope check)
	if len(rule.Conditions) == 0 {
		return true
	}

	// Evaluate each condition
	for _, cond := range rule.Conditions {
		result := m.evaluateCondition(cond, req, respStatus, respHeaders, body, requestID)
		if cond.Negate {
			result = !result
		}
		if !result {
			return false // Short-circuit on first failure
		}
	}

	return true
}

// evaluateCondition evaluates a single condition.
func (m *Matcher) evaluateCondition(cond Condition, req *http.Request, respStatus int, respHeaders http.Header, body []byte, requestID string) bool {
	// Get the value to check based on location
	value := m.getLocationValue(cond.Location, cond.Name, req, respStatus, respHeaders, body)

	// Evaluate based on condition type
	switch cond.Type {
	case ConditionMatch:
		return value == cond.Pattern

	case ConditionNotMatch:
		return value != cond.Pattern

	case ConditionContains:
		return strings.Contains(value, cond.Pattern)

	case ConditionRegex:
		if cond.compiledRegex == nil {
			return false
		}
		return cond.compiledRegex.MatchString(value)

	case ConditionJSONPath:
		return m.evaluateJSONPath(body, cond.Pattern)

	case ConditionXPath:
		// XPath evaluation would require an XML parser
		// For now, return false (can be implemented later with a library)
		return false

	case ConditionLength:
		// Pattern should be like ">100" or "<=50" or "==10"
		return m.evaluateLengthCondition(value, cond.Pattern)

	case ConditionExists:
		return value != ""

	default:
		return false
	}
}

// getLocationValue retrieves the value from the specified location.
func (m *Matcher) getLocationValue(location Location, name string, req *http.Request, respStatus int, respHeaders http.Header, body []byte) string {
	switch location {
	case LocationHeader:
		if req != nil {
			return req.Header.Get(name)
		}
		if respHeaders != nil {
			return respHeaders.Get(name)
		}
		return ""

	case LocationCookie:
		if req != nil {
			cookie, err := req.Cookie(name)
			if err == nil {
				return cookie.Value
			}
		}
		return ""

	case LocationBody:
		return string(body)

	case LocationURL:
		if req != nil {
			return req.URL.String()
		}
		return ""

	case LocationPath:
		if req != nil {
			return req.URL.Path
		}
		return ""

	case LocationQuery:
		if req != nil {
			return req.URL.Query().Get(name)
		}
		return ""

	case LocationStatus:
		if respStatus > 0 {
			return strconv.Itoa(respStatus)
		}
		return ""

	case LocationMethod:
		if req != nil {
			return req.Method
		}
		return ""

	default:
		return ""
	}
}

// evaluateJSONPath evaluates a JSON path condition using gjson.
func (m *Matcher) evaluateJSONPath(body []byte, path string) bool {
	if len(body) == 0 {
		return false
	}

	result := gjson.GetBytes(body, path)
	return result.Exists()
}

// evaluateLengthCondition evaluates a length comparison condition.
// Pattern should be like ">100", "<=50", "==10", etc.
func (m *Matcher) evaluateLengthCondition(value, pattern string) bool {
	length := len(value)

	// Parse the pattern
	if len(pattern) < 2 {
		return false
	}

	var op string
	var threshold int

	// Try two-character operators first
	if len(pattern) >= 2 {
		twoChar := pattern[:2]
		if twoChar == ">=" || twoChar == "<=" || twoChar == "==" || twoChar == "!=" {
			op = twoChar
			val, err := strconv.Atoi(strings.TrimSpace(pattern[2:]))
			if err != nil {
				return false
			}
			threshold = val
		}
	}

	// Try single-character operators
	if op == "" {
		oneChar := pattern[:1]
		if oneChar == ">" || oneChar == "<" {
			op = oneChar
			val, err := strconv.Atoi(strings.TrimSpace(pattern[1:]))
			if err != nil {
				return false
			}
			threshold = val
		}
	}

	if op == "" {
		return false
	}

	// Perform comparison
	switch op {
	case ">":
		return length > threshold
	case "<":
		return length < threshold
	case ">=":
		return length >= threshold
	case "<=":
		return length <= threshold
	case "==":
		return length == threshold
	case "!=":
		return length != threshold
	default:
		return false
	}
}

// CaptureRequestBody safely reads and replaces the request body.
func CaptureRequestBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	// Replace the body so it can be read again
	req.Body = io.NopCloser(bytes.NewReader(body))

	return body, nil
}

// CaptureResponseBody safely reads a response body.
func CaptureResponseBody(body io.ReadCloser) ([]byte, error) {
	if body == nil {
		return nil, nil
	}

	data, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}

	return data, nil
}
