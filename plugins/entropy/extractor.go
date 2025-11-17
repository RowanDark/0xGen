package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	pluginsdk "github.com/RowanDark/0xgen/sdk/plugin-sdk"
)

// ExtractTokens extracts tokens from HTTP response based on extractor configuration
func ExtractTokens(response *pluginsdk.HTTPResponse, extractor TokenExtractor, requestID string) ([]TokenSample, error) {
	var tokens []TokenSample
	now := time.Now().UTC()

	switch strings.ToLower(extractor.Location) {
	case "header":
		if vals := response.Headers[extractor.Name]; len(vals) > 0 {
			for _, val := range vals {
				if token := extractByPattern(val, extractor.Pattern); token != "" {
					tokens = append(tokens, TokenSample{
						TokenValue:      token,
						TokenLength:     len(token),
						CapturedAt:      now,
						SourceRequestID: requestID,
					})
				}
			}
		}

	case "cookie":
		// Parse Set-Cookie headers
		for _, cookieStr := range response.Headers["Set-Cookie"] {
			if cookie := parseCookie(cookieStr, extractor.Name); cookie != "" {
				if token := extractByPattern(cookie, extractor.Pattern); token != "" {
					tokens = append(tokens, TokenSample{
						TokenValue:      token,
						TokenLength:     len(token),
						CapturedAt:      now,
						SourceRequestID: requestID,
					})
				}
			}
		}

	case "body", "json":
		// Try JSON extraction first
		if jsonTokens := extractFromJSON(response.Body, extractor.Pattern, extractor.Name); len(jsonTokens) > 0 {
			for _, token := range jsonTokens {
				tokens = append(tokens, TokenSample{
					TokenValue:      token,
					TokenLength:     len(token),
					CapturedAt:      now,
					SourceRequestID: requestID,
				})
			}
		} else if extractor.Pattern != "" {
			// Fall back to regex pattern matching in body
			if token := extractByPattern(string(response.Body), extractor.Pattern); token != "" {
				tokens = append(tokens, TokenSample{
					TokenValue:      token,
					TokenLength:     len(token),
					CapturedAt:      now,
					SourceRequestID: requestID,
				})
			}
		}

	case "xml":
		if xmlTokens := extractFromXML(response.Body, extractor.Name); len(xmlTokens) > 0 {
			for _, token := range xmlTokens {
				if extractor.Pattern != "" {
					if matched := extractByPattern(token, extractor.Pattern); matched != "" {
						token = matched
					}
				}
				tokens = append(tokens, TokenSample{
					TokenValue:      token,
					TokenLength:     len(token),
					CapturedAt:      now,
					SourceRequestID: requestID,
				})
			}
		}

	default:
		return nil, fmt.Errorf("unsupported location: %s", extractor.Location)
	}

	return tokens, nil
}

// extractByPattern uses regex to extract token
func extractByPattern(text, pattern string) string {
	if pattern == "" {
		return text
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return ""
	}

	matches := re.FindStringSubmatch(text)
	if len(matches) > 1 {
		// Return first capture group
		return matches[1]
	} else if len(matches) == 1 {
		// Return entire match
		return matches[0]
	}

	return ""
}

// parseCookie extracts cookie value by name from Set-Cookie header
func parseCookie(setCookie, name string) string {
	// Simple parsing: "name=value; other-directives"
	parts := strings.Split(setCookie, ";")
	if len(parts) == 0 {
		return ""
	}

	nameValue := strings.TrimSpace(parts[0])
	kv := strings.SplitN(nameValue, "=", 2)
	if len(kv) != 2 {
		return ""
	}

	if strings.TrimSpace(kv[0]) == name {
		return strings.TrimSpace(kv[1])
	}

	return ""
}

// extractFromJSON extracts value from JSON using JSONPath-like syntax
func extractFromJSON(body []byte, jsonPath, fieldName string) []string {
	var data interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil
	}

	// Support simple JSONPath like "$.token", "$.session.id", or just field name
	path := jsonPath
	if path == "" {
		path = fieldName
	}

	// Remove leading "$." if present
	path = strings.TrimPrefix(path, "$.")
	path = strings.TrimPrefix(path, ".")

	// Split path by "."
	parts := strings.Split(path, ".")

	return extractJSONValue(data, parts)
}

// extractJSONValue recursively navigates JSON structure
func extractJSONValue(data interface{}, path []string) []string {
	if len(path) == 0 {
		return nil
	}

	switch v := data.(type) {
	case map[string]interface{}:
		if len(path) == 1 {
			// Last element in path
			if val, ok := v[path[0]]; ok {
				return []string{fmt.Sprintf("%v", val)}
			}
		} else {
			// Navigate deeper
			if next, ok := v[path[0]]; ok {
				return extractJSONValue(next, path[1:])
			}
		}

	case []interface{}:
		// If it's an array, check all elements
		var results []string
		for _, item := range v {
			if vals := extractJSONValue(item, path); len(vals) > 0 {
				results = append(results, vals...)
			}
		}
		return results

	case string:
		if len(path) == 0 {
			return []string{v}
		}
	}

	return nil
}

// extractFromXML extracts value from XML by tag name
func extractFromXML(body []byte, tagName string) []string {
	// Parse XML into a generic map structure
	var data map[string]interface{}
	if err := xml.Unmarshal(body, &data); err != nil {
		// Try simple regex extraction as fallback
		pattern := fmt.Sprintf("<%s>([^<]+)</%s>", tagName, tagName)
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil
		}
		matches := re.FindAllStringSubmatch(string(body), -1)
		var results []string
		for _, match := range matches {
			if len(match) > 1 {
				results = append(results, match[1])
			}
		}
		return results
	}

	// Extract from parsed map
	if val, ok := data[tagName]; ok {
		return []string{fmt.Sprintf("%v", val)}
	}

	return nil
}

// ExtractTokenFromHeaders is a convenience function for header extraction
func ExtractTokenFromHeaders(headers http.Header, headerName string) string {
	if vals := headers[headerName]; len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// ExtractSessionID attempts to extract common session IDs
func ExtractSessionID(response *pluginsdk.HTTPResponse) string {
	// Try common session cookie names
	sessionNames := []string{"PHPSESSID", "JSESSIONID", "sessionid", "session_id", "sid", "ASP.NET_SessionId"}

	for _, name := range sessionNames {
		for _, cookieStr := range response.Headers["Set-Cookie"] {
			if val := parseCookie(cookieStr, name); val != "" {
				return val
			}
		}
	}

	// Try Authorization header
	if auth := response.Headers["Authorization"]; len(auth) > 0 {
		// Extract token from "Bearer <token>"
		parts := strings.Fields(auth[0])
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			return parts[1]
		}
	}

	return ""
}
