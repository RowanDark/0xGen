package rewrite

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// VariableScope defines the lifetime of a variable.
type VariableScope int

const (
	ScopeGlobal  VariableScope = iota // Persists across requests
	ScopeSession                       // Per-session (not yet implemented)
	ScopeRequest                       // Single request only
)

func (v VariableScope) String() string {
	switch v {
	case ScopeGlobal:
		return "global"
	case ScopeSession:
		return "session"
	case ScopeRequest:
		return "request"
	default:
		return "unknown"
	}
}

// VariableStore manages variable storage and retrieval with thread-safety.
type VariableStore struct {
	sync.RWMutex
	global  map[string]string            // Global variables
	request map[string]map[string]string // Request-scoped: requestID -> variables
	scopes  map[string]VariableScope     // Variable name -> scope
}

// NewVariableStore creates a new variable store.
func NewVariableStore() *VariableStore {
	return &VariableStore{
		global:  make(map[string]string),
		request: make(map[string]map[string]string),
		scopes:  make(map[string]VariableScope),
	}
}

// Set stores a variable with the given scope.
func (vs *VariableStore) Set(name, value string, scope VariableScope) {
	vs.Lock()
	defer vs.Unlock()

	vs.scopes[name] = scope
	if scope == ScopeGlobal {
		vs.global[name] = value
	}
	// Request-scoped variables are handled separately via SetRequestVar
}

// SetRequestVar stores a request-scoped variable.
func (vs *VariableStore) SetRequestVar(requestID, name, value string) {
	vs.Lock()
	defer vs.Unlock()

	if vs.request[requestID] == nil {
		vs.request[requestID] = make(map[string]string)
	}
	vs.request[requestID][name] = value
	vs.scopes[name] = ScopeRequest
}

// Get retrieves a variable value. For request-scoped, provide requestID.
func (vs *VariableStore) Get(name string, requestID string) (string, bool) {
	vs.RLock()
	defer vs.RUnlock()

	// Check request scope first
	if requestID != "" {
		if reqVars, ok := vs.request[requestID]; ok {
			if val, ok := reqVars[name]; ok {
				return val, true
			}
		}
	}

	// Fall back to global
	val, ok := vs.global[name]
	return val, ok
}

// Delete removes a variable.
func (vs *VariableStore) Delete(name string) {
	vs.Lock()
	defer vs.Unlock()

	delete(vs.global, name)
	delete(vs.scopes, name)
}

// ClearRequest clears all variables for a specific request.
func (vs *VariableStore) ClearRequest(requestID string) {
	vs.Lock()
	defer vs.Unlock()

	delete(vs.request, requestID)
}

// GetBuiltinVariable returns the value of a built-in variable.
func (vs *VariableStore) GetBuiltinVariable(name string, requestMethod, requestURL string) (string, bool) {
	switch name {
	case "timestamp":
		return strconv.FormatInt(time.Now().Unix(), 10), true
	case "timestamp_ms":
		return strconv.FormatInt(time.Now().UnixMilli(), 10), true
	case "random":
		return generateRandomString(16), true
	case "uuid":
		return uuid.New().String(), true
	case "request.method":
		return requestMethod, true
	case "request.url":
		return requestURL, true
	default:
		return "", false
	}
}

var (
	// Pattern to match variable references: ${varname} or ${varname:default} or ${varname|transform}
	varPattern = regexp.MustCompile(`\$\{([^}:|\s]+)(?::([^}|]+))?(?:\|([^}]+))?\}`)
)

// SubstituteVariables replaces variable references in a string with their values.
// Supports:
//   - ${varname} - simple substitution
//   - ${varname:default} - with default value if not found
//   - ${varname|transform} - with transformation (base64, url, etc.)
//   - ${varname:default|transform} - both default and transform
func (vs *VariableStore) SubstituteVariables(input string, requestID string, requestMethod, requestURL string) string {
	return varPattern.ReplaceAllStringFunc(input, func(match string) string {
		// Extract variable name, default, and transform
		parts := varPattern.FindStringSubmatch(match)
		if len(parts) < 2 {
			return match // Shouldn't happen, but be safe
		}

		varName := parts[1]
		defaultVal := ""
		if len(parts) > 2 {
			defaultVal = parts[2]
		}
		transform := ""
		if len(parts) > 3 {
			transform = parts[3]
		}

		// Try to get the variable value
		value, ok := vs.Get(varName, requestID)
		if !ok {
			// Try built-in variables
			value, ok = vs.GetBuiltinVariable(varName, requestMethod, requestURL)
		}
		if !ok {
			// Use default if provided
			if defaultVal != "" {
				value = defaultVal
			} else {
				return match // Keep original if no value and no default
			}
		}

		// Apply transformation if specified
		if transform != "" {
			value = ApplyTransform(value, transform)
		}

		return value
	})
}

// ExtractVariables extracts variables from a string using a regex pattern.
// Pattern should contain named capture groups: (?P<varname>...)
func (vs *VariableStore) ExtractVariables(pattern, input string, requestID string, scope VariableScope) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid regex pattern: %w", err)
	}

	matches := re.FindStringSubmatch(input)
	if matches == nil {
		return nil // No matches, not an error
	}

	// Get named capture groups
	for i, name := range re.SubexpNames() {
		if i == 0 || name == "" {
			continue
		}
		if i < len(matches) {
			if scope == ScopeRequest && requestID != "" {
				vs.SetRequestVar(requestID, name, matches[i])
			} else {
				vs.Set(name, matches[i], scope)
			}
		}
	}

	return nil
}

// ApplyTransform applies a transformation to a value.
func ApplyTransform(value, transform string) string {
	switch transform {
	case "base64":
		return base64.StdEncoding.EncodeToString([]byte(value))
	case "base64_decode":
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return value // Return original on error
		}
		return string(decoded)

	case "url":
		return url.QueryEscape(value)
	case "url_decode":
		decoded, err := url.QueryUnescape(value)
		if err != nil {
			return value
		}
		return decoded

	case "html":
		return html.EscapeString(value)
	case "html_decode":
		return html.UnescapeString(value)

	case "hex":
		return hex.EncodeToString([]byte(value))
	case "hex_decode":
		decoded, err := hex.DecodeString(value)
		if err != nil {
			return value
		}
		return string(decoded)

	case "md5":
		hash := md5.Sum([]byte(value))
		return hex.EncodeToString(hash[:])
	case "sha1":
		hash := sha1.Sum([]byte(value))
		return hex.EncodeToString(hash[:])
	case "sha256":
		hash := sha256.Sum256([]byte(value))
		return hex.EncodeToString(hash[:])

	case "uppercase":
		return strings.ToUpper(value)
	case "lowercase":
		return strings.ToLower(value)

	default:
		return value // Unknown transform, return original
	}
}

// generateRandomString generates a random alphanumeric string of given length.
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}

// ComputeHash computes a hash of the input using the specified algorithm.
func ComputeHash(input, algorithm string) string {
	return ApplyTransform(input, algorithm)
}
