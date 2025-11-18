package rewrite

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// Executor handles rule action execution.
type Executor struct {
	variables *VariableStore
	logger    *slog.Logger
}

// NewExecutor creates a new executor with the given variable store.
func NewExecutor(variables *VariableStore, logger *slog.Logger) *Executor {
	if logger == nil {
		logger = slog.Default()
	}
	return &Executor{
		variables: variables,
		logger:    logger,
	}
}

// ExecuteRequestActions executes all actions for a request.
func (e *Executor) ExecuteRequestActions(rule *Rule, req *http.Request, requestID string) error {
	// Read body if needed
	var body []byte
	var err error
	needsBody := e.actionsNeedBody(rule.Actions, false)
	if needsBody {
		body, err = CaptureRequestBody(req)
		if err != nil {
			e.logger.Warn("failed to capture request body", "error", err)
		}
	}

	// Execute each action
	for _, action := range rule.Actions {
		if err := e.executeRequestAction(action, req, body, requestID); err != nil {
			e.logger.Warn("failed to execute request action",
				"action", action.Type,
				"error", err,
			)
			// Continue with other actions despite error
		}
	}

	// If body was modified, replace it
	if needsBody && len(body) > 0 {
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
	}

	return nil
}

// ExecuteResponseActions executes all actions for a response.
func (e *Executor) ExecuteResponseActions(rule *Rule, resp *http.Response, requestID string) error {
	// Read body if needed
	var body []byte
	var err error
	needsBody := e.actionsNeedBody(rule.Actions, true)
	if needsBody {
		body, err = CaptureResponseBody(resp.Body)
		if err != nil {
			e.logger.Warn("failed to capture response body", "error", err)
		}
	}

	// Execute each action
	for _, action := range rule.Actions {
		if err := e.executeResponseAction(action, resp, body, requestID); err != nil {
			e.logger.Warn("failed to execute response action",
				"action", action.Type,
				"error", err,
			)
			// Continue with other actions despite error
		}
	}

	// If body was modified, replace it
	if needsBody && len(body) > 0 {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
	}

	return nil
}

// actionsNeedBody checks if any action requires reading the body.
func (e *Executor) actionsNeedBody(actions []Action, isResponse bool) bool {
	for _, action := range actions {
		if action.Location == LocationBody {
			return true
		}
		// Extract actions might need body depending on location
		if action.Type == ActionExtract && action.Location == LocationBody {
			return true
		}
	}
	return false
}

// executeRequestAction executes a single action on a request.
func (e *Executor) executeRequestAction(action Action, req *http.Request, body []byte, requestID string) error {
	// Substitute variables in action values
	value := e.variables.SubstituteVariables(action.Value, requestID, req.Method, req.URL.String())

	switch action.Type {
	case ActionReplace:
		return e.executeReplace(action, req, nil, body, value, requestID, false)

	case ActionRemove:
		return e.executeRemove(action, req, nil, false)

	case ActionAdd:
		return e.executeAdd(action, req, nil, value, false)

	case ActionExtract:
		return e.executeExtract(action, req, nil, body, requestID, false)

	case ActionTransform:
		return e.executeTransform(action, req, nil, body, requestID, false)

	case ActionSetVariable:
		e.variables.SetRequestVar(requestID, action.Name, value)
		return nil

	case ActionComputeHash:
		return e.executeComputeHash(action, req, nil, body, requestID, false)

	default:
		return fmt.Errorf("unknown action type: %v", action.Type)
	}
}

// executeResponseAction executes a single action on a response.
func (e *Executor) executeResponseAction(action Action, resp *http.Response, body []byte, requestID string) error {
	// Substitute variables in action values
	var reqMethod, reqURL string
	if resp.Request != nil {
		reqMethod = resp.Request.Method
		reqURL = resp.Request.URL.String()
	}
	value := e.variables.SubstituteVariables(action.Value, requestID, reqMethod, reqURL)

	switch action.Type {
	case ActionReplace:
		return e.executeReplace(action, nil, resp, body, value, requestID, true)

	case ActionRemove:
		return e.executeRemove(action, nil, resp, true)

	case ActionAdd:
		return e.executeAdd(action, nil, resp, value, true)

	case ActionExtract:
		return e.executeExtract(action, nil, resp, body, requestID, true)

	case ActionTransform:
		return e.executeTransform(action, nil, resp, body, requestID, true)

	case ActionSetVariable:
		e.variables.SetRequestVar(requestID, action.Name, value)
		return nil

	case ActionComputeHash:
		return e.executeComputeHash(action, nil, resp, body, requestID, true)

	default:
		return fmt.Errorf("unknown action type: %v", action.Type)
	}
}

// executeReplace handles replace actions.
func (e *Executor) executeReplace(action Action, req *http.Request, resp *http.Response, body []byte, value string, requestID string, isResponse bool) error {
	switch action.Location {
	case LocationHeader:
		if isResponse && resp != nil {
			current := resp.Header.Get(action.Name)
			if action.compiledRegex != nil {
				resp.Header.Set(action.Name, action.compiledRegex.ReplaceAllString(current, value))
			} else {
				resp.Header.Set(action.Name, strings.ReplaceAll(current, action.Pattern, value))
			}
		} else if !isResponse && req != nil {
			current := req.Header.Get(action.Name)
			if action.compiledRegex != nil {
				req.Header.Set(action.Name, action.compiledRegex.ReplaceAllString(current, value))
			} else {
				req.Header.Set(action.Name, strings.ReplaceAll(current, action.Pattern, value))
			}
		}

	case LocationCookie:
		if !isResponse && req != nil {
			// Replace cookie value
			for i, cookie := range req.Cookies() {
				if cookie.Name == action.Name {
					if action.compiledRegex != nil {
						cookie.Value = action.compiledRegex.ReplaceAllString(cookie.Value, value)
					} else {
						cookie.Value = strings.ReplaceAll(cookie.Value, action.Pattern, value)
					}
					req.Header.Set("Cookie", "")
					for j, c := range req.Cookies() {
						if j == i {
							req.AddCookie(cookie)
						} else {
							req.AddCookie(c)
						}
					}
					break
				}
			}
		}

	case LocationBody:
		// Replace in body (modifies the body slice in place)
		bodyStr := string(body)
		if action.compiledRegex != nil {
			bodyStr = action.compiledRegex.ReplaceAllString(bodyStr, value)
		} else {
			bodyStr = strings.ReplaceAll(bodyStr, action.Pattern, value)
		}
		copy(body, []byte(bodyStr))

	case LocationURL, LocationPath:
		if !isResponse && req != nil {
			urlStr := req.URL.String()
			if action.compiledRegex != nil {
				urlStr = action.compiledRegex.ReplaceAllString(urlStr, value)
			} else {
				urlStr = strings.ReplaceAll(urlStr, action.Pattern, value)
			}
			newURL, err := url.Parse(urlStr)
			if err != nil {
				return err
			}
			req.URL = newURL
		}

	case LocationQuery:
		if !isResponse && req != nil {
			q := req.URL.Query()
			current := q.Get(action.Name)
			if action.compiledRegex != nil {
				q.Set(action.Name, action.compiledRegex.ReplaceAllString(current, value))
			} else {
				q.Set(action.Name, strings.ReplaceAll(current, action.Pattern, value))
			}
			req.URL.RawQuery = q.Encode()
		}
	}

	return nil
}

// executeRemove handles remove actions.
func (e *Executor) executeRemove(action Action, req *http.Request, resp *http.Response, isResponse bool) error {
	switch action.Location {
	case LocationHeader:
		if isResponse && resp != nil {
			resp.Header.Del(action.Name)
		} else if !isResponse && req != nil {
			req.Header.Del(action.Name)
		}

	case LocationCookie:
		if !isResponse && req != nil {
			// Remove cookie by rebuilding cookie header without it
			var cookies []*http.Cookie
			for _, cookie := range req.Cookies() {
				if cookie.Name != action.Name {
					cookies = append(cookies, cookie)
				}
			}
			req.Header.Del("Cookie")
			for _, cookie := range cookies {
				req.AddCookie(cookie)
			}
		}

	case LocationQuery:
		if !isResponse && req != nil {
			q := req.URL.Query()
			q.Del(action.Name)
			req.URL.RawQuery = q.Encode()
		}
	}

	return nil
}

// executeAdd handles add actions.
func (e *Executor) executeAdd(action Action, req *http.Request, resp *http.Response, value string, isResponse bool) error {
	switch action.Location {
	case LocationHeader:
		if isResponse && resp != nil {
			resp.Header.Add(action.Name, value)
		} else if !isResponse && req != nil {
			req.Header.Add(action.Name, value)
		}

	case LocationCookie:
		if !isResponse && req != nil {
			cookie := &http.Cookie{
				Name:  action.Name,
				Value: value,
			}
			req.AddCookie(cookie)
		}

	case LocationQuery:
		if !isResponse && req != nil {
			q := req.URL.Query()
			q.Add(action.Name, value)
			req.URL.RawQuery = q.Encode()
		}
	}

	return nil
}

// executeExtract handles extract actions.
func (e *Executor) executeExtract(action Action, req *http.Request, resp *http.Response, body []byte, requestID string, isResponse bool) error {
	var value string

	// Get value from location
	switch action.Location {
	case LocationHeader:
		if isResponse && resp != nil {
			value = resp.Header.Get(action.Name)
		} else if !isResponse && req != nil {
			value = req.Header.Get(action.Name)
		}

	case LocationCookie:
		if !isResponse && req != nil {
			cookie, err := req.Cookie(action.Name)
			if err == nil {
				value = cookie.Value
			}
		}

	case LocationBody:
		value = string(body)

	case LocationURL:
		if !isResponse && req != nil {
			value = req.URL.String()
		}

	case LocationPath:
		if !isResponse && req != nil {
			value = req.URL.Path
		}

	case LocationQuery:
		if !isResponse && req != nil {
			value = req.URL.Query().Get(action.Name)
		}
	}

	// Extract using regex pattern
	if action.compiledRegex != nil {
		matches := action.compiledRegex.FindStringSubmatch(value)
		if matches != nil {
			// If there are named groups, extract them
			for i, name := range action.compiledRegex.SubexpNames() {
				if i == 0 || name == "" {
					continue
				}
				if i < len(matches) {
					e.variables.SetRequestVar(requestID, name, matches[i])
				}
			}

			// Also store the primary extracted value
			if action.ExtractTo != "" && len(matches) > 0 {
				// Use first capture group if available, otherwise full match
				extractedValue := matches[0]
				if len(matches) > 1 {
					extractedValue = matches[1]
				}
				e.variables.SetRequestVar(requestID, action.ExtractTo, extractedValue)
			}
		}
	}

	return nil
}

// executeTransform handles transform actions.
func (e *Executor) executeTransform(action Action, req *http.Request, resp *http.Response, body []byte, requestID string, isResponse bool) error {
	var value string

	// Get value from location
	switch action.Location {
	case LocationHeader:
		if isResponse && resp != nil {
			value = resp.Header.Get(action.Name)
		} else if !isResponse && req != nil {
			value = req.Header.Get(action.Name)
		}

	case LocationCookie:
		if !isResponse && req != nil {
			cookie, err := req.Cookie(action.Name)
			if err == nil {
				value = cookie.Value
			}
		}

	case LocationBody:
		value = string(body)
	}

	// Apply transformation
	transformed := ApplyTransform(value, action.Transform)

	// Store result in variable if specified
	if action.Name != "" {
		e.variables.SetRequestVar(requestID, action.Name, transformed)
	}

	return nil
}

// executeComputeHash handles compute hash actions.
func (e *Executor) executeComputeHash(action Action, req *http.Request, resp *http.Response, body []byte, requestID string, isResponse bool) error {
	var value string

	// Get value from location
	switch action.Location {
	case LocationHeader:
		if isResponse && resp != nil {
			value = resp.Header.Get(action.Name)
		} else if !isResponse && req != nil {
			value = req.Header.Get(action.Name)
		}

	case LocationBody:
		value = string(body)

	case LocationURL:
		if !isResponse && req != nil {
			value = req.URL.String()
		}
	}

	// Compute hash
	hash := ComputeHash(value, action.Transform)

	// Store in variable
	if action.Value != "" {
		e.variables.SetRequestVar(requestID, action.Value, hash)
	}

	return nil
}

// JSONPathReplace replaces a value in JSON using a path.
func JSONPathReplace(body []byte, path, value string) ([]byte, error) {
	result, err := sjson.SetBytes(body, path, value)
	if err != nil {
		return body, err
	}
	return result, nil
}

// JSONPathGet gets a value from JSON using a path.
func JSONPathGet(body []byte, path string) string {
	result := gjson.GetBytes(body, path)
	return result.String()
}
