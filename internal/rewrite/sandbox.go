package rewrite

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"time"
)

// DefaultMaxBodySize is the default maximum size for request/response bodies (10MB).
const DefaultMaxBodySize int64 = 10 * 1024 * 1024

// Sandbox provides an isolated environment for testing rules without affecting live traffic.
type Sandbox struct {
	engine      *Engine
	logger      *slog.Logger
	validator   *Validator
	maxBodySize int64
}

// NewSandbox creates a new sandbox instance.
func NewSandbox(engine *Engine, logger *slog.Logger) *Sandbox {
	if logger == nil {
		logger = slog.Default()
	}

	maxBodySize := DefaultMaxBodySize

	// Check environment variable for override
	if envVal := os.Getenv("0XGEN_MAX_BODY_SIZE"); envVal != "" {
		if parsed, err := strconv.ParseInt(envVal, 10, 64); err == nil && parsed > 0 {
			maxBodySize = parsed
		}
	}

	return &Sandbox{
		engine:      engine,
		logger:      logger,
		validator:   NewValidator(logger),
		maxBodySize: maxBodySize,
	}
}

// readBody reads from a reader with a size limit to prevent DoS attacks.
// Returns an error if the body exceeds the maximum allowed size.
func (s *Sandbox) readBody(r io.Reader) ([]byte, error) {
	maxSize := s.maxBodySize
	if maxSize <= 0 {
		maxSize = DefaultMaxBodySize
	}

	// Use LimitReader with +1 to detect overflow
	limitedReader := io.LimitReader(r, maxSize+1)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	if int64(len(body)) > maxSize {
		return nil, fmt.Errorf("body size %d bytes exceeds maximum allowed size of %d bytes", len(body), maxSize)
	}

	return body, nil
}

// TestRequestInput represents a request to test in the sandbox.
type TestRequestInput struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// TestResponseInput represents a response to test in the sandbox.
type TestResponseInput struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
}

// SandboxResult contains the results of a sandbox execution.
type SandboxResult struct {
	Success       bool              `json:"success"`
	OriginalInput interface{}       `json:"original_input"`
	ModifiedInput interface{}       `json:"modified_input"`
	ExecutionLog  *ExecutionLog     `json:"execution_log"`
	Diff          *DiffResult       `json:"diff,omitempty"`
	Warnings      []ValidationError `json:"warnings,omitempty"`
	Duration      time.Duration     `json:"duration"`
}

// ExecutionLog tracks the execution of rules in the sandbox.
type ExecutionLog struct {
	Steps          []ExecutionStep            `json:"steps"`
	TotalDuration  time.Duration              `json:"total_duration"`
	RulesExecuted  int                        `json:"rules_executed"`
	RulesMatched   int                        `json:"rules_matched"`
	ActionsApplied int                        `json:"actions_applied"`
	Variables      map[string]string          `json:"variables"`
	Errors         []string                   `json:"errors,omitempty"`
}

// ExecutionStep represents a single step in the execution log.
type ExecutionStep struct {
	RuleID         int               `json:"rule_id"`
	RuleName       string            `json:"rule_name"`
	Priority       int               `json:"priority"`
	Matched        bool              `json:"matched"`
	MatchReason    string            `json:"match_reason,omitempty"`
	ActionsApplied []ActionResult    `json:"actions_applied"`
	Variables      map[string]string `json:"variables"`
	Duration       time.Duration     `json:"duration"`
	Errors         []string          `json:"errors,omitempty"`
}

// ActionResult represents the result of executing a single action.
type ActionResult struct {
	ActionType  ActionType `json:"action_type"`
	Location    Location   `json:"location"`
	Name        string     `json:"name"`
	OldValue    string     `json:"old_value,omitempty"`
	NewValue    string     `json:"new_value,omitempty"`
	Success     bool       `json:"success"`
	Error       string     `json:"error,omitempty"`
}

// DiffResult represents the differences between original and modified input.
type DiffResult struct {
	HeaderChanges  []HeaderDiff `json:"header_changes,omitempty"`
	BodyChanged    bool         `json:"body_changed"`
	BodyDiff       string       `json:"body_diff,omitempty"`
	URLChanged     bool         `json:"url_changed"`
	URLDiff        string       `json:"url_diff,omitempty"`
	StatusChanged  bool         `json:"status_changed,omitempty"`
	OldStatus      int          `json:"old_status,omitempty"`
	NewStatus      int          `json:"new_status,omitempty"`
}

// HeaderDiff represents a change to a header.
type HeaderDiff struct {
	Name     string `json:"name"`
	OldValue string `json:"old_value"`
	NewValue string `json:"new_value"`
	Action   string `json:"action"` // "added", "removed", "modified"
}

// TestRequest tests rules against a request in the sandbox.
func (s *Sandbox) TestRequest(ctx context.Context, input *TestRequestInput, ruleIDs []int) (*SandboxResult, error) {
	start := time.Now()

	// Convert input to http.Request
	req, err := s.inputToRequest(input)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Clone the request for modification
	originalReq, err := s.cloneRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to clone original request: %w", err)
	}
	modifiedReq, err := s.cloneRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to clone modified request: %w", err)
	}

	// Initialize execution log
	log := &ExecutionLog{
		Steps:     make([]ExecutionStep, 0),
		Variables: make(map[string]string),
		Errors:    make([]string, 0),
	}

	// Get rules to test
	var rules []*Rule
	if len(ruleIDs) > 0 {
		for _, id := range ruleIDs {
			rule, err := s.engine.GetRule(ctx, id)
			if err != nil {
				log.Errors = append(log.Errors, fmt.Sprintf("Failed to get rule %d: %v", id, err))
				continue
			}
			rules = append(rules, rule)
		}
	} else {
		// Test all active rules
		rules = s.engine.GetActiveRules(DirectionRequest)
	}

	// Sort by priority
	rules = sortRulesByPriority(rules)

	// Execute each rule
	requestID := "sandbox-" + time.Now().Format("20060102-150405")
	for _, rule := range rules {
		stepStart := time.Now()

		step := ExecutionStep{
			RuleID:         rule.ID,
			RuleName:       rule.Name,
			Priority:       rule.Priority,
			Matched:        false,
			ActionsApplied: make([]ActionResult, 0),
			Variables:      make(map[string]string),
			Errors:         make([]string, 0),
		}

		// Check if rule matches
		if s.engine.matcher.MatchesScope(rule, modifiedReq, false) {
			// Evaluate conditions
			body, _ := CaptureRequestBody(modifiedReq)
			if s.engine.matcher.EvaluateConditions(rule, modifiedReq, 0, nil, body, requestID) {
				step.Matched = true
				step.MatchReason = "Scope and conditions matched"
				log.RulesMatched++

				// Execute actions and track results
				for _, action := range rule.Actions {
					actionResult := s.executeRequestActionWithTracking(action, modifiedReq, body, requestID)
					step.ActionsApplied = append(step.ActionsApplied, actionResult)
					if actionResult.Success {
						log.ActionsApplied++
					}
				}

				// Update body if needed
				if len(body) > 0 {
					modifiedReq.Body = io.NopCloser(bytes.NewReader(body))
					modifiedReq.ContentLength = int64(len(body))
				}
			} else {
				step.MatchReason = "Conditions not met"
			}
		} else {
			step.MatchReason = "Scope not matched"
		}

		step.Duration = time.Since(stepStart)
		log.Steps = append(log.Steps, step)
		log.RulesExecuted++
	}

	log.TotalDuration = time.Since(start)

	// Generate diff
	diff := s.generateRequestDiff(originalReq, modifiedReq)

	// Validate rules and get warnings
	warnings := s.validator.ValidateRules(rules)

	// Convert requests to serializable format
	originalInput, err := s.requestToOutput(originalReq)
	if err != nil {
		return nil, fmt.Errorf("failed to convert original request to output: %w", err)
	}
	modifiedInput, err := s.requestToOutput(modifiedReq)
	if err != nil {
		return nil, fmt.Errorf("failed to convert modified request to output: %w", err)
	}

	result := &SandboxResult{
		Success:       len(log.Errors) == 0,
		OriginalInput: originalInput,
		ModifiedInput: modifiedInput,
		ExecutionLog:  log,
		Diff:          diff,
		Warnings:      warnings,
		Duration:      time.Since(start),
	}

	return result, nil
}

// TestResponse tests rules against a response in the sandbox.
func (s *Sandbox) TestResponse(ctx context.Context, input *TestResponseInput, ruleIDs []int) (*SandboxResult, error) {
	start := time.Now()

	// Convert input to http.Response
	resp := s.inputToResponse(input)

	// Clone the response for modification
	originalResp, err := s.cloneResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to clone original response: %w", err)
	}
	modifiedResp, err := s.cloneResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to clone modified response: %w", err)
	}

	// Initialize execution log
	log := &ExecutionLog{
		Steps:     make([]ExecutionStep, 0),
		Variables: make(map[string]string),
		Errors:    make([]string, 0),
	}

	// Get rules to test
	var rules []*Rule
	if len(ruleIDs) > 0 {
		for _, id := range ruleIDs {
			rule, err := s.engine.GetRule(ctx, id)
			if err != nil {
				log.Errors = append(log.Errors, fmt.Sprintf("Failed to get rule %d: %v", id, err))
				continue
			}
			rules = append(rules, rule)
		}
	} else {
		// Test all active rules
		rules = s.engine.GetActiveRules(DirectionResponse)
	}

	// Sort by priority
	rules = sortRulesByPriority(rules)

	// Create a dummy request for matcher
	dummyReq, _ := http.NewRequest("GET", "http://example.com", nil)

	// Execute each rule
	requestID := "sandbox-" + time.Now().Format("20060102-150405")
	for _, rule := range rules {
		stepStart := time.Now()

		step := ExecutionStep{
			RuleID:         rule.ID,
			RuleName:       rule.Name,
			Priority:       rule.Priority,
			Matched:        false,
			ActionsApplied: make([]ActionResult, 0),
			Variables:      make(map[string]string),
			Errors:         make([]string, 0),
		}

		// Check if rule matches
		if s.engine.matcher.MatchesScope(rule, dummyReq, true) {
			// Evaluate conditions
			body, _ := CaptureResponseBody(modifiedResp.Body)
			modifiedResp.Body = io.NopCloser(bytes.NewReader(body))

			if s.engine.matcher.EvaluateConditions(rule, dummyReq, modifiedResp.StatusCode, modifiedResp.Header, body, requestID) {
				step.Matched = true
				step.MatchReason = "Scope and conditions matched"
				log.RulesMatched++

				// Execute actions and track results
				for _, action := range rule.Actions {
					actionResult := s.executeResponseActionWithTracking(action, modifiedResp, body, requestID)
					step.ActionsApplied = append(step.ActionsApplied, actionResult)
					if actionResult.Success {
						log.ActionsApplied++
					}
				}

				// Update body if needed
				if len(body) > 0 {
					modifiedResp.Body = io.NopCloser(bytes.NewReader(body))
					modifiedResp.ContentLength = int64(len(body))
				}
			} else {
				step.MatchReason = "Conditions not met"
			}
		} else {
			step.MatchReason = "Scope not matched"
		}

		step.Duration = time.Since(stepStart)
		log.Steps = append(log.Steps, step)
		log.RulesExecuted++
	}

	log.TotalDuration = time.Since(start)

	// Generate diff
	diff := s.generateResponseDiff(originalResp, modifiedResp)

	// Validate rules and get warnings
	warnings := s.validator.ValidateRules(rules)

	// Convert responses to serializable format
	originalOutput, err := s.responseToOutput(originalResp)
	if err != nil {
		return nil, fmt.Errorf("failed to convert original response to output: %w", err)
	}
	modifiedOutput, err := s.responseToOutput(modifiedResp)
	if err != nil {
		return nil, fmt.Errorf("failed to convert modified response to output: %w", err)
	}

	result := &SandboxResult{
		Success:       len(log.Errors) == 0,
		OriginalInput: originalOutput,
		ModifiedInput: modifiedOutput,
		ExecutionLog:  log,
		Diff:          diff,
		Warnings:      warnings,
		Duration:      time.Since(start),
	}

	return result, nil
}

// Helper functions

func (s *Sandbox) inputToRequest(input *TestRequestInput) (*http.Request, error) {
	var body io.Reader
	if input.Body != "" {
		body = bytes.NewReader([]byte(input.Body))
	}

	req, err := http.NewRequest(input.Method, input.URL, body)
	if err != nil {
		return nil, err
	}

	for k, v := range input.Headers {
		req.Header.Set(k, v)
	}

	return req, nil
}

func (s *Sandbox) inputToResponse(input *TestResponseInput) *http.Response {
	resp := &http.Response{
		StatusCode: input.StatusCode,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader([]byte(input.Body))),
	}

	for k, v := range input.Headers {
		resp.Header.Set(k, v)
	}

	return resp
}

func (s *Sandbox) cloneRequest(req *http.Request) (*http.Request, error) {
	// Read body with size limit
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = s.readBody(req.Body)
		if err != nil {
			return nil, fmt.Errorf("clone request body: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// Clone request
	clone, err := http.NewRequest(req.Method, req.URL.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create request clone: %w", err)
	}
	clone.Header = req.Header.Clone()

	return clone, nil
}

func (s *Sandbox) cloneResponse(resp *http.Response) (*http.Response, error) {
	// Read body with size limit
	var bodyBytes []byte
	if resp.Body != nil {
		var err error
		bodyBytes, err = s.readBody(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("clone response body: %w", err)
		}
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// Clone response
	clone := &http.Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
		Body:       io.NopCloser(bytes.NewReader(bodyBytes)),
	}

	return clone, nil
}

func (s *Sandbox) requestToOutput(req *http.Request) (map[string]interface{}, error) {
	bodyBytes, err := s.readBody(req.Body)
	if err != nil {
		return nil, fmt.Errorf("read request body for output: %w", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Convert to dump for readability
	dump, _ := httputil.DumpRequest(req, true)

	return map[string]interface{}{
		"method":  req.Method,
		"url":     req.URL.String(),
		"headers": req.Header,
		"body":    string(bodyBytes),
		"dump":    string(dump),
	}, nil
}

func (s *Sandbox) responseToOutput(resp *http.Response) (map[string]interface{}, error) {
	bodyBytes, err := s.readBody(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body for output: %w", err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Convert to dump for readability
	dump, _ := httputil.DumpResponse(resp, true)

	return map[string]interface{}{
		"status_code": resp.StatusCode,
		"headers":     resp.Header,
		"body":        string(bodyBytes),
		"dump":        string(dump),
	}, nil
}

func (s *Sandbox) executeRequestActionWithTracking(action Action, req *http.Request, body []byte, requestID string) ActionResult {
	result := ActionResult{
		ActionType: action.Type,
		Location:   action.Location,
		Name:       action.Name,
		Success:    true,
	}

	// Get old value
	result.OldValue = s.getLocationValue(action.Location, action.Name, req, nil, body)

	// Execute action
	if err := s.executeRequestActionSingle(action, req, body, requestID); err != nil {
		result.Success = false
		result.Error = err.Error()
		return result
	}

	// Get new value
	result.NewValue = s.getLocationValue(action.Location, action.Name, req, nil, body)

	return result
}

func (s *Sandbox) executeResponseActionWithTracking(action Action, resp *http.Response, body []byte, requestID string) ActionResult {
	result := ActionResult{
		ActionType: action.Type,
		Location:   action.Location,
		Name:       action.Name,
		Success:    true,
	}

	// Get old value
	result.OldValue = s.getLocationValue(action.Location, action.Name, nil, resp, body)

	// Execute action
	if err := s.executeResponseActionSingle(action, resp, body, requestID); err != nil {
		result.Success = false
		result.Error = err.Error()
		return result
	}

	// Get new value
	result.NewValue = s.getLocationValue(action.Location, action.Name, nil, resp, body)

	return result
}

func (s *Sandbox) getLocationValue(location Location, name string, req *http.Request, resp *http.Response, body []byte) string {
	switch location {
	case LocationHeader:
		if req != nil {
			return req.Header.Get(name)
		}
		if resp != nil {
			return resp.Header.Get(name)
		}
	case LocationCookie:
		if req != nil {
			cookie, _ := req.Cookie(name)
			if cookie != nil {
				return cookie.Value
			}
		}
	case LocationBody:
		return string(body)
	case LocationURL:
		if req != nil {
			return req.URL.String()
		}
	case LocationStatus:
		if resp != nil {
			return fmt.Sprintf("%d", resp.StatusCode)
		}
	}
	return ""
}

func (s *Sandbox) executeRequestActionSingle(action Action, req *http.Request, body []byte, requestID string) error {
	// Use the executor but in sandbox mode
	return s.engine.executor.executeRequestAction(action, req, body, requestID)
}

func (s *Sandbox) executeResponseActionSingle(action Action, resp *http.Response, body []byte, requestID string) error {
	// Use the executor but in sandbox mode
	return s.engine.executor.executeResponseAction(action, resp, body, requestID)
}

func sortRulesByPriority(rules []*Rule) []*Rule {
	// Copy and sort by priority (higher first)
	sorted := make([]*Rule, len(rules))
	copy(sorted, rules)

	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].Priority > sorted[i].Priority {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	return sorted
}
