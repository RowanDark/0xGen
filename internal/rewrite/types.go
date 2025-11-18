// Package rewrite implements 0xGen's traffic transformation engine - a powerful
// alternative to Burp's Match/Replace with visual rule builder, variable extraction,
// and testing sandbox capabilities.
package rewrite

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

// Direction specifies whether a rule applies to requests, responses, or both.
type Direction int

const (
	DirectionRequest Direction = iota
	DirectionResponse
	DirectionBoth
)

func (d Direction) String() string {
	switch d {
	case DirectionRequest:
		return "request"
	case DirectionResponse:
		return "response"
	case DirectionBoth:
		return "both"
	default:
		return "unknown"
	}
}

func (d Direction) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *Direction) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch s {
	case "request":
		*d = DirectionRequest
	case "response":
		*d = DirectionResponse
	case "both":
		*d = DirectionBoth
	default:
		return fmt.Errorf("invalid direction: %s", s)
	}
	return nil
}

// ConditionType specifies the type of condition check to perform.
type ConditionType int

const (
	ConditionMatch      ConditionType = iota // Exact match
	ConditionNotMatch                        // Not equal
	ConditionContains                        // Contains substring
	ConditionRegex                           // Regex match
	ConditionJSONPath                        // JSON path evaluation
	ConditionXPath                           // XPath evaluation
	ConditionLength                          // Length comparison
	ConditionExists                          // Header/cookie exists
)

func (c ConditionType) String() string {
	switch c {
	case ConditionMatch:
		return "match"
	case ConditionNotMatch:
		return "not_match"
	case ConditionContains:
		return "contains"
	case ConditionRegex:
		return "regex"
	case ConditionJSONPath:
		return "jsonpath"
	case ConditionXPath:
		return "xpath"
	case ConditionLength:
		return "length"
	case ConditionExists:
		return "exists"
	default:
		return "unknown"
	}
}

func (c ConditionType) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

func (c *ConditionType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch s {
	case "match":
		*c = ConditionMatch
	case "not_match":
		*c = ConditionNotMatch
	case "contains":
		*c = ConditionContains
	case "regex":
		*c = ConditionRegex
	case "jsonpath":
		*c = ConditionJSONPath
	case "xpath":
		*c = ConditionXPath
	case "length":
		*c = ConditionLength
	case "exists":
		*c = ConditionExists
	default:
		return fmt.Errorf("invalid condition type: %s", s)
	}
	return nil
}

// ActionType specifies the type of action to perform.
type ActionType int

const (
	ActionReplace     ActionType = iota // Replace value
	ActionRemove                        // Remove header/cookie/parameter
	ActionAdd                           // Add new value
	ActionExtract                       // Extract to variable
	ActionTransform                     // Apply transformation
	ActionSetVariable                   // Set variable directly
	ActionComputeHash                   // Compute hash (MD5, SHA256, etc.)
)

func (a ActionType) String() string {
	switch a {
	case ActionReplace:
		return "replace"
	case ActionRemove:
		return "remove"
	case ActionAdd:
		return "add"
	case ActionExtract:
		return "extract"
	case ActionTransform:
		return "transform"
	case ActionSetVariable:
		return "set_variable"
	case ActionComputeHash:
		return "compute_hash"
	default:
		return "unknown"
	}
}

func (a ActionType) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.String())
}

func (a *ActionType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch s {
	case "replace":
		*a = ActionReplace
	case "remove":
		*a = ActionRemove
	case "add":
		*a = ActionAdd
	case "extract":
		*a = ActionExtract
	case "transform":
		*a = ActionTransform
	case "set_variable":
		*a = ActionSetVariable
	case "compute_hash":
		*a = ActionComputeHash
	default:
		return fmt.Errorf("invalid action type: %s", s)
	}
	return nil
}

// Location specifies where in the request/response to operate.
type Location int

const (
	LocationHeader Location = iota
	LocationCookie
	LocationBody
	LocationURL
	LocationStatus
	LocationMethod
	LocationPath
	LocationQuery
)

func (l Location) String() string {
	switch l {
	case LocationHeader:
		return "header"
	case LocationCookie:
		return "cookie"
	case LocationBody:
		return "body"
	case LocationURL:
		return "url"
	case LocationStatus:
		return "status"
	case LocationMethod:
		return "method"
	case LocationPath:
		return "path"
	case LocationQuery:
		return "query"
	default:
		return "unknown"
	}
}

func (l Location) MarshalJSON() ([]byte, error) {
	return json.Marshal(l.String())
}

func (l *Location) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch s {
	case "header":
		*l = LocationHeader
	case "cookie":
		*l = LocationCookie
	case "body":
		*l = LocationBody
	case "url":
		*l = LocationURL
	case "status":
		*l = LocationStatus
	case "method":
		*l = LocationMethod
	case "path":
		*l = LocationPath
	case "query":
		*l = LocationQuery
	default:
		return fmt.Errorf("invalid location: %s", s)
	}
	return nil
}

// Rule represents a complete rewrite rule with conditions and actions.
type Rule struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	Priority    int       `json:"priority"` // Higher = applied first

	// Conditions (when to apply)
	Scope      RuleScope   `json:"scope"`
	Conditions []Condition `json:"conditions"`

	// Actions (what to do)
	Actions []Action `json:"actions"`

	// Metadata
	CreatedAt  time.Time `json:"created_at"`
	ModifiedAt time.Time `json:"modified_at"`
	Author     string    `json:"author"`
	Tags       []string  `json:"tags"`

	// Version tracking
	Version int `json:"version"`
}

// RuleScope defines when a rule should be evaluated.
type RuleScope struct {
	Direction   Direction `json:"direction"`      // Request, Response, Both
	Methods     []string  `json:"methods"`        // GET, POST, etc. (nil = all)
	URLPattern  string    `json:"url_pattern"`    // Regex or glob
	ContentType string    `json:"content_type"`   // Regex or glob (e.g., "*/json")

	// Compiled patterns (not serialized)
	urlRegex         *regexp.Regexp `json:"-"`
	contentTypeRegex *regexp.Regexp `json:"-"`
}

// Condition represents a single condition that must be met for a rule to apply.
type Condition struct {
	Type     ConditionType `json:"type"`     // Match, NotMatch, Contains, Regex, etc.
	Location Location      `json:"location"` // Header, Cookie, Body, URL, Status
	Name     string        `json:"name"`     // Header name, cookie name, etc.
	Pattern  string        `json:"pattern"`  // Regex, string, or path
	Negate   bool          `json:"negate"`   // Invert the condition result

	// Compiled pattern (not serialized)
	compiledRegex *regexp.Regexp `json:"-"`
}

// Action represents a single action to perform when a rule matches.
type Action struct {
	Type     ActionType `json:"type"`     // Replace, Remove, Add, Extract, Transform
	Location Location   `json:"location"` // Where to apply the action
	Name     string     `json:"name"`     // Header name, cookie name, variable name, etc.
	Value    string     `json:"value"`    // May contain variables: ${var}
	Pattern  string     `json:"pattern"`  // For replace actions - what to find

	// For ActionTransform
	Transform string `json:"transform,omitempty"` // base64, url, html, md5, sha256, etc.

	// For ActionExtract
	ExtractTo string `json:"extract_to,omitempty"` // Variable name to extract to

	// Compiled pattern (not serialized)
	compiledRegex *regexp.Regexp `json:"-"`
}

// Validate checks if a rule is valid and compiles any regexes.
func (r *Rule) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("rule name is required")
	}

	// Validate scope
	if err := r.Scope.Validate(); err != nil {
		return fmt.Errorf("scope validation failed: %w", err)
	}

	// Validate conditions
	for i, cond := range r.Conditions {
		if err := cond.Validate(); err != nil {
			return fmt.Errorf("condition %d validation failed: %w", i, err)
		}
	}

	// Validate actions
	if len(r.Actions) == 0 {
		return fmt.Errorf("at least one action is required")
	}
	for i, action := range r.Actions {
		if err := action.Validate(); err != nil {
			return fmt.Errorf("action %d validation failed: %w", i, err)
		}
	}

	return nil
}

// Validate checks if a scope is valid and compiles regexes.
func (s *RuleScope) Validate() error {
	// Compile URL pattern if provided
	if s.URLPattern != "" {
		re, err := regexp.Compile(s.URLPattern)
		if err != nil {
			return fmt.Errorf("invalid url_pattern regex: %w", err)
		}
		s.urlRegex = re
	}

	// Compile content type pattern if provided
	if s.ContentType != "" {
		re, err := regexp.Compile(s.ContentType)
		if err != nil {
			return fmt.Errorf("invalid content_type regex: %w", err)
		}
		s.contentTypeRegex = re
	}

	return nil
}

// Validate checks if a condition is valid and compiles regexes.
func (c *Condition) Validate() error {
	// Compile regex patterns
	if c.Type == ConditionRegex {
		if c.Pattern == "" {
			return fmt.Errorf("pattern is required for regex condition")
		}
		re, err := regexp.Compile(c.Pattern)
		if err != nil {
			return fmt.Errorf("invalid regex pattern: %w", err)
		}
		c.compiledRegex = re
	}

	// Validate JSONPath and XPath patterns exist
	if c.Type == ConditionJSONPath || c.Type == ConditionXPath {
		if c.Pattern == "" {
			return fmt.Errorf("pattern is required for %s condition", c.Type)
		}
	}

	return nil
}

// Validate checks if an action is valid and compiles regexes.
func (a *Action) Validate() error {
	// Validate based on action type
	switch a.Type {
	case ActionReplace:
		if a.Pattern == "" {
			return fmt.Errorf("pattern is required for replace action")
		}
		// Try to compile as regex
		if re, err := regexp.Compile(a.Pattern); err == nil {
			a.compiledRegex = re
		}
		// If not a valid regex, we'll treat it as a literal string

	case ActionExtract:
		if a.ExtractTo == "" {
			return fmt.Errorf("extract_to is required for extract action")
		}
		if a.Pattern == "" {
			return fmt.Errorf("pattern is required for extract action")
		}
		// Compile regex pattern
		re, err := regexp.Compile(a.Pattern)
		if err != nil {
			return fmt.Errorf("invalid regex pattern for extract: %w", err)
		}
		a.compiledRegex = re

	case ActionTransform:
		if a.Transform == "" {
			return fmt.Errorf("transform is required for transform action")
		}
		// Validate transform type
		validTransforms := []string{
			"base64", "base64_decode",
			"url", "url_decode",
			"html", "html_decode",
			"hex", "hex_decode",
			"md5", "sha1", "sha256",
			"uppercase", "lowercase",
		}
		valid := false
		for _, t := range validTransforms {
			if a.Transform == t {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid transform type: %s", a.Transform)
		}

	case ActionComputeHash:
		if a.Transform == "" {
			return fmt.Errorf("transform (hash type) is required for compute_hash action")
		}
		validHashes := []string{"md5", "sha1", "sha256"}
		valid := false
		for _, h := range validHashes {
			if a.Transform == h {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid hash type: %s", a.Transform)
		}

	case ActionRemove:
		// Name should be specified for headers/cookies
		if a.Location == LocationHeader || a.Location == LocationCookie {
			if a.Name == "" {
				return fmt.Errorf("name is required for remove action on %s", a.Location)
			}
		}

	case ActionAdd:
		if a.Value == "" {
			return fmt.Errorf("value is required for add action")
		}
	}

	return nil
}

// Clone creates a deep copy of the rule (useful for versioning).
func (r *Rule) Clone() *Rule {
	clone := *r
	clone.Conditions = make([]Condition, len(r.Conditions))
	copy(clone.Conditions, r.Conditions)
	clone.Actions = make([]Action, len(r.Actions))
	copy(clone.Actions, r.Actions)
	clone.Tags = make([]string, len(r.Tags))
	copy(clone.Tags, r.Tags)
	return &clone
}
