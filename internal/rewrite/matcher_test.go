package rewrite

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"testing"
)

func TestMatchesScope(t *testing.T) {
	vs := NewVariableStore()
	matcher := NewMatcher(vs)

	tests := []struct {
		name       string
		rule       *Rule
		method     string
		url        string
		isResponse bool
		want       bool
	}{
		{
			name: "request direction matches request",
			rule: &Rule{
				Scope: RuleScope{Direction: DirectionRequest},
			},
			method:     "GET",
			url:        "https://example.com",
			isResponse: false,
			want:       true,
		},
		{
			name: "request direction does not match response",
			rule: &Rule{
				Scope: RuleScope{Direction: DirectionRequest},
			},
			method:     "GET",
			url:        "https://example.com",
			isResponse: true,
			want:       false,
		},
		{
			name: "response direction matches response",
			rule: &Rule{
				Scope: RuleScope{Direction: DirectionResponse},
			},
			method:     "GET",
			url:        "https://example.com",
			isResponse: true,
			want:       true,
		},
		{
			name: "both direction matches request",
			rule: &Rule{
				Scope: RuleScope{Direction: DirectionBoth},
			},
			method:     "GET",
			url:        "https://example.com",
			isResponse: false,
			want:       true,
		},
		{
			name: "both direction matches response",
			rule: &Rule{
				Scope: RuleScope{Direction: DirectionBoth},
			},
			method:     "GET",
			url:        "https://example.com",
			isResponse: true,
			want:       true,
		},
		{
			name: "method filter matches",
			rule: &Rule{
				Scope: RuleScope{
					Direction: DirectionRequest,
					Methods:   []string{"GET", "POST"},
				},
			},
			method:     "GET",
			url:        "https://example.com",
			isResponse: false,
			want:       true,
		},
		{
			name: "method filter does not match",
			rule: &Rule{
				Scope: RuleScope{
					Direction: DirectionRequest,
					Methods:   []string{"POST", "PUT"},
				},
			},
			method:     "GET",
			url:        "https://example.com",
			isResponse: false,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate rule to compile regexes
			tt.rule.Validate()

			req, _ := http.NewRequest(tt.method, tt.url, nil)
			got := matcher.MatchesScope(tt.rule, req, tt.isResponse)

			if got != tt.want {
				t.Errorf("MatchesScope() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchesScopeURLPattern(t *testing.T) {
	vs := NewVariableStore()
	matcher := NewMatcher(vs)

	rule := &Rule{
		Scope: RuleScope{
			Direction:  DirectionRequest,
			URLPattern: `^https://api\.example\.com/.*`,
		},
	}
	rule.Validate() // Compile regex

	tests := []struct {
		url  string
		want bool
	}{
		{"https://api.example.com/users", true},
		{"https://api.example.com/", true},
		{"https://example.com/api", false},
		{"http://api.example.com/users", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			req, _ := http.NewRequest("GET", tt.url, nil)
			got := matcher.MatchesScope(rule, req, false)

			if got != tt.want {
				t.Errorf("MatchesScope() = %v, want %v for URL %s", got, tt.want, tt.url)
			}
		})
	}
}

func TestEvaluateConditions(t *testing.T) {
	vs := NewVariableStore()
	matcher := NewMatcher(vs)

	tests := []struct {
		name      string
		condition Condition
		headers   map[string]string
		body      string
		want      bool
	}{
		{
			name: "exact match",
			condition: Condition{
				Type:     ConditionMatch,
				Location: LocationHeader,
				Name:     "X-Test",
				Pattern:  "test-value",
			},
			headers: map[string]string{"X-Test": "test-value"},
			want:    true,
		},
		{
			name: "exact match fails",
			condition: Condition{
				Type:     ConditionMatch,
				Location: LocationHeader,
				Name:     "X-Test",
				Pattern:  "test-value",
			},
			headers: map[string]string{"X-Test": "other-value"},
			want:    false,
		},
		{
			name: "contains",
			condition: Condition{
				Type:     ConditionContains,
				Location: LocationBody,
				Pattern:  "search-term",
			},
			body: "This contains search-term in the middle",
			want: true,
		},
		{
			name: "regex match",
			condition: Condition{
				Type:     ConditionRegex,
				Location: LocationHeader,
				Name:     "Authorization",
				Pattern:  `^Bearer [a-zA-Z0-9]+$`,
			},
			headers: map[string]string{"Authorization": "Bearer abc123"},
			want:    true,
		},
		{
			name: "header exists",
			condition: Condition{
				Type:     ConditionExists,
				Location: LocationHeader,
				Name:     "X-Custom",
			},
			headers: map[string]string{"X-Custom": "any-value"},
			want:    true,
		},
		{
			name: "header does not exist",
			condition: Condition{
				Type:     ConditionExists,
				Location: LocationHeader,
				Name:     "X-Missing",
			},
			headers: map[string]string{},
			want:    false,
		},
		{
			name: "negated condition",
			condition: Condition{
				Type:     ConditionMatch,
				Location: LocationHeader,
				Name:     "X-Test",
				Pattern:  "test",
				Negate:   true,
			},
			headers: map[string]string{"X-Test": "other"},
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create rule with condition
			rule := &Rule{
				Conditions: []Condition{tt.condition},
			}
			rule.Validate() // Compile regexes

			// Create request
			req, _ := http.NewRequest("GET", "https://example.com", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			body := []byte(tt.body)
			got := matcher.EvaluateConditions(rule, req, 0, nil, body, "test-req")

			if got != tt.want {
				t.Errorf("EvaluateConditions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvaluateLengthCondition(t *testing.T) {
	vs := NewVariableStore()
	matcher := NewMatcher(vs)

	tests := []struct {
		value   string
		pattern string
		want    bool
	}{
		{"hello", ">3", true},
		{"hello", ">10", false},
		{"hello", "<10", true},
		{"hello", "<3", false},
		{"hello", ">=5", true},
		{"hello", ">=10", false},
		{"hello", "<=5", true},
		{"hello", "<=3", false},
		{"hello", "==5", true},
		{"hello", "==3", false},
		{"hello", "!=3", true},
		{"hello", "!=5", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			got := matcher.evaluateLengthCondition(tt.value, tt.pattern)
			if got != tt.want {
				t.Errorf("evaluateLengthCondition(%s, %s) = %v, want %v",
					tt.value, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestEvaluateJSONPath(t *testing.T) {
	vs := NewVariableStore()
	matcher := NewMatcher(vs)

	body := []byte(`{"user":{"id":123,"name":"John"},"active":true}`)

	tests := []struct {
		path string
		want bool
	}{
		{"user.id", true},
		{"user.name", true},
		{"active", true},
		{"user.missing", false},
		{"nonexistent", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := matcher.evaluateJSONPath(body, tt.path)
			if got != tt.want {
				t.Errorf("evaluateJSONPath(%s) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestCaptureRequestBody(t *testing.T) {
	bodyContent := "test body content"
	req, _ := http.NewRequest("POST", "https://example.com", bytes.NewReader([]byte(bodyContent)))

	// Capture body
	body, err := CaptureRequestBody(req)
	if err != nil {
		t.Fatalf("CaptureRequestBody failed: %v", err)
	}

	if string(body) != bodyContent {
		t.Errorf("Captured body = %s, want %s", string(body), bodyContent)
	}

	// Body should be readable again
	body2, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("Reading body again failed: %v", err)
	}

	if string(body2) != bodyContent {
		t.Errorf("Second read = %s, want %s", string(body2), bodyContent)
	}
}

func TestGetLocationValue(t *testing.T) {
	vs := NewVariableStore()
	matcher := NewMatcher(vs)

	// Create request
	req, _ := http.NewRequest("GET", "https://example.com/path?query=value", nil)
	req.Header.Set("X-Test", "header-value")
	req.AddCookie(&http.Cookie{Name: "session", Value: "cookie-value"})

	tests := []struct {
		location Location
		name     string
		want     string
	}{
		{LocationHeader, "X-Test", "header-value"},
		{LocationCookie, "session", "cookie-value"},
		{LocationURL, "", "https://example.com/path?query=value"},
		{LocationPath, "", "/path"},
		{LocationQuery, "query", "value"},
		{LocationMethod, "", "GET"},
	}

	for _, tt := range tests {
		t.Run(tt.location.String(), func(t *testing.T) {
			got := matcher.getLocationValue(tt.location, tt.name, req, 0, nil, nil)
			if got != tt.want {
				t.Errorf("getLocationValue(%s, %s) = %s, want %s",
					tt.location, tt.name, got, tt.want)
			}
		})
	}
}
