package rewrite

import (
	"strings"
	"testing"
)

func TestVariableStore(t *testing.T) {
	vs := NewVariableStore()

	// Test global variables
	vs.Set("global_var", "global_value", ScopeGlobal)
	if val, ok := vs.Get("global_var", ""); !ok || val != "global_value" {
		t.Errorf("Get global var failed: got %s, want global_value", val)
	}

	// Test request-scoped variables
	vs.SetRequestVar("req1", "req_var", "req1_value")
	if val, ok := vs.Get("req_var", "req1"); !ok || val != "req1_value" {
		t.Errorf("Get request var failed: got %s, want req1_value", val)
	}

	// Request-scoped var should not be visible to other requests
	if val, ok := vs.Get("req_var", "req2"); ok {
		t.Errorf("Request var leaked to other request: got %s", val)
	}

	// Clear request variables
	vs.ClearRequest("req1")
	if _, ok := vs.Get("req_var", "req1"); ok {
		t.Error("ClearRequest did not remove variables")
	}

	// Global var should still exist
	if val, ok := vs.Get("global_var", ""); !ok || val != "global_value" {
		t.Error("ClearRequest affected global variables")
	}

	// Test delete
	vs.Delete("global_var")
	if _, ok := vs.Get("global_var", ""); ok {
		t.Error("Delete did not remove variable")
	}
}

func TestBuiltinVariables(t *testing.T) {
	vs := NewVariableStore()

	tests := []struct {
		name   string
		expect string
	}{
		{"timestamp", ""},     // Should be a number
		{"timestamp_ms", ""},  // Should be a number
		{"random", ""},        // Should be 16 chars
		{"uuid", ""},          // Should be a valid UUID
		{"request.method", "GET"},
		{"request.url", "https://example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, ok := vs.GetBuiltinVariable(tt.name, "GET", "https://example.com")
			if !ok {
				t.Errorf("GetBuiltinVariable(%s) failed", tt.name)
				return
			}

			switch tt.name {
			case "random":
				if len(val) != 16 {
					t.Errorf("random length = %d, want 16", len(val))
				}
			case "uuid":
				if !strings.Contains(val, "-") {
					t.Errorf("uuid format invalid: %s", val)
				}
			default:
				if tt.expect != "" && val != tt.expect {
					t.Errorf("GetBuiltinVariable(%s) = %s, want %s", tt.name, val, tt.expect)
				}
			}
		})
	}
}

func TestVariableSubstitution(t *testing.T) {
	vs := NewVariableStore()
	vs.Set("token", "abc123", ScopeGlobal)
	vs.SetRequestVar("req1", "session", "xyz789")

	tests := []struct {
		name      string
		input     string
		requestID string
		want      string
	}{
		{
			name:      "simple substitution",
			input:     "Bearer ${token}",
			requestID: "",
			want:      "Bearer abc123",
		},
		{
			name:      "request variable",
			input:     "Session: ${session}",
			requestID: "req1",
			want:      "Session: xyz789",
		},
		{
			name:      "with default",
			input:     "Value: ${missing:default}",
			requestID: "",
			want:      "Value: default",
		},
		{
			name:      "with transform",
			input:     "Hash: ${token|md5}",
			requestID: "",
			want:      "Hash: e99a18c428cb38d5f260853678922e03", // MD5 of "abc123"
		},
		{
			name:      "builtin timestamp",
			input:     "Time: ${timestamp}",
			requestID: "",
			want:      "Time: ", // Just check it doesn't error
		},
		{
			name:      "builtin uuid",
			input:     "ID: ${uuid}",
			requestID: "",
			want:      "ID: ", // Just check it doesn't error
		},
		{
			name:      "no substitution",
			input:     "No variables here",
			requestID: "",
			want:      "No variables here",
		},
		{
			name:      "multiple variables",
			input:     "${token}-${session}",
			requestID: "req1",
			want:      "abc123-xyz789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := vs.SubstituteVariables(tt.input, tt.requestID, "GET", "https://example.com")

			// For builtin variables, just check they were replaced
			if strings.Contains(tt.input, "${timestamp}") || strings.Contains(tt.input, "${uuid}") {
				if strings.Contains(got, "${") {
					t.Errorf("Variable not substituted: %s", got)
				}
				return
			}

			if got != tt.want {
				t.Errorf("SubstituteVariables() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestApplyTransform(t *testing.T) {
	tests := []struct {
		value     string
		transform string
		want      string
	}{
		{"hello", "base64", "aGVsbG8="},
		{"aGVsbG8=", "base64_decode", "hello"},
		{"hello world", "url", "hello+world"},
		{"hello+world", "url_decode", "hello world"},
		{"<script>", "html", "&lt;script&gt;"},
		{"&lt;script&gt;", "html_decode", "<script>"},
		{"hello", "hex", "68656c6c6f"},
		{"68656c6c6f", "hex_decode", "hello"},
		{"hello", "md5", "5d41402abc4b2a76b9719d911017c592"},
		{"hello", "sha1", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"},
		{"hello", "sha256", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"},
		{"hello", "uppercase", "HELLO"},
		{"HELLO", "lowercase", "hello"},
		{"hello", "unknown", "hello"}, // Unknown transform returns original
	}

	for _, tt := range tests {
		t.Run(tt.transform, func(t *testing.T) {
			got := ApplyTransform(tt.value, tt.transform)
			if got != tt.want {
				t.Errorf("ApplyTransform(%s, %s) = %s, want %s", tt.value, tt.transform, got, tt.want)
			}
		})
	}
}

func TestExtractVariables(t *testing.T) {
	vs := NewVariableStore()

	// Test regex extraction with named groups
	pattern := `Bearer (?P<token>[a-zA-Z0-9]+)`
	input := "Bearer abc123xyz"

	err := vs.ExtractVariables(pattern, input, "req1", ScopeRequest)
	if err != nil {
		t.Fatalf("ExtractVariables failed: %v", err)
	}

	val, ok := vs.Get("token", "req1")
	if !ok {
		t.Fatal("Variable 'token' not extracted")
	}
	if val != "abc123xyz" {
		t.Errorf("Extracted token = %s, want abc123xyz", val)
	}

	// Test no match
	err = vs.ExtractVariables(pattern, "No bearer token here", "req2", ScopeRequest)
	if err != nil {
		t.Errorf("ExtractVariables should not error on no match: %v", err)
	}

	// Test invalid regex
	err = vs.ExtractVariables("[invalid", "test", "req3", ScopeRequest)
	if err == nil {
		t.Error("ExtractVariables should error on invalid regex")
	}
}

func TestComputeHash(t *testing.T) {
	input := "test"

	tests := []struct {
		algorithm string
		want      string
	}{
		{"md5", "098f6bcd4621d373cade4e832627b4f6"},
		{"sha1", "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"},
		{"sha256", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			got := ComputeHash(input, tt.algorithm)
			if got != tt.want {
				t.Errorf("ComputeHash(%s, %s) = %s, want %s", input, tt.algorithm, got, tt.want)
			}
		})
	}
}
