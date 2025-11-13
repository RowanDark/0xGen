package blitz

import (
	"testing"
)

func TestAIPayloadSelector_AnalyzeTarget(t *testing.T) {
	request := `GET /api/user/{{id}}/profile?role={{role}} HTTP/1.1
Host: api.example.com
Content-Type: application/json

`

	markers := Markers{Open: "{{", Close: "}}"}
	req, err := ParseRequest(request, markers)
	if err != nil {
		t.Fatalf("ParseRequest failed: %v", err)
	}

	selector := NewAIPayloadSelector(nil)
	ctx := selector.AnalyzeTarget(req)

	if ctx.Method != "GET" {
		t.Errorf("Expected method GET, got %s", ctx.Method)
	}

	if len(ctx.Parameters) != 2 {
		t.Errorf("Expected 2 parameters, got %d", len(ctx.Parameters))
	}

	if !contains(ctx.InferredContext, "database") {
		t.Error("Expected 'database' context for /api/ path")
	}
}

func TestAIPayloadSelector_SQLiContext(t *testing.T) {
	request := `GET /search?query={{search}} HTTP/1.1
Host: example.com

`

	markers := Markers{Open: "{{", Close: "}}"}
	req, _ := ParseRequest(request, markers)

	selector := NewAIPayloadSelector(nil)
	ctx := selector.AnalyzeTarget(req)

	param := ctx.Parameters[0]
	categories := selector.selectCategories(ctx, param)

	found := false
	for _, cat := range categories {
		if cat == VulnCategorySQLi {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected SQL injection category for search parameter")
	}
}

func TestAIPayloadSelector_XSSContext(t *testing.T) {
	request := `GET /view?comment={{comment}} HTTP/1.1
Host: example.com
Content-Type: text/html

`

	markers := Markers{Open: "{{", Close: "}}"}
	req, _ := ParseRequest(request, markers)

	selector := NewAIPayloadSelector(nil)
	ctx := selector.AnalyzeTarget(req)

	param := ctx.Parameters[0]
	categories := selector.selectCategories(ctx, param)

	found := false
	for _, cat := range categories {
		if cat == VulnCategoryXSS {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected XSS category for comment parameter in HTML context")
	}
}

func TestAIPayloadSelector_GenerateSQLiPayloads(t *testing.T) {
	selector := NewAIPayloadSelector(&AIPayloadConfig{
		EnableAdvancedPayloads: false,
		MaxPayloadsPerCategory: 10,
	})

	ctx := &TargetContext{}
	param := ParameterInfo{Name: "id"}

	payloads := selector.generateSQLiPayloads(ctx, param)

	if len(payloads) == 0 {
		t.Error("Expected SQL injection payloads")
	}

	// Check for common SQLi patterns
	hasBasicPayload := false
	for _, p := range payloads {
		if p == "' OR '1'='1" || p == "' OR 1=1--" {
			hasBasicPayload = true
			break
		}
	}

	if !hasBasicPayload {
		t.Error("Expected basic SQL injection payloads")
	}
}

func TestAIPayloadSelector_GenerateXSSPayloads(t *testing.T) {
	selector := NewAIPayloadSelector(nil)

	ctx := &TargetContext{}
	param := ParameterInfo{Name: "comment"}

	payloads := selector.generateXSSPayloads(ctx, param)

	if len(payloads) == 0 {
		t.Error("Expected XSS payloads")
	}

	// Check for script tags
	hasScriptTag := false
	for _, p := range payloads {
		if contains([]string{p}, "<script>") {
			hasScriptTag = true
			break
		}
	}

	if !hasScriptTag {
		t.Error("Expected script tag in XSS payloads")
	}
}

func TestCreateAIPayloadGenerator(t *testing.T) {
	request := `GET /api/user/{{id}} HTTP/1.1
Host: api.example.com

`

	markers := Markers{Open: "{{", Close: "}}"}
	req, _ := ParseRequest(request, markers)

	selector := NewAIPayloadSelector(&AIPayloadConfig{
		MaxPayloadsPerCategory: 5,
	})

	generators := CreateAIPayloadGenerator(selector, req)

	if len(generators) != 1 {
		t.Errorf("Expected 1 generator, got %d", len(generators))
	}

	payloads, err := generators[0].Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if len(payloads) == 0 {
		t.Error("Expected AI-generated payloads")
	}
}

func TestInferLocation(t *testing.T) {
	selector := NewAIPayloadSelector(nil)

	tests := []struct {
		name     string
		raw      string
		posName  string
		expected string
	}{
		{
			name:     "query parameter",
			raw:      "GET /page?id={{id}} HTTP/1.1\nHost: test.com\n\n",
			posName:  "id",
			expected: "query",
		},
		{
			name:     "path parameter",
			raw:      "GET /user/{{id}}/profile HTTP/1.1\nHost: test.com\n\n",
			posName:  "id",
			expected: "path",
		},
		{
			name:     "header parameter",
			raw:      "GET / HTTP/1.1\nHost: test.com\nX-Custom: {{value}}\n\n",
			posName:  "value",
			expected: "header",
		},
		{
			name:     "body parameter",
			raw:      "POST / HTTP/1.1\nHost: test.com\n\n{\"key\": \"{{value}}\"}",
			posName:  "value",
			expected: "body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pos := Position{Name: tt.posName}
			location := selector.inferLocation(tt.raw, pos)

			if location != tt.expected {
				t.Errorf("Expected location %s, got %s", tt.expected, location)
			}
		})
	}
}
