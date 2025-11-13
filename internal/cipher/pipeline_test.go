package cipher

import (
	"context"
	"testing"
)

func TestPipelineExecution(t *testing.T) {
	tests := []struct {
		name       string
		operations []OperationConfig
		input      string
		expected   string
	}{
		{
			name: "single operation",
			operations: []OperationConfig{
				{Name: "base64_encode"},
			},
			input:    "hello",
			expected: "aGVsbG8=",
		},
		{
			name: "double encoding",
			operations: []OperationConfig{
				{Name: "base64_encode"},
				{Name: "base64_encode"},
			},
			input:    "test",
			expected: "ZEdWemRBPT0=",
		},
		{
			name: "encode then decode",
			operations: []OperationConfig{
				{Name: "url_encode"},
				{Name: "url_decode"},
			},
			input:    "hello world",
			expected: "hello world",
		},
		{
			name: "complex chain",
			operations: []OperationConfig{
				{Name: "base64_encode"},
				{Name: "url_encode"},
				{Name: "hex_encode"},
			},
			input: "test",
		},
	}

	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pipeline := &Pipeline{
				Operations: tt.operations,
				Reversible: true,
			}

			result, err := pipeline.Execute(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("pipeline execution failed: %v", err)
			}

			if tt.expected != "" && string(result) != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, string(result))
			}
		})
	}
}

func TestPipelineReversibility(t *testing.T) {
	tests := []struct {
		name       string
		operations []OperationConfig
		input      string
	}{
		{
			name: "single reversible operation",
			operations: []OperationConfig{
				{Name: "base64_encode"},
			},
			input: "hello world",
		},
		{
			name: "multiple reversible operations",
			operations: []OperationConfig{
				{Name: "url_encode"},
				{Name: "base64_encode"},
				{Name: "hex_encode"},
			},
			input: "test@example.com?query=value",
		},
		{
			name: "compression and encoding",
			operations: []OperationConfig{
				{Name: "gzip_compress"},
				{Name: "base64_encode"},
			},
			input: "This is a long text that should compress well. " +
				"It has lots of repetitive content. " +
				"This is a long text that should compress well.",
		},
	}

	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pipeline := &Pipeline{
				Operations: tt.operations,
				Reversible: true,
			}

			// Execute forward
			encoded, err := pipeline.Execute(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("forward pipeline failed: %v", err)
			}

			// Get reverse pipeline
			reversePipeline, err := pipeline.Reverse()
			if err != nil {
				t.Fatalf("failed to create reverse pipeline: %v", err)
			}

			// Execute reverse
			decoded, err := reversePipeline.Execute(ctx, encoded)
			if err != nil {
				t.Fatalf("reverse pipeline failed: %v", err)
			}

			if string(decoded) != tt.input {
				t.Errorf("roundtrip failed: expected %q, got %q", tt.input, string(decoded))
			}
		})
	}
}

func TestPipelineNonReversible(t *testing.T) {
	pipeline := &Pipeline{
		Operations: []OperationConfig{
			{Name: "md5_hash"},
		},
		Reversible: true,
	}

	_, err := pipeline.Reverse()
	if err == nil {
		t.Error("expected error when reversing pipeline with hash operation")
	}
}

func TestPipelineUnknownOperation(t *testing.T) {
	pipeline := &Pipeline{
		Operations: []OperationConfig{
			{Name: "unknown_operation"},
		},
		Reversible: false,
	}

	ctx := context.Background()
	_, err := pipeline.Execute(ctx, []byte("test"))
	if err == nil {
		t.Error("expected error for unknown operation")
	}
}

func TestPipelineWithParameters(t *testing.T) {
	ctx := context.Background()

	// Create JWT signing pipeline
	claims := `{"sub":"user123","name":"Test User"}`
	pipeline := &Pipeline{
		Operations: []OperationConfig{
			{
				Name: "jwt_sign",
				Parameters: map[string]interface{}{
					"secret": "test-secret",
				},
			},
		},
		Reversible: false,
	}

	token, err := pipeline.Execute(ctx, []byte(claims))
	if err != nil {
		t.Fatalf("jwt signing pipeline failed: %v", err)
	}

	if len(token) == 0 {
		t.Error("expected non-empty JWT token")
	}

	// Decode the token
	decodePipeline := &Pipeline{
		Operations: []OperationConfig{
			{Name: "jwt_decode"},
		},
		Reversible: false,
	}

	decoded, err := decodePipeline.Execute(ctx, token)
	if err != nil {
		t.Fatalf("jwt decode pipeline failed: %v", err)
	}

	if len(decoded) == 0 {
		t.Error("expected non-empty decoded JWT")
	}
}

func TestPipelineEmptyOperations(t *testing.T) {
	pipeline := &Pipeline{
		Operations: []OperationConfig{},
		Reversible: true,
	}

	ctx := context.Background()
	input := []byte("test")
	result, err := pipeline.Execute(ctx, input)
	if err != nil {
		t.Fatalf("empty pipeline should not fail: %v", err)
	}

	if string(result) != string(input) {
		t.Errorf("empty pipeline should return input unchanged")
	}
}

func TestComplexPipelineScenarios(t *testing.T) {
	scenarios := []struct {
		name        string
		pipeline    []OperationConfig
		input       string
		description string
	}{
		{
			name: "double base64 encoding",
			pipeline: []OperationConfig{
				{Name: "base64_encode"},
				{Name: "base64_encode"},
			},
			input:       "secret payload",
			description: "Common obfuscation technique",
		},
		{
			name: "url encode then base64",
			pipeline: []OperationConfig{
				{Name: "url_encode"},
				{Name: "base64_encode"},
			},
			input:       "test?query=value&foo=bar",
			description: "Common in web security testing",
		},
		{
			name: "compress then encode",
			pipeline: []OperationConfig{
				{Name: "gzip_compress"},
				{Name: "base64_encode"},
			},
			input:       "This is a payload that will be compressed and then encoded",
			description: "Efficient payload transmission",
		},
	}

	ctx := context.Background()

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			pipeline := &Pipeline{
				Operations: scenario.pipeline,
				Reversible: true,
			}

			// Forward transformation
			transformed, err := pipeline.Execute(ctx, []byte(scenario.input))
			if err != nil {
				t.Fatalf("%s: forward failed: %v", scenario.description, err)
			}

			// Reverse transformation
			reversed, err := pipeline.Reverse()
			if err != nil {
				t.Fatalf("%s: reverse creation failed: %v", scenario.description, err)
			}

			original, err := reversed.Execute(ctx, transformed)
			if err != nil {
				t.Fatalf("%s: reverse execution failed: %v", scenario.description, err)
			}

			if string(original) != scenario.input {
				t.Errorf("%s: roundtrip failed", scenario.description)
			}
		})
	}
}
