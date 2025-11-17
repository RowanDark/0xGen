package cipher

import (
	"context"
	"testing"
)

func TestBase64Operations(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple text", "Hello, World!", "SGVsbG8sIFdvcmxkIQ=="},
		{"special chars", "Test@123!#$", "VGVzdEAxMjMhIyQ="},
		{"empty string", "", ""},
		{"unicode", "Hello 世界", "SGVsbG8g5LiW55WM"},
	}

	ctx := context.Background()
	encoder, _ := GetOperation("base64_encode")
	decoder, _ := GetOperation("base64_decode")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test encoding
			encoded, err := encoder.Execute(ctx, []byte(tt.input), nil)
			if err != nil {
				t.Fatalf("encode failed: %v", err)
			}
			if string(encoded) != tt.expected {
				t.Errorf("encode: expected %q, got %q", tt.expected, string(encoded))
			}

			// Test decoding
			decoded, err := decoder.Execute(ctx, encoded, nil)
			if err != nil {
				t.Fatalf("decode failed: %v", err)
			}
			if string(decoded) != tt.input {
				t.Errorf("decode: expected %q, got %q", tt.input, string(decoded))
			}
		})
	}
}

func TestBase64URLOperations(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"url safe chars", "test?&=", "dGVzdD8mPQ=="},
		{"simple", "hello", "aGVsbG8="},
	}

	ctx := context.Background()
	encoder, _ := GetOperation("base64url_encode")
	decoder, _ := GetOperation("base64url_decode")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := encoder.Execute(ctx, []byte(tt.input), nil)
			if err != nil {
				t.Fatalf("encode failed: %v", err)
			}

			decoded, err := decoder.Execute(ctx, encoded, nil)
			if err != nil {
				t.Fatalf("decode failed: %v", err)
			}
			if string(decoded) != tt.input {
				t.Errorf("roundtrip failed: expected %q, got %q", tt.input, string(decoded))
			}
		})
	}
}

func TestURLOperations(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"spaces", "hello world", "hello+world"},
		{"special chars", "test@example.com?query=value", "test%40example.com%3Fquery%3Dvalue"},
		{"already safe", "simple", "simple"},
	}

	ctx := context.Background()
	encoder, _ := GetOperation("url_encode")
	decoder, _ := GetOperation("url_decode")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := encoder.Execute(ctx, []byte(tt.input), nil)
			if err != nil {
				t.Fatalf("encode failed: %v", err)
			}
			if string(encoded) != tt.expected {
				t.Errorf("encode: expected %q, got %q", tt.expected, string(encoded))
			}

			decoded, err := decoder.Execute(ctx, encoded, nil)
			if err != nil {
				t.Fatalf("decode failed: %v", err)
			}
			if string(decoded) != tt.input {
				t.Errorf("decode: expected %q, got %q", tt.input, string(decoded))
			}
		})
	}
}

func TestHTMLOperations(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple tag", "<div>", "&lt;div&gt;"},
		{"quotes", `"test"`, "&#34;test&#34;"},
		{"ampersand", "A & B", "A &amp; B"},
		{"mixed", `<script>alert("XSS")</script>`, "&lt;script&gt;alert(&#34;XSS&#34;)&lt;/script&gt;"},
	}

	ctx := context.Background()
	encoder, _ := GetOperation("html_encode")
	decoder, _ := GetOperation("html_decode")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := encoder.Execute(ctx, []byte(tt.input), nil)
			if err != nil {
				t.Fatalf("encode failed: %v", err)
			}
			if string(encoded) != tt.expected {
				t.Errorf("encode: expected %q, got %q", tt.expected, string(encoded))
			}

			decoded, err := decoder.Execute(ctx, encoded, nil)
			if err != nil {
				t.Fatalf("decode failed: %v", err)
			}
			if string(decoded) != tt.input {
				t.Errorf("decode: expected %q, got %q", tt.input, string(decoded))
			}
		})
	}
}

func TestHexOperations(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{"simple", []byte("hello"), "68656c6c6f"},
		{"bytes", []byte{0x01, 0x02, 0x03, 0xff}, "010203ff"},
		{"empty", []byte(""), ""},
	}

	ctx := context.Background()
	encoder, _ := GetOperation("hex_encode")
	decoder, _ := GetOperation("hex_decode")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := encoder.Execute(ctx, tt.input, nil)
			if err != nil {
				t.Fatalf("encode failed: %v", err)
			}
			if string(encoded) != tt.expected {
				t.Errorf("encode: expected %q, got %q", tt.expected, string(encoded))
			}

			decoded, err := decoder.Execute(ctx, encoded, nil)
			if err != nil {
				t.Fatalf("decode failed: %v", err)
			}
			if string(decoded) != string(tt.input) {
				t.Errorf("decode: expected %q, got %q", tt.input, decoded)
			}
		})
	}
}

func TestHexDecodeWithPrefixes(t *testing.T) {
	ctx := context.Background()
	decoder, _ := GetOperation("hex_decode")

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"0x prefix", "0x48656c6c6f", "Hello"},
		{"spaces", "48 65 6c 6c 6f", "Hello"},
		{"colons", "48:65:6c:6c:6f", "Hello"},
		{"dashes", "48-65-6c-6c-6f", "Hello"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoded, err := decoder.Execute(ctx, []byte(tt.input), nil)
			if err != nil {
				t.Fatalf("decode failed: %v", err)
			}
			if string(decoded) != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, string(decoded))
			}
		})
	}
}

func TestBinaryOperations(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{"simple", []byte("AB"), "01000001 01000010"},
		{"single byte", []byte{0xff}, "11111111"},
		{"zeros", []byte{0x00}, "00000000"},
	}

	ctx := context.Background()
	encoder, _ := GetOperation("binary_encode")
	decoder, _ := GetOperation("binary_decode")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := encoder.Execute(ctx, tt.input, nil)
			if err != nil {
				t.Fatalf("encode failed: %v", err)
			}
			if string(encoded) != tt.expected {
				t.Errorf("encode: expected %q, got %q", tt.expected, string(encoded))
			}

			decoded, err := decoder.Execute(ctx, encoded, nil)
			if err != nil {
				t.Fatalf("decode failed: %v", err)
			}
			if string(decoded) != string(tt.input) {
				t.Errorf("decode: expected %q, got %q", tt.input, decoded)
			}
		})
	}
}

func TestASCIIHexOperations(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple", "hello", "68 65 6c 6c 6f"},
		{"numbers", "123", "31 32 33"},
	}

	ctx := context.Background()
	toHex, _ := GetOperation("ascii_to_hex")
	fromHex, _ := GetOperation("hex_to_ascii")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := toHex.Execute(ctx, []byte(tt.input), nil)
			if err != nil {
				t.Fatalf("ascii_to_hex failed: %v", err)
			}
			if string(encoded) != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, string(encoded))
			}

			decoded, err := fromHex.Execute(ctx, encoded, nil)
			if err != nil {
				t.Fatalf("hex_to_ascii failed: %v", err)
			}
			if string(decoded) != tt.input {
				t.Errorf("expected %q, got %q", tt.input, string(decoded))
			}
		})
	}
}

func TestOperationReversibility(t *testing.T) {
	reversibleOps := []string{
		"base64_encode",
		"base64url_encode",
		"url_encode",
		"html_encode",
		"hex_encode",
		"binary_encode",
		"ascii_to_hex",
	}

	for _, opName := range reversibleOps {
		t.Run(opName, func(t *testing.T) {
			op, exists := GetOperation(opName)
			if !exists {
				t.Fatalf("operation %s not found", opName)
			}

			reverse, ok := op.Reverse()
			if !ok {
				t.Errorf("operation %s should be reversible", opName)
			}

			if reverse == nil {
				t.Errorf("reverse operation for %s is nil", opName)
			}
		})
	}
}
