package cipher

import (
	"context"
	"testing"
)

func TestDetectBase64(t *testing.T) {
	detector := NewSmartDetector()
	ctx := context.Background()

	tests := []struct {
		name              string
		input             string
		expectedEncoding  string
		minConfidence     float64
		shouldDetect      bool
	}{
		{
			name:             "standard base64",
			input:            "SGVsbG8sIFdvcmxkIQ==",
			expectedEncoding: "base64",
			minConfidence:    0.8,
			shouldDetect:     true,
		},
		{
			name:             "base64 no padding",
			input:            "SGVsbG8",
			expectedEncoding: "base64",
			minConfidence:    0.6,
			shouldDetect:     true,
		},
		{
			name:             "url-safe base64",
			input:            "SGVsbG8_V29ybGQh",
			expectedEncoding: "base64url",
			minConfidence:    0.7,
			shouldDetect:     true,
		},
		{
			name:         "not base64",
			input:        "Hello, World!",
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := detector.Detect(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("detect failed: %v", err)
			}

			if tt.shouldDetect {
				found := false
				for _, result := range results {
					if result.Encoding == tt.expectedEncoding && result.Confidence >= tt.minConfidence {
						found = true
						t.Logf("Detected %s with confidence %.2f", result.Encoding, result.Confidence)
						break
					}
				}
				if !found {
					t.Errorf("expected to detect %s with confidence >= %.2f", tt.expectedEncoding, tt.minConfidence)
				}
			}
		})
	}
}

func TestDetectHex(t *testing.T) {
	detector := NewSmartDetector()
	ctx := context.Background()

	tests := []struct {
		name          string
		input         string
		minConfidence float64
		shouldDetect  bool
	}{
		{
			name:          "hex with 0x prefix",
			input:         "0x48656c6c6f",
			minConfidence: 0.9,
			shouldDetect:  true,
		},
		{
			name:          "hex lowercase",
			input:         "48656c6c6f",
			minConfidence: 0.5,
			shouldDetect:  true,
		},
		{
			name:          "hex uppercase",
			input:         "48656C6C6F",
			minConfidence: 0.5,
			shouldDetect:  true,
		},
		{
			name:          "hex with spaces",
			input:         "48 65 6c 6c 6f",
			minConfidence: 0.7,
			shouldDetect:  true,
		},
		{
			name:          "hex with colons",
			input:         "48:65:6c:6c:6f",
			minConfidence: 0.7,
			shouldDetect:  true,
		},
		{
			name:         "not hex (odd length)",
			input:        "123",
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := detector.Detect(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("detect failed: %v", err)
			}

			if tt.shouldDetect {
				found := false
				for _, result := range results {
					if result.Encoding == "hex" && result.Confidence >= tt.minConfidence {
						found = true
						t.Logf("Detected hex with confidence %.2f", result.Confidence)
						break
					}
				}
				if !found {
					t.Errorf("expected to detect hex with confidence >= %.2f", tt.minConfidence)
				}
			}
		})
	}
}

func TestDetectURL(t *testing.T) {
	detector := NewSmartDetector()
	ctx := context.Background()

	tests := []struct {
		name          string
		input         string
		minConfidence float64
	}{
		{
			name:          "url encoded spaces",
			input:         "hello%20world",
			minConfidence: 0.5,
		},
		{
			name:          "url encoded special chars",
			input:         "test%40example.com%3Fquery%3Dvalue",
			minConfidence: 0.7,
		},
		{
			name:          "single encoded char",
			input:         "test%20",
			minConfidence: 0.3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := detector.Detect(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("detect failed: %v", err)
			}

			found := false
			for _, result := range results {
				if result.Encoding == "url-encoded" && result.Confidence >= tt.minConfidence {
					found = true
					t.Logf("Detected URL encoding with confidence %.2f", result.Confidence)
					break
				}
			}
			if !found {
				t.Errorf("expected to detect URL encoding with confidence >= %.2f", tt.minConfidence)
			}
		})
	}
}

func TestDetectHTML(t *testing.T) {
	detector := NewSmartDetector()
	ctx := context.Background()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "html entities",
			input: "&lt;div&gt;",
		},
		{
			name:  "numeric entities",
			input: "&#65;&#66;&#67;",
		},
		{
			name:  "hex entities",
			input: "&#x41;&#x42;&#x43;",
		},
		{
			name:  "mixed entities",
			input: "&lt;script&gt;alert(&#34;XSS&#34;)&lt;/script&gt;",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := detector.Detect(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("detect failed: %v", err)
			}

			found := false
			for _, result := range results {
				if result.Encoding == "html-entities" {
					found = true
					t.Logf("Detected HTML entities with confidence %.2f", result.Confidence)
					break
				}
			}
			if !found {
				t.Error("expected to detect HTML entities")
			}
		})
	}
}

func TestDetectBinary(t *testing.T) {
	detector := NewSmartDetector()
	ctx := context.Background()

	tests := []struct {
		name          string
		input         string
		minConfidence float64
		shouldDetect  bool
	}{
		{
			name:          "binary string",
			input:         "01001000 01100101 01101100 01101100 01101111",
			minConfidence: 0.6,
			shouldDetect:  true,
		},
		{
			name:          "binary no spaces",
			input:         "0100100001100101",
			minConfidence: 0.6,
			shouldDetect:  true,
		},
		{
			name:         "too short",
			input:        "01010",
			shouldDetect: false,
		},
		{
			name:         "not binary",
			input:        "012345",
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := detector.Detect(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("detect failed: %v", err)
			}

			if tt.shouldDetect {
				found := false
				for _, result := range results {
					if result.Encoding == "binary" && result.Confidence >= tt.minConfidence {
						found = true
						t.Logf("Detected binary with confidence %.2f", result.Confidence)
						break
					}
				}
				if !found {
					t.Errorf("expected to detect binary with confidence >= %.2f", tt.minConfidence)
				}
			}
		})
	}
}

func TestDetectJWT(t *testing.T) {
	detector := NewSmartDetector()
	ctx := context.Background()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "valid jwt",
			input: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := detector.Detect(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("detect failed: %v", err)
			}

			found := false
			for _, result := range results {
				if result.Encoding == "jwt" && result.Confidence >= 0.9 {
					found = true
					t.Logf("Detected JWT with confidence %.2f", result.Confidence)
					break
				}
			}
			if !found {
				t.Error("expected to detect JWT with high confidence")
			}
		})
	}
}

func TestDetectGzip(t *testing.T) {
	detector := NewSmartDetector()
	ctx := context.Background()

	// Create gzip compressed data
	compress, _ := GetOperation("gzip_compress")
	compressed, _ := compress.Execute(ctx, []byte("Hello, World!"), nil)

	results, err := detector.Detect(ctx, compressed)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}

	found := false
	for _, result := range results {
		if result.Encoding == "gzip" && result.Confidence >= 0.95 {
			found = true
			t.Logf("Detected gzip with confidence %.2f", result.Confidence)
			break
		}
	}
	if !found {
		t.Error("expected to detect gzip with high confidence")
	}
}

func TestDetectMultipleEncodings(t *testing.T) {
	detector := NewSmartDetector()
	ctx := context.Background()

	// Create input that could be multiple encodings
	input := "48656c6c6f" // This is hex, but could also be interpreted as base64

	results, err := detector.Detect(ctx, []byte(input))
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("expected at least one detection")
	}

	// Should detect hex with higher confidence
	if results[0].Encoding != "hex" {
		t.Logf("Warning: expected hex to be highest confidence, got %s (%.2f)",
			results[0].Encoding, results[0].Confidence)
	}

	t.Logf("Detected %d possible encodings", len(results))
	for i, result := range results {
		t.Logf("  %d. %s (%.2f): %s", i+1, result.Encoding, result.Confidence, result.Reasoning)
	}
}

func TestDecodeAll(t *testing.T) {
	ctx := context.Background()

	// Test with Base64 encoded string
	input := "SGVsbG8sIFdvcmxkIQ==" // "Hello, World!"

	results, err := DecodeAll(ctx, []byte(input))
	if err != nil {
		t.Fatalf("DecodeAll failed: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("expected at least one successful decode")
	}

	// Should successfully decode as Base64
	found := false
	for _, result := range results {
		if result.Detection.Encoding == "base64" && result.Success {
			found = true
			if string(result.Decoded) != "Hello, World!" {
				t.Errorf("expected 'Hello, World!', got %q", string(result.Decoded))
			}
		}
	}

	if !found {
		t.Error("expected successful Base64 decode")
	}
}

func TestDetectorAccuracy(t *testing.T) {
	detector := NewSmartDetector()
	ctx := context.Background()

	// Test cases with known encodings
	tests := []struct {
		name             string
		input            string
		expectedEncoding string
		minConfidence    float64
	}{
		{"base64", "SGVsbG8gV29ybGQ=", "base64", 0.8},
		{"hex", "0x48656c6c6f", "hex", 0.9},
		{"url", "hello%20world%21", "url-encoded", 0.5},
		{"jwt", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.abc123", "jwt", 0.9},
		{"html", "&lt;div&gt;&amp;&quot;", "html-entities", 0.4},
	}

	correct := 0
	total := len(tests)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := detector.Detect(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("detect failed: %v", err)
			}

			// Check if expected encoding is in top results with sufficient confidence
			for _, result := range results {
				if result.Encoding == tt.expectedEncoding && result.Confidence >= tt.minConfidence {
					correct++
					return
				}
			}

			t.Errorf("failed to detect %s with confidence >= %.2f", tt.expectedEncoding, tt.minConfidence)
		})
	}

	accuracy := float64(correct) / float64(total) * 100
	t.Logf("Detection accuracy: %.1f%% (%d/%d)", accuracy, correct, total)

	if accuracy < 90 {
		t.Errorf("detection accuracy %.1f%% is below 90%% threshold", accuracy)
	}
}

func TestSupportedEncodings(t *testing.T) {
	detector := NewSmartDetector()
	encodings := detector.SupportedEncodings()

	expectedEncodings := []string{
		"base64",
		"base64url",
		"hex",
		"url-encoded",
		"html-entities",
		"binary",
		"jwt",
		"gzip",
	}

	if len(encodings) != len(expectedEncodings) {
		t.Errorf("expected %d encodings, got %d", len(expectedEncodings), len(encodings))
	}

	for _, expected := range expectedEncodings {
		found := false
		for _, actual := range encodings {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected encoding %s not found in supported list", expected)
		}
	}
}
