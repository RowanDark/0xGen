package blitz

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseRange(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		wantLen int
		wantErr bool
	}{
		{
			name:    "numeric range",
			spec:    "1-10",
			wantLen: 10,
			wantErr: false,
		},
		{
			name:    "character range",
			spec:    "a-z",
			wantLen: 26,
			wantErr: false,
		},
		{
			name:    "invalid format",
			spec:    "1-2-3",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen, err := ParseRange(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRange() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			payloads, err := gen.Generate()
			if err != nil {
				t.Fatalf("Generate() error = %v", err)
			}

			if len(payloads) != tt.wantLen {
				t.Errorf("Expected %d payloads, got %d", tt.wantLen, len(payloads))
			}
		})
	}
}

func TestStaticGenerator(t *testing.T) {
	values := []string{"test1", "test2", "test3"}
	gen := NewStaticGenerator("test", values)

	payloads, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if len(payloads) != 3 {
		t.Errorf("Expected 3 payloads, got %d", len(payloads))
	}

	if payloads[0] != "test1" {
		t.Errorf("First payload = %v, want 'test1'", payloads[0])
	}
}

func TestWordlistGenerator(t *testing.T) {
	// Create temp file
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "wordlist.txt")

	content := "payload1\npayload2\npayload3\n"
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	gen := &WordlistGenerator{FilePath: filePath}
	payloads, err := gen.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if len(payloads) != 3 {
		t.Errorf("Expected 3 payloads, got %d", len(payloads))
	}

	if payloads[0] != "payload1" {
		t.Errorf("First payload = %v, want 'payload1'", payloads[0])
	}
}

func TestRegexGenerator(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		minLen  int
	}{
		{
			name:    "character class",
			pattern: "[a-z]",
			minLen:  26,
		},
		{
			name:    "alternation",
			pattern: "(opt1|opt2|opt3)",
			minLen:  3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := &RegexGenerator{Pattern: tt.pattern, Limit: 100}
			payloads, err := gen.Generate()

			if err != nil {
				t.Fatalf("Generate() error = %v", err)
			}

			if len(payloads) < tt.minLen {
				t.Errorf("Expected at least %d payloads, got %d", tt.minLen, len(payloads))
			}
		})
	}
}

func TestLoadPayload(t *testing.T) {
	// Test comma-separated list
	gen, err := LoadPayload("a,b,c")
	if err != nil {
		t.Fatalf("LoadPayload() error = %v", err)
	}

	payloads, _ := gen.Generate()
	if len(payloads) != 3 {
		t.Errorf("Expected 3 payloads, got %d", len(payloads))
	}

	// Test range
	gen, err = LoadPayload("1-5")
	if err != nil {
		t.Fatalf("LoadPayload() error = %v", err)
	}

	payloads, _ = gen.Generate()
	if len(payloads) != 5 {
		t.Errorf("Expected 5 payloads, got %d", len(payloads))
	}

	// Test single value
	gen, err = LoadPayload("single")
	if err != nil {
		t.Fatalf("LoadPayload() error = %v", err)
	}

	payloads, _ = gen.Generate()
	if len(payloads) != 1 {
		t.Errorf("Expected 1 payload, got %d", len(payloads))
	}
}
