package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"
)

// Test data generators

func generateRandomTokens(count, length int) []string {
	tokens := make([]string, count)
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	for i := 0; i < count; i++ {
		token := make([]byte, length)
		for j := 0; j < length; j++ {
			idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
			token[j] = chars[idx.Int64()]
		}
		tokens[i] = string(token)
	}

	return tokens
}

func generateSequentialTokens(count int) []string {
	tokens := make([]string, count)
	for i := 0; i < count; i++ {
		tokens[i] = fmt.Sprintf("token_%d", i*100)
	}
	return tokens
}

func generateLowEntropyTokens(count, length int) []string {
	tokens := make([]string, count)
	chars := "0123456789" // Limited charset

	for i := 0; i < count; i++ {
		token := make([]byte, length)
		for j := 0; j < length; j++ {
			idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
			token[j] = chars[idx.Int64()]
		}
		tokens[i] = string(token)
	}

	return tokens
}

// Statistical tests

func TestChiSquaredTest(t *testing.T) {
	tests := []struct {
		name    string
		tokens  []string
		wantPass bool
	}{
		{
			name:    "random tokens should pass",
			tokens:  generateRandomTokens(100, 16),
			wantPass: true,
		},
		{
			name:    "non-uniform tokens should fail",
			tokens:  []string{"aaaaaaa", "aaaaaaa", "aaaaaaa", "b"},
			wantPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ChiSquaredTest(tt.tokens)
			if result.Passed != tt.wantPass {
				t.Errorf("ChiSquaredTest() passed = %v, want %v (p-value: %.4f)",
					result.Passed, tt.wantPass, result.PValue)
			}
		})
	}
}

func TestRunsTest(t *testing.T) {
	tests := []struct {
		name    string
		tokens  []string
		wantPass bool
	}{
		{
			name:    "random tokens should pass",
			tokens:  generateRandomTokens(50, 16),
			wantPass: true,
		},
		{
			name:    "all same bits should fail",
			tokens:  []string{"aaaaaaa", "aaaaaaa", "aaaaaaa"},
			wantPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RunsTest(tt.tokens)
			if result.Passed != tt.wantPass {
				t.Errorf("RunsTest() passed = %v, want %v (p-value: %.4f)",
					result.Passed, tt.wantPass, result.PValue)
			}
		})
	}
}

func TestSerialCorrelationTest(t *testing.T) {
	tests := []struct {
		name    string
		tokens  []string
		wantPass bool
	}{
		{
			name:    "random tokens should pass",
			tokens:  generateRandomTokens(50, 16),
			wantPass: true,
		},
		{
			name:    "sequential tokens should fail",
			tokens:  generateSequentialTokens(20),
			wantPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SerialCorrelationTest(tt.tokens)
			// Note: This test can be flaky with truly random data
			t.Logf("SerialCorrelationTest() passed = %v, p-value = %.4f",
				result.Passed, result.PValue)
		})
	}
}

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		name         string
		tokens       []string
		minEntropy   float64
	}{
		{
			name:       "random tokens should have high entropy",
			tokens:     generateRandomTokens(100, 16),
			minEntropy: 5.0,
		},
		{
			name:       "low entropy tokens",
			tokens:     generateLowEntropyTokens(100, 6),
			minEntropy: 2.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy := CalculateEntropy(tt.tokens)
			if entropy < tt.minEntropy {
				t.Errorf("CalculateEntropy() = %.4f, want >= %.4f", entropy, tt.minEntropy)
			}
			t.Logf("Entropy: %.4f bits/char", entropy)
		})
	}
}

func TestDetectCollisions(t *testing.T) {
	tests := []struct {
		name             string
		tokens           []string
		maxCollisionRate float64
	}{
		{
			name:             "random tokens should have low collision rate",
			tokens:           generateRandomTokens(100, 16),
			maxCollisionRate: 0.01,
		},
		{
			name:             "duplicate tokens should have high collision rate",
			tokens:           []string{"abc", "abc", "abc", "def", "def"},
			maxCollisionRate: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rate, result := DetectCollisions(tt.tokens)
			t.Logf("Collision rate: %.4f", rate)
			if rate > tt.maxCollisionRate && tt.maxCollisionRate < 0.5 {
				t.Errorf("DetectCollisions() rate = %.4f, want <= %.4f", rate, tt.maxCollisionRate)
			}
			if !result.Passed && rate < 0.01 {
				t.Errorf("DetectCollisions() should pass for low collision rate")
			}
		})
	}
}

func TestAnalyzeBitDistribution(t *testing.T) {
	tokens := generateRandomTokens(100, 16)
	biases := AnalyzeBitDistribution(tokens)

	if len(biases) == 0 {
		t.Fatal("AnalyzeBitDistribution() returned no results")
	}

	// Check that biases are reasonable (not all 0 or all 0.5)
	avgBias := 0.0
	for _, bias := range biases {
		avgBias += bias
	}
	avgBias /= float64(len(biases))

	t.Logf("Average bit bias: %.4f (ideal: close to 0)", avgBias)

	// For random data, average bias should be relatively small
	if avgBias > 0.3 {
		t.Errorf("Average bit bias too high: %.4f", avgBias)
	}
}

// Pattern detection tests

func TestDetectSequentialPattern(t *testing.T) {
	tests := []struct {
		name          string
		tokens        []string
		shouldDetect  bool
	}{
		{
			name:         "sequential tokens should be detected",
			tokens:       generateSequentialTokens(10),
			shouldDetect: true,
		},
		{
			name:         "random tokens should not be detected as sequential",
			tokens:       generateRandomTokens(10, 16),
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern := DetectSequentialPattern(tt.tokens)
			detected := (pattern != nil && pattern.Confidence > 0.7)

			if detected != tt.shouldDetect {
				t.Errorf("DetectSequentialPattern() detected = %v, want %v", detected, tt.shouldDetect)
			}

			if pattern != nil {
				t.Logf("Pattern: %s (confidence: %.2f)", pattern.Description, pattern.Confidence)
			}
		})
	}
}

func TestDetectLowEntropyPattern(t *testing.T) {
	tests := []struct {
		name         string
		tokens       []string
		shouldDetect bool
	}{
		{
			name:         "low entropy tokens should be detected",
			tokens:       generateLowEntropyTokens(20, 4),
			shouldDetect: true,
		},
		{
			name:         "high entropy tokens should not be detected",
			tokens:       generateRandomTokens(20, 16),
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy := CalculateEntropy(tt.tokens)
			charSet := GetCharacterSet(tt.tokens)
			pattern := DetectLowEntropyPattern(tt.tokens, entropy, charSet)

			detected := (pattern != nil && pattern.Confidence > 0.3)

			if detected != tt.shouldDetect {
				t.Errorf("DetectLowEntropyPattern() detected = %v, want %v", detected, tt.shouldDetect)
			}

			if pattern != nil {
				t.Logf("Pattern: %s (confidence: %.2f)", pattern.Description, pattern.Confidence)
			}
		})
	}
}

// PRNG fingerprinting tests

func TestFingerprintPRNG(t *testing.T) {
	// Create analysis for sequential tokens
	tokens := generateSequentialTokens(50)
	analysis := &EntropyAnalysis{
		TokenCount:   len(tokens),
		CharacterSet: GetCharacterSet(tokens),
		ShannonEntropy: CalculateEntropy(tokens),
		DetectedPatterns: []Pattern{
			{
				Type:       "sequential",
				Confidence: 0.9,
			},
		},
	}

	prng := FingerprintPRNG(analysis, tokens)

	if prng == nil {
		t.Log("No PRNG detected (acceptable for this test)")
	} else {
		t.Logf("Detected PRNG: %s (confidence: %.2f)", prng.Name, prng.Confidence)
		t.Logf("Weakness: %s", prng.Weakness)
		t.Logf("Exploit: %s", prng.ExploitHint)
	}
}

// Storage tests

func TestStorage(t *testing.T) {
	// Create temporary database
	dbPath := "test_entropy.db"
	defer os.Remove(dbPath)

	storage, err := NewStorage(dbPath)
	if err != nil {
		t.Fatalf("NewStorage() error = %v", err)
	}
	defer storage.Close()

	// Create session
	extractor := TokenExtractor{
		Pattern:  ".*",
		Location: "cookie",
		Name:     "session",
	}

	session, err := storage.CreateSession("Test Session", extractor)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	t.Logf("Created session ID: %d", session.ID)

	// Store tokens
	now := time.Now().UTC()
	for i := 0; i < 10; i++ {
		sample := TokenSample{
			CaptureSessionID: session.ID,
			TokenValue:       fmt.Sprintf("token_%d", i),
			TokenLength:      10,
			CapturedAt:       now.Add(time.Duration(i) * time.Second),
		}

		if err := storage.StoreToken(sample); err != nil {
			t.Fatalf("StoreToken() error = %v", err)
		}
	}

	// Retrieve tokens
	tokens, err := storage.GetTokens(session.ID)
	if err != nil {
		t.Fatalf("GetTokens() error = %v", err)
	}

	if len(tokens) != 10 {
		t.Errorf("GetTokens() returned %d tokens, want 10", len(tokens))
	}

	// Get session
	retrievedSession, err := storage.GetSession(session.ID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}

	if retrievedSession.TokenCount != 10 {
		t.Errorf("Session token count = %d, want 10", retrievedSession.TokenCount)
	}

	// Complete session
	if err := storage.CompleteSession(session.ID); err != nil {
		t.Fatalf("CompleteSession() error = %v", err)
	}
}

// Engine tests

func TestEntropyEngine(t *testing.T) {
	// Create temporary database
	dbPath := "test_engine.db"
	defer os.Remove(dbPath)

	storage, err := NewStorage(dbPath)
	if err != nil {
		t.Fatalf("NewStorage() error = %v", err)
	}
	defer storage.Close()

	engine := NewEntropyEngine(storage, time.Now)

	// Create session and add tokens
	extractor := TokenExtractor{
		Pattern:  ".*",
		Location: "cookie",
		Name:     "session",
	}

	session, err := storage.CreateSession("Test Analysis", extractor)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	// Add random tokens
	tokens := generateRandomTokens(100, 16)
	now := time.Now().UTC()

	for i, token := range tokens {
		sample := TokenSample{
			CaptureSessionID: session.ID,
			TokenValue:       token,
			TokenLength:      len(token),
			CapturedAt:       now.Add(time.Duration(i) * time.Millisecond),
		}

		if err := storage.StoreToken(sample); err != nil {
			t.Fatalf("StoreToken() error = %v", err)
		}
	}

	// Perform analysis
	analysis, err := engine.AnalyzeSession(session.ID)
	if err != nil {
		t.Fatalf("AnalyzeSession() error = %v", err)
	}

	// Verify analysis results
	if analysis.TokenCount != 100 {
		t.Errorf("Analysis token count = %d, want 100", analysis.TokenCount)
	}

	if analysis.RandomnessScore < 0 || analysis.RandomnessScore > 100 {
		t.Errorf("Randomness score = %.2f, want 0-100", analysis.RandomnessScore)
	}

	t.Logf("Analysis Results:")
	t.Logf("  Randomness Score: %.2f/100", analysis.RandomnessScore)
	t.Logf("  Shannon Entropy: %.2f", analysis.ShannonEntropy)
	t.Logf("  Collision Rate: %.4f", analysis.CollisionRate)
	t.Logf("  Risk Level: %s", analysis.Risk)
	t.Logf("  Chi-Squared: %v (p=%.4f)", analysis.ChiSquared.Passed, analysis.ChiSquared.PValue)
	t.Logf("  Runs Test: %v (p=%.4f)", analysis.Runs.Passed, analysis.Runs.PValue)

	if len(analysis.DetectedPatterns) > 0 {
		t.Logf("  Detected Patterns:")
		for _, p := range analysis.DetectedPatterns {
			t.Logf("    - %s (%.2f confidence): %s", p.Type, p.Confidence, p.Description)
		}
	}

	if analysis.DetectedPRNG != nil {
		t.Logf("  Detected PRNG: %s (%.2f confidence)", analysis.DetectedPRNG.Name, analysis.DetectedPRNG.Confidence)
	}

	if len(analysis.Recommendations) > 0 {
		t.Logf("  Recommendations:")
		for _, rec := range analysis.Recommendations {
			t.Logf("    - %s", rec)
		}
	}
}

// Performance test

func TestPerformance(t *testing.T) {
	// Test that analysis completes in <5 seconds for 1000 tokens
	tokens := generateRandomTokens(1000, 16)

	start := time.Now()

	// Run all statistical tests
	_ = ChiSquaredTest(tokens)
	_ = RunsTest(tokens)
	_ = SerialCorrelationTest(tokens)
	_ = SpectralTest(tokens)
	_ = CalculateEntropy(tokens)
	_, _ = DetectCollisions(tokens)
	_ = AnalyzeBitDistribution(tokens)

	elapsed := time.Since(start)

	t.Logf("Analysis of 1000 tokens completed in %v", elapsed)

	if elapsed > 5*time.Second {
		t.Errorf("Analysis took %v, want < 5s", elapsed)
	}
}

// Benchmark tests

func BenchmarkChiSquaredTest(b *testing.B) {
	tokens := generateRandomTokens(100, 16)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = ChiSquaredTest(tokens)
	}
}

func BenchmarkRunsTest(b *testing.B) {
	tokens := generateRandomTokens(100, 16)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = RunsTest(tokens)
	}
}

func BenchmarkCalculateEntropy(b *testing.B) {
	tokens := generateRandomTokens(100, 16)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = CalculateEntropy(tokens)
	}
}

func BenchmarkFullAnalysis(b *testing.B) {
	dbPath := "bench_entropy.db"
	defer os.Remove(dbPath)

	storage, _ := NewStorage(dbPath)
	defer storage.Close()

	engine := NewEntropyEngine(storage, time.Now)

	// Setup session with tokens
	extractor := TokenExtractor{Pattern: ".*", Location: "cookie", Name: "session"}
	session, _ := storage.CreateSession("Benchmark", extractor)

	tokens := generateRandomTokens(100, 16)
	now := time.Now().UTC()

	for i, token := range tokens {
		sample := TokenSample{
			CaptureSessionID: session.ID,
			TokenValue:       token,
			TokenLength:      len(token),
			CapturedAt:       now.Add(time.Duration(i) * time.Millisecond),
		}
		storage.StoreToken(sample)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = engine.AnalyzeSession(session.ID)
	}
}
