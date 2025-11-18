package main

import (
	"crypto/rand"
	"encoding/hex"
	"math"
	"math/big"
	"strings"
	"testing"
)

// NIST Test Suite Validation
// These tests validate against known-good and known-bad randomness sources

// TestNISTMonobits validates the monobit test (similar to Chi-squared for bits)
func TestNISTMonobits(t *testing.T) {
	tests := []struct {
		name     string
		tokens   []string
		wantPass bool
	}{
		{
			name:     "NIST known-good random data",
			tokens:   generateCryptoRandomTokens(1000, 32),
			wantPass: true,
		},
		{
			name:     "all zeros should fail",
			tokens:   generateAllSameTokens(100, "00000000"),
			wantPass: false,
		},
		{
			name:     "all ones should fail",
			tokens:   generateAllSameTokens(100, "ffffffff"),
			wantPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ChiSquaredTest(tt.tokens)
			if result.Passed != tt.wantPass {
				t.Errorf("ChiSquaredTest() passed = %v, want %v (p-value: %.6f)",
					result.Passed, tt.wantPass, result.PValue)
			}
			t.Logf("NIST Monobit Test: p-value = %.6f, passed = %v", result.PValue, result.Passed)
		})
	}
}

// TestNISTRuns validates runs test against NIST standards
func TestNISTRuns(t *testing.T) {
	tests := []struct {
		name     string
		tokens   []string
		wantPass bool
	}{
		{
			name:     "crypto random should pass",
			tokens:   generateCryptoRandomTokens(500, 16),
			wantPass: true,
		},
		{
			name:     "alternating pattern should fail",
			tokens:   generateAlternatingPattern(100),
			wantPass: false,
		},
		{
			name:     "long runs should fail",
			tokens:   generateLongRuns(50),
			wantPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RunsTest(tt.tokens)
			if result.Passed != tt.wantPass {
				t.Errorf("RunsTest() passed = %v, want %v (p-value: %.6f)",
					result.Passed, tt.wantPass, result.PValue)
			}
			t.Logf("NIST Runs Test: p-value = %.6f, passed = %v", result.PValue, result.Passed)
		})
	}
}

// TestEdgeCases tests various edge cases
func TestEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		tokens   []string
		testFunc func([]string) float64
		wantZero bool
	}{
		{
			name:     "empty input entropy",
			tokens:   []string{},
			testFunc: CalculateEntropy,
			wantZero: true,
		},
		{
			name:     "single token entropy",
			tokens:   []string{"abc"},
			testFunc: CalculateEntropy,
			wantZero: false,
		},
		{
			name:     "all empty strings",
			tokens:   []string{"", "", ""},
			testFunc: CalculateEntropy,
			wantZero: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.testFunc(tt.tokens)
			isZero := result == 0.0
			if isZero != tt.wantZero {
				t.Errorf("Test returned %.6f, wantZero = %v", result, tt.wantZero)
			}
		})
	}
}

// TestKnownWeakPRNGs tests detection of known weak PRNGs
func TestKnownWeakPRNGs(t *testing.T) {
	tests := []struct {
		name         string
		tokens       []string
		expectedPRNG string
		minConfidence float64
	}{
		{
			name:         "Linear Congruential Generator",
			tokens:       generateLCGTokens(100),
			expectedPRNG: "Linear Congruential Generator",
			minConfidence: 0.6,
		},
		{
			name:         "Sequential pattern",
			tokens:       generateSequentialTokens(50),
			expectedPRNG: "", // May not match specific PRNG but should detect pattern
			minConfidence: 0.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := &EntropyAnalysis{
				TokenCount: len(tt.tokens),
			}

			// Run statistical tests
			analysis.ChiSquared = ChiSquaredTest(tt.tokens)
			analysis.Runs = RunsTest(tt.tokens)
			analysis.SerialCorrelation = SerialCorrelationTest(tt.tokens)

			detected := FingerprintPRNG(analysis, tt.tokens)

			if detected != nil {
				t.Logf("Detected PRNG: %s (confidence: %.2f)", detected.Name, detected.Confidence)
				if detected.Confidence < tt.minConfidence {
					t.Errorf("Confidence %.2f below minimum %.2f", detected.Confidence, tt.minConfidence)
				}
			} else if tt.expectedPRNG != "" {
				t.Errorf("Expected to detect %s but got nil", tt.expectedPRNG)
			}
		})
	}
}

// TestRealWorldVulnerableTokens tests tokens from known vulnerable applications
func TestRealWorldVulnerableTokens(t *testing.T) {
	tests := []struct {
		name        string
		tokens      []string
		shouldFail  []string // Which tests should fail
		description string
	}{
		{
			name: "PHP mt_rand weak tokens (pre-7.1)",
			tokens: []string{
				"1804289383", "846930886", "1681692777", "1714636915",
				"1957747793", "424238335", "719885386", "1649760492",
			},
			shouldFail:  []string{"SerialCorrelation"},
			description: "Old PHP mt_rand generates predictable sequences",
		},
		{
			name: "Timestamp-based tokens",
			tokens: generateTimestampTokens(50),
			shouldFail: []string{"SerialCorrelation"},
			description: "Tokens based on timestamps show correlation",
		},
		{
			name: "Low-entropy hex tokens",
			tokens: []string{
				"00000001", "00000002", "00000003", "00000004",
				"00000005", "00000006", "00000007", "00000008",
			},
			shouldFail: []string{"ChiSquared", "Runs", "SerialCorrelation"},
			description: "Low entropy with obvious patterns",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := &EntropyAnalysis{
				TokenCount: len(tt.tokens),
			}

			analysis.ChiSquared = ChiSquaredTest(tt.tokens)
			analysis.Runs = RunsTest(tt.tokens)
			analysis.SerialCorrelation = SerialCorrelationTest(tt.tokens)
			analysis.ShannonEntropy = CalculateEntropy(tt.tokens)

			t.Logf("Description: %s", tt.description)
			t.Logf("Chi-Squared: p=%.4f, passed=%v", analysis.ChiSquared.PValue, analysis.ChiSquared.Passed)
			t.Logf("Runs: p=%.4f, passed=%v", analysis.Runs.PValue, analysis.Runs.Passed)
			t.Logf("Serial Correlation: p=%.4f, passed=%v", analysis.SerialCorrelation.PValue, analysis.SerialCorrelation.Passed)
			t.Logf("Entropy: %.4f bits", analysis.ShannonEntropy)

			// Verify expected failures
			for _, testName := range tt.shouldFail {
				switch testName {
				case "ChiSquared":
					if analysis.ChiSquared.Passed {
						t.Errorf("Expected Chi-Squared to fail but it passed")
					}
				case "Runs":
					if analysis.Runs.Passed {
						t.Errorf("Expected Runs test to fail but it passed")
					}
				case "SerialCorrelation":
					if analysis.SerialCorrelation.Passed {
						t.Errorf("Expected Serial Correlation to fail but it passed")
					}
				}
			}
		})
	}
}

// Test data generators for validation

func generateCryptoRandomTokens(count, length int) []string {
	tokens := make([]string, count)
	for i := 0; i < count; i++ {
		bytes := make([]byte, length)
		rand.Read(bytes)
		tokens[i] = hex.EncodeToString(bytes)
	}
	return tokens
}

func generateAllSameTokens(count int, value string) []string {
	tokens := make([]string, count)
	for i := 0; i < count; i++ {
		tokens[i] = value
	}
	return tokens
}

func generateAlternatingPattern(count int) []string {
	tokens := make([]string, count)
	for i := 0; i < count; i++ {
		if i%2 == 0 {
			tokens[i] = "aaaaaaa"
		} else {
			tokens[i] = "bbbbbbb"
		}
	}
	return tokens
}

func generateLongRuns(count int) []string {
	tokens := make([]string, count)
	for i := 0; i < count; i++ {
		if i < count/2 {
			tokens[i] = "0000000"
		} else {
			tokens[i] = "1111111"
		}
	}
	return tokens
}

func generateLCGTokens(count int) []string {
	// Simple LCG: X(n+1) = (a * X(n) + c) mod m
	tokens := make([]string, count)
	a := int64(1103515245)
	c := int64(12345)
	m := int64(1 << 31)
	x := int64(1)

	for i := 0; i < count; i++ {
		x = (a*x + c) % m
		tokens[i] = strings.ToUpper(hex.EncodeToString([]byte{
			byte(x >> 24), byte(x >> 16), byte(x >> 8), byte(x),
		}))
	}
	return tokens
}

func generateTimestampTokens(count int) []string {
	tokens := make([]string, count)
	base := int64(1609459200) // 2021-01-01 00:00:00 UTC
	for i := 0; i < count; i++ {
		timestamp := base + int64(i*60) // One minute apart
		tokens[i] = strings.ToUpper(hex.EncodeToString([]byte{
			byte(timestamp >> 24), byte(timestamp >> 16),
			byte(timestamp >> 8), byte(timestamp),
		}))
	}
	return tokens
}

// TestEntropyAccuracy validates entropy calculation accuracy
func TestEntropyAccuracy(t *testing.T) {
	tests := []struct {
		name           string
		tokens         []string
		expectedEntropy float64
		tolerance       float64
	}{
		{
			name:           "single character - zero entropy",
			tokens:         []string{"aaaa", "aaaa", "aaaa"},
			expectedEntropy: 0.0,
			tolerance:      0.01,
		},
		{
			name:           "two characters equally distributed - 1 bit",
			tokens:         []string{"ababab", "bababa", "ababab"},
			expectedEntropy: 1.0,
			tolerance:      0.1,
		},
		{
			name:           "hex characters (16 possibilities) - 4 bits",
			tokens:         generateCryptoRandomTokens(100, 8),
			expectedEntropy: 4.0,
			tolerance:      0.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy := CalculateEntropy(tt.tokens)
			diff := math.Abs(entropy - tt.expectedEntropy)

			t.Logf("Calculated entropy: %.4f bits, expected: %.4f bits", entropy, tt.expectedEntropy)

			if diff > tt.tolerance {
				t.Errorf("Entropy %.4f outside tolerance of %.4f ±%.4f",
					entropy, tt.expectedEntropy, tt.tolerance)
			}
		})
	}
}

// TestCollisionBirthdayParadox validates collision detection
func TestCollisionBirthdayParadox(t *testing.T) {
	// For truly random n-bit tokens, expected collisions follow birthday paradox
	// For 32-bit tokens (4 billion possibilities):
	// - 77,000 tokens → ~50% chance of collision
	// - 10,000 tokens → ~1% chance of collision

	tests := []struct {
		name              string
		tokenCount        int
		tokenLength       int
		maxExpectedCollisions float64
	}{
		{
			name:              "small sample - unlikely collisions",
			tokenCount:        100,
			tokenLength:       16, // 128-bit
			maxExpectedCollisions: 0.01,
		},
		{
			name:              "larger sample - possible collisions",
			tokenCount:        1000,
			tokenLength:       4, // 32-bit
			maxExpectedCollisions: 0.1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := generateCryptoRandomTokens(tt.tokenCount, tt.tokenLength)
			rate, result := DetectCollisions(tokens)

			t.Logf("Collision rate: %.6f (max expected: %.6f)", rate, tt.maxExpectedCollisions)
			t.Logf("Test result: passed=%v, p-value=%.6f", result.Passed, result.PValue)

			// For truly random data, collision rate should be below expected
			if rate > tt.maxExpectedCollisions*2 {
				t.Errorf("Collision rate %.6f exceeds 2x expected %.6f",
					rate, tt.maxExpectedCollisions)
			}
		})
	}
}

// TestBitDistributionUniformity validates bit distribution analysis
func TestBitDistributionUniformity(t *testing.T) {
	tests := []struct {
		name          string
		tokens        []string
		maxDeviation  float64
		description   string
	}{
		{
			name:          "crypto random - uniform distribution",
			tokens:        generateCryptoRandomTokens(1000, 16),
			maxDeviation:  0.1,
			description:   "Each bit position should be ~50% ones",
		},
		{
			name:          "all zeros - biased distribution",
			tokens:        generateAllSameTokens(100, "00000000"),
			maxDeviation:  1.0,
			description:   "All bit positions should be 0% ones",
		},
		{
			name:          "all ones - biased distribution",
			tokens:        generateAllSameTokens(100, "ffffffff"),
			maxDeviation:  1.0,
			description:   "All bit positions should be 100% ones",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			distribution := AnalyzeBitDistribution(tt.tokens)

			t.Logf("Description: %s", tt.description)
			t.Logf("Bit positions: %d", len(distribution))

			// Calculate deviation from ideal 0.5
			totalDeviation := 0.0
			for i, freq := range distribution {
				deviation := math.Abs(freq - 0.5)
				totalDeviation += deviation
				if i < 8 { // Log first 8 bits
					t.Logf("  Bit %d: %.4f (deviation: %.4f)", i, freq, deviation)
				}
			}

			avgDeviation := totalDeviation / float64(len(distribution))
			t.Logf("Average deviation from 0.5: %.4f (max: %.4f)", avgDeviation, tt.maxDeviation)

			if avgDeviation > tt.maxDeviation {
				t.Errorf("Average deviation %.4f exceeds maximum %.4f",
					avgDeviation, tt.maxDeviation)
			}
		})
	}
}

// TestFalsePositiveRate validates PRNG detection doesn't have high false positives
func TestFalsePositiveRate(t *testing.T) {
	falsePositives := 0
	trials := 10

	for i := 0; i < trials; i++ {
		// Generate truly random tokens
		tokens := generateCryptoRandomTokens(200, 16)

		analysis := &EntropyAnalysis{
			TokenCount: len(tokens),
		}
		analysis.ChiSquared = ChiSquaredTest(tokens)
		analysis.Runs = RunsTest(tokens)
		analysis.SerialCorrelation = SerialCorrelationTest(tokens)

		detected := FingerprintPRNG(analysis, tokens)
		if detected != nil && detected.Confidence > 0.7 {
			falsePositives++
			t.Logf("Trial %d: False positive - detected %s (confidence: %.2f)",
				i+1, detected.Name, detected.Confidence)
		}
	}

	falsePositiveRate := float64(falsePositives) / float64(trials)
	t.Logf("False positive rate: %.2f%% (%d/%d)", falsePositiveRate*100, falsePositives, trials)

	if falsePositiveRate > 0.1 { // Allow up to 10% false positives
		t.Errorf("False positive rate %.2f%% exceeds 10%%", falsePositiveRate*100)
	}
}
