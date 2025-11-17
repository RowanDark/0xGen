package main

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

// PRNGDatabase contains signatures of known weak PRNGs
var PRNGDatabase = []PRNGSignature{
	{
		Name: "Linear Congruential Generator (LCG)",
		Indicators: []Indicator{
			{
				Test:      "serial_correlation",
				Threshold: 0.3, // High correlation
				Pattern:   "",
			},
			{
				Test:      "spectral",
				Threshold: 5.0, // High peak-to-average ratio
				Pattern:   "",
			},
		},
		Weakness:    "Predictable sequence based on linear recurrence relation. Can be broken with a few consecutive outputs.",
		ExploitHint: "Collect 3-6 consecutive outputs, solve linear equations to recover internal state, predict future values.",
	},
	{
		Name: "PHP mt_rand (pre-7.1)",
		Indicators: []Indicator{
			{
				Test:      "chi_squared",
				Threshold: 0.05, // Moderate uniformity issues
				Pattern:   "",
			},
			{
				Test:      "bit_bias",
				Threshold: 0.15, // Noticeable bit bias
				Pattern:   "",
			},
		},
		Weakness:    "Mersenne Twister with known vulnerabilities in seeding. State can be recovered from 624 consecutive outputs.",
		ExploitHint: "Capture 624 consecutive values, use MT predictor tool to recover state, predict all future values.",
	},
	{
		Name: "Java Random",
		Indicators: []Indicator{
			{
				Test:      "serial_correlation",
				Threshold: 0.2,
				Pattern:   "",
			},
			{
				Test:      "pattern_sequential",
				Threshold: 0.5,
				Pattern:   "",
			},
		},
		Weakness:    "LCG-based with 48-bit seed. Predictable if seed can be guessed or brute-forced.",
		ExploitHint: "If timestamp-seeded, narrow down seed space by request time. Brute force 48-bit space or use known-plaintext attack.",
	},
	{
		Name: "Microsoft RAND (weak)",
		Indicators: []Indicator{
			{
				Test:      "entropy",
				Threshold: 12.0, // Low entropy (should be closer to charset size)
				Pattern:   "",
			},
			{
				Test:      "collision_rate",
				Threshold: 0.05, // High collision rate
				Pattern:   "",
			},
		},
		Weakness:    "Small state space (32 bits), high collision probability.",
		ExploitHint: "Enumerate the limited output space (~4 billion values), build rainbow table, predict by lookup.",
	},
	{
		Name: "Sequential Counter",
		Indicators: []Indicator{
			{
				Test:      "pattern_sequential",
				Threshold: 0.8, // Very high confidence
				Pattern:   "",
			},
		},
		Weakness:    "Tokens increment by a fixed value (e.g., +1). Completely predictable.",
		ExploitHint: "Calculate the increment, predict next N tokens: token[n] = token[0] + n*increment",
	},
	{
		Name: "Timestamp-based",
		Indicators: []Indicator{
			{
				Test:      "pattern_timestamp",
				Threshold: 0.7,
				Pattern:   "",
			},
		},
		Weakness:    "Tokens correlate with generation time. Predictable if attacker can sync clocks.",
		ExploitHint: "Synchronize system clock with server, generate candidate tokens around predicted time window.",
	},
	{
		Name: "Low Entropy (Custom/Homebrew)",
		Indicators: []Indicator{
			{
				Test:      "entropy",
				Threshold: 3.0, // Very low bits per character
				Pattern:   "",
			},
			{
				Test:      "char_set_size",
				Threshold: 10.0, // Small character set
				Pattern:   "",
			},
		},
		Weakness:    "Limited character set or short length results in tiny keyspace. Brute-forceable.",
		ExploitHint: "Enumerate all possible combinations: charset^length. For charset=10, length=6: only 1M possibilities.",
	},
}

// FingerprintPRNG attempts to identify the PRNG used based on test results
func FingerprintPRNG(analysis *EntropyAnalysis, tokens []string) *PRNGSignature {
	if len(tokens) < 10 {
		return nil // Not enough data
	}

	// Calculate metrics for pattern matching
	metrics := calculateMetrics(analysis, tokens)

	// Score each PRNG signature
	bestMatch := (*PRNGSignature)(nil)
	bestScore := 0.0

	for i := range PRNGDatabase {
		signature := PRNGDatabase[i]
		score := scorePRNGMatch(signature, metrics)

		if score > bestScore && score > 0.5 { // Minimum confidence threshold
			bestScore = score
			matchedSig := signature
			matchedSig.Confidence = score
			bestMatch = &matchedSig
		}
	}

	return bestMatch
}

// calculateMetrics extracts relevant metrics from analysis and tokens
func calculateMetrics(analysis *EntropyAnalysis, tokens []string) map[string]float64 {
	metrics := make(map[string]float64)

	// Statistical test results
	metrics["chi_squared_pvalue"] = analysis.ChiSquared.PValue
	metrics["serial_correlation_conf"] = analysis.SerialCorrelation.Confidence
	metrics["spectral_conf"] = analysis.Spectral.Confidence
	metrics["entropy"] = analysis.ShannonEntropy
	metrics["collision_rate"] = analysis.CollisionRate

	// Bit distribution analysis
	if len(analysis.BitDistribution) > 0 {
		avgBias := 0.0
		for _, bias := range analysis.BitDistribution {
			avgBias += bias
		}
		avgBias /= float64(len(analysis.BitDistribution))
		metrics["bit_bias"] = avgBias
	}

	// Character set size
	metrics["char_set_size"] = float64(len(analysis.CharacterSet))

	// Pattern detection results
	for _, pattern := range analysis.DetectedPatterns {
		switch pattern.Type {
		case "sequential":
			metrics["pattern_sequential"] = pattern.Confidence
		case "timestamp":
			metrics["pattern_timestamp"] = pattern.Confidence
		case "low_entropy":
			metrics["pattern_low_entropy"] = pattern.Confidence
		}
	}

	return metrics
}

// scorePRNGMatch calculates how well metrics match a PRNG signature
func scorePRNGMatch(signature PRNGSignature, metrics map[string]float64) float64 {
	if len(signature.Indicators) == 0 {
		return 0
	}

	matchCount := 0
	totalIndicators := len(signature.Indicators)

	for _, indicator := range signature.Indicators {
		var metricValue float64
		var exists bool

		// Map indicator test to metric key
		switch indicator.Test {
		case "chi_squared":
			metricValue, exists = metrics["chi_squared_pvalue"]
			if exists && metricValue < indicator.Threshold {
				matchCount++
			}
		case "serial_correlation":
			metricValue, exists = metrics["serial_correlation_conf"]
			if exists && metricValue > indicator.Threshold {
				matchCount++
			}
		case "spectral":
			metricValue, exists = metrics["spectral_conf"]
			if exists && metricValue > indicator.Threshold {
				matchCount++
			}
		case "entropy":
			metricValue, exists = metrics["entropy"]
			if exists && metricValue < indicator.Threshold {
				matchCount++
			}
		case "bit_bias":
			metricValue, exists = metrics["bit_bias"]
			if exists && metricValue > indicator.Threshold {
				matchCount++
			}
		case "collision_rate":
			metricValue, exists = metrics["collision_rate"]
			if exists && metricValue > indicator.Threshold {
				matchCount++
			}
		case "char_set_size":
			metricValue, exists = metrics["char_set_size"]
			if exists && metricValue < indicator.Threshold {
				matchCount++
			}
		case "pattern_sequential", "pattern_timestamp", "pattern_low_entropy":
			metricValue, exists = metrics[indicator.Test]
			if exists && metricValue > indicator.Threshold {
				matchCount++
			}
		}
	}

	// Calculate confidence as percentage of matched indicators
	return float64(matchCount) / float64(totalIndicators)
}

// DetectSequentialPattern detects if tokens follow a sequential pattern
func DetectSequentialPattern(tokens []string) *Pattern {
	if len(tokens) < 3 {
		return nil
	}

	// Try to parse tokens as numbers
	values := make([]int64, 0, len(tokens))
	for _, token := range tokens {
		// Try to extract numeric part
		if val := extractNumeric(token); val != -1 {
			values = append(values, val)
		}
	}

	if len(values) < 3 {
		return nil
	}

	// Check if differences are consistent (arithmetic sequence)
	diffs := make([]int64, len(values)-1)
	for i := 0; i < len(values)-1; i++ {
		diffs[i] = values[i+1] - values[i]
	}

	// Calculate consistency of differences
	if len(diffs) == 0 {
		return nil
	}

	avgDiff := diffs[0]
	consistent := 0
	for _, diff := range diffs {
		if diff == avgDiff {
			consistent++
		}
	}

	confidence := float64(consistent) / float64(len(diffs))

	if confidence > 0.7 {
		return &Pattern{
			Type:        "sequential",
			Confidence:  confidence,
			Description: "Tokens follow sequential pattern with consistent increment",
			Evidence:    formatSequentialEvidence(values, avgDiff),
		}
	}

	return nil
}

// DetectTimestampPattern detects timestamp-based token generation
func DetectTimestampPattern(tokens []TokenSample) *Pattern {
	if len(tokens) < 5 {
		return nil
	}

	// Try to extract numeric values and correlate with timestamps
	correlations := make([]float64, 0)

	for i := 0; i < len(tokens)-1; i++ {
		val1 := extractNumeric(tokens[i].TokenValue)
		val2 := extractNumeric(tokens[i+1].TokenValue)

		if val1 == -1 || val2 == -1 {
			continue
		}

		timeDiff := tokens[i+1].CapturedAt.Unix() - tokens[i].CapturedAt.Unix()
		valueDiff := val2 - val1

		if timeDiff > 0 {
			// Calculate correlation
			ratio := float64(valueDiff) / float64(timeDiff)
			correlations = append(correlations, ratio)
		}
	}

	if len(correlations) < 3 {
		return nil
	}

	// Check if ratios are consistent
	avgRatio := 0.0
	for _, r := range correlations {
		avgRatio += math.Abs(r)
	}
	avgRatio /= float64(len(correlations))

	// Calculate variance
	variance := 0.0
	for _, r := range correlations {
		diff := math.Abs(r) - avgRatio
		variance += diff * diff
	}
	variance /= float64(len(correlations))

	// Low variance indicates consistent time-based pattern
	consistency := 1.0 / (1.0 + variance/avgRatio)

	if consistency > 0.6 {
		return &Pattern{
			Type:        "timestamp",
			Confidence:  consistency,
			Description: "Token values correlate with generation time",
			Evidence:    "Time-value correlation detected",
		}
	}

	return nil
}

// DetectLowEntropyPattern detects limited character set usage
func DetectLowEntropyPattern(tokens []string, entropy float64, charSet []rune) *Pattern {
	if len(tokens) == 0 {
		return nil
	}

	// Calculate ideal entropy for character set
	idealEntropy := math.Log2(float64(len(charSet)))

	// Compare actual vs ideal
	entropyRatio := entropy / idealEntropy

	if entropyRatio < 0.7 || len(charSet) < 16 {
		confidence := 1.0 - entropyRatio

		// Calculate keyspace
		avgLen := 0
		for _, token := range tokens {
			avgLen += len(token)
		}
		avgLen /= len(tokens)

		keyspace := math.Pow(float64(len(charSet)), float64(avgLen))

		return &Pattern{
			Type:        "low_entropy",
			Confidence:  confidence,
			Description: "Limited character set results in small keyspace",
			Evidence:    formatLowEntropyEvidence(len(charSet), avgLen, keyspace),
		}
	}

	return nil
}

// Helper functions

func extractNumeric(s string) int64 {
	// Extract first contiguous sequence of digits
	re := regexp.MustCompile(`\d+`)
	match := re.FindString(s)
	if match == "" {
		// Try hex
		re = regexp.MustCompile(`[0-9a-fA-F]+`)
		match = re.FindString(s)
		if match == "" {
			return -1
		}
		// Parse as hex
		var val int64
		for _, ch := range strings.ToLower(match) {
			val *= 16
			if ch >= '0' && ch <= '9' {
				val += int64(ch - '0')
			} else if ch >= 'a' && ch <= 'f' {
				val += int64(ch - 'a' + 10)
			}
		}
		return val
	}

	// Parse decimal
	var val int64
	for _, ch := range match {
		val = val*10 + int64(ch-'0')
	}
	return val
}

func formatSequentialEvidence(values []int64, increment int64) string {
	if len(values) < 3 {
		return ""
	}
	return fmt.Sprintf("Pattern: %d → %d → %d (increment: %d)", values[0], values[1], values[2], increment)
}

func formatLowEntropyEvidence(charsetSize, avgLen int, keyspace float64) string {
	if keyspace < 1e9 {
		return fmt.Sprintf("Charset: %d chars, Length: %d, Keyspace: %.0f (brute-forceable)", charsetSize, avgLen, keyspace)
	}
	return fmt.Sprintf("Charset: %d chars, Length: %d, Keyspace: %.2e", charsetSize, avgLen, keyspace)
}
