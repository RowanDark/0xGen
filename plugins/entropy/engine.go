package main

import (
	"fmt"
	"math"
	"time"

	pluginsdk "github.com/RowanDark/0xgen/sdk/plugin-sdk"
)

// EntropyEngine is the main analysis engine
type EntropyEngine struct {
	storage *Storage
	now     func() time.Time
}

// NewEntropyEngine creates a new entropy analysis engine
func NewEntropyEngine(storage *Storage, now func() time.Time) *EntropyEngine {
	if now == nil {
		now = time.Now
	}
	return &EntropyEngine{
		storage: storage,
		now:     now,
	}
}

// AnalyzeSession performs complete entropy analysis on a capture session
func (e *EntropyEngine) AnalyzeSession(sessionID int64) (*EntropyAnalysis, error) {
	// Retrieve session and tokens
	session, err := e.storage.GetSession(sessionID)
	if err != nil {
		return nil, fmt.Errorf("get session: %w", err)
	}

	tokens, err := e.storage.GetTokens(sessionID)
	if err != nil {
		return nil, fmt.Errorf("get tokens: %w", err)
	}

	if len(tokens) == 0 {
		return nil, fmt.Errorf("no tokens found for session %d", sessionID)
	}

	// Extract token values
	tokenValues := make([]string, len(tokens))
	for i, t := range tokens {
		tokenValues[i] = t.TokenValue
	}

	// Calculate average token length
	avgLength := 0
	for _, token := range tokenValues {
		avgLength += len(token)
	}
	avgLength /= len(tokenValues)

	// Extract character set
	charSet := GetCharacterSet(tokenValues)

	// Perform statistical tests
	analysis := &EntropyAnalysis{
		CaptureSessionID: sessionID,
		TokenCount:       len(tokens),
		TokenLength:      avgLength,
		CharacterSet:     charSet,
	}

	// Run all statistical tests
	analysis.ChiSquared = ChiSquaredTest(tokenValues)
	analysis.Runs = RunsTest(tokenValues)
	analysis.SerialCorrelation = SerialCorrelationTest(tokenValues)
	analysis.Spectral = SpectralTest(tokenValues)
	analysis.ShannonEntropy = CalculateEntropy(tokenValues)

	collisionRate, collisionTest := DetectCollisions(tokenValues)
	analysis.CollisionRate = collisionRate
	// Store collision test result in metadata if needed

	analysis.BitDistribution = AnalyzeBitDistribution(tokenValues)

	// AI Pattern Detection
	analysis.DetectedPatterns = e.detectPatterns(tokenValues, tokens)

	// PRNG Fingerprinting
	analysis.DetectedPRNG = FingerprintPRNG(analysis, tokenValues)

	// Calculate overall randomness score
	analysis.RandomnessScore = e.calculateRandomnessScore(analysis)

	// Assess risk level
	analysis.Risk = e.assessRisk(analysis)

	// Calculate confidence metrics
	e.calculateConfidenceMetrics(analysis)

	// Generate recommendations
	analysis.Recommendations = e.generateRecommendations(analysis)

	return analysis, nil
}

// detectPatterns runs AI pattern detection
func (e *EntropyEngine) detectPatterns(tokenValues []string, tokens []TokenSample) []Pattern {
	var patterns []Pattern

	// Detect sequential pattern
	if p := DetectSequentialPattern(tokenValues); p != nil {
		patterns = append(patterns, *p)
	}

	// Detect timestamp-based pattern
	if p := DetectTimestampPattern(tokens); p != nil {
		patterns = append(patterns, *p)
	}

	// Detect low entropy pattern
	entropy := CalculateEntropy(tokenValues)
	charSet := GetCharacterSet(tokenValues)
	if p := DetectLowEntropyPattern(tokenValues, entropy, charSet); p != nil {
		patterns = append(patterns, *p)
	}

	// Detect repeated substrings
	if p := detectRepeatedSubstrings(tokenValues); p != nil {
		patterns = append(patterns, *p)
	}

	// Detect user-ID correlation
	if p := detectUserIDCorrelation(tokenValues); p != nil {
		patterns = append(patterns, *p)
	}

	return patterns
}

// calculateRandomnessScore computes overall randomness score (0-100)
func (e *EntropyEngine) calculateRandomnessScore(analysis *EntropyAnalysis) float64 {
	score := 100.0

	// Deduct points for failed tests
	if !analysis.ChiSquared.Passed {
		score -= 15.0
	}
	if !analysis.Runs.Passed {
		score -= 15.0
	}
	if !analysis.SerialCorrelation.Passed {
		score -= 15.0
	}
	if !analysis.Spectral.Passed {
		score -= 10.0
	}

	// Deduct for low entropy
	idealEntropy := math.Log2(float64(len(analysis.CharacterSet)))
	if idealEntropy > 0 {
		entropyRatio := analysis.ShannonEntropy / idealEntropy
		if entropyRatio < 0.9 {
			score -= (1.0 - entropyRatio) * 20.0
		}
	}

	// Deduct for collisions
	if analysis.CollisionRate > 0.01 {
		score -= analysis.CollisionRate * 100.0
	}

	// Deduct for detected patterns
	for _, pattern := range analysis.DetectedPatterns {
		score -= pattern.Confidence * 15.0
	}

	// Deduct for detected PRNG
	if analysis.DetectedPRNG != nil {
		score -= analysis.DetectedPRNG.Confidence * 25.0
	}

	// Ensure score is in valid range
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}

// assessRisk determines risk level based on analysis
func (e *EntropyEngine) assessRisk(analysis *EntropyAnalysis) RiskLevel {
	score := analysis.RandomnessScore

	// Critical risk conditions
	if analysis.DetectedPRNG != nil && analysis.DetectedPRNG.Confidence > 0.8 {
		return RiskCritical
	}
	if analysis.CollisionRate > 0.1 {
		return RiskCritical
	}
	for _, p := range analysis.DetectedPatterns {
		if p.Type == "sequential" && p.Confidence > 0.8 {
			return RiskCritical
		}
	}

	// Score-based assessment
	if score < 30 {
		return RiskCritical
	} else if score < 50 {
		return RiskHigh
	} else if score < 70 {
		return RiskMedium
	} else {
		return RiskLow
	}
}

// calculateConfidenceMetrics determines confidence based on sample size
func (e *EntropyEngine) calculateConfidenceMetrics(analysis *EntropyAnalysis) {
	minSampleSize := 100 // Minimum tokens for reliable results
	tokenCount := analysis.TokenCount

	// Calculate confidence level using sigmoid function
	// Reaches 90% at minSampleSize, approaches 100% asymptotically
	x := float64(tokenCount) / float64(minSampleSize)
	analysis.ConfidenceLevel = 1.0 / (1.0 + math.Exp(-5*(x-0.5)))

	// Calculate reliability score (0-100)
	analysis.ReliabilityScore = analysis.ConfidenceLevel * 100

	// Tokens needed for full confidence
	if tokenCount < minSampleSize {
		analysis.TokensNeeded = minSampleSize - tokenCount
	} else {
		analysis.TokensNeeded = 0
	}

	// Determine sample quality
	if tokenCount < 20 {
		analysis.SampleQuality = "insufficient"
	} else if tokenCount < 50 {
		analysis.SampleQuality = "marginal"
	} else if tokenCount < minSampleSize {
		analysis.SampleQuality = "adequate"
	} else {
		analysis.SampleQuality = "excellent"
	}

	// Add warning to recommendations if sample size is small
	if tokenCount < minSampleSize {
		// Will be prepended to recommendations
	}
}

// generateRecommendations creates actionable recommendations
func (e *EntropyEngine) generateRecommendations(analysis *EntropyAnalysis) []string {
	var recommendations []string

	// Sample size warnings
	if analysis.TokenCount < 100 {
		if analysis.TokensNeeded > 0 {
			recommendations = append(recommendations,
				fmt.Sprintf("ℹ️ Sample size: %s (%d tokens)", analysis.SampleQuality, analysis.TokenCount),
				fmt.Sprintf("📊 Need %d more tokens for reliable results (%.0f%% confidence)",
					analysis.TokensNeeded, analysis.ReliabilityScore),
			)
		}
	}

	// PRNG-specific recommendations
	if analysis.DetectedPRNG != nil {
		recommendations = append(recommendations,
			fmt.Sprintf("⚠️ Detected: %s", analysis.DetectedPRNG.Name),
			fmt.Sprintf("Weakness: %s", analysis.DetectedPRNG.Weakness),
			fmt.Sprintf("Exploit: %s", analysis.DetectedPRNG.ExploitHint),
		)
	}

	// Pattern-specific recommendations
	for _, pattern := range analysis.DetectedPatterns {
		switch pattern.Type {
		case "sequential":
			recommendations = append(recommendations,
				"🔴 Sequential tokens detected - predict next tokens by incrementing",
				"Attack: Calculate increment, generate future token values",
			)
		case "timestamp":
			recommendations = append(recommendations,
				"🔴 Timestamp-based tokens detected - predict by syncing clocks",
				"Attack: Synchronize with server time, generate tokens for target time windows",
			)
		case "low_entropy":
			recommendations = append(recommendations,
				"🔴 Low entropy detected - brute force attack feasible",
				fmt.Sprintf("Attack: %s", pattern.Evidence),
			)
		}
	}

	// Statistical test failures
	if !analysis.ChiSquared.Passed {
		recommendations = append(recommendations,
			"⚠️ Non-uniform distribution detected - some characters appear more frequently",
		)
	}
	if !analysis.Runs.Passed {
		recommendations = append(recommendations,
			"⚠️ Pattern in bit runs detected - tokens are not independent",
		)
	}
	if !analysis.SerialCorrelation.Passed {
		recommendations = append(recommendations,
			"⚠️ Serial correlation detected - adjacent tokens are predictable",
		)
	}

	// Collision-based recommendations
	if analysis.CollisionRate > 0.05 {
		recommendations = append(recommendations,
			fmt.Sprintf("🔴 High collision rate (%.2f%%) - token space is too small", analysis.CollisionRate*100),
			"Attack: Build rainbow table of all observed tokens",
		)
	}

	// Entropy-based recommendations
	idealEntropy := math.Log2(float64(len(analysis.CharacterSet)))
	if idealEntropy > 0 && analysis.ShannonEntropy < idealEntropy*0.7 {
		recommendations = append(recommendations,
			fmt.Sprintf("⚠️ Low Shannon entropy (%.2f bits vs %.2f ideal)", analysis.ShannonEntropy, idealEntropy),
			"Recommendation: Use cryptographically secure random number generator (CSRNG)",
		)
	}

	// General recommendations based on risk
	switch analysis.Risk {
	case RiskCritical:
		recommendations = append(recommendations,
			"🚨 CRITICAL: Token generation is severely flawed",
			"Immediate action: Replace with crypto.rand or equivalent CSRNG",
			"Security impact: Session hijacking, account takeover highly likely",
		)
	case RiskHigh:
		recommendations = append(recommendations,
			"⚠️ HIGH RISK: Token generation has significant weaknesses",
			"Recommendation: Audit and replace token generation mechanism",
		)
	case RiskMedium:
		recommendations = append(recommendations,
			"⚠️ MEDIUM RISK: Some randomness issues detected",
			"Recommendation: Review token generation implementation",
		)
	case RiskLow:
		recommendations = append(recommendations,
			"✅ Token generation appears secure",
			"Continue monitoring for anomalies",
		)
	}

	return recommendations
}

// CreateFinding converts analysis to a plugin finding
func (e *EntropyEngine) CreateFinding(analysis *EntropyAnalysis, session *CaptureSession) pluginsdk.Finding {
	message := fmt.Sprintf("Entropy Analysis: %s tokens (%s)",
		session.Name, analysis.Risk)

	evidence := formatEvidence(analysis)

	metadata := map[string]string{
		"analysis_engine":   "entropy",
		"token_count":       fmt.Sprintf("%d", analysis.TokenCount),
		"randomness_score":  fmt.Sprintf("%.2f", analysis.RandomnessScore),
		"shannon_entropy":   fmt.Sprintf("%.2f", analysis.ShannonEntropy),
		"collision_rate":    fmt.Sprintf("%.4f", analysis.CollisionRate),
		"risk_level":        string(analysis.Risk),
	}

	if analysis.DetectedPRNG != nil {
		metadata["detected_prng"] = analysis.DetectedPRNG.Name
		metadata["prng_confidence"] = fmt.Sprintf("%.2f", analysis.DetectedPRNG.Confidence)
	}

	if len(analysis.DetectedPatterns) > 0 {
		metadata["pattern_count"] = fmt.Sprintf("%d", len(analysis.DetectedPatterns))
	}

	return pluginsdk.Finding{
		Type:       "weak-randomness",
		Message:    message,
		Target:     fmt.Sprintf("entropy://session/%d", session.ID),
		Evidence:   evidence,
		Severity:   analysis.Risk.ToSeverity(),
		DetectedAt: e.now().UTC(),
		Metadata:   metadata,
	}
}

// Helper functions

func formatEvidence(analysis *EntropyAnalysis) string {
	evidence := fmt.Sprintf("Randomness Score: %.2f/100\n", analysis.RandomnessScore)
	evidence += fmt.Sprintf("Shannon Entropy: %.2f bits/char\n", analysis.ShannonEntropy)
	evidence += fmt.Sprintf("Collision Rate: %.4f\n", analysis.CollisionRate)
	evidence += fmt.Sprintf("\nStatistical Tests:\n")
	evidence += fmt.Sprintf("  Chi-Squared: %s (p=%.4f)\n", passedStr(analysis.ChiSquared.Passed), analysis.ChiSquared.PValue)
	evidence += fmt.Sprintf("  Runs Test: %s (p=%.4f)\n", passedStr(analysis.Runs.Passed), analysis.Runs.PValue)
	evidence += fmt.Sprintf("  Serial Correlation: %s (p=%.4f)\n", passedStr(analysis.SerialCorrelation.Passed), analysis.SerialCorrelation.PValue)
	evidence += fmt.Sprintf("  Spectral: %s (p=%.4f)\n", passedStr(analysis.Spectral.Passed), analysis.Spectral.PValue)

	if analysis.DetectedPRNG != nil {
		evidence += fmt.Sprintf("\nDetected PRNG: %s (%.0f%% confidence)\n",
			analysis.DetectedPRNG.Name, analysis.DetectedPRNG.Confidence*100)
	}

	if len(analysis.DetectedPatterns) > 0 {
		evidence += fmt.Sprintf("\nDetected Patterns:\n")
		for _, p := range analysis.DetectedPatterns {
			evidence += fmt.Sprintf("  - %s (%.0f%% confidence): %s\n",
				p.Type, p.Confidence*100, p.Description)
		}
	}

	return evidence
}

func passedStr(passed bool) string {
	if passed {
		return "PASS"
	}
	return "FAIL"
}

// detectRepeatedSubstrings looks for repeated patterns in tokens
func detectRepeatedSubstrings(tokens []string) *Pattern {
	if len(tokens) < 5 {
		return nil
	}

	// Look for common substrings across tokens
	substringCounts := make(map[string]int)

	for _, token := range tokens {
		// Check substrings of length 3-8
		for length := 3; length <= 8 && length <= len(token); length++ {
			for i := 0; i <= len(token)-length; i++ {
				substr := token[i : i+length]
				substringCounts[substr]++
			}
		}
	}

	// Find most common substring
	maxCount := 0
	var mostCommon string
	for substr, count := range substringCounts {
		if count > maxCount {
			maxCount = count
			mostCommon = substr
		}
	}

	// If a substring appears in >30% of tokens, it's suspicious
	threshold := float64(len(tokens)) * 0.3
	if float64(maxCount) > threshold {
		confidence := float64(maxCount) / float64(len(tokens))
		return &Pattern{
			Type:        "repeated_substring",
			Confidence:  confidence,
			Description: fmt.Sprintf("Repeated substring '%s' found in %d tokens", mostCommon, maxCount),
			Evidence:    mostCommon,
		}
	}

	return nil
}

// detectUserIDCorrelation looks for correlation with incrementing IDs
func detectUserIDCorrelation(tokens []string) *Pattern {
	if len(tokens) < 5 {
		return nil
	}

	// Extract numeric components from tokens
	numericParts := make([]int64, 0)
	for _, token := range tokens {
		if num := extractNumeric(token); num != -1 {
			numericParts = append(numericParts, num)
		}
	}

	if len(numericParts) < 5 {
		return nil
	}

	// Check if they're monotonically increasing (suggesting user ID correlation)
	increasing := 0
	for i := 1; i < len(numericParts); i++ {
		if numericParts[i] > numericParts[i-1] {
			increasing++
		}
	}

	ratio := float64(increasing) / float64(len(numericParts)-1)
	if ratio > 0.7 {
		return &Pattern{
			Type:        "user_id_correlation",
			Confidence:  ratio,
			Description: "Token values correlate with incrementing user IDs",
			Evidence:    "Monotonically increasing numeric components detected",
		}
	}

	return nil
}
