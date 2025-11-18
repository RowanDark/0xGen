package main

import (
	"math"
	"math/cmplx"
	"sort"
)

// ChiSquaredTest tests for uniform distribution of bits
// Returns p-value (0-1, where <0.01 suggests non-random)
func ChiSquaredTest(tokens []string) TestResult {
	if len(tokens) == 0 {
		return TestResult{
			PValue:      0,
			Passed:      false,
			Confidence:  0,
			Description: "No tokens to analyze",
		}
	}

	// Count character frequencies
	freqMap := make(map[rune]int)
	totalChars := 0

	for _, token := range tokens {
		for _, ch := range token {
			freqMap[ch]++
			totalChars++
		}
	}

	if totalChars == 0 {
		return TestResult{
			PValue:      0,
			Passed:      false,
			Confidence:  0,
			Description: "No characters to analyze",
		}
	}

	// Calculate expected frequency (uniform distribution)
	numCategories := len(freqMap)
	expectedFreq := float64(totalChars) / float64(numCategories)

	// Calculate chi-squared statistic
	chiSquared := 0.0
	for _, observed := range freqMap {
		diff := float64(observed) - expectedFreq
		chiSquared += (diff * diff) / expectedFreq
	}

	// Calculate p-value using chi-squared distribution
	// Degrees of freedom = numCategories - 1
	df := numCategories - 1
	pValue := chiSquaredPValue(chiSquared, df)

	passed := pValue > 0.01
	confidence := 1.0 - pValue

	return TestResult{
		PValue:      pValue,
		Passed:      passed,
		Confidence:  confidence,
		Description: "Tests uniform distribution of characters",
	}
}

// RunsTest (Wald-Wolfowitz) tests for independence (no patterns)
func RunsTest(tokens []string) TestResult {
	if len(tokens) < 2 {
		return TestResult{
			PValue:      0,
			Passed:      false,
			Confidence:  0,
			Description: "Not enough tokens for runs test",
		}
	}

	// Convert tokens to binary representation and count runs
	bitString := tokensToBitString(tokens)
	if len(bitString) == 0 {
		return TestResult{
			PValue:      0,
			Passed:      false,
			Confidence:  0,
			Description: "Cannot convert tokens to bits",
		}
	}

	// Count runs (sequences of same bit)
	runs := 1
	ones := 0
	zeros := 0

	for i, bit := range bitString {
		if bit == 1 {
			ones++
		} else {
			zeros++
		}

		if i > 0 && bitString[i] != bitString[i-1] {
			runs++
		}
	}

	n := len(bitString)
	if ones == 0 || zeros == 0 {
		return TestResult{
			PValue:      0,
			Passed:      false,
			Confidence:  1.0,
			Description: "All bits are the same (no randomness)",
		}
	}

	// Calculate expected runs and standard deviation
	expectedRuns := (2.0*float64(ones)*float64(zeros))/float64(n) + 1
	variance := (2.0*float64(ones)*float64(zeros)*(2.0*float64(ones)*float64(zeros)-float64(n))) /
		(float64(n)*float64(n)*float64(n-1))
	stdDev := math.Sqrt(variance)

	// Calculate z-score
	z := (float64(runs) - expectedRuns) / stdDev

	// Calculate p-value from z-score (two-tailed test)
	pValue := 2.0 * (1.0 - normalCDF(math.Abs(z)))

	passed := pValue > 0.01
	confidence := 1.0 - pValue

	return TestResult{
		PValue:      pValue,
		Passed:      passed,
		Confidence:  confidence,
		Description: "Tests for independence (consecutive runs of same bit)",
	}
}

// SerialCorrelationTest tests if adjacent values are correlated
func SerialCorrelationTest(tokens []string) TestResult {
	if len(tokens) < 2 {
		return TestResult{
			PValue:      0,
			Passed:      false,
			Confidence:  0,
			Description: "Not enough tokens for correlation test",
		}
	}

	// Convert tokens to numeric values (hash-based)
	values := make([]float64, len(tokens))
	for i, token := range tokens {
		values[i] = float64(hashString(token))
	}

	// Calculate serial correlation coefficient
	n := len(values)
	meanX := 0.0
	meanY := 0.0

	for i := 0; i < n-1; i++ {
		meanX += values[i]
		meanY += values[i+1]
	}
	meanX /= float64(n - 1)
	meanY /= float64(n - 1)

	covariance := 0.0
	varianceX := 0.0
	varianceY := 0.0

	for i := 0; i < n-1; i++ {
		dx := values[i] - meanX
		dy := values[i+1] - meanY
		covariance += dx * dy
		varianceX += dx * dx
		varianceY += dy * dy
	}

	if varianceX == 0 || varianceY == 0 {
		return TestResult{
			PValue:      0,
			Passed:      false,
			Confidence:  1.0,
			Description: "No variance in token values",
		}
	}

	correlation := covariance / math.Sqrt(varianceX*varianceY)

	// For random data, correlation should be near 0
	// Convert correlation to p-value (approximate)
	t := correlation * math.Sqrt(float64(n-2)) / math.Sqrt(1-correlation*correlation)
	pValue := 2.0 * (1.0 - normalCDF(math.Abs(t)/math.Sqrt(2.0)))

	passed := pValue > 0.01
	confidence := math.Abs(correlation)

	return TestResult{
		PValue:      pValue,
		Passed:      passed,
		Confidence:  confidence,
		Description: "Tests for serial correlation between adjacent tokens",
	}
}

// SpectralTest uses FFT to detect periodic patterns
func SpectralTest(tokens []string) TestResult {
	if len(tokens) < 4 {
		return TestResult{
			PValue:      0,
			Passed:      false,
			Confidence:  0,
			Description: "Not enough tokens for spectral analysis",
		}
	}

	// Convert tokens to bit string
	bitString := tokensToBitString(tokens)
	if len(bitString) < 4 {
		return TestResult{
			PValue:      0,
			Passed:      false,
			Confidence:  0,
			Description: "Bit string too short for FFT",
		}
	}

	// Convert bits to complex numbers for FFT
	n := len(bitString)
	signal := make([]complex128, n)
	for i, bit := range bitString {
		if bit == 1 {
			signal[i] = complex(1, 0)
		} else {
			signal[i] = complex(-1, 0)
		}
	}

	// Perform FFT
	spectrum := fft(signal)

	// Calculate power spectrum (magnitude squared)
	powerSpectrum := make([]float64, n/2)
	for i := 0; i < n/2; i++ {
		mag := cmplx.Abs(spectrum[i])
		powerSpectrum[i] = mag * mag
	}

	// Find dominant frequency (excluding DC component)
	maxPower := 0.0
	for i := 1; i < len(powerSpectrum); i++ {
		if powerSpectrum[i] > maxPower {
			maxPower = powerSpectrum[i]
		}
	}

	// Calculate average power (excluding DC)
	avgPower := 0.0
	for i := 1; i < len(powerSpectrum); i++ {
		avgPower += powerSpectrum[i]
	}
	avgPower /= float64(len(powerSpectrum) - 1)

	// Calculate peak-to-average ratio
	peakToAvg := maxPower / (avgPower + 1e-10)

	// For random data, peak-to-average should be low (< 3.0 typically)
	// Convert to p-value (empirical threshold)
	pValue := 1.0 / (1.0 + peakToAvg/3.0)
	passed := peakToAvg < 3.0
	confidence := math.Min(peakToAvg/10.0, 1.0)

	return TestResult{
		PValue:      pValue,
		Passed:      passed,
		Confidence:  confidence,
		Description: "Tests for periodic patterns using FFT",
	}
}

// CalculateEntropy calculates Shannon entropy
// Returns bits of entropy per character
func CalculateEntropy(tokens []string) float64 {
	if len(tokens) == 0 {
		return 0
	}

	// Count character frequencies
	freqMap := make(map[rune]int)
	totalChars := 0

	for _, token := range tokens {
		for _, ch := range token {
			freqMap[ch]++
			totalChars++
		}
	}

	if totalChars == 0 {
		return 0
	}

	// Calculate Shannon entropy: H(X) = -Σ(P(x) × log₂(P(x)))
	entropy := 0.0
	for _, count := range freqMap {
		probability := float64(count) / float64(totalChars)
		entropy -= probability * math.Log2(probability)
	}

	return entropy
}

// DetectCollisions detects duplicate tokens (Birthday paradox test)
func DetectCollisions(tokens []string) (float64, TestResult) {
	if len(tokens) < 2 {
		return 0, TestResult{
			PValue:      1.0,
			Passed:      true,
			Confidence:  0,
			Description: "Not enough tokens to detect collisions",
		}
	}

	// Count duplicates
	seen := make(map[string]bool)
	collisions := 0

	for _, token := range tokens {
		if seen[token] {
			collisions++
		} else {
			seen[token] = true
		}
	}

	collisionRate := float64(collisions) / float64(len(tokens))

	// For cryptographically random tokens, collision rate should be near 0
	// Even with birthday paradox, for large keyspaces it's negligible
	passed := collisionRate < 0.01
	pValue := 1.0 - collisionRate
	confidence := collisionRate

	return collisionRate, TestResult{
		PValue:      pValue,
		Passed:      passed,
		Confidence:  confidence,
		Description: "Tests for duplicate tokens (collisions)",
	}
}

// AnalyzeBitDistribution analyzes distribution of bits at each position
func AnalyzeBitDistribution(tokens []string) []float64 {
	if len(tokens) == 0 {
		return nil
	}

	// Convert all tokens to binary and find max length
	binaryTokens := make([][]int, len(tokens))
	maxLen := 0

	for i, token := range tokens {
		binaryTokens[i] = stringToBits(token)
		if len(binaryTokens[i]) > maxLen {
			maxLen = len(binaryTokens[i])
		}
	}

	if maxLen == 0 {
		return nil
	}

	// Count 1s at each bit position
	bitCounts := make([]int, maxLen)
	totalCounts := make([]int, maxLen)

	for _, binary := range binaryTokens {
		for i := 0; i < len(binary) && i < maxLen; i++ {
			if binary[i] == 1 {
				bitCounts[i]++
			}
			totalCounts[i]++
		}
	}

	// Calculate bias percentage at each position
	// Ideal: 50% 1s, 50% 0s → bias = 0
	// All 1s or all 0s → bias = 0.5
	biases := make([]float64, maxLen)
	for i := 0; i < maxLen; i++ {
		if totalCounts[i] > 0 {
			ratio := float64(bitCounts[i]) / float64(totalCounts[i])
			// Bias is distance from 0.5 (ideal)
			biases[i] = math.Abs(ratio - 0.5)
		}
	}

	return biases
}

// Helper functions

func tokensToBitString(tokens []string) []int {
	var bits []int
	for _, token := range tokens {
		bits = append(bits, stringToBits(token)...)
	}
	return bits
}

func stringToBits(s string) []int {
	var bits []int
	for _, ch := range s {
		// Convert each character to 8 bits
		for i := 7; i >= 0; i-- {
			if (ch>>uint(i))&1 == 1 {
				bits = append(bits, 1)
			} else {
				bits = append(bits, 0)
			}
		}
	}
	return bits
}

func hashString(s string) uint32 {
	// Simple FNV-1a hash
	hash := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		hash ^= uint32(s[i])
		hash *= 16777619
	}
	return hash
}

// chiSquaredPValue approximates p-value for chi-squared test
func chiSquaredPValue(chiSquared float64, df int) float64 {
	// Simplified approximation using gamma function
	// For production, use a proper statistical library
	if df <= 0 {
		return 0
	}

	// Use normal approximation for large df
	if df > 30 {
		mean := float64(df)
		stdDev := math.Sqrt(2.0 * float64(df))
		z := (chiSquared - mean) / stdDev
		return 1.0 - normalCDF(z)
	}

	// Rough approximation for small df
	// This is not statistically rigorous but provides a reasonable estimate
	k := float64(df) / 2.0
	x := chiSquared / 2.0

	// Incomplete gamma function approximation
	pValue := 1.0 - incompleteGamma(k, x)

	return math.Max(0, math.Min(1, pValue))
}

// normalCDF calculates cumulative distribution function for standard normal
func normalCDF(x float64) float64 {
	// Approximation using error function
	return 0.5 * (1.0 + math.Erf(x/math.Sqrt2))
}

// incompleteGamma approximates the incomplete gamma function
func incompleteGamma(a, x float64) float64 {
	if x <= 0 {
		return 0
	}
	if a <= 0 {
		return 1
	}

	// Series approximation
	sum := 1.0 / a
	term := 1.0 / a
	for i := 1; i < 100; i++ {
		term *= x / (a + float64(i))
		sum += term
		if term < 1e-10 {
			break
		}
	}

	return sum * math.Exp(-x) * math.Pow(x, a) / gamma(a)
}

// gamma approximates the gamma function
func gamma(x float64) float64 {
	// Stirling's approximation
	if x < 1 {
		return gamma(x+1) / x
	}
	return math.Sqrt(2*math.Pi/x) * math.Pow(x/math.E, x)
}

// fft performs Fast Fourier Transform (Cooley-Tukey algorithm)
func fft(x []complex128) []complex128 {
	n := len(x)
	if n <= 1 {
		return x
	}

	// Pad to power of 2
	n2 := 1
	for n2 < n {
		n2 <<= 1
	}
	if n2 != n {
		padded := make([]complex128, n2)
		copy(padded, x)
		x = padded
		n = n2
	}

	// Recursive FFT
	if n == 1 {
		return x
	}

	// Divide
	even := make([]complex128, n/2)
	odd := make([]complex128, n/2)
	for i := 0; i < n/2; i++ {
		even[i] = x[2*i]
		odd[i] = x[2*i+1]
	}

	// Conquer
	even = fft(even)
	odd = fft(odd)

	// Combine
	result := make([]complex128, n)
	for i := 0; i < n/2; i++ {
		theta := -2 * math.Pi * float64(i) / float64(n)
		w := complex(math.Cos(theta), math.Sin(theta))
		t := w * odd[i]
		result[i] = even[i] + t
		result[i+n/2] = even[i] - t
	}

	return result
}

// GetCharacterSet extracts unique characters from tokens
func GetCharacterSet(tokens []string) []rune {
	charSet := make(map[rune]bool)
	for _, token := range tokens {
		for _, ch := range token {
			charSet[ch] = true
		}
	}

	chars := make([]rune, 0, len(charSet))
	for ch := range charSet {
		chars = append(chars, ch)
	}

	sort.Slice(chars, func(i, j int) bool {
		return chars[i] < chars[j]
	})

	return chars
}
