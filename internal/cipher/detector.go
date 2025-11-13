package cipher

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"strings"
)

// SmartDetector implements intelligent encoding detection
type SmartDetector struct{}

// NewSmartDetector creates a new smart detector
func NewSmartDetector() *SmartDetector {
	return &SmartDetector{}
}

// Detect attempts to identify the encoding of the input
func (d *SmartDetector) Detect(ctx context.Context, input []byte) ([]DetectionResult, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	results := []DetectionResult{}

	// Run all detectors
	results = append(results, d.detectBase64(input)...)
	results = append(results, d.detectHex(input)...)
	results = append(results, d.detectURL(input)...)
	results = append(results, d.detectHTML(input)...)
	results = append(results, d.detectBinary(input)...)
	results = append(results, d.detectJWT(input)...)
	results = append(results, d.detectGzip(input)...)

	// Sort by confidence (highest first)
	sortResultsByConfidence(results)

	// Filter low confidence results (< 0.3)
	filtered := []DetectionResult{}
	for _, r := range results {
		if r.Confidence >= 0.3 {
			filtered = append(filtered, r)
		}
	}

	return filtered, nil
}

// SupportedEncodings returns a list of encodings this detector can identify
func (d *SmartDetector) SupportedEncodings() []string {
	return []string{
		"base64",
		"base64url",
		"hex",
		"url-encoded",
		"html-entities",
		"binary",
		"jwt",
		"gzip",
	}
}

// detectBase64 checks if input is Base64 encoded
func (d *SmartDetector) detectBase64(input []byte) []DetectionResult {
	results := []DetectionResult{}
	inputStr := strings.TrimSpace(string(input))

	// Check for Base64 pattern
	base64Pattern := regexp.MustCompile(`^[A-Za-z0-9+/]+=*$`)
	base64URLPattern := regexp.MustCompile(`^[A-Za-z0-9_-]+=*$`)

	if base64Pattern.MatchString(inputStr) {
		// Try to decode with standard encoding
		_, err := base64.StdEncoding.DecodeString(inputStr)
		if err == nil {
			confidence := 0.9
			// Adjust confidence based on length (valid Base64 should be multiple of 4 or have padding)
			if len(inputStr)%4 != 0 && !strings.HasSuffix(inputStr, "=") {
				confidence = 0.7
			}

			results = append(results, DetectionResult{
				Encoding:   "base64",
				Confidence: confidence,
				Reasoning:  "Matches Base64 pattern and decodes successfully",
				Operation:  "base64_decode",
			})
		} else {
			// Try with RawStdEncoding (no padding)
			_, err := base64.RawStdEncoding.DecodeString(inputStr)
			if err == nil {
				results = append(results, DetectionResult{
					Encoding:   "base64",
					Confidence: 0.7,
					Reasoning:  "Matches Base64 pattern without padding",
					Operation:  "base64_decode",
				})
			}
		}
	}

	if base64URLPattern.MatchString(inputStr) {
		// Try to decode as URL-safe Base64
		_, err := base64.URLEncoding.DecodeString(inputStr)
		if err == nil {
			results = append(results, DetectionResult{
				Encoding:   "base64url",
				Confidence: 0.85,
				Reasoning:  "Matches URL-safe Base64 pattern",
				Operation:  "base64url_decode",
			})
		}
	}

	return results
}

// detectHex checks if input is hexadecimal
func (d *SmartDetector) detectHex(input []byte) []DetectionResult {
	results := []DetectionResult{}
	inputStr := strings.TrimSpace(string(input))

	// Remove common prefixes
	cleanedInput := inputStr
	hasPrefix := false
	if strings.HasPrefix(inputStr, "0x") {
		cleanedInput = strings.TrimPrefix(inputStr, "0x")
		hasPrefix = true
	}

	// Remove separators
	cleanedInput = strings.ReplaceAll(cleanedInput, " ", "")
	cleanedInput = strings.ReplaceAll(cleanedInput, ":", "")
	cleanedInput = strings.ReplaceAll(cleanedInput, "-", "")

	// Check for hex pattern
	hexPattern := regexp.MustCompile(`^[0-9a-fA-F]+$`)
	if hexPattern.MatchString(cleanedInput) && len(cleanedInput)%2 == 0 {
		_, err := hex.DecodeString(cleanedInput)
		if err == nil {
			confidence := 0.8
			if hasPrefix {
				confidence = 0.95
			}
			// Lower confidence if it's all numbers (could be decimal)
			if regexp.MustCompile(`^[0-9]+$`).MatchString(cleanedInput) {
				confidence *= 0.6
			}

			results = append(results, DetectionResult{
				Encoding:   "hex",
				Confidence: confidence,
				Reasoning:  "Matches hexadecimal pattern",
				Operation:  "hex_decode",
			})
		}
	}

	return results
}

// detectURL checks if input is URL-encoded
func (d *SmartDetector) detectURL(input []byte) []DetectionResult {
	results := []DetectionResult{}
	inputStr := string(input)

	// Check for URL encoding patterns (% followed by two hex digits)
	percentPattern := regexp.MustCompile(`%[0-9A-Fa-f]{2}`)
	matches := percentPattern.FindAllString(inputStr, -1)

	if len(matches) > 0 {
		// Calculate confidence based on number of matches and density
		// Each match is 3 characters, so calculate encoded portion
		encodedChars := float64(len(matches) * 3)
		density := encodedChars / float64(len(inputStr))

		// Base confidence on number of matches and density
		confidence := 0.5 + math.Min(float64(len(matches))*0.1, 0.3) + math.Min(density, 0.2)
		confidence = math.Min(confidence, 0.95)

		results = append(results, DetectionResult{
			Encoding:   "url-encoded",
			Confidence: confidence,
			Reasoning:  fmt.Sprintf("Contains %d URL-encoded sequences", len(matches)),
			Operation:  "url_decode",
		})
	}

	return results
}

// detectHTML checks if input contains HTML entities
func (d *SmartDetector) detectHTML(input []byte) []DetectionResult {
	results := []DetectionResult{}
	inputStr := string(input)

	// Check for HTML entity patterns
	entityPattern := regexp.MustCompile(`&[a-zA-Z]+;|&#[0-9]+;|&#x[0-9a-fA-F]+;`)
	matches := entityPattern.FindAllString(inputStr, -1)

	if len(matches) > 0 {
		confidence := math.Min(0.4+float64(len(matches))*0.1, 0.9)

		results = append(results, DetectionResult{
			Encoding:   "html-entities",
			Confidence: confidence,
			Reasoning:  fmt.Sprintf("Contains %d HTML entities", len(matches)),
			Operation:  "html_decode",
		})
	}

	return results
}

// detectBinary checks if input is binary string
func (d *SmartDetector) detectBinary(input []byte) []DetectionResult {
	results := []DetectionResult{}
	inputStr := strings.TrimSpace(string(input))
	inputStr = strings.ReplaceAll(inputStr, " ", "")

	// Check if it's all 0s and 1s
	binaryPattern := regexp.MustCompile(`^[01]+$`)
	if binaryPattern.MatchString(inputStr) && len(inputStr)%8 == 0 && len(inputStr) >= 8 {
		confidence := 0.85
		// Lower confidence for short strings
		if len(inputStr) < 32 {
			confidence = 0.6
		}

		results = append(results, DetectionResult{
			Encoding:   "binary",
			Confidence: confidence,
			Reasoning:  "String contains only 0s and 1s in 8-bit groups",
			Operation:  "binary_decode",
		})
	}

	return results
}

// detectJWT checks if input is a JWT token
func (d *SmartDetector) detectJWT(input []byte) []DetectionResult {
	results := []DetectionResult{}
	inputStr := strings.TrimSpace(string(input))

	// JWT has 3 parts separated by dots
	parts := strings.Split(inputStr, ".")
	if len(parts) == 3 {
		// Each part should be Base64URL encoded
		allValid := true
		for _, part := range parts {
			if len(part) == 0 {
				allValid = false
				break
			}
			// Check if it looks like Base64URL
			if !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(part) {
				allValid = false
				break
			}
		}

		if allValid {
			results = append(results, DetectionResult{
				Encoding:   "jwt",
				Confidence: 0.95,
				Reasoning:  "Has 3 Base64URL-encoded parts separated by dots (JWT structure)",
				Operation:  "jwt_decode",
			})
		}
	}

	return results
}

// detectGzip checks if input is gzip compressed
func (d *SmartDetector) detectGzip(input []byte) []DetectionResult {
	results := []DetectionResult{}

	// Gzip magic bytes: 0x1f 0x8b
	if len(input) >= 2 && input[0] == 0x1f && input[1] == 0x8b {
		results = append(results, DetectionResult{
			Encoding:   "gzip",
			Confidence: 0.99,
			Reasoning:  "Starts with gzip magic bytes (0x1f 0x8b)",
			Operation:  "gzip_decompress",
		})
	}

	return results
}

// calculateEntropy calculates Shannon entropy of the input
func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	// Count byte frequencies
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	// Calculate entropy
	entropy := 0.0
	dataLen := float64(len(data))
	for _, count := range freq {
		p := float64(count) / dataLen
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// sortResultsByConfidence sorts detection results by confidence (descending)
func sortResultsByConfidence(results []DetectionResult) {
	// Simple bubble sort (fine for small arrays)
	n := len(results)
	for i := 0; i < n-1; i++ {
		for j := 0; j < n-i-1; j++ {
			if results[j].Confidence < results[j+1].Confidence {
				results[j], results[j+1] = results[j+1], results[j]
			}
		}
	}
}

// DecodeAll attempts to decode using all detected encodings
func DecodeAll(ctx context.Context, input []byte) ([]DecodeResult, error) {
	detector := NewSmartDetector()
	detections, err := detector.Detect(ctx, input)
	if err != nil {
		return nil, err
	}

	results := []DecodeResult{}
	for _, detection := range detections {
		op, exists := GetOperation(detection.Operation)
		if !exists {
			continue
		}

		decoded, err := op.Execute(ctx, input, nil)
		if err != nil {
			// Skip operations that fail
			continue
		}

		results = append(results, DecodeResult{
			Detection: detection,
			Decoded:   decoded,
			Success:   true,
		})
	}

	return results, nil
}

// DecodeResult represents the result of a decode attempt
type DecodeResult struct {
	Detection DetectionResult `json:"detection"`
	Decoded   []byte          `json:"decoded"`
	Success   bool            `json:"success"`
	Error     string          `json:"error,omitempty"`
}
