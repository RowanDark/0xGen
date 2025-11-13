package blitz

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// WordlistGenerator loads payloads from a file (txt, csv, json).
type WordlistGenerator struct {
	FilePath string
	Column   int // For CSV files, which column to use (0-indexed)
	JSONPath string // For JSON files, path to array (e.g., "data.payloads")
}

func (g *WordlistGenerator) Name() string {
	return fmt.Sprintf("Wordlist:%s", filepath.Base(g.FilePath))
}

func (g *WordlistGenerator) Generate() ([]string, error) {
	ext := strings.ToLower(filepath.Ext(g.FilePath))

	switch ext {
	case ".txt", ".lst":
		return g.loadTextFile()
	case ".csv":
		return g.loadCSVFile()
	case ".json":
		return g.loadJSONFile()
	default:
		// Default to text format
		return g.loadTextFile()
	}
}

func (g *WordlistGenerator) loadTextFile() ([]string, error) {
	file, err := os.Open(g.FilePath)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	var payloads []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r\n")
		if line != "" {
			payloads = append(payloads, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	if len(payloads) == 0 {
		return nil, fmt.Errorf("file contains no payloads")
	}

	return payloads, nil
}

func (g *WordlistGenerator) loadCSVFile() ([]string, error) {
	file, err := os.Open(g.FilePath)
	if err != nil {
		return nil, fmt.Errorf("open CSV: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("read CSV: %w", err)
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("CSV file is empty")
	}

	var payloads []string
	for i, record := range records {
		if g.Column >= len(record) {
			return nil, fmt.Errorf("row %d does not have column %d", i, g.Column)
		}
		value := strings.TrimSpace(record[g.Column])
		if value != "" {
			payloads = append(payloads, value)
		}
	}

	if len(payloads) == 0 {
		return nil, fmt.Errorf("no payloads found in CSV column %d", g.Column)
	}

	return payloads, nil
}

func (g *WordlistGenerator) loadJSONFile() ([]string, error) {
	data, err := os.ReadFile(g.FilePath)
	if err != nil {
		return nil, fmt.Errorf("read JSON: %w", err)
	}

	var content interface{}
	if err := json.Unmarshal(data, &content); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}

	// If JSONPath is specified, navigate to it
	if g.JSONPath != "" {
		parts := strings.Split(g.JSONPath, ".")
		for _, part := range parts {
			if m, ok := content.(map[string]interface{}); ok {
				content = m[part]
			} else {
				return nil, fmt.Errorf("invalid JSON path: %s", g.JSONPath)
			}
		}
	}

	// Extract array of strings
	switch v := content.(type) {
	case []interface{}:
		var payloads []string
		for _, item := range v {
			if str, ok := item.(string); ok {
				payloads = append(payloads, str)
			} else {
				// Convert to string
				payloads = append(payloads, fmt.Sprint(item))
			}
		}
		if len(payloads) == 0 {
			return nil, fmt.Errorf("JSON contains no string values")
		}
		return payloads, nil
	default:
		return nil, fmt.Errorf("JSON root must be an array")
	}
}

// RangeGenerator generates numeric or character ranges.
type RangeGenerator struct {
	Start interface{} // int or rune
	End   interface{} // int or rune
	Step  int         // Step size (default 1)
}

func (g *RangeGenerator) Name() string {
	return fmt.Sprintf("Range:%v-%v", g.Start, g.End)
}

func (g *RangeGenerator) Generate() ([]string, error) {
	step := g.Step
	if step <= 0 {
		step = 1
	}

	// Numeric range
	if start, ok := g.Start.(int); ok {
		end, ok := g.End.(int)
		if !ok {
			return nil, fmt.Errorf("start and end must be same type")
		}
		if end < start {
			return nil, fmt.Errorf("end must be >= start")
		}

		var payloads []string
		for i := start; i <= end; i += step {
			payloads = append(payloads, strconv.Itoa(i))
		}
		return payloads, nil
	}

	// Character range
	if start, ok := g.Start.(rune); ok {
		end, ok := g.End.(rune)
		if !ok {
			return nil, fmt.Errorf("start and end must be same type")
		}
		if end < start {
			return nil, fmt.Errorf("end must be >= start")
		}

		var payloads []string
		for r := start; r <= end; r += rune(step) {
			payloads = append(payloads, string(r))
		}
		return payloads, nil
	}

	return nil, fmt.Errorf("unsupported range type")
}

// ParseRange creates a RangeGenerator from a string specification.
// Examples: "1-100", "a-z", "A-Z", "0-255"
func ParseRange(spec string) (*RangeGenerator, error) {
	spec = strings.TrimSpace(spec)
	parts := strings.Split(spec, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("range must be in format 'start-end'")
	}

	start := strings.TrimSpace(parts[0])
	end := strings.TrimSpace(parts[1])

	// Try numeric range first
	if startNum, err := strconv.Atoi(start); err == nil {
		endNum, err := strconv.Atoi(end)
		if err != nil {
			return nil, fmt.Errorf("inconsistent range types")
		}
		return &RangeGenerator{Start: startNum, End: endNum, Step: 1}, nil
	}

	// Try character range
	if len(start) == 1 && len(end) == 1 {
		return &RangeGenerator{
			Start: rune(start[0]),
			End:   rune(end[0]),
			Step:  1,
		}, nil
	}

	return nil, fmt.Errorf("invalid range format")
}

// RegexGenerator generates payloads matching a regex pattern.
// Note: This is a simplified implementation. Full regex generation is complex.
type RegexGenerator struct {
	Pattern string
	Limit   int // Maximum number of payloads to generate
}

func (g *RegexGenerator) Name() string {
	return fmt.Sprintf("Regex:%s", g.Pattern)
}

func (g *RegexGenerator) Generate() ([]string, error) {
	// This is a basic implementation that handles simple patterns.
	// For production, consider using a library like github.com/lucasjones/reggen

	if g.Limit <= 0 {
		g.Limit = 100 // Default limit
	}

	var payloads []string

	// Handle character classes
	if matched, _ := regexp.MatchString(`^\[.*\]\+?$`, g.Pattern); matched {
		payloads = g.expandCharacterClass()
	} else if matched, _ := regexp.MatchString(`^\(.*\|.*\)$`, g.Pattern); matched {
		// Handle alternation: (opt1|opt2|opt3)
		payloads = g.expandAlternation()
	} else {
		return nil, fmt.Errorf("unsupported regex pattern (use character classes like [a-z] or alternations like (opt1|opt2))")
	}

	if len(payloads) > g.Limit {
		payloads = payloads[:g.Limit]
	}

	if len(payloads) == 0 {
		return nil, fmt.Errorf("regex generated no payloads")
	}

	return payloads, nil
}

func (g *RegexGenerator) expandCharacterClass() []string {
	pattern := strings.Trim(g.Pattern, "[]")
	pattern = strings.TrimSuffix(pattern, "+")

	var payloads []string

	// Handle ranges like a-z, A-Z, 0-9
	parts := strings.Split(pattern, "-")
	if len(parts) == 2 && len(parts[0]) == 1 && len(parts[1]) == 1 {
		start := rune(parts[0][0])
		end := rune(parts[1][0])

		for r := start; r <= end && len(payloads) < g.Limit; r++ {
			payloads = append(payloads, string(r))
		}
	} else {
		// Individual characters
		for _, r := range pattern {
			if unicode.IsLetter(r) || unicode.IsDigit(r) {
				payloads = append(payloads, string(r))
			}
		}
	}

	return payloads
}

func (g *RegexGenerator) expandAlternation() []string {
	pattern := strings.Trim(g.Pattern, "()")
	parts := strings.Split(pattern, "|")

	var payloads []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			payloads = append(payloads, part)
		}
	}

	return payloads
}

// StaticGenerator returns a fixed list of payloads.
type StaticGenerator struct {
	Values []string
	label  string
}

func (g *StaticGenerator) Name() string {
	if g.label != "" {
		return g.label
	}
	return fmt.Sprintf("Static:%d_items", len(g.Values))
}

func (g *StaticGenerator) Generate() ([]string, error) {
	if len(g.Values) == 0 {
		return nil, fmt.Errorf("static generator has no values")
	}
	return g.Values, nil
}

// NewStaticGenerator creates a static generator with a label.
func NewStaticGenerator(label string, values []string) *StaticGenerator {
	return &StaticGenerator{Values: values, label: label}
}

// LoadPayload creates a generator from a specification string.
// Supports: file paths, ranges (1-100, a-z), comma-separated lists.
func LoadPayload(spec string) (PayloadGenerator, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty payload specification")
	}

	// Check if it's a file
	if _, err := os.Stat(spec); err == nil {
		return &WordlistGenerator{FilePath: spec}, nil
	}

	// Check if it's a range
	if strings.Contains(spec, "-") && !strings.Contains(spec, ",") {
		gen, err := ParseRange(spec)
		if err == nil {
			return gen, nil
		}
		// If not a valid range, fall through to other interpretations
	}

	// Check if it's a comma-separated list
	if strings.Contains(spec, ",") {
		parts := strings.Split(spec, ",")
		var values []string
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				values = append(values, trimmed)
			}
		}
		if len(values) > 0 {
			return NewStaticGenerator("List", values), nil
		}
	}

	// Single value
	return NewStaticGenerator("Single", []string{spec}), nil
}

// CombineGenerators merges multiple generators into one static generator.
func CombineGenerators(generators []PayloadGenerator) (PayloadGenerator, error) {
	var allPayloads []string

	for _, gen := range generators {
		payloads, err := gen.Generate()
		if err != nil {
			return nil, fmt.Errorf("generate from %s: %w", gen.Name(), err)
		}
		allPayloads = append(allPayloads, payloads...)
	}

	return NewStaticGenerator("Combined", allPayloads), nil
}
