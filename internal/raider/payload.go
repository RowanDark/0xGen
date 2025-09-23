package raider

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// LoadPayloads expands the payload specification into a concrete slice used
// during fuzzing. The specification can reference a file, a numeric range or a
// comma separated word list.
func LoadPayloads(spec string) ([]string, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return nil, fmt.Errorf("payload specification is required")
	}

	if exists(trimmed) {
		return readPayloadFile(trimmed)
	}

	if values, ok := parseNumericRange(trimmed); ok {
		return values, nil
	}

	return parseWordList(trimmed), nil
}

func exists(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	}
	return false
}

func readPayloadFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open payload file: %w", err)
	}
	defer file.Close()

	var values []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r\n")
		if line == "" {
			continue
		}
		values = append(values, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read payload file: %w", err)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("payload file %s contained no values", filepath.Base(path))
	}
	return values, nil
}

func parseNumericRange(input string) ([]string, bool) {
	parts := strings.Split(input, "-")
	if len(parts) != 2 {
		return nil, false
	}
	start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil, false
	}
	end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || end < start {
		return nil, false
	}
	values := make([]string, 0, end-start+1)
	for i := start; i <= end; i++ {
		values = append(values, strconv.Itoa(i))
	}
	return values, true
}

func parseWordList(input string) []string {
	if !strings.Contains(input, ",") {
		return []string{input}
	}
	parts := strings.Split(input, ",")
	values := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		values = append(values, trimmed)
	}
	return values
}
