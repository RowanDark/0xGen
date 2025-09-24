package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/RowanDark/Glyph/internal/findings"
	"github.com/RowanDark/Glyph/internal/reporter"
)

func runFindings(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "findings subcommand required")
		return 2
	}
	switch args[0] {
	case "validate":
		return runFindingsValidate(args[1:])
	case "migrate":
		return runFindingsMigrate(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown findings subcommand: %s\n", args[0])
		return 2
	}
}

func runFindingsValidate(args []string) int {
	fs := flag.NewFlagSet("findings validate", flag.ContinueOnError)
	input := fs.String("input", reporter.DefaultFindingsPath, "path to findings JSONL input")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	path := strings.TrimSpace(*input)
	if path == "" {
		fmt.Fprintln(os.Stderr, "--input is required")
		return 2
	}
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "input not found: %v\n", err)
			return 2
		}
		fmt.Fprintf(os.Stderr, "open input: %v\n", err)
		return 2
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 256<<10), 4<<20)

	entries := 0
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}
		entries++
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.DisallowUnknownFields()
		var f findings.Finding
		if err := dec.Decode(&f); err != nil {
			fmt.Fprintf(os.Stderr, "line %d: %v\n", lineNo, err)
			return 1
		}
		if err := f.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "line %d: %v\n", lineNo, err)
			return 1
		}
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			fmt.Fprintln(os.Stderr, "line too long; increase buffer")
		} else {
			fmt.Fprintf(os.Stderr, "scan input: %v\n", err)
		}
		return 2
	}
	if _, err := fmt.Fprintf(os.Stdout, "ok (%d entries)\n", entries); err != nil {
		fmt.Fprintf(os.Stderr, "write stdout: %v\n", err)
		return 2
	}
	return 0
}

type legacyFinding struct {
	ID         string            `json:"id"`
	Plugin     string            `json:"plugin"`
	Type       string            `json:"type"`
	Message    string            `json:"message"`
	Target     string            `json:"target"`
	Evidence   string            `json:"evidence"`
	Severity   findings.Severity `json:"severity"`
	DetectedAt string            `json:"detected_at"`
	Metadata   map[string]string `json:"metadata"`
}

func runFindingsMigrate(args []string) int {
	fs := flag.NewFlagSet("findings migrate", flag.ContinueOnError)
	input := fs.String("input", "", "path to v0.1 findings JSONL input")
	output := fs.String("output", "", "path for v0.2 findings JSONL output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	in := strings.TrimSpace(*input)
	out := strings.TrimSpace(*output)
	if in == "" || out == "" {
		fmt.Fprintln(os.Stderr, "--input and --output are required")
		return 2
	}
	file, err := os.Open(in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open input: %v\n", err)
		return 2
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 256<<10), 4<<20)

	var payloads [][]byte
	line := 0
	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}
		var legacy legacyFinding
		if err := json.Unmarshal([]byte(raw), &legacy); err != nil {
			fmt.Fprintf(os.Stderr, "line %d: decode legacy finding: %v\n", line, err)
			return 1
		}
		converted, err := convertLegacyFinding(legacy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "line %d: %v\n", line, err)
			return 1
		}
		if err := converted.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "line %d: invalid finding: %v\n", line, err)
			return 1
		}
		data, err := json.Marshal(converted)
		if err != nil {
			fmt.Fprintf(os.Stderr, "line %d: encode finding: %v\n", line, err)
			return 2
		}
		payloads = append(payloads, append(data, '\n'))
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			fmt.Fprintln(os.Stderr, "line too long; increase buffer")
		} else {
			fmt.Fprintf(os.Stderr, "scan input: %v\n", err)
		}
		return 2
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "create output dir: %v\n", err)
		return 2
	}
	tmp, err := os.Create(out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create output: %v\n", err)
		return 2
	}
	defer func() { _ = tmp.Close() }()
	for _, payload := range payloads {
		if _, err := tmp.Write(payload); err != nil {
			fmt.Fprintf(os.Stderr, "write output: %v\n", err)
			return 2
		}
	}
	if err := tmp.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "flush output: %v\n", err)
		return 2
	}
	if _, err := fmt.Fprintf(os.Stdout, "wrote %d findings\n", len(payloads)); err != nil {
		fmt.Fprintf(os.Stderr, "write stdout: %v\n", err)
		return 2
	}
	return 0
}

func convertLegacyFinding(old legacyFinding) (findings.Finding, error) {
	if strings.TrimSpace(old.DetectedAt) == "" {
		return findings.Finding{}, errors.New("detected_at is required")
	}
	ts, err := time.Parse(time.RFC3339, old.DetectedAt)
	if err != nil {
		return findings.Finding{}, fmt.Errorf("parse detected_at: %w", err)
	}
	meta := old.Metadata
	if len(meta) == 0 {
		meta = nil
	}
	id := strings.ToUpper(strings.TrimSpace(old.ID))
	plugin := strings.TrimSpace(old.Plugin)
	fType := strings.TrimSpace(old.Type)
	message := strings.TrimSpace(old.Message)
	target := strings.TrimSpace(old.Target)
	evidence := strings.TrimSpace(old.Evidence)
	return findings.Finding{
		Version:    findings.SchemaVersion,
		ID:         id,
		Plugin:     plugin,
		Type:       fType,
		Message:    message,
		Target:     target,
		Evidence:   evidence,
		Severity:   old.Severity,
		DetectedAt: findings.NewTimestamp(ts),
		Metadata:   meta,
	}, nil
}
