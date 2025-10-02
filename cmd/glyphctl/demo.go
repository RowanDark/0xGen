package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/RowanDark/Glyph/internal/findings"
	"github.com/RowanDark/Glyph/internal/ranker"
	"github.com/RowanDark/Glyph/internal/reporter"
	"github.com/RowanDark/Glyph/internal/seer"
)

type demoResult struct {
	TargetURL   string
	Findings    []findings.Finding
	FindingsOut string
	RankedOut   string
	ReportOut   string
}

func runDemo(args []string) int {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	outDir := fs.String("out", filepath.Join("out", "demo"), "directory to write demo artifacts")
	keep := fs.Bool("keep", false, "retain existing demo artifacts")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "unexpected argument: %s\n", fs.Arg(0))
		return 2
	}

	if strings.TrimSpace(*outDir) == "" {
		fmt.Fprintln(os.Stderr, "--out must not be empty")
		return 2
	}

	result, err := executeDemo(strings.TrimSpace(*outDir), *keep)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			// Context cancellations stem from shutdown signalling; treat as transient failure.
			fmt.Fprintln(os.Stderr, "demo cancelled")
			return 1
		}
		fmt.Fprintf(os.Stderr, "demo failed: %v\n", err)
		return 1
	}

	fmt.Fprintln(os.Stdout, "Glyph demo completed successfully!")
	fmt.Fprintf(os.Stdout, "Target served at %s\n", result.TargetURL)
	fmt.Fprintf(os.Stdout, "Findings written to %s\n", result.FindingsOut)
	fmt.Fprintf(os.Stdout, "Ranked findings written to %s\n", result.RankedOut)
	fmt.Fprintf(os.Stdout, "Report available at %s\n", fileURLFromPath(result.ReportOut))
	return 0
}

func executeDemo(outDir string, keep bool) (demoResult, error) {
	absOut, err := filepath.Abs(outDir)
	if err != nil {
		return demoResult{}, fmt.Errorf("resolve output directory: %w", err)
	}
	if !keep {
		if err := os.RemoveAll(absOut); err != nil {
			return demoResult{}, fmt.Errorf("reset output directory: %w", err)
		}
	}
	if err := os.MkdirAll(absOut, 0o755); err != nil {
		return demoResult{}, fmt.Errorf("create output directory: %w", err)
	}

	srv, addr, err := startDemoTarget(demoTargetHTML)
	if err != nil {
		return demoResult{}, err
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = srv.Shutdown(shutdownCtx)
		cancel()
	}()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(addr)
	if err != nil {
		return demoResult{}, fmt.Errorf("fetch demo target: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return demoResult{}, fmt.Errorf("read demo response: %w", err)
	}

	base := time.Now().UTC().Truncate(time.Second)
	findingsList := seer.Scan(addr, string(body), seer.Config{Now: func() time.Time { return base }})

	findingsList = append(findingsList, demoShowcaseFinding(addr, base))
	// Ensure deterministic ordering for downstream files by sorting IDs.
	sort.Slice(findingsList, func(i, j int) bool {
		return findingsList[i].ID < findingsList[j].ID
	})

	findingsPath := filepath.Join(absOut, "findings.jsonl")
	rankedPath := filepath.Join(absOut, "ranked.jsonl")
	reportPath := filepath.Join(absOut, "report.html")

	if err := writeFindings(findingsPath, findingsList); err != nil {
		return demoResult{}, err
	}

	ranked := ranker.Rank(findingsList)
	if err := ranker.WriteJSONL(rankedPath, ranked); err != nil {
		return demoResult{}, fmt.Errorf("write ranked findings: %w", err)
	}

	if err := reporter.RenderReport(findingsPath, reportPath, reporter.FormatHTML, reporter.ReportOptions{Now: base}); err != nil {
		return demoResult{}, fmt.Errorf("render report: %w", err)
	}

	if err := writeExcavatorSummary(absOut, addr, resp.Header, len(body), base); err != nil {
		return demoResult{}, err
	}

	return demoResult{
		TargetURL:   addr,
		Findings:    findingsList,
		FindingsOut: findingsPath,
		RankedOut:   rankedPath,
		ReportOut:   reportPath,
	}, nil
}

func startDemoTarget(html string) (*http.Server, string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", fmt.Errorf("start demo listener: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(html))
	})

	server := &http.Server{Handler: mux}
	go func() {
		_ = server.Serve(listener)
	}()

	addr := fmt.Sprintf("http://%s", listener.Addr().String())
	return server, addr, nil
}

func writeFindings(path string, list []findings.Finding) error {
	writer := findings.NewWriter(path)
	for _, entry := range list {
		if err := writer.Write(entry); err != nil {
			return fmt.Errorf("write finding: %w", err)
		}
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("flush findings: %w", err)
	}
	return nil
}

func demoShowcaseFinding(target string, now time.Time) findings.Finding {
	metadata := map[string]string{
		"scope":            "in-scope",
		"poc":              "curl -H 'Authorization: Bearer demo-token' %s/api/health",
		"thumbnail":        sampleThumbnailDataURI,
		"session_token":    "demo-tok-session",
		"glyph.case_note":  "Auto-generated by glyphctl demo",
		"glyph.case_owner": "Glyph Demo",
	}
	metadata["poc"] = fmt.Sprintf(metadata["poc"], target)

	return findings.Finding{
		Version:    findings.SchemaVersion,
		ID:         findings.NewID(),
		Plugin:     "glyphctl",
		Type:       "demo.case.thumbnail",
		Message:    "Captured login preview containing a session token",
		Target:     target + "/login",
		Evidence:   "Screenshot thumbnail available",
		Severity:   findings.SeverityMedium,
		DetectedAt: findings.NewTimestamp(now.Add(-90 * time.Second)),
		Metadata:   metadata,
	}
}

func fileURLFromPath(p string) string {
	if strings.TrimSpace(p) == "" {
		return ""
	}

	normalized := filepath.ToSlash(p)
	if strings.Contains(normalized, "\\") {
		normalized = strings.ReplaceAll(normalized, "\\", "/")
	}

	if strings.HasPrefix(normalized, "//") {
		trimmed := strings.TrimPrefix(normalized, "//")
		trimmed = strings.TrimLeft(trimmed, "/")
		if trimmed == "" {
			return (&url.URL{Scheme: "file", Path: "/"}).String()
		}
		parts := strings.SplitN(trimmed, "/", 2)
		host := parts[0]
		rest := "/"
		if len(parts) == 2 {
			clean := path.Clean("/" + parts[1])
			if clean == "." {
				clean = "/"
			}
			rest = clean
		}
		u := url.URL{Scheme: "file", Host: host, Path: rest}
		return u.String()
	}

	normalized = path.Clean(normalized)
	if !strings.HasPrefix(normalized, "/") {
		normalized = "/" + normalized
	}
	u := url.URL{Scheme: "file", Path: normalized}
	return u.String()
}

func writeExcavatorSummary(outDir, target string, headers http.Header, bodyBytes int, ts time.Time) error {
	record := map[string]any{
		"version":     "1",
		"target":      target,
		"captured_at": ts.Format(time.RFC3339),
		"responses": []map[string]any{{
			"url":          target,
			"status":       200,
			"content_type": headers.Get("Content-Type"),
			"bytes":        bodyBytes,
		}},
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("encode excavator summary: %w", err)
	}
	path := filepath.Join(outDir, "excavator.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write excavator summary: %w", err)
	}
	return nil
}
