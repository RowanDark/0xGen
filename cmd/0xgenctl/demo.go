package main

import (
	"bytes"
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

	"golang.org/x/net/html"

	"github.com/RowanDark/0xgen/internal/findings"
	"github.com/RowanDark/0xgen/internal/ranker"
	"github.com/RowanDark/0xgen/internal/reporter"
	"github.com/RowanDark/0xgen/internal/seer"
)

type demoResult struct {
	TargetURL         string
	Findings          []findings.Finding
	FindingsOut       string
	RankedOut         string
	ReportOut         string
	ExcavatorOut      string
	OutDir            string
	ScanDuration      time.Duration
	InternalLinkCount int
	ExternalLinkCount int
	Showcase          ranker.ScoredFinding
	ShowcaseAvailable bool
}

type demoProgress struct {
	Writer io.Writer
}

func (p demoProgress) Step(prefix, format string, args ...any) {
	if p.Writer == nil {
		return
	}
	message := fmt.Sprintf(format, args...)
	fmt.Fprintf(p.Writer, "%s ▸ %s\n", prefix, message)
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

	progress := demoProgress{Writer: os.Stdout}
	result, err := executeDemo(strings.TrimSpace(*outDir), *keep, progress)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			// Context cancellations stem from shutdown signalling; treat as transient failure.
			fmt.Fprintln(os.Stderr, "demo cancelled")
			return 1
		}
		fmt.Fprintf(os.Stderr, "demo failed: %v\n", err)
		return 1
	}

	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "Glyph demo completed successfully!")
	fmt.Fprintf(os.Stdout, "Target served at %s\n", result.TargetURL)
	if strings.TrimSpace(result.ExcavatorOut) != "" {
		fmt.Fprintf(os.Stdout, "Crawl transcript written to %s\n", result.ExcavatorOut)
	}
	fmt.Fprintf(os.Stdout, "Findings written to %s\n", result.FindingsOut)
	fmt.Fprintf(os.Stdout, "Ranked findings written to %s\n", result.RankedOut)
	fmt.Fprintf(os.Stdout, "Report available at %s\n", fileURLFromPath(result.ReportOut))
	if strings.TrimSpace(result.OutDir) != "" {
		fmt.Fprintf(os.Stdout, "Artifacts directory: %s\n", result.OutDir)
	}
	if result.ShowcaseAvailable {
		fmt.Fprintln(os.Stdout)
		printCasePreview(os.Stdout, result.Showcase)
	}
	return 0
}

func executeDemo(outDir string, keep bool, progress demoProgress) (demoResult, error) {
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
	progress.Step("0xgenctl demo", "Launching static target on %s", addr)
	progress.Step("0xgenctl demo", "Using bundled fixtures so the demo works offline")
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
	internalLinks, externalLinks := discoverLinks(addr, body)

	base := time.Now().UTC().Truncate(time.Second)
	excavatorPath, err := writeExcavatorSummary(absOut, addr, resp.Header, len(body), base, internalLinks, externalLinks)
	if err != nil {
		return demoResult{}, err
	}
	progress.Step("excavator", "Discovered %d internal links and %d external links", internalLinks, externalLinks)
	progress.Step("excavator", "Wrote crawl transcript to %s", excavatorPath)

	scanStart := time.Now()
	findingsList := seer.Scan(addr, string(body), seer.Config{Now: func() time.Time { return base }})
	scanDuration := time.Since(scanStart)

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
	progress.Step("seer", "Evaluated detectors in %s (produced %d findings)", formatDuration(scanDuration), len(findingsList))
	progress.Step("seer", "Persisted findings to %s", findingsPath)

	ranked := ranker.Rank(findingsList)
	if err := ranker.WriteJSONL(rankedPath, ranked); err != nil {
		return demoResult{}, fmt.Errorf("write ranked findings: %w", err)
	}
	progress.Step("ranker", "Loaded %d findings and produced deterministic scores", len(ranked))
	progress.Step("ranker", "Saved ranked output to %s", rankedPath)

	if err := reporter.RenderReport(findingsPath, reportPath, reporter.FormatHTML, reporter.ReportOptions{Now: base}); err != nil {
		return demoResult{}, fmt.Errorf("render report: %w", err)
	}
	progress.Step("scribe", "Generated HTML report with evidence thumbnails")
	progress.Step("scribe", "Report available at %s", fileURLFromPath(reportPath))

	showcase, hasShowcase := selectShowcase(ranked)

	return demoResult{
		TargetURL:         addr,
		Findings:          findingsList,
		FindingsOut:       findingsPath,
		RankedOut:         rankedPath,
		ReportOut:         reportPath,
		ExcavatorOut:      excavatorPath,
		OutDir:            absOut,
		ScanDuration:      scanDuration,
		InternalLinkCount: internalLinks,
		ExternalLinkCount: externalLinks,
		Showcase:          showcase,
		ShowcaseAvailable: hasShowcase,
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
		"glyph.case_note":  "Auto-generated by 0xgenctl demo",
		"glyph.case_owner": "Glyph Demo",
	}
	metadata["poc"] = fmt.Sprintf(metadata["poc"], target)

	return findings.Finding{
		Version:    findings.SchemaVersion,
		ID:         findings.NewID(),
		Plugin:     "0xgenctl",
		Type:       "demo.case.thumbnail",
		Message:    "Captured login preview containing a session token",
		Target:     target + "/login",
		Evidence:   "Screenshot thumbnail available",
		Severity:   findings.SeverityMedium,
		DetectedAt: findings.NewTimestamp(now.Add(-90 * time.Second)),
		Metadata:   metadata,
	}
}

func selectShowcase(ranked []ranker.ScoredFinding) (ranker.ScoredFinding, bool) {
	for idx := range ranked {
		if ranked[idx].Type == "demo.case.thumbnail" {
			return ranked[idx], true
		}
	}
	if len(ranked) == 0 {
		return ranker.ScoredFinding{}, false
	}
	return ranked[0], true
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

func writeExcavatorSummary(outDir, target string, headers http.Header, bodyBytes int, ts time.Time, internalLinks, externalLinks int) (string, error) {
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
		"links": map[string]int{
			"internal": internalLinks,
			"external": externalLinks,
		},
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode excavator summary: %w", err)
	}
	path := filepath.Join(outDir, "excavator.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("write excavator summary: %w", err)
	}
	return path, nil
}

func discoverLinks(base string, markup []byte) (internal, external int) {
	baseURL, err := url.Parse(base)
	if err != nil {
		return 0, 0
	}
	tokenizer := html.NewTokenizer(bytes.NewReader(markup))
	seen := make(map[string]struct{})
	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}
		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			t := tokenizer.Token()
			if strings.EqualFold(t.Data, "a") {
				for _, attr := range t.Attr {
					if strings.EqualFold(attr.Key, "href") {
						href := strings.TrimSpace(attr.Val)
						lhref := strings.ToLower(href)
						if href == "" ||
							strings.HasPrefix(lhref, "javascript:") ||
							strings.HasPrefix(lhref, "data:") ||
							strings.HasPrefix(lhref, "vbscript:") {
							continue
						}
						if strings.HasPrefix(lhref, "mailto:") {
							continue
						}
						parsed, err := baseURL.Parse(href)
						if err != nil {
							continue
						}
						normalized := parsed.Scheme + "://" + parsed.Host + parsed.Path
						if _, ok := seen[normalized]; ok {
							continue
						}
						seen[normalized] = struct{}{}
						if parsed.Hostname() == baseURL.Hostname() || parsed.Host == "" {
							internal++
						} else {
							external++
						}
					}
				}
			}
		}
	}
	return internal, external
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	if d < time.Microsecond {
		return "<1µs"
	}
	if d < time.Millisecond {
		rounded := d.Round(10 * time.Microsecond)
		if rounded <= 0 {
			return "<1ms"
		}
		return rounded.String()
	}
	if d < time.Second {
		rounded := d.Round(100 * time.Microsecond)
		if rounded <= 0 {
			return "<1ms"
		}
		return rounded.String()
	}
	rounded := d.Round(10 * time.Millisecond)
	if rounded <= 0 {
		return "0s"
	}
	return rounded.String()
}

func printCasePreview(w io.Writer, finding ranker.ScoredFinding) {
	if w == nil {
		return
	}
	fmt.Fprintln(w, "Case preview")
	severity := severityLabel(finding.Severity)
	fmt.Fprintf(w, "  • %s (%s)\n", strings.TrimSpace(finding.Message), severity)
	fmt.Fprintf(w, "    Target: %s\n", strings.TrimSpace(finding.Target))
	detected := finding.DetectedAt.Time().Format(time.RFC3339)
	fmt.Fprintf(w, "    Detected: %s\n", detected)
	if owner := strings.TrimSpace(finding.Metadata["glyph.case_owner"]); owner != "" {
		fmt.Fprintf(w, "    Case owner: %s\n", owner)
	}
	if note := strings.TrimSpace(finding.Metadata["glyph.case_note"]); note != "" {
		fmt.Fprintf(w, "    Note: %s\n", note)
	}
	if poc := strings.TrimSpace(finding.Metadata["poc"]); poc != "" {
		fmt.Fprintf(w, "    Proof of concept: %s\n", poc)
	}
	if token := strings.TrimSpace(finding.Metadata["session_token"]); token != "" {
		fmt.Fprintf(w, "    Session token: %s\n", token)
	}
	if finding.Score > 0 {
		primary := "secondary"
		if finding.Primary {
			primary = "primary"
		}
		exposure := strings.TrimSpace(finding.ExposureHint)
		if exposure == "" {
			exposure = "n/a"
		}
		fmt.Fprintf(w, "    Score: %.0f (%s, exposure: %s)\n", finding.Score, primary, exposure)
	}
	if thumb := strings.TrimSpace(finding.Metadata["thumbnail"]); thumb != "" {
		fmt.Fprintln(w, "    Thumbnail: embedded data URI ready for copy/paste")
	}
}

func severityLabel(sev findings.Severity) string {
	switch sev {
	case findings.SeverityCritical:
		return "Critical"
	case findings.SeverityHigh:
		return "High"
	case findings.SeverityMedium:
		return "Medium"
	case findings.SeverityLow:
		return "Low"
	case findings.SeverityInfo:
		return "Informational"
	default:
		return strings.TrimSpace(string(sev))
	}
}
