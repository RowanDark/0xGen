package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/RowanDark/0xgen/internal/blitz"
)

func runBlitz(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "blitz subcommand required (run, export)")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  0xgenctl blitz run     - Run fuzzing campaign")
		fmt.Fprintln(os.Stderr, "  0xgenctl blitz export  - Export results from database")
		return 2
	}

	switch args[0] {
	case "run":
		return runBlitzRun(args[1:])
	case "export":
		return runBlitzExport(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown blitz subcommand: %s\n", args[0])
		return 2
	}
}

func runBlitzRun(args []string) int {
	fs := flag.NewFlagSet("blitz run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	// Required flags
	reqPath := fs.String("req", "", "path to HTTP request template (required)")

	// Attack configuration
	attackType := fs.String("attack", "sniper", "attack type: sniper, battering-ram, pitchfork, cluster-bomb")
	markers := fs.String("markers", "{{}}", "marker delimiters for insertion points (e.g., '{{}}' or '§§')")

	// Payload configuration
	payloads := fs.String("payloads", "", "payload specification (file, range, or comma-separated)")
	payload1 := fs.String("payload1", "", "payload for position 1 (pitchfork/cluster-bomb)")
	payload2 := fs.String("payload2", "", "payload for position 2 (pitchfork/cluster-bomb)")
	payload3 := fs.String("payload3", "", "payload for position 3 (pitchfork/cluster-bomb)")

	// Engine configuration
	concurrency := fs.Int("concurrency", 10, "number of concurrent workers")
	rateLimit := fs.Float64("rate", 0, "requests per second (0 = unlimited)")
	maxRetries := fs.Int("retries", 2, "maximum retries for failed requests")

	// Analysis configuration
	patterns := fs.String("patterns", "", "comma-separated regex patterns to search in responses")
	enableAnomaly := fs.Bool("anomaly", true, "enable anomaly detection")

	// Output configuration
	output := fs.String("output", "", "output database path (default: blitz_<timestamp>.db)")
	exportCSV := fs.String("export-csv", "", "export results to CSV file")
	exportJSON := fs.String("export-json", "", "export results to JSON file")
	exportHTML := fs.String("export-html", "", "export results to HTML report")
	quiet := fs.Bool("quiet", false, "suppress progress output")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Validate required flags
	if *reqPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --req is required")
		return 2
	}

	// Read request template
	reqData, err := os.ReadFile(*reqPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading request template: %v\n", err)
		return 1
	}

	// Parse markers
	markerSpec, err := blitz.ParseMarkers(*markers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing markers: %v\n", err)
		return 1
	}

	// Parse request template
	request, err := blitz.ParseRequest(string(reqData), markerSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing request template: %v\n", err)
		return 1
	}

	if len(request.Positions) == 0 {
		fmt.Fprintln(os.Stderr, "Error: no insertion points found in request template")
		return 1
	}

	if !*quiet {
		fmt.Printf("Found %d insertion point(s)\n", len(request.Positions))
		for _, pos := range request.Positions {
			fmt.Printf("  [%d] %s\n", pos.Index, pos.Name)
		}
		fmt.Println()
	}

	// Load payload generators
	var generators []blitz.PayloadGenerator

	// Determine payload strategy
	if *payloads != "" {
		// Single payload set for all positions
		gen, err := blitz.LoadPayload(*payloads)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading payloads: %v\n", err)
			return 1
		}
		generators = append(generators, gen)
	} else {
		// Multiple payload sets (for pitchfork/cluster-bomb)
		payloadSpecs := []string{*payload1, *payload2, *payload3}
		for _, spec := range payloadSpecs {
			if spec != "" {
				gen, err := blitz.LoadPayload(spec)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error loading payload: %v\n", err)
					return 1
				}
				generators = append(generators, gen)
			}
		}

		if len(generators) == 0 {
			fmt.Fprintln(os.Stderr, "Error: no payloads specified (use --payloads or --payload1, --payload2, etc.)")
			return 2
		}
	}

	// Parse patterns
	var patternList []*regexp.Regexp
	if *patterns != "" {
		patternStrs := strings.Split(*patterns, ",")
		for _, p := range patternStrs {
			p = strings.TrimSpace(p)
			if p != "" {
				patternList = append(patternList, regexp.MustCompile(p))
			}
		}
	}

	// Create analyzer config
	analyzerConfig := &blitz.AnalyzerConfig{
		Patterns:                     patternList,
		EnableAnomalyDetection:       *enableAnomaly,
		StatusCodeDeviationThreshold: 0,
		ContentLengthDeviationPct:    0.2,
		ResponseTimeDeviationFactor:  2.0,
	}

	// Create storage
	dbPath := *output
	if dbPath == "" {
		dbPath = fmt.Sprintf("blitz_%s.db", time.Now().Format("20060102_150405"))
	}

	storage, err := blitz.NewSQLiteStorage(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating storage: %v\n", err)
		return 1
	}
	defer storage.Close()

	if !*quiet {
		fmt.Printf("Results will be stored in: %s\n\n", dbPath)
	}

	// Create engine config
	engineConfig := &blitz.EngineConfig{
		Request:      request,
		AttackType:   blitz.AttackType(*attackType),
		Generators:   generators,
		Concurrency:  *concurrency,
		RateLimit:    *rateLimit,
		MaxRetries:   *maxRetries,
		CaptureLimit: 1024,
		Analyzer:     analyzerConfig,
		Storage:      storage,
	}

	// Create engine
	engine, err := blitz.NewEngine(engineConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating engine: %v\n", err)
		return 1
	}

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\nReceived interrupt, stopping...")
		cancel()
	}()

	// Progress tracking
	var mu sync.Mutex
	var total, completed, errors, anomalies int64
	startTime := time.Now()

	// Progress ticker
	var ticker *time.Ticker
	if !*quiet {
		ticker = time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		go func() {
			for range ticker.C {
				mu.Lock()
				elapsed := time.Since(startTime)
				rate := float64(completed) / elapsed.Seconds()
				fmt.Printf("\rProgress: %d/%d completed | %d errors | %d anomalies | %.1f req/s",
					completed, total, errors, anomalies, rate)
				mu.Unlock()
			}
		}()
	}

	// Run engine
	err = engine.Run(ctx, func(result *blitz.FuzzResult) error {
		mu.Lock()
		defer mu.Unlock()

		completed++
		if result.Error != "" {
			errors++
		}
		if result.Anomaly != nil && result.Anomaly.IsInteresting {
			anomalies++
			if !*quiet {
				fmt.Printf("\n[!] Anomaly detected: Status=%d Duration=%dms Payload=%s\n",
					result.StatusCode, result.Duration, truncate(result.Payload, 50))
			}
		}

		return nil
	})

	if ticker != nil {
		ticker.Stop()
	}

	if !*quiet {
		fmt.Println() // New line after progress
	}

	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "Fuzzing error: %v\n", err)
		return 1
	}

	// Get final stats
	stats, err := storage.GetStats()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting stats: %v\n", err)
	} else if !*quiet {
		fmt.Println("\n=== Fuzzing Summary ===")
		fmt.Printf("Total Requests:    %d\n", stats.TotalRequests)
		fmt.Printf("Successful:        %d\n", stats.SuccessfulReqs)
		fmt.Printf("Failed:            %d\n", stats.FailedReqs)
		fmt.Printf("Anomalies:         %d\n", stats.AnomalyCount)
		fmt.Printf("Pattern Matches:   %d\n", stats.PatternMatchCount)
		fmt.Printf("Avg Duration:      %dms\n", stats.AvgDuration)
		fmt.Printf("Duration Range:    %dms - %dms\n", stats.MinDuration, stats.MaxDuration)

		fmt.Println("\nStatus Code Distribution:")
		for code, count := range stats.UniqueStatuses {
			fmt.Printf("  %d: %d requests\n", code, count)
		}
	}

	// Export if requested
	if *exportCSV != "" {
		if err := exportResults(storage, *exportCSV, "csv", stats); err != nil {
			fmt.Fprintf(os.Stderr, "Error exporting CSV: %v\n", err)
		} else if !*quiet {
			fmt.Printf("\nExported to CSV: %s\n", *exportCSV)
		}
	}

	if *exportJSON != "" {
		if err := exportResults(storage, *exportJSON, "json", stats); err != nil {
			fmt.Fprintf(os.Stderr, "Error exporting JSON: %v\n", err)
		} else if !*quiet {
			fmt.Printf("Exported to JSON: %s\n", *exportJSON)
		}
	}

	if *exportHTML != "" {
		if err := exportResults(storage, *exportHTML, "html", stats); err != nil {
			fmt.Fprintf(os.Stderr, "Error exporting HTML: %v\n", err)
		} else if !*quiet {
			fmt.Printf("Exported to HTML: %s\n", *exportHTML)
		}
	}

	return 0
}

func runBlitzExport(args []string) int {
	fs := flag.NewFlagSet("blitz export", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	dbPath := fs.String("db", "", "path to results database (required)")
	format := fs.String("format", "html", "export format: csv, json, html")
	output := fs.String("output", "", "output file path")
	anomaliesOnly := fs.Bool("anomalies-only", false, "export only interesting results")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *dbPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --db is required")
		return 2
	}

	if *output == "" {
		ext := *format
		if ext == "html" {
			ext = "html"
		}
		*output = fmt.Sprintf("blitz_export.%s", ext)
	}

	// Open storage
	storage, err := blitz.NewSQLiteStorage(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening database: %v\n", err)
		return 1
	}
	defer storage.Close()

	// Get stats
	stats, err := storage.GetStats()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting stats: %v\n", err)
		return 1
	}

	// Export
	if err := exportResults(storage, *output, *format, stats); err != nil {
		fmt.Fprintf(os.Stderr, "Error exporting: %v\n", err)
		return 1
	}

	fmt.Printf("Exported %d results to: %s\n", stats.TotalRequests, *output)
	return 0
}

func exportResults(storage *blitz.SQLiteStorage, path, format string, stats *blitz.Stats) error {
	// Query all results
	results, err := storage.Query(blitz.QueryFilters{Limit: 100000})
	if err != nil {
		return fmt.Errorf("query results: %w", err)
	}

	var exporter blitz.Exporter

	switch format {
	case "csv":
		exporter = &blitz.CSVExporter{}
	case "json":
		exporter = &blitz.JSONExporter{Pretty: true}
	case "html":
		exporter = &blitz.HTMLExporter{
			Title: fmt.Sprintf("Blitz Fuzzing Report - %s", time.Now().Format("2006-01-02")),
			Stats: stats,
		}
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}

	return exporter.Export(results, path)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen < 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
