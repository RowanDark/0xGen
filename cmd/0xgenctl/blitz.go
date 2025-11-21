package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/RowanDark/0xgen/internal/blitz"
	"github.com/RowanDark/0xgen/internal/findings"
	"github.com/RowanDark/0xgen/internal/templates"
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

	// Template flag
	templateName := fs.String("template", "", "use a predefined scan template")

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

	// AI configuration
	enableAI := fs.Bool("ai", false, "enable all AI features (payloads, classification, findings)")
	aiPayloads := fs.Bool("ai-payloads", false, "use AI to generate contextually relevant payloads")
	aiClassify := fs.Bool("ai-classify", false, "use AI to classify responses")
	aiFindings := fs.Bool("ai-findings", false, "correlate interesting results to 0xGen findings")
	findingsOutput := fs.String("findings-output", "", "write findings to file (JSON Lines format)")

	// Output configuration
	output := fs.String("output", "", "output database path (default: blitz_<timestamp>.db)")
	exportCSV := fs.String("export-csv", "", "export results to CSV file")
	exportJSON := fs.String("export-json", "", "export results to JSON file")
	exportHTML := fs.String("export-html", "", "export results to HTML report")
	quiet := fs.Bool("quiet", false, "suppress progress output")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Load and apply template if specified
	if *templateName != "" {
		mgr, err := templates.NewManager()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error initializing template manager: %v\n", err)
			return 1
		}

		tmpl, err := mgr.Get(*templateName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading template '%s': %v\n", *templateName, err)
			return 1
		}

		// Apply template defaults (only if flag wasn't explicitly set by user)
		applyTemplateDefaults(tmpl, fs, args)

		fmt.Printf("Using template: %s\n", tmpl.Name)
		if tmpl.Description != "" {
			fmt.Printf("  %s\n", tmpl.Description)
		}
		fmt.Println()
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

	// Determine if AI features are enabled
	useAIPayloads := *enableAI || *aiPayloads
	useAIClassify := *enableAI || *aiClassify
	useAIFindings := *enableAI || *aiFindings

	// Load payload generators
	var generators []blitz.PayloadGenerator

	// AI Payload Generation
	if useAIPayloads {
		if !*quiet {
			fmt.Println("🤖 AI Payload Generation enabled - analyzing target context...")
		}

		aiConfig := &blitz.AIPayloadConfig{
			EnableContextAnalysis:  true,
			MaxPayloadsPerCategory: 15,
			EnableAdvancedPayloads: true,
		}

		selector := blitz.NewAIPayloadSelector(aiConfig)
		generators = blitz.CreateAIPayloadGenerator(selector, request)

		if !*quiet {
			fmt.Printf("Generated %d AI-powered payload sets\n\n", len(generators))
		}
	} else {
		// Manual payload specification
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
				fmt.Fprintln(os.Stderr, "Error: no payloads specified (use --payloads, --payload1, etc., or --ai-payloads)")
				return 2
			}
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

	// Setup findings output if enabled
	var findingsFile *os.File
	var findingsMu sync.Mutex
	var findingsCount int

	if useAIFindings && *findingsOutput != "" {
		findingsFile, err = os.Create(*findingsOutput)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating findings file: %v\n", err)
			return 1
		}
		defer findingsFile.Close()

		if !*quiet {
			fmt.Printf("Findings will be written to: %s\n", *findingsOutput)
		}
	}

	// Create engine config
	engineConfig := &blitz.EngineConfig{
		Request:                   request,
		AttackType:                blitz.AttackType(*attackType),
		Generators:                generators,
		Concurrency:               *concurrency,
		RateLimit:                 *rateLimit,
		MaxRetries:                *maxRetries,
		CaptureLimit:              1024,
		Analyzer:                  analyzerConfig,
		Storage:                   storage,
		EnableAIPayloads:          useAIPayloads,
		EnableAIClassification:    useAIClassify,
		EnableFindingsCorrelation: useAIFindings,
	}

	// Add findings callback if enabled
	if useAIFindings {
		engineConfig.FindingsCallback = func(finding *findings.Finding) error {
			findingsMu.Lock()
			defer findingsMu.Unlock()

			findingsCount++

			// Write to file if configured
			if findingsFile != nil {
				encoder := json.NewEncoder(findingsFile)
				encoder.SetEscapeHTML(false)
				if err := encoder.Encode(finding); err != nil {
					return fmt.Errorf("write finding: %w", err)
				}
			}

			// Print summary to stderr
			if !*quiet {
				severity := finding.Severity
				fmt.Fprintf(os.Stderr, "\n[🔍 FINDING] %s - %s (%s)\n", severity, finding.Message, finding.Type)
				if cwe, ok := finding.Metadata["cwe"]; ok {
					fmt.Fprintf(os.Stderr, "    %s | %s\n", cwe, finding.Metadata["owasp"])
				}
			}

			return nil
		}
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
	var total, completed, errorCount, anomalies int64
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
					completed, total, errorCount, anomalies, rate)
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
			errorCount++
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
		if useAIFindings {
			fmt.Printf("Findings (AI):     %d\n", findingsCount)
		}
		fmt.Printf("Avg Duration:      %dms\n", stats.AvgDuration)
		fmt.Printf("Duration Range:    %dms - %dms\n", stats.MinDuration, stats.MaxDuration)

		fmt.Println("\nStatus Code Distribution:")
		for code, count := range stats.UniqueStatuses {
			fmt.Printf("  %d: %d requests\n", code, count)
		}

		// AI feature summary
		if useAIPayloads || useAIClassify || useAIFindings {
			fmt.Println("\n=== AI Features Used ===")
			if useAIPayloads {
				fmt.Println("✓ AI Payload Generation")
			}
			if useAIClassify {
				fmt.Println("✓ AI Response Classification")
			}
			if useAIFindings {
				fmt.Println("✓ Findings Correlation")
			}
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

// applyTemplateDefaults applies template configuration to flag values
func applyTemplateDefaults(tmpl *templates.Template, fs *flag.FlagSet, args []string) {
	cfg := tmpl.Config

	// Track which flags were explicitly set by the user
	explicitFlags := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		explicitFlags[f.Name] = true
	})

	// Helper to set flag value if not explicitly set
	setIfNotExplicit := func(name string, value interface{}) {
		if explicitFlags[name] {
			return // User explicitly set this flag, don't override
		}

		flag := fs.Lookup(name)
		if flag == nil {
			return
		}

		switch v := value.(type) {
		case int:
			flag.Value.Set(fmt.Sprintf("%d", v))
		case float64:
			flag.Value.Set(fmt.Sprintf("%f", v))
		case string:
			flag.Value.Set(v)
		case bool:
			flag.Value.Set(fmt.Sprintf("%t", v))
		}
	}

	// Apply template values
	if cfg.MaxConcurrency != nil {
		setIfNotExplicit("concurrency", *cfg.MaxConcurrency)
	}
	if cfg.RateLimit != nil {
		setIfNotExplicit("rate", *cfg.RateLimit)
	}
	if cfg.AttackType != nil {
		setIfNotExplicit("attack", *cfg.AttackType)
	}
	if cfg.Markers != nil {
		setIfNotExplicit("markers", *cfg.Markers)
	}
	if cfg.EnableAnomaly != nil {
		setIfNotExplicit("anomaly", *cfg.EnableAnomaly)
	}
	if cfg.EnableAI != nil {
		setIfNotExplicit("ai", *cfg.EnableAI)
	}
	if cfg.EnableAIPayloads != nil {
		setIfNotExplicit("ai-payloads", *cfg.EnableAIPayloads)
	}
	if cfg.EnableAIClassify != nil {
		setIfNotExplicit("ai-classify", *cfg.EnableAIClassify)
	}
	if cfg.EnableAIFindings != nil {
		setIfNotExplicit("ai-findings", *cfg.EnableAIFindings)
	}
	if cfg.MaxRetries != nil {
		setIfNotExplicit("retries", *cfg.MaxRetries)
	}
	if len(cfg.Patterns) > 0 {
		setIfNotExplicit("patterns", strings.Join(cfg.Patterns, ","))
	}
}
