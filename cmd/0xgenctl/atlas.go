package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/RowanDark/0xgen/internal/atlas"
	"github.com/RowanDark/0xgen/internal/atlas/modules"
	"github.com/RowanDark/0xgen/internal/findings"
	"github.com/RowanDark/0xgen/internal/logging"
)

func runAtlas(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "atlas subcommand required (scan, status, findings, list)")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  0xgenctl atlas scan      - Start active vulnerability scan")
		fmt.Fprintln(os.Stderr, "  0xgenctl atlas status    - Get scan status")
		fmt.Fprintln(os.Stderr, "  0xgenctl atlas findings  - List findings from a scan")
		fmt.Fprintln(os.Stderr, "  0xgenctl atlas list      - List all scans")
		return 2
	}

	switch args[0] {
	case "scan":
		return runAtlasScan(args[1:])
	case "status":
		return runAtlasStatus(args[1:])
	case "findings":
		return runAtlasFindings(args[1:])
	case "list":
		return runAtlasList(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown atlas subcommand: %s\n", args[0])
		return 2
	}
}

func runAtlasScan(args []string) int {
	fs := flag.NewFlagSet("atlas scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	// Target configuration
	url := fs.String("url", "", "target URL to scan (required)")
	urlList := fs.String("url-list", "", "file containing URLs to scan (one per line)")

	// Scan configuration
	depth := fs.Int("depth", 1, "crawl depth (0 = no crawl, 1-5)")
	intensity := fs.Int("intensity", 3, "scan intensity (1-5, 3 = default)")
	thoroughness := fs.Int("thoroughness", 3, "scan thoroughness (1-5, 3 = default)")

	// Module selection
	modules := fs.String("modules", "all", "comma-separated module list (sqli,xss,ssrf,xxe,cmdi,path-traversal,auth) or 'all'")
	excludeModules := fs.String("exclude-modules", "", "comma-separated list of modules to exclude")

	// Performance
	concurrency := fs.Int("concurrency", 10, "max parallel requests")
	rateLimit := fs.Int("rate-limit", 0, "requests per second (0 = unlimited)")
	timeout := fs.Duration("timeout", 30*time.Second, "per-request timeout")

	// OAST
	enableOAST := fs.Bool("oast", false, "enable out-of-band testing")
	oastTimeout := fs.Duration("oast-timeout", 60*time.Second, "wait time for OAST callbacks")

	// Authentication
	authType := fs.String("auth-type", "", "authentication type (basic, bearer, session-cookie)")
	authUser := fs.String("auth-user", "", "authentication username")
	authPass := fs.String("auth-pass", "", "authentication password")
	authToken := fs.String("auth-token", "", "authentication bearer token")
	authCookie := fs.String("auth-cookie", "", "authentication cookie")

	// HTTP options
	followRedirects := fs.Bool("follow-redirects", true, "follow HTTP redirects")
	verifySSL := fs.Bool("verify-ssl", true, "verify SSL certificates")
	userAgent := fs.String("user-agent", "0xgen/1.0 Atlas Scanner", "custom User-Agent header")
	headers := fs.String("headers", "", "custom headers (format: 'Header1: Value1; Header2: Value2')")

	// Output
	output := fs.String("output", "", "write findings to file (JSON Lines format)")
	scanID := fs.String("scan-id", "", "custom scan ID (default: auto-generated)")
	scanName := fs.String("name", "", "scan name for reference")
	quiet := fs.Bool("quiet", false, "suppress progress output")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Validate required flags
	if *url == "" && *urlList == "" {
		fmt.Fprintln(os.Stderr, "Error: either --url or --url-list is required")
		return 2
	}

	if *url != "" && *urlList != "" {
		fmt.Fprintln(os.Stderr, "Error: cannot specify both --url and --url-list")
		return 2
	}

	// Determine target URLs
	var urls []string
	if *url != "" {
		urls = []string{*url}
	} else {
		data, err := os.ReadFile(*urlList)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading URL list: %v\n", err)
			return 1
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				urls = append(urls, line)
			}
		}
	}

	if len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "Error: no URLs to scan")
		return 1
	}

	// Build scan configuration
	scan := &atlas.Scan{
		ID:   generateScanID(*scanID),
		Name: *scanName,
		Target: atlas.Target{
			Type:    atlas.TargetTypeURLList,
			URLs:    urls,
			BaseURL: urls[0],
		},
		Config: atlas.ScanConfig{
			Depth:          *depth,
			Intensity:      *intensity,
			Thoroughness:   *thoroughness,
			MaxConcurrency: *concurrency,
			RateLimit:      *rateLimit,
			Timeout:        *timeout,
			EnableOAST:     *enableOAST,
			OASTTimeout:    *oastTimeout,
			FollowRedirects: *followRedirects,
			VerifySSL:      *verifySSL,
			UserAgent:      *userAgent,
		},
		StartTime: time.Now(),
	}

	// Parse module selection
	if *modules != "all" {
		scan.Config.EnabledModules = strings.Split(*modules, ",")
	}
	if *excludeModules != "" {
		scan.Config.DisabledModules = strings.Split(*excludeModules, ",")
	}

	// Parse authentication
	if *authType != "" {
		scan.Config.AuthConfig = &atlas.AuthConfig{
			Type:     atlas.AuthType(*authType),
			Username: *authUser,
			Password: *authPass,
			Token:    *authToken,
			Cookie:   *authCookie,
		}
	}

	// Parse custom headers
	if *headers != "" {
		scan.Config.CustomHeaders = make(map[string]string)
		for _, header := range strings.Split(*headers, ";") {
			parts := strings.SplitN(strings.TrimSpace(header), ":", 2)
			if len(parts) == 2 {
				scan.Config.CustomHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	// Create logger
	logger := logging.NewJSONLogger(os.Stderr)

	// Create components
	storage := atlas.NewMemoryStorage()
	eventBus := atlas.NewBus()
	oastClient := newStubOASTClient() // Stub implementation

	// Create modules
	modules := []atlas.Module{
		modules.NewSQLiModule(logger, oastClient),
		modules.NewXSSModule(logger, oastClient),
		modules.NewSSRFModule(logger, oastClient),
		modules.NewXXEModule(logger, oastClient),
		modules.NewCMDiModule(logger, oastClient),
		modules.NewPathTraversalModule(logger, oastClient),
		modules.NewAuthModule(logger, oastClient),
	}

	// Create orchestrator
	orchestrator := atlas.NewOrchestrator(modules, storage, oastClient, eventBus, logger)

	// Set up context and signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	go func() {
		<-sigCh
		if !*quiet {
			fmt.Fprintln(os.Stderr, "\nReceived interrupt, stopping scan...")
		}
		cancel()
	}()

	// Start scan
	if !*quiet {
		fmt.Printf("Starting Atlas scan: %s\n", scan.ID)
		fmt.Printf("Target: %d URL(s)\n", len(urls))
		fmt.Printf("Intensity: %d/5\n", *intensity)
		fmt.Printf("Thoroughness: %d/5\n", *thoroughness)
		fmt.Printf("Modules: %s\n", *modules)
		fmt.Println()
	}

	if err := orchestrator.StartScan(ctx, scan); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting scan: %v\n", err)
		return 1
	}

	// Subscribe to events
	events := eventBus.Subscribe(ctx, "findings")

	// Monitor progress
	var findingCount int
	done := make(chan struct{})

	go func() {
		for {
			select {
			case <-ctx.Done():
				close(done)
				return
			case event := <-events:
				if finding, ok := event.Data.(*atlas.Finding); ok {
					findingCount++
					if !*quiet {
						fmt.Printf("[%s] %s: %s\n", finding.Severity, finding.Type, finding.Title)
					}
				}
			}
		}
	}()

	// Wait for scan completion
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			<-done
			if !*quiet {
				fmt.Println("\nScan interrupted")
			}
			return 130
		case <-ticker.C:
			status, err := orchestrator.GetStatus(ctx, scan.ID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error getting status: %v\n", err)
				return 1
			}

			if status.State == atlas.ScanStateCompleted || status.State == atlas.ScanStateFailed {
				<-done

				if !*quiet {
					fmt.Printf("\nScan completed in %v\n", status.Duration)
					fmt.Printf("Findings: %d\n", findingCount)
				}

				// Export findings if requested
				if *output != "" {
					if err := exportFindings(ctx, storage, scan.ID, *output); err != nil {
						fmt.Fprintf(os.Stderr, "Error exporting findings: %v\n", err)
						return 1
					}
					if !*quiet {
						fmt.Printf("Findings written to: %s\n", *output)
					}
				}

				if status.State == atlas.ScanStateFailed {
					return 1
				}
				return 0
			}

			if !*quiet {
				fmt.Printf("Progress: %d/%d (%d%%)\n",
					status.Progress.CompletedTests,
					status.Progress.TotalTests,
					status.Progress.Percentage)
			}
		}
	}
}

func runAtlasStatus(args []string) int {
	fs := flag.NewFlagSet("atlas status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	scanID := fs.String("scan-id", "", "scan ID (required)")
	jsonOutput := fs.Bool("json", false, "output as JSON")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *scanID == "" {
		fmt.Fprintln(os.Stderr, "Error: --scan-id is required")
		return 2
	}

	// TODO: Implement status retrieval from storage
	fmt.Fprintln(os.Stderr, "Status retrieval not yet implemented")
	return 1
}

func runAtlasFindings(args []string) int {
	fs := flag.NewFlagSet("atlas findings", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	scanID := fs.String("scan-id", "", "scan ID (required)")
	severity := fs.String("severity", "", "filter by severity (critical,high,medium,low,info)")
	typeFilter := fs.String("type", "", "filter by vulnerability type")
	output := fs.String("output", "", "write findings to file (JSON Lines format)")
	jsonOutput := fs.Bool("json", false, "output as JSON")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *scanID == "" {
		fmt.Fprintln(os.Stderr, "Error: --scan-id is required")
		return 2
	}

	// TODO: Implement findings retrieval from storage
	fmt.Fprintln(os.Stderr, "Findings retrieval not yet implemented")
	return 1
}

func runAtlasList(args []string) int {
	fs := flag.NewFlagSet("atlas list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	jsonOutput := fs.Bool("json", false, "output as JSON")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	// TODO: Implement scan listing from storage
	fmt.Fprintln(os.Stderr, "Scan listing not yet implemented")
	return 1
}

// Helper functions

func generateScanID(custom string) string {
	if custom != "" {
		return custom
	}
	return fmt.Sprintf("scan-%d", time.Now().Unix())
}

func exportFindings(ctx context.Context, storage atlas.Storage, scanID string, outputPath string) error {
	scan, err := storage.GetScan(ctx, scanID)
	if err != nil {
		return fmt.Errorf("get scan: %w", err)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	for _, atlasFinding := range scan.Findings {
		// Convert Atlas finding to 0xGen finding format
		finding := convertAtlasFinding(atlasFinding)
		if err := encoder.Encode(finding); err != nil {
			return fmt.Errorf("encode finding: %w", err)
		}
	}

	return nil
}

func convertAtlasFinding(af *atlas.Finding) *findings.Finding {
	return &findings.Finding{
		Type:     fmt.Sprintf("atlas.%s", af.Type),
		Message:  af.Title,
		Severity: convertSeverity(af.Severity),
		Metadata: map[string]interface{}{
			"atlas_id":      af.ID,
			"confidence":    string(af.Confidence),
			"url":           af.URL,
			"method":        af.Method,
			"parameter":     af.Parameter,
			"location":      string(af.Location),
			"description":   af.Description,
			"remediation":   af.Remediation,
			"cwe":           af.CWE,
			"cvss":          af.CVSS,
			"payload":       af.Payload,
			"evidence":      af.Evidence,
			"false_positive": af.FalsePositive,
		},
	}
}

func convertSeverity(s atlas.Severity) findings.Severity {
	switch s {
	case atlas.SeverityCritical:
		return findings.SeverityCritical
	case atlas.SeverityHigh:
		return findings.SeverityHigh
	case atlas.SeverityMedium:
		return findings.SeverityMedium
	case atlas.SeverityLow:
		return findings.SeverityLow
	case atlas.SeverityInfo:
		return findings.SeverityInfo
	default:
		return findings.SeverityInfo
	}
}

// Stub OAST client implementation
type stubOASTClient struct{}

func newStubOASTClient() atlas.OASTClient {
	return &stubOASTClient{}
}

func (c *stubOASTClient) GeneratePayload(ctx context.Context, testID string) (string, error) {
	// Return a dummy payload for now
	return fmt.Sprintf("http://oast.example.com/callback/%s", testID), nil
}

func (c *stubOASTClient) CheckInteractions(ctx context.Context, testID string) ([]atlas.OASTInteraction, error) {
	// No interactions for stub
	return nil, nil
}
