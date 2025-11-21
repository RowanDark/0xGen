package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/RowanDark/0xgen/internal/comparison"
)

func runBaseline(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "baseline subcommand required (set, get, list, delete)")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  0xgenctl baseline set    - Set a baseline scan")
		fmt.Fprintln(os.Stderr, "  0xgenctl baseline get    - Get baseline for a target")
		fmt.Fprintln(os.Stderr, "  0xgenctl baseline list   - List all baselines")
		fmt.Fprintln(os.Stderr, "  0xgenctl baseline delete - Delete a baseline")
		return 2
	}

	switch args[0] {
	case "set":
		return runBaselineSet(args[1:])
	case "get":
		return runBaselineGet(args[1:])
	case "list":
		return runBaselineList(args[1:])
	case "delete":
		return runBaselineDelete(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown baseline subcommand: %s\n", args[0])
		return 2
	}
}

func runBaselineSet(args []string) int {
	fs := flag.NewFlagSet("baseline set", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	scanID := fs.String("scan-id", "", "scan ID or findings file to use as baseline (required)")
	target := fs.String("target", "", "target URL or identifier (required)")
	name := fs.String("name", "", "baseline name (optional)")
	setBy := fs.String("set-by", "", "who set the baseline (optional)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *scanID == "" {
		fmt.Fprintln(os.Stderr, "Error: --scan-id is required")
		return 2
	}

	if *target == "" {
		fmt.Fprintln(os.Stderr, "Error: --target is required")
		return 2
	}

	// Load scan to count findings
	summary, findingsList, err := loadFindings(*scanID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading scan: %v\n", err)
		return 1
	}

	// Initialize baseline manager
	mgr, err := comparison.NewBaselineManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing baseline manager: %v\n", err)
		return 1
	}

	// Set baseline
	baselineName := *name
	if baselineName == "" {
		baselineName = fmt.Sprintf("Baseline for %s", *target)
	}

	if err := mgr.SetBaseline(*scanID, *target, baselineName, *setBy, len(findingsList)); err != nil {
		fmt.Fprintf(os.Stderr, "Error setting baseline: %v\n", err)
		return 1
	}

	fmt.Printf("✓ Baseline set for target: %s\n", *target)
	fmt.Printf("  Scan ID: %s\n", *scanID)
	fmt.Printf("  Findings: %d\n", summary.TotalFindings)

	return 0
}

func runBaselineGet(args []string) int {
	fs := flag.NewFlagSet("baseline get", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	target := fs.String("target", "", "target URL or identifier (required)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *target == "" {
		fmt.Fprintln(os.Stderr, "Error: --target is required")
		return 2
	}

	// Initialize baseline manager
	mgr, err := comparison.NewBaselineManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing baseline manager: %v\n", err)
		return 1
	}

	// Get baseline
	baseline, err := mgr.GetBaseline(*target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	// Display baseline info
	fmt.Printf("Baseline for: %s\n", baseline.Target)
	fmt.Printf("  Scan ID: %s\n", baseline.ScanID)
	fmt.Printf("  Name: %s\n", baseline.Name)
	fmt.Printf("  Findings: %d\n", baseline.Findings)
	fmt.Printf("  Set At: %s\n", baseline.SetAt.Format("2006-01-02 15:04:05"))
	if baseline.SetBy != "" {
		fmt.Printf("  Set By: %s\n", baseline.SetBy)
	}

	return 0
}

func runBaselineList(args []string) int {
	// Initialize baseline manager
	mgr, err := comparison.NewBaselineManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing baseline manager: %v\n", err)
		return 1
	}

	// List baselines
	baselines, err := mgr.ListBaselines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing baselines: %v\n", err)
		return 1
	}

	if len(baselines) == 0 {
		fmt.Println("No baselines set")
		return 0
	}

	fmt.Print(comparison.FormatBaselineList(baselines))

	return 0
}

func runBaselineDelete(args []string) int {
	fs := flag.NewFlagSet("baseline delete", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	target := fs.String("target", "", "target URL or identifier (required)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *target == "" {
		fmt.Fprintln(os.Stderr, "Error: --target is required")
		return 2
	}

	// Initialize baseline manager
	mgr, err := comparison.NewBaselineManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing baseline manager: %v\n", err)
		return 1
	}

	// Delete baseline
	if err := mgr.DeleteBaseline(*target); err != nil {
		fmt.Fprintf(os.Stderr, "Error deleting baseline: %v\n", err)
		return 1
	}

	fmt.Printf("✓ Baseline deleted for target: %s\n", *target)

	return 0
}
