package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/RowanDark/Glyph/internal/perf"
)

func main() {
	var (
		baselinePath  string
		outputPath    string
		threshold     float64
		iterations    int
		reportVersion string
		historyPath   string
		historyMDPath string
	)

	flag.StringVar(&baselinePath, "baseline", "", "optional baseline report for regression detection")
	flag.StringVar(&outputPath, "output", "", "where to write the current metrics report (JSON)")
	flag.Float64Var(&threshold, "threshold", 0.10, "maximum allowed regression expressed as a ratio (0.10 = 10%)")
	flag.IntVar(&iterations, "iterations", 1, "number of times to run each workload and average the results")
	flag.StringVar(&reportVersion, "report-version", runtime.Version(), "version label embedded in the metrics report")
	flag.StringVar(&historyPath, "history", "", "optional JSONL file that accumulates metrics over time")
	flag.StringVar(&historyMDPath, "history-markdown", "", "optional Markdown summary generated from the history data")
	flag.Parse()

	if threshold <= 0 || threshold >= 1 {
		log.Fatalf("threshold must be between 0 and 1 (got %.3f)", threshold)
	}
	if iterations <= 0 {
		log.Fatalf("iterations must be positive (got %d)", iterations)
	}

	ctx := context.Background()
	results := make([]perf.BusWorkloadMetrics, 0, len(perf.DefaultBusWorkloads))

	for _, cfg := range perf.DefaultBusWorkloads {
		samples := make([]perf.BusWorkloadMetrics, 0, iterations)
		for i := 0; i < iterations; i++ {
			res, err := perf.RunBusWorkload(ctx, cfg)
			if err != nil {
				log.Fatalf("workload %s run %d: %v", cfg.Name, i+1, err)
			}
			samples = append(samples, res)
		}
		results = append(results, averageMetrics(samples))
	}

	report := perf.Report{
		Version:   reportVersion,
		Timestamp: time.Now().UTC(),
		GitRef:    gitRef(),
		Workloads: results,
	}

	if outputPath != "" {
		if err := perf.SaveReport(outputPath, report); err != nil {
			log.Fatalf("save report: %v", err)
		}
		fmt.Fprintf(os.Stdout, "Saved metrics report to %s\n", outputPath)
	}

	if historyMDPath != "" && historyPath == "" {
		log.Fatalf("--history-markdown requires --history to be set")
	}

	if historyPath != "" {
		history, err := perf.UpdateHistory(historyPath, report)
		if err != nil {
			log.Fatalf("update history: %v", err)
		}
		fmt.Fprintf(os.Stdout, "Appended metrics to history %s\n", historyPath)
		if historyMDPath != "" {
			if err := perf.SaveHistoryMarkdown(historyMDPath, history); err != nil {
				log.Fatalf("write history markdown: %v", err)
			}
			fmt.Fprintf(os.Stdout, "Rendered history markdown to %s\n", historyMDPath)
		}
	}

	if baselinePath != "" {
		baseline, err := perf.LoadReport(baselinePath)
		if err != nil {
			log.Fatalf("load baseline: %v", err)
		}
		diff := perf.CompareReports(baseline, report, threshold)
		fmt.Print(diff.RenderText())
		if diff.HasRegressions() {
			log.Fatalf("performance regressions detected (threshold %.1f%%)", threshold*100)
		}
	} else {
		printSummary(report)
	}
}

func averageMetrics(samples []perf.BusWorkloadMetrics) perf.BusWorkloadMetrics {
	if len(samples) == 0 {
		return perf.BusWorkloadMetrics{}
	}
	out := samples[0]
	var durationSum time.Duration
	var throughputSum float64
	var errorRateSum float64
	var p50Sum float64
	var p95Sum float64
	var p99Sum float64
	maxLatency := samples[0].Latency.Max
	var bytesTotalSum float64
	var bytesPerEventSum float64
	peakG := samples[0].Memory.PeakGoroutines
	baselineG := samples[0].Memory.BaselineGoroutines
	successes := 0
	errors := 0
	var cpuSecondsSum float64

	for _, sample := range samples {
		durationSum += sample.Duration
		throughputSum += sample.Throughput
		errorRateSum += sample.ErrorRate
		p50Sum += sample.Latency.P50
		p95Sum += sample.Latency.P95
		p99Sum += sample.Latency.P99
		if sample.Latency.Max > maxLatency {
			maxLatency = sample.Latency.Max
		}
		bytesTotalSum += float64(sample.Memory.BytesTotal)
		bytesPerEventSum += sample.Memory.BytesPerEvent
		if sample.Memory.PeakGoroutines > peakG {
			peakG = sample.Memory.PeakGoroutines
		}
		successes += sample.Successes
		errors += sample.Errors
		cpuSecondsSum += sample.CPUSeconds
	}

	count := float64(len(samples))
	out.Duration = time.Duration(float64(durationSum) / count)
	out.Throughput = throughputSum / count
	out.ErrorRate = errorRateSum / count
	out.Successes = int(math.Round(float64(successes) / count))
	out.Errors = int(math.Round(float64(errors) / count))
	out.Latency = perf.LatencyMetrics{
		P50: p50Sum / count,
		P95: p95Sum / count,
		P99: p99Sum / count,
		Max: maxLatency,
	}
	out.Memory = perf.MemoryMetrics{
		BytesTotal:         uint64(bytesTotalSum / count),
		BytesPerEvent:      bytesPerEventSum / count,
		PeakGoroutines:     peakG,
		BaselineGoroutines: baselineG,
	}
	out.CPUSeconds = cpuSecondsSum / count
	return out
}

func gitRef() string {
	cmd := exec.Command("git", "rev-parse", "--short", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func printSummary(report perf.Report) {
	fmt.Println("Synthetic workload metrics:")
	writer := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(writer, "Workload\tThroughput (eps)\tP95 Latency (ms)\tBytes/Event\tCPU (s)\tErrors\n")
	for _, wl := range report.Workloads {
		fmt.Fprintf(writer, "%s\t%.0f\t%.2f\t%.0f\t%.2f\t%d\n",
			wl.Name,
			wl.Throughput,
			wl.Latency.P95,
			wl.Memory.BytesPerEvent,
			wl.CPUSeconds,
			wl.Errors,
		)
	}
	_ = writer.Flush()
}
