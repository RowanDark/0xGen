package perf

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Report captures the outcome of one or more synthetic workloads.
type Report struct {
	Version   string               `json:"version"`
	Timestamp time.Time            `json:"timestamp"`
	GitRef    string               `json:"git_ref"`
	Workloads []BusWorkloadMetrics `json:"workloads"`
}

// MetricDelta summarises the difference between the baseline and a fresh run for
// a single metric.
type MetricDelta struct {
	Workload      string  `json:"workload"`
	Metric        string  `json:"metric"`
	Units         string  `json:"units"`
	Baseline      float64 `json:"baseline"`
	Current       float64 `json:"current"`
	Change        float64 `json:"change"`
	ChangePercent float64 `json:"change_percent"`
	BetterWhen    string  `json:"better_when"`
	Regression    bool    `json:"regression"`
	Threshold     float64 `json:"threshold"`
}

// DiffResult contains the computed deltas for all workloads and indicates
// whether regressions were observed.
type DiffResult struct {
	Threshold   float64       `json:"threshold"`
	Deltas      []MetricDelta `json:"deltas"`
	Regressions []MetricDelta `json:"regressions"`
}

// HasRegressions reports whether any metric breached the supplied threshold.
func (d DiffResult) HasRegressions() bool {
	return len(d.Regressions) > 0
}

// RenderText returns a human-readable summary suitable for CI logs.
func (d DiffResult) RenderText() string {
	if len(d.Deltas) == 0 {
		return "No overlapping workloads found between baseline and current run.\n"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "Performance diff (threshold %.1f%%)\n", d.Threshold*100)
	current := ""
	for _, delta := range d.Deltas {
		if delta.Workload != current {
			current = delta.Workload
			fmt.Fprintf(&sb, "%s:\n", current)
		}
		status := "OK"
		if delta.Regression {
			status = "REGRESSION"
		}
		fmt.Fprintf(&sb, "  • %s: %.2f %s → %.2f %s (%+.2f%%) [%s]\n",
			delta.Metric,
			delta.Baseline,
			delta.Units,
			delta.Current,
			delta.Units,
			delta.ChangePercent,
			status,
		)
	}
	return sb.String()
}

// CompareReports computes the metric deltas between the provided baseline and
// current run using the supplied regression threshold.
func CompareReports(baseline, current Report, threshold float64) DiffResult {
	baseMap := make(map[string]BusWorkloadMetrics, len(baseline.Workloads))
	for _, wl := range baseline.Workloads {
		baseMap[wl.Name] = wl
	}
	deltas := make([]MetricDelta, 0, len(current.Workloads)*5)
	for _, curr := range current.Workloads {
		base, ok := baseMap[curr.Name]
		if !ok {
			// New workload – no baseline to compare against yet.
			continue
		}
		deltas = append(deltas,
			throughputDelta(curr.Name, base, curr, threshold),
			latencyDelta(curr.Name, "latency_p95_ms", base.Latency.P95, curr.Latency.P95, threshold),
			memoryDelta(curr.Name, base.Memory.BytesPerEvent, curr.Memory.BytesPerEvent, threshold),
			cpuDelta(curr.Name, base.CPUSeconds, curr.CPUSeconds, threshold),
			errorRateDelta(curr.Name, base.ErrorRate, curr.ErrorRate, threshold),
		)
	}
	sort.Slice(deltas, func(i, j int) bool {
		if deltas[i].Workload == deltas[j].Workload {
			return deltas[i].Metric < deltas[j].Metric
		}
		return deltas[i].Workload < deltas[j].Workload
	})
	regressions := make([]MetricDelta, 0)
	for _, delta := range deltas {
		if delta.Regression {
			regressions = append(regressions, delta)
		}
	}
	return DiffResult{
		Threshold:   threshold,
		Deltas:      deltas,
		Regressions: regressions,
	}
}

func throughputDelta(workload string, base, curr BusWorkloadMetrics, threshold float64) MetricDelta {
	return makeDelta(workload, "throughput_eps", "events/s", "higher", base.Throughput, curr.Throughput, threshold)
}

func latencyDelta(workload, metric string, base, curr float64, threshold float64) MetricDelta {
	return makeDelta(workload, metric, "ms", "lower", base, curr, threshold)
}

func memoryDelta(workload string, base, curr float64, threshold float64) MetricDelta {
	return makeDelta(workload, "memory_bytes_per_event", "bytes/event", "lower", base, curr, threshold)
}

func cpuDelta(workload string, base, curr float64, threshold float64) MetricDelta {
	return makeDelta(workload, "cpu_seconds", "seconds", "lower", base, curr, threshold)
}

func errorRateDelta(workload string, base, curr float64, threshold float64) MetricDelta {
	delta := MetricDelta{
		Workload:      workload,
		Metric:        "error_rate",
		Units:         "fraction",
		Baseline:      base,
		Current:       curr,
		BetterWhen:    "lower",
		Threshold:     threshold,
		Change:        curr - base,
		ChangePercent: (curr - base) * 100,
	}
	epsilon := math.Max(0.001, base*threshold)
	delta.Regression = curr > base+epsilon
	return delta
}

func makeDelta(workload, metric, units, betterWhen string, base, curr, threshold float64) MetricDelta {
	delta := MetricDelta{
		Workload:   workload,
		Metric:     metric,
		Units:      units,
		Baseline:   base,
		Current:    curr,
		BetterWhen: betterWhen,
		Threshold:  threshold,
		Change:     curr - base,
	}
	if base != 0 {
		delta.ChangePercent = ((curr - base) / base) * 100
	}
	switch betterWhen {
	case "higher":
		if base > 0 {
			delta.Regression = curr < base*(1-threshold)
		}
	case "lower":
		if base > 0 {
			delta.Regression = curr > base*(1+threshold)
		} else {
			// No baseline yet – treat any increase beyond the threshold as a regression.
			delta.Regression = curr > threshold
		}
	}
	return delta
}

// LoadReport reads a report from disk.
func LoadReport(path string) (Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Report{}, err
	}
	var rep Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return Report{}, fmt.Errorf("parse report %s: %w", path, err)
	}
	return rep, nil
}

// SaveReport persists the report to disk creating any missing directories.
func SaveReport(path string, rep Report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
