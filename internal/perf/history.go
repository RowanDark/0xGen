package perf

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// HistoryPoint captures the headline metrics for a workload at a point in time.
type HistoryPoint struct {
	Timestamp           time.Time `json:"timestamp"`
	GitRef              string    `json:"git_ref"`
	Workload            string    `json:"workload"`
	Throughput          float64   `json:"throughput_eps"`
	CPUSeconds          float64   `json:"cpu_seconds"`
	ErrorRate           float64   `json:"error_rate"`
	MemoryBytesPerEvent float64   `json:"memory_bytes_per_event"`
}

// UpdateHistory appends the current report metrics to the supplied history file
// and returns the complete timeline sorted by timestamp.
func UpdateHistory(path string, report Report) ([]HistoryPoint, error) {
	history, err := LoadHistory(path)
	if err != nil {
		return nil, err
	}
	for _, wl := range report.Workloads {
		history = append(history, HistoryPoint{
			Timestamp:           report.Timestamp,
			GitRef:              report.GitRef,
			Workload:            wl.Name,
			Throughput:          wl.Throughput,
			CPUSeconds:          wl.CPUSeconds,
			ErrorRate:           wl.ErrorRate,
			MemoryBytesPerEvent: wl.Memory.BytesPerEvent,
		})
	}
	sort.Slice(history, func(i, j int) bool {
		if history[i].Workload == history[j].Workload {
			return history[i].Timestamp.Before(history[j].Timestamp)
		}
		return history[i].Workload < history[j].Workload
	})
	if len(history) > 0 {
		// Keep the most recent 120 entries per workload (~1 year of daily runs).
		grouped := make(map[string][]HistoryPoint)
		for _, pt := range history {
			grouped[pt.Workload] = append(grouped[pt.Workload], pt)
		}
		trimmed := make([]HistoryPoint, 0, len(history))
		for _, pts := range grouped {
			if len(pts) > 120 {
				pts = pts[len(pts)-120:]
			}
			trimmed = append(trimmed, pts...)
		}
		history = trimmed
	}
	sort.Slice(history, func(i, j int) bool {
		if history[i].Workload == history[j].Workload {
			return history[i].Timestamp.Before(history[j].Timestamp)
		}
		return history[i].Workload < history[j].Workload
	})
	if err := saveHistory(path, history); err != nil {
		return nil, err
	}
	return history, nil
}

// LoadHistory reads all points from the history file. It returns an empty slice
// if the file does not exist.
func LoadHistory(path string) ([]HistoryPoint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	history := make([]HistoryPoint, 0)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var pt HistoryPoint
		if err := json.Unmarshal([]byte(line), &pt); err != nil {
			return nil, fmt.Errorf("parse history line: %w", err)
		}
		history = append(history, pt)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.Slice(history, func(i, j int) bool {
		if history[i].Workload == history[j].Workload {
			return history[i].Timestamp.Before(history[j].Timestamp)
		}
		return history[i].Workload < history[j].Workload
	})
	return history, nil
}

func saveHistory(path string, history []HistoryPoint) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	encoder := json.NewEncoder(writer)
	for _, pt := range history {
		if err := encoder.Encode(pt); err != nil {
			return err
		}
	}
	return writer.Flush()
}

// SaveHistoryMarkdown renders a Markdown summary to the supplied path using the
// provided history points.
func SaveHistoryMarkdown(path string, history []HistoryPoint) error {
	summary := RenderHistoryMarkdown(history)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(summary), 0o644)
}

// RenderHistoryMarkdown converts the supplied history into a Markdown report
// with sparklines for throughput, CPU, and error rates.
func RenderHistoryMarkdown(history []HistoryPoint) string {
	if len(history) == 0 {
		return "# Performance history\n\n_No data collected yet._\n"
	}
	grouped := make(map[string][]HistoryPoint)
	for _, pt := range history {
		grouped[pt.Workload] = append(grouped[pt.Workload], pt)
	}
	workloads := make([]string, 0, len(grouped))
	for name := range grouped {
		workloads = append(workloads, name)
	}
	sort.Strings(workloads)

	var b strings.Builder
	fmt.Fprintf(&b, "# Performance history\n\nGenerated %s with %d samples.\n\n", time.Now().UTC().Format(time.RFC3339), len(history))
	for _, name := range workloads {
		pts := grouped[name]
		sort.Slice(pts, func(i, j int) bool { return pts[i].Timestamp.Before(pts[j].Timestamp) })
		throughput := make([]float64, 0, len(pts))
		cpu := make([]float64, 0, len(pts))
		errors := make([]float64, 0, len(pts))
		for _, pt := range pts {
			throughput = append(throughput, pt.Throughput)
			cpu = append(cpu, pt.CPUSeconds)
			errors = append(errors, pt.ErrorRate)
		}
		fmt.Fprintf(&b, "## %s\n\n", name)
		fmt.Fprintf(&b, "Throughput (events/s): `%s`\n\n", sparkline(throughput))
		fmt.Fprintf(&b, "CPU seconds: `%s`\n\n", sparkline(cpu))
		fmt.Fprintf(&b, "Error rate: `%s`\n\n", sparkline(errors))
		fmt.Fprintf(&b, "| Timestamp | Git ref | Events/s | CPU (s) | Error rate | Bytes/event |\n")
		fmt.Fprintf(&b, "| --- | --- | --- | --- | --- | --- |\n")
		for i := len(pts) - 1; i >= 0 && i >= len(pts)-10; i-- {
			pt := pts[i]
			fmt.Fprintf(&b, "| %s | %s | %.0f | %.2f | %.3f | %.0f |\n",
				pt.Timestamp.Format(time.RFC3339),
				orDefault(pt.GitRef, "-"),
				pt.Throughput,
				pt.CPUSeconds,
				pt.ErrorRate,
				pt.MemoryBytesPerEvent,
			)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func sparkline(values []float64) string {
	if len(values) == 0 {
		return ""
	}
	const charset = "▁▂▃▄▅▆▇█"
	runes := []rune(charset)
	min := values[0]
	max := values[0]
	for _, v := range values[1:] {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	if max == min {
		return strings.Repeat(string(runes[0]), len(values))
	}
	span := max - min
	var b strings.Builder
	for _, v := range values {
		idx := int((v - min) / span * float64(len(runes)-1))
		if idx < 0 {
			idx = 0
		}
		if idx >= len(runes) {
			idx = len(runes) - 1
		}
		b.WriteRune(runes[idx])
	}
	return b.String()
}

func orDefault(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
