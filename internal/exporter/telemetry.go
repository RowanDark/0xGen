package exporter

import (
	"strings"
	"time"

	"github.com/RowanDark/0xgen/internal/cases"
	"github.com/RowanDark/0xgen/internal/findings"
)

// Telemetry summarises a pipeline export for downstream data lakes.
type Telemetry struct {
	GeneratedAt    findings.Timestamp `json:"generated_at"`
	CaseCount      int                `json:"case_count"`
	FindingCount   int                `json:"finding_count"`
	SeverityCounts map[string]int     `json:"severity_counts"`
	PluginCounts   map[string]int     `json:"plugin_counts"`
}

// CaseMetrics captures per-case aggregates emitted alongside case entries.
type CaseMetrics struct {
	SourceCount   int `json:"source_count"`
	EvidenceCount int `json:"evidence_count"`
}

// BuildTelemetry derives aggregate metrics for the provided cases.
func BuildTelemetry(casesList []cases.Case, findingsCount int) Telemetry {
	severityCounts := map[string]int{
		string(findings.SeverityCritical): 0,
		string(findings.SeverityHigh):     0,
		string(findings.SeverityMedium):   0,
		string(findings.SeverityLow):      0,
		string(findings.SeverityInfo):     0,
	}
	pluginCounts := make(map[string]int)

	var latest time.Time
	for _, c := range casesList {
		sev := normaliseSeverity(c.Risk.Severity)
		severityCounts[sev]++

		ts := c.GeneratedAt.Time().UTC()
		if ts.After(latest) {
			latest = ts
		}

		for _, src := range c.Sources {
			plugin := strings.ToLower(strings.TrimSpace(src.Plugin))
			if plugin == "" {
				plugin = "(unknown)"
			}
			pluginCounts[plugin]++
		}
	}

	if latest.IsZero() {
		latest = time.Now().UTC()
	}

	// Ensure severity keys are present even when no cases were produced.
	for _, key := range []string{
		string(findings.SeverityCritical),
		string(findings.SeverityHigh),
		string(findings.SeverityMedium),
		string(findings.SeverityLow),
		string(findings.SeverityInfo),
	} {
		if _, ok := severityCounts[key]; !ok {
			severityCounts[key] = 0
		}
	}

	return Telemetry{
		GeneratedAt:    findings.NewTimestamp(latest.Truncate(time.Second)),
		CaseCount:      len(casesList),
		FindingCount:   findingsCount,
		SeverityCounts: severityCounts,
		PluginCounts:   pluginCounts,
	}
}

func normaliseSeverity(sev findings.Severity) string {
	switch sev {
	case findings.SeverityCritical:
		return string(findings.SeverityCritical)
	case findings.SeverityHigh:
		return string(findings.SeverityHigh)
	case findings.SeverityMedium:
		return string(findings.SeverityMedium)
	case findings.SeverityLow:
		return string(findings.SeverityLow)
	default:
		return string(findings.SeverityInfo)
	}
}
