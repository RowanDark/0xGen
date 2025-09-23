package reporter

import (
	"sort"
	"strings"
	"time"

	"github.com/RowanDark/Glyph/internal/findings"
)

// ReportFormat identifies the type of report to generate.
type ReportFormat string

const (
	// FormatMarkdown renders a Markdown report.
	FormatMarkdown ReportFormat = "md"
	// FormatHTML renders an HTML report.
	FormatHTML ReportFormat = "html"
)

type targetCount struct {
	Target string
	Count  int
}

type pluginCount struct {
	Plugin string
	Count  int
}

type reportSummary struct {
	WindowStart   *time.Time
	WindowEnd     time.Time
	GeneratedAt   time.Time
	Total         int
	SeverityCount map[findings.Severity]int
	Targets       []targetCount
	Plugins       []pluginCount
	Recent        []findings.Finding
}

func buildSummary(list []findings.Finding, opts ReportOptions) reportSummary {
	since, now, filtered := opts.reportingWindow()
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	var windowStart *time.Time
	if filtered {
		windowStart = &since
	}

	filteredList := list
	if windowStart != nil {
		trimmed := make([]findings.Finding, 0, len(list))
		for _, f := range list {
			ts := f.DetectedAt.Time().UTC()
			if ts.Before(*windowStart) {
				continue
			}
			if ts.After(now) {
				continue
			}
			trimmed = append(trimmed, f)
		}
		filteredList = trimmed
	}

	counts := map[findings.Severity]int{
		findings.SeverityCritical: 0,
		findings.SeverityHigh:     0,
		findings.SeverityMedium:   0,
		findings.SeverityLow:      0,
		findings.SeverityInfo:     0,
	}
	targets := map[string]int{}
	plugins := map[string]int{}

	for _, f := range filteredList {
		sev := canonicalSeverity(f.Severity)
		counts[sev]++

		target := strings.TrimSpace(f.Target)
		if target == "" {
			target = "(not specified)"
		}
		targets[target]++

		plugin := strings.TrimSpace(f.Plugin)
		if plugin == "" {
			plugin = "(not specified)"
		}
		plugins[plugin]++
	}

	rankedTargets := make([]targetCount, 0, len(targets))
	for target, count := range targets {
		if count == 0 {
			continue
		}
		rankedTargets = append(rankedTargets, targetCount{Target: target, Count: count})
	}

	sort.Slice(rankedTargets, func(i, j int) bool {
		if rankedTargets[i].Count == rankedTargets[j].Count {
			return rankedTargets[i].Target < rankedTargets[j].Target
		}
		return rankedTargets[i].Count > rankedTargets[j].Count
	})

	targetLimit := len(rankedTargets)
	if DefaultTopTargets > 0 && DefaultTopTargets < targetLimit {
		targetLimit = DefaultTopTargets
	}
	rankedTargets = rankedTargets[:targetLimit]

	rankedPlugins := make([]pluginCount, 0, len(plugins))
	for plugin, count := range plugins {
		if count == 0 {
			continue
		}
		rankedPlugins = append(rankedPlugins, pluginCount{Plugin: plugin, Count: count})
	}

	sort.Slice(rankedPlugins, func(i, j int) bool {
		if rankedPlugins[i].Count == rankedPlugins[j].Count {
			return rankedPlugins[i].Plugin < rankedPlugins[j].Plugin
		}
		return rankedPlugins[i].Count > rankedPlugins[j].Count
	})

	pluginLimit := len(rankedPlugins)
	if defaultTopPlugins > 0 && pluginLimit > defaultTopPlugins {
		pluginLimit = defaultTopPlugins
	}
	rankedPlugins = rankedPlugins[:pluginLimit]

	recent := make([]findings.Finding, len(filteredList))
	copy(recent, filteredList)
	sort.Slice(recent, func(i, j int) bool {
		ti := recent[i].DetectedAt.Time()
		tj := recent[j].DetectedAt.Time()
		if ti.Equal(tj) {
			return recent[i].ID > recent[j].ID
		}
		return ti.After(tj)
	})
	if len(recent) > defaultRecentFindings {
		recent = recent[:defaultRecentFindings]
	}

	return reportSummary{
		WindowStart:   windowStart,
		WindowEnd:     now,
		GeneratedAt:   now,
		Total:         len(filteredList),
		SeverityCount: counts,
		Targets:       rankedTargets,
		Plugins:       rankedPlugins,
		Recent:        recent,
	}
}

func canonicalSeverity(input findings.Severity) findings.Severity {
	switch strings.ToLower(strings.TrimSpace(string(input))) {
	case string(findings.SeverityCritical):
		return findings.SeverityCritical
	case string(findings.SeverityHigh):
		return findings.SeverityHigh
	case string(findings.SeverityMedium):
		return findings.SeverityMedium
	case string(findings.SeverityLow):
		return findings.SeverityLow
	case string(findings.SeverityInfo):
		return findings.SeverityInfo
	default:
		return findings.SeverityInfo
	}
}

func findingExcerpt(f findings.Finding) string {
	raw := strings.TrimSpace(f.Evidence)
	if raw == "" {
		raw = strings.TrimSpace(f.Message)
	}
	if raw == "" {
		return "(not provided)"
	}
	raw = strings.ReplaceAll(raw, "\r", " ")
	raw = strings.ReplaceAll(raw, "\n", " ")
	raw = strings.Join(strings.Fields(raw), " ")
	if evidenceExcerptLimit > 0 {
		runes := []rune(raw)
		if len(runes) > evidenceExcerptLimit {
			raw = strings.TrimSpace(string(runes[:evidenceExcerptLimit])) + "…"
		}
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "(not provided)"
	}
	return trimmed
}
