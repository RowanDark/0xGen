package ranker

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/RowanDark/0xgen/internal/env"
	"github.com/RowanDark/0xgen/internal/findings"
)

// ScoredFinding represents a finding annotated with deterministic ranking
// metadata. The embedded findings.Finding fields remain untouched so callers can
// write the ranked output back to JSONL without any additional translation.
type ScoredFinding struct {
	findings.Finding
	Score          float64 `json:"score"`
	ExposureHint   string  `json:"exposure_hint,omitempty"`
	Frequency      int     `json:"frequency"`
	DuplicateCount int     `json:"duplicate_count"`
	Primary        bool    `json:"primary"`
}

const (
	defaultOutputDir = "/out"
	rankedFilename   = "ranked.jsonl"
)

// DefaultOutputPath identifies where ranked findings should be written when no
// explicit --out flag is provided. The location respects GLYPH_OUT when set so
// CLI consumers stay consistent with other tooling.
var DefaultOutputPath = filepath.Join(defaultOutputDir, rankedFilename)

func init() {
	if val, ok := env.Lookup("0XGEN_OUT", "GLYPH_OUT"); ok {
		if custom := strings.TrimSpace(val); custom != "" {
			DefaultOutputPath = filepath.Join(custom, rankedFilename)
		}
	}
}

// Rank computes a deterministic score for each finding and returns the slice
// sorted in priority order. Higher severity, public-facing exposure and
// widespread occurrences contribute positively to the score, while duplicate
// detections for the same target are collapsed so they do not dominate the
// output.
func Rank(findingsList []findings.Finding) []ScoredFinding {
	if len(findingsList) == 0 {
		return nil
	}

	dedupeKeyFor := make([]string, len(findingsList))
	freqKeyFor := make([]string, len(findingsList))

	duplicateGroups := make(map[string][]int)
	frequencyGroups := make(map[string]map[string]struct{})
	for idx, finding := range findingsList {
		dKey := dedupeKey(finding)
		fKey := frequencyKey(finding)
		dedupeKeyFor[idx] = dKey
		freqKeyFor[idx] = fKey

		duplicateGroups[dKey] = append(duplicateGroups[dKey], idx)

		targets := frequencyGroups[fKey]
		if targets == nil {
			targets = make(map[string]struct{})
			frequencyGroups[fKey] = targets
		}
		targets[strings.TrimSpace(finding.Target)] = struct{}{}
	}

	primary := make(map[int]bool, len(findingsList))
	duplicateCount := make(map[int]int, len(findingsList))
	for _, indexes := range duplicateGroups {
		best := indexes[0]
		for _, idx := range indexes[1:] {
			if preferFinding(findingsList[idx], findingsList[best]) {
				best = idx
			}
		}
		for _, idx := range indexes {
			duplicateCount[idx] = len(indexes)
		}
		primary[best] = true
	}

	ranked := make([]ScoredFinding, len(findingsList))
	for idx, finding := range findingsList {
		freqCount := len(frequencyGroups[freqKeyFor[idx]])
		dupCount := duplicateCount[idx]
		if dupCount == 0 {
			dupCount = 1
		}

		hint := determineExposure(finding)
		isPrimary := primary[idx] || dupCount == 1
		score := computeScore(finding, hint, freqCount, dupCount, isPrimary)

		ranked[idx] = ScoredFinding{
			Finding:        finding,
			Score:          score,
			ExposureHint:   hint,
			Frequency:      freqCount,
			DuplicateCount: dupCount,
			Primary:        isPrimary,
		}
	}

	sort.SliceStable(ranked, func(i, j int) bool {
		if almostEqual(ranked[i].Score, ranked[j].Score) {
			ti := ranked[i].DetectedAt.Time()
			tj := ranked[j].DetectedAt.Time()
			if !ti.Equal(tj) {
				return ti.Before(tj)
			}
			return ranked[i].ID < ranked[j].ID
		}
		return ranked[i].Score > ranked[j].Score
	})

	return ranked
}

// WriteJSONL persists the ranked findings to a JSON Lines file at the provided
// path. Each ScoredFinding is encoded on its own line to match the repository's
// existing findings format.
func WriteJSONL(path string, ranked []ScoredFinding) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("output path is required")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open ranked output: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	encoder := json.NewEncoder(writer)
	for _, entry := range ranked {
		if err := encoder.Encode(entry); err != nil {
			return fmt.Errorf("encode ranked finding: %w", err)
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush ranked output: %w", err)
	}
	return nil
}

func computeScore(f finding, exposure string, freqCount, dupCount int, primary bool) float64 {
	base := severityWeights[f.Severity]
	if !primary && dupCount > 1 {
		return base * duplicatePenalty
	}

	bonus := exposureWeight(exposure) + frequencyBonus(freqCount)
	return base + bonus
}

func dedupeKey(f finding) string {
	return strings.Join([]string{strings.ToLower(strings.TrimSpace(f.Plugin)), strings.ToLower(strings.TrimSpace(f.Type)), strings.TrimSpace(f.Target)}, "|")
}

func frequencyKey(f finding) string {
	return strings.Join([]string{strings.ToLower(strings.TrimSpace(f.Plugin)), strings.ToLower(strings.TrimSpace(f.Type))}, "|")
}

func preferFinding(candidate, current finding) bool {
	ct := candidate.DetectedAt.Time()
	cur := current.DetectedAt.Time()
	if ct.Before(cur) {
		return true
	}
	if cur.Before(ct) {
		return false
	}
	return candidate.ID < current.ID
}

func exposureWeight(hint string) float64 {
	switch hint {
	case "public", "internet", "internet-facing", "external":
		return 15
	case "dmz", "partner":
		return 8
	default:
		return 0
	}
}

func frequencyBonus(count int) float64 {
	if count <= 1 {
		return 0
	}
	return math.Log1p(float64(count-1)) * frequencyWeight
}

func determineExposure(f finding) string {
	if len(f.Metadata) > 0 {
		for _, key := range []string{"exposure", "surface", "visibility", "zone"} {
			if raw, ok := f.Metadata[key]; ok {
				trimmed := strings.ToLower(strings.TrimSpace(raw))
				if trimmed != "" {
					return trimmed
				}
			}
		}
	}

	target := strings.TrimSpace(f.Target)
	if target == "" {
		return ""
	}
	if u, err := url.Parse(target); err == nil {
		host := strings.ToLower(u.Hostname())
		if host == "" {
			return ""
		}
		if strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".corp") || strings.HasSuffix(host, ".intranet") || strings.HasSuffix(host, ".local") {
			return "internal"
		}
		if ip := net.ParseIP(host); ip != nil {
			if isPrivateIP(ip) {
				return "internal"
			}
			return "public"
		}
		return "public"
	}
	return ""
}

func isPrivateIP(ip net.IP) bool {
	privateCIDRs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
	}
	for _, cidr := range privateCIDRs {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func almostEqual(a, b float64) bool {
	return math.Abs(a-b) < 1e-6
}

const (
	duplicatePenalty = 0.1
	frequencyWeight  = 12.0
)

var severityWeights = map[findings.Severity]float64{
	findings.SeverityCritical: 100,
	findings.SeverityHigh:     75,
	findings.SeverityMedium:   50,
	findings.SeverityLow:      30,
	findings.SeverityInfo:     10,
}

// finding is a local alias to shorten function signatures.
type finding = findings.Finding
