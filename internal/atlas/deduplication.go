package atlas

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// Deduplicator handles finding deduplication and merging.
type Deduplicator struct {
	seen map[string]*Finding // fingerprint -> finding
}

// NewDeduplicator creates a new finding deduplicator.
func NewDeduplicator() *Deduplicator {
	return &Deduplicator{
		seen: make(map[string]*Finding),
	}
}

// Deduplicate checks if finding is duplicate and merges evidence.
// Returns the merged finding and true if it was a duplicate.
func (d *Deduplicator) Deduplicate(finding *Finding) (*Finding, bool) {
	fingerprint := d.generateFingerprint(finding)

	existing, isDuplicate := d.seen[fingerprint]
	if isDuplicate {
		// Merge evidence from duplicate finding
		existing = d.mergeFinding(existing, finding)
		d.seen[fingerprint] = existing
		return existing, true
	}

	// New unique finding
	d.seen[fingerprint] = finding
	return finding, false
}

// generateFingerprint creates unique identifier for finding.
func (d *Deduplicator) generateFingerprint(f *Finding) string {
	// Fingerprint components (order matters for consistency)
	components := []string{
		f.Type,
		normalizeURL(f.URL),
		f.Parameter,
		string(f.Location),
		f.Method,
	}

	// Create hash
	data := strings.Join(components, "|")
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// normalizeURL removes query parameters for fingerprint consistency.
func normalizeURL(rawURL string) string {
	// Remove query parameters for fingerprint
	if idx := strings.Index(rawURL, "?"); idx != -1 {
		return rawURL[:idx]
	}
	return rawURL
}

// mergeFinding combines evidence from duplicate findings.
func (d *Deduplicator) mergeFinding(existing, new *Finding) *Finding {
	// Keep the first occurrence
	merged := *existing

	// Upgrade confidence if new finding has higher confidence
	if new.Confidence == ConfidenceConfirmed && existing.Confidence != ConfidenceConfirmed {
		merged.Confidence = ConfidenceConfirmed
		merged.Proof = new.Proof // Use the confirmed proof
	} else if new.Confidence == ConfidenceFirm && existing.Confidence == ConfidenceTentative {
		merged.Confidence = ConfidenceFirm
		merged.Proof = new.Proof
	}

	// Append additional evidence if different
	if new.Proof != "" && new.Proof != existing.Proof {
		if merged.Proof == "" {
			merged.Proof = new.Proof
		} else {
			merged.Proof += "\n\nAdditional evidence:\n" + new.Proof
		}
	}

	// Track multiple occurrences
	if merged.Metadata == nil {
		merged.Metadata = make(map[string]interface{})
	}
	count, _ := merged.Metadata["occurrence_count"].(int)
	merged.Metadata["occurrence_count"] = count + 1

	// Store all payloads that triggered the finding
	payloads, _ := merged.Metadata["payloads"].([]string)
	if new.Payload != "" {
		// Check if this payload is already recorded
		found := false
		for _, p := range payloads {
			if p == new.Payload {
				found = true
				break
			}
		}
		if !found {
			payloads = append(payloads, new.Payload)
			merged.Metadata["payloads"] = payloads
		}
	}

	return &merged
}

// GetUniqueFindings returns all unique findings sorted by severity and confidence.
func (d *Deduplicator) GetUniqueFindings() []*Finding {
	findings := make([]*Finding, 0, len(d.seen))
	for _, f := range d.seen {
		findings = append(findings, f)
	}

	// Sort by severity (descending), then confidence (descending)
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return severityWeight(findings[i].Severity) > severityWeight(findings[j].Severity)
		}
		return confidenceWeight(findings[i].Confidence) > confidenceWeight(findings[j].Confidence)
	})

	return findings
}

// Count returns the number of unique findings.
func (d *Deduplicator) Count() int {
	return len(d.seen)
}

// Clear resets the deduplicator.
func (d *Deduplicator) Clear() {
	d.seen = make(map[string]*Finding)
}

// severityWeight returns numeric weight for severity sorting.
func severityWeight(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// confidenceWeight returns numeric weight for confidence sorting.
func confidenceWeight(c Confidence) int {
	switch c {
	case ConfidenceConfirmed:
		return 3
	case ConfidenceFirm:
		return 2
	case ConfidenceTentative:
		return 1
	default:
		return 0
	}
}
