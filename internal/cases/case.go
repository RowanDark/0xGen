package cases

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/RowanDark/0xgen/internal/findings"
)

// CaseSchemaVersion captures the version of the Case JSON structure emitted by the builder.
const CaseSchemaVersion = "1.1"

// Case represents a deduplicated issue that merges evidence from multiple plugins.
type Case struct {
	Version       string             `json:"version"`
	ID            string             `json:"id"`
	Asset         Asset              `json:"asset"`
	Vector        AttackVector       `json:"vector"`
	Summary       string             `json:"summary"`
	Evidence      []EvidenceItem     `json:"evidence"`
	Proof         ProofOfConcept     `json:"proof"`
	Risk          Risk               `json:"risk"`
	Confidence    float64            `json:"confidence"`
	ConfidenceLog string             `json:"confidence_log,omitempty"`
	Sources       []SourceFinding    `json:"sources"`
	GeneratedAt   findings.Timestamp `json:"generated_at"`
	Labels        map[string]string  `json:"labels,omitempty"`
	Graph         ExploitGraph       `json:"graph"`
}

// Asset describes the affected resource in a normalised form.
type Asset struct {
	Kind       string `json:"kind"`
	Identifier string `json:"identifier"`
	Details    string `json:"details,omitempty"`
}

// AttackVector captures the avenue that led to the case being raised.
type AttackVector struct {
	Kind  string `json:"kind"`
	Value string `json:"value,omitempty"`
}

// EvidenceItem collates raw signals that contributed to the case.
type EvidenceItem struct {
	Plugin   string            `json:"plugin"`
	Type     string            `json:"type"`
	Message  string            `json:"message"`
	Evidence string            `json:"evidence,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// ProofOfConcept aggregates reproduction steps and rationale.
type ProofOfConcept struct {
	Summary string   `json:"summary,omitempty"`
	Steps   []string `json:"steps"`
}

// ExploitGraph captures a deterministic state machine illustrating the exploit path.
type ExploitGraph struct {
	DOT        string      `json:"dot"`
	Mermaid    string      `json:"mermaid"`
	Summary    string      `json:"summary,omitempty"`
	AttackPath []ChainStep `json:"attack_path,omitempty"`
}

// ChainStep captures an individual hop within the correlated attack path.
type ChainStep struct {
	Stage       int               `json:"stage"`
	From        string            `json:"from"`
	To          string            `json:"to"`
	Description string            `json:"description"`
	Plugin      string            `json:"plugin"`
	Type        string            `json:"type"`
	FindingID   string            `json:"finding_id"`
	Severity    findings.Severity `json:"severity"`
	WeakLink    bool              `json:"weak_link,omitempty"`
}

// Risk captures the severity and supporting rationale for the case.
type Risk struct {
	Severity  findings.Severity `json:"severity"`
	Score     float64           `json:"score"`
	Rationale string            `json:"rationale,omitempty"`
}

// SourceFinding references the plugin findings that were rolled up into the case.
type SourceFinding struct {
	ID       string            `json:"id"`
	Plugin   string            `json:"plugin"`
	Type     string            `json:"type"`
	Severity findings.Severity `json:"severity"`
	Target   string            `json:"target,omitempty"`
}

// Clone returns a deep copy of the case ensuring cached results cannot be mutated by callers.
func (c Case) Clone() Case {
	clone := c
	if len(c.Evidence) > 0 {
		clone.Evidence = make([]EvidenceItem, len(c.Evidence))
		for i, item := range c.Evidence {
			clone.Evidence[i] = item.Clone()
		}
	}
	if len(c.Sources) > 0 {
		clone.Sources = make([]SourceFinding, len(c.Sources))
		copy(clone.Sources, c.Sources)
	}
	if len(c.Proof.Steps) > 0 {
		clone.Proof.Steps = append([]string(nil), c.Proof.Steps...)
	}
	if len(c.Labels) > 0 {
		clone.Labels = make(map[string]string, len(c.Labels))
		for k, v := range c.Labels {
			clone.Labels[k] = v
		}
	}
	clone.Graph = c.Graph.Clone()
	return clone
}

// Clone returns a deep copy of the evidence item.
func (e EvidenceItem) Clone() EvidenceItem {
	clone := e
	if len(e.Metadata) > 0 {
		clone.Metadata = make(map[string]string, len(e.Metadata))
		for k, v := range e.Metadata {
			clone.Metadata[k] = v
		}
	}
	return clone
}

// MarshalJSON ensures evidence metadata is emitted in a stable order to aid golden tests.
func (e EvidenceItem) MarshalJSON() ([]byte, error) {
	type Alias EvidenceItem
	alias := Alias(e.Clone())
	if len(alias.Metadata) > 0 {
		keys := make([]string, 0, len(alias.Metadata))
		for k := range alias.Metadata {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ordered := make(map[string]string, len(alias.Metadata))
		for _, k := range keys {
			ordered[k] = alias.Metadata[k]
		}
		alias.Metadata = ordered
	}
	return json.Marshal(alias)
}

// MarshalJSON ensures labels are emitted in stable order.
func (c Case) MarshalJSON() ([]byte, error) {
	type Alias Case
	alias := Alias(c.Clone())
	if len(alias.Labels) > 0 {
		keys := make([]string, 0, len(alias.Labels))
		for k := range alias.Labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ordered := make(map[string]string, len(alias.Labels))
		for _, k := range keys {
			ordered[k] = alias.Labels[k]
		}
		alias.Labels = ordered
	}
	return json.Marshal(alias)
}

// NormalisedKey returns a stable identifier used when deduplicating plugin findings.
func (c Case) NormalisedKey() string {
	var b strings.Builder
	b.WriteString(strings.ToLower(strings.TrimSpace(c.Asset.Kind)))
	b.WriteString("|")
	b.WriteString(strings.ToLower(strings.TrimSpace(c.Asset.Identifier)))
	b.WriteString("|")
	b.WriteString(strings.ToLower(strings.TrimSpace(c.Vector.Kind)))
	if v := strings.TrimSpace(c.Vector.Value); v != "" {
		b.WriteString("|")
		b.WriteString(strings.ToLower(v))
	}
	return b.String()
}

// Clone returns a deep copy of the exploit graph to avoid shared slices between cases.
func (g ExploitGraph) Clone() ExploitGraph {
	clone := g
	if len(g.AttackPath) > 0 {
		clone.AttackPath = make([]ChainStep, len(g.AttackPath))
		copy(clone.AttackPath, g.AttackPath)
	}
	return clone
}
