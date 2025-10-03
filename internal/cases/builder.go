package cases

import (
	"context"
	"crypto/sha1"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/RowanDark/Glyph/internal/findings"
	"github.com/RowanDark/Glyph/internal/redact"
)

// Builder reduces raw plugin findings into high-confidence Cases.
type Builder struct {
	summarizer    Summarizer
	cache         SummaryCache
	deterministic bool
	seed          int64
	now           func() time.Time
	mu            sync.Mutex
}

// Option controls Builder behaviour.
type Option func(*Builder)

// WithSummarizer configures a custom summarizer implementation.
func WithSummarizer(s Summarizer) Option {
	return func(b *Builder) {
		if s != nil {
			b.summarizer = s
		}
	}
}

// WithCache registers a cache used to store summarisation results.
func WithCache(cache SummaryCache) Option {
	return func(b *Builder) {
		b.cache = cache
	}
}

// WithDeterministicMode enables deterministic replay using the provided seed.
func WithDeterministicMode(seed int64) Option {
	return func(b *Builder) {
		b.deterministic = true
		b.seed = seed
	}
}

// WithClock replaces the time source used for generated timestamps.
func WithClock(now func() time.Time) Option {
	return func(b *Builder) {
		if now != nil {
			b.now = now
		}
	}
}

// NewBuilder constructs a Builder with optional configuration.
func NewBuilder(opts ...Option) *Builder {
	b := &Builder{
		summarizer: DefaultSummarizer(),
		cache:      NewMemoryCache(),
		now:        time.Now,
	}
	for _, opt := range opts {
		opt(b)
	}
	if b.cache == nil {
		b.cache = NewMemoryCache()
	}
	return b
}

// Build collapses the provided findings into deterministic cases.
func (b *Builder) Build(ctx context.Context, findingsList []findings.Finding) ([]Case, error) {
	if len(findingsList) == 0 {
		return nil, nil
	}

	groups := b.clusterFindings(findingsList)

	sort.SliceStable(groups, func(i, j int) bool {
		return b.componentOrderKey(groups[i]) < b.componentOrderKey(groups[j])
	})

	cases := make([]Case, 0, len(groups))

	for _, fs := range groups {
		casePrototype := b.derivePrototype(fs)
		summaryInput := b.buildSummaryInput(casePrototype, fs)
		summaryOutput, err := b.summarize(ctx, summaryInput)
		if err != nil {
			return nil, fmt.Errorf("summarise case: %w", err)
		}
		assembled := b.assembleCase(casePrototype, fs, summaryOutput)
		cases = append(cases, assembled)
	}

	sort.SliceStable(cases, func(i, j int) bool {
		return cases[i].ID < cases[j].ID
	})

	return cases, nil
}

func (b *Builder) summarize(ctx context.Context, input SummaryInput) (SummaryOutput, error) {
	cacheKey := hashSummaryInput(input)
	if b.cache != nil {
		if cached, ok := b.cache.Get(cacheKey); ok {
			return cached, nil
		}
	}
	output, err := b.summarizer.Summarize(ctx, input)
	if err != nil {
		return SummaryOutput{}, err
	}
	if b.cache != nil {
		b.cache.Set(cacheKey, output)
	}
	return output, nil
}

func (b *Builder) derivePrototype(fs []findings.Finding) Case {
	dominant := selectDominantFinding(fs)
	asset := normaliseAsset(dominant)
	vector := normaliseVector(fs)
	id := b.generateID(asset, vector)
	labels := mergeLabels(fs)
	return Case{
		Version:     CaseSchemaVersion,
		ID:          id,
		Asset:       asset,
		Vector:      vector,
		Evidence:    make([]EvidenceItem, 0, len(fs)),
		Sources:     make([]SourceFinding, 0, len(fs)),
		GeneratedAt: findings.NewTimestamp(b.resolveNow()),
		Labels:      labels,
	}
}

func (b *Builder) assembleCase(proto Case, fs []findings.Finding, summary SummaryOutput) Case {
	caseCopy := proto
	caseCopy.Summary = summary.Summary
	caseCopy.Proof = ProofOfConcept{Summary: summary.ProofSummary, Steps: append([]string(nil), summary.ReproductionSteps...)}
	caseCopy.Risk = Risk{
		Severity:  summary.RiskSeverity,
		Score:     summary.RiskScore,
		Rationale: summary.RiskRationale,
	}
	caseCopy.Confidence = summary.ConfidenceScore
	caseCopy.ConfidenceLog = summary.ConfidenceLog
	caseCopy.Graph = buildExploitGraph(caseCopy, summary)
	caseCopy.Evidence = append(caseCopy.Evidence, buildEvidence(fs)...)
	caseCopy.Sources = append(caseCopy.Sources, buildSources(fs)...)
	return sanitizeCase(caseCopy)
}

func (b *Builder) resolveNow() time.Time {
	if b.now == nil {
		return time.Now()
	}
	return b.now().UTC().Truncate(time.Second)
}

func (b *Builder) generateID(asset Asset, vector AttackVector) string {
	key := asset.Kind + "|" + asset.Identifier + "|" + vector.Kind + "|" + vector.Value
	if b.deterministic {
		h := sha1.New()
		buf := make([]byte, 8)
		for i := 0; i < 8; i++ {
			buf[i] = byte(b.seed >> (8 * i))
		}
		_, _ = h.Write(buf)
		_, _ = h.Write([]byte(strings.ToLower(key)))
		sum := h.Sum(nil)
		encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
		encoded := encoding.EncodeToString(sum)
		if len(encoded) > 26 {
			encoded = encoded[:26]
		}
		return encoded
	}
	return findings.NewID()
}

func (b *Builder) buildSummaryInput(proto Case, fs []findings.Finding) SummaryInput {
	normals := make([]NormalisedFinding, len(fs))
	for i, f := range fs {
		normals[i] = normaliseFinding(f)
	}
	sort.SliceStable(normals, func(i, j int) bool {
		if normals[i].Severity == normals[j].Severity {
			if normals[i].Plugin == normals[j].Plugin {
				return normals[i].Type < normals[j].Type
			}
			return normals[i].Plugin < normals[j].Plugin
		}
		return normals[i].Severity > normals[j].Severity
	})
	prompts := BuildPrompts(proto, normals)
	return SummaryInput{
		Case:     proto,
		Findings: normals,
		Prompts:  prompts,
	}
}

func (b *Builder) groupKey(f findings.Finding) string {
	if explicit := strings.TrimSpace(f.Metadata["case_key"]); explicit != "" {
		return strings.ToLower(explicit)
	}
	if target := canonicalTarget(f.Target); target != "" {
		return target
	}
	asset := normaliseAsset(f)
	return strings.ToLower(asset.Kind) + "|" + strings.ToLower(asset.Identifier)
}

func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	var prev string
	for i, v := range in {
		if i == 0 || v != prev {
			out = append(out, v)
			prev = v
		}
	}
	return out
}

func mergeLabels(fs []findings.Finding) map[string]string {
	labels := make(map[string]string)
	for _, f := range fs {
		for k, v := range f.Metadata {
			if strings.HasPrefix(k, "label:") {
				key := strings.TrimPrefix(k, "label:")
				labels[key] = v
			}
		}
	}
	if len(labels) == 0 {
		return nil
	}
	return labels
}

func hashSummaryInput(input SummaryInput) string {
	snapshot := struct {
		Asset    Asset               `json:"asset"`
		Vector   AttackVector        `json:"vector"`
		Findings []NormalisedFinding `json:"findings"`
		Prompts  PromptSet           `json:"prompts"`
		Labels   orderedStringMap    `json:"labels,omitempty"`
	}{
		Asset:    input.Case.Asset,
		Vector:   input.Case.Vector,
		Findings: append([]NormalisedFinding(nil), input.Findings...),
		Prompts:  input.Prompts,
	}
	if len(input.Case.Labels) > 0 {
		snapshot.Labels = orderedStringMap(cloneMetadata(input.Case.Labels))
	}
	buf, _ := json.Marshal(snapshot)
	sum := sha1.Sum(buf)
	return hex.EncodeToString(sum[:])
}

func buildEvidence(fs []findings.Finding) []EvidenceItem {
	evidence := make([]EvidenceItem, 0, len(fs))
	for _, f := range fs {
		evidence = append(evidence, EvidenceItem{
			Plugin:   f.Plugin,
			Type:     f.Type,
			Message:  f.Message,
			Evidence: f.Evidence,
			Metadata: cloneMetadata(f.Metadata),
		})
	}
	sort.SliceStable(evidence, func(i, j int) bool {
		if evidence[i].Plugin == evidence[j].Plugin {
			if evidence[i].Type == evidence[j].Type {
				return evidence[i].Message < evidence[j].Message
			}
			return evidence[i].Type < evidence[j].Type
		}
		return evidence[i].Plugin < evidence[j].Plugin
	})
	return evidence
}

func buildSources(fs []findings.Finding) []SourceFinding {
	sources := make([]SourceFinding, 0, len(fs))
	for _, f := range fs {
		sources = append(sources, SourceFinding{
			ID:       f.ID,
			Plugin:   f.Plugin,
			Type:     f.Type,
			Severity: f.Severity,
			Target:   f.Target,
		})
	}
	sort.SliceStable(sources, func(i, j int) bool {
		if sources[i].Plugin == sources[j].Plugin {
			if sources[i].Type == sources[j].Type {
				return sources[i].ID < sources[j].ID
			}
			return sources[i].Type < sources[j].Type
		}
		return sources[i].Plugin < sources[j].Plugin
	})
	return sources
}

func cloneMetadata(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func sanitizeCase(c Case) Case {
	c.Asset.Identifier = redact.String(c.Asset.Identifier)
	c.Asset.Details = redact.String(c.Asset.Details)
	c.Vector.Value = redact.String(c.Vector.Value)
	c.Summary = redact.String(c.Summary)
	c.ConfidenceLog = redact.String(c.ConfidenceLog)
	c.Proof.Summary = redact.String(c.Proof.Summary)
	if len(c.Proof.Steps) > 0 {
		c.Proof.Steps = redact.Slice(c.Proof.Steps)
	}
	c.Risk.Rationale = redact.String(c.Risk.Rationale)
	if len(c.Labels) > 0 {
		sanitized := make(map[string]string, len(c.Labels))
		for k, v := range c.Labels {
			sanitized[k] = redact.String(v)
		}
		c.Labels = sanitized
	}
	if len(c.Evidence) > 0 {
		for i := range c.Evidence {
			c.Evidence[i] = sanitizeEvidence(c.Evidence[i])
		}
	}
	if len(c.Sources) > 0 {
		for i := range c.Sources {
			c.Sources[i].Target = redact.String(c.Sources[i].Target)
		}
	}
	c.Graph.DOT = redact.String(c.Graph.DOT)
	c.Graph.Mermaid = redact.String(c.Graph.Mermaid)
	return c
}

func sanitizeEvidence(e EvidenceItem) EvidenceItem {
	e.Message = redact.String(e.Message)
	e.Evidence = redact.String(e.Evidence)
	if len(e.Metadata) > 0 {
		sanitized := make(map[string]string, len(e.Metadata))
		for k, v := range e.Metadata {
			sanitized[k] = redact.String(v)
		}
		e.Metadata = sanitized
	}
	return e
}
