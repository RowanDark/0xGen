package cases

import (
	"context"
	"fmt"
	"strings"

	"github.com/RowanDark/0xgen/internal/findings"
)

// SummaryInput contains the data passed to the summariser implementation.
type SummaryInput struct {
	Case     Case                `json:"case"`
	Findings []NormalisedFinding `json:"findings"`
	Prompts  PromptSet           `json:"prompts"`
}

// SummaryOutput captures the structured content returned by the summariser.
type SummaryOutput struct {
	Summary           string            `json:"summary"`
	ProofSummary      string            `json:"proof_summary"`
	ReproductionSteps []string          `json:"reproduction_steps"`
	RiskSeverity      findings.Severity `json:"risk_severity"`
	RiskScore         float64           `json:"risk_score"`
	RiskRationale     string            `json:"risk_rationale"`
	ConfidenceScore   float64           `json:"confidence_score"`
	ConfidenceLog     string            `json:"confidence_log"`
}

// Summarizer collapses multiple findings into a single explanation and proof of concept.
type Summarizer interface {
	Summarize(ctx context.Context, input SummaryInput) (SummaryOutput, error)
}

// DefaultSummarizer returns a deterministic summarizer that does not require network calls.
func DefaultSummarizer() Summarizer {
	return deterministicSummarizer{}
}

type deterministicSummarizer struct{}

func (deterministicSummarizer) Summarize(_ context.Context, input SummaryInput) (SummaryOutput, error) {
	if len(input.Findings) == 0 {
		return SummaryOutput{}, fmt.Errorf("no findings supplied to summarizer")
	}

	asset := input.Case.Asset.Identifier
	if input.Case.Asset.Details != "" {
		asset = fmt.Sprintf("%s (%s)", asset, input.Case.Asset.Details)
	}

	pluginSet := make(map[string]struct{})
	severity := findings.SeverityInfo
	var summaryLines []string
	for _, f := range input.Findings {
		pluginSet[f.Plugin] = struct{}{}
		if severityOrder[f.Severity] > severityOrder[severity] {
			severity = f.Severity
		}
		summaryLines = append(summaryLines, fmt.Sprintf("- [%s] %s (%s)", strings.Title(f.Plugin), f.Message, strings.ToUpper(string(f.Severity))))
	}

	summary := fmt.Sprintf("%d plugin signal(s) indicate an issue affecting %s.", len(pluginSet), asset)
	summary += "\n\nKey evidence:\n" + strings.Join(summaryLines, "\n")

	steps := buildReproductionSteps(input)
	confidence, log := scoreConfidence(pluginSet, input.Findings)
	riskScore := scoreRisk(severity)

	return SummaryOutput{
		Summary:           summary,
		ProofSummary:      fmt.Sprintf("Reproduce the issue on %s by following %d synthesised steps.", input.Case.Asset.Identifier, len(steps)),
		ReproductionSteps: steps,
		RiskSeverity:      severity,
		RiskScore:         riskScore,
		RiskRationale:     fmt.Sprintf("Highest severity reported by contributing plugins: %s", strings.ToUpper(string(severity))),
		ConfidenceScore:   confidence,
		ConfidenceLog:     log,
	}, nil
}

func buildReproductionSteps(input SummaryInput) []string {
	if len(input.Prompts.ReproductionPrompt) > 0 {
		// Provide deterministic synthetic steps derived from prompts to emulate prompt chaining.
		return []string{
			fmt.Sprintf("Review plugin evidence: %s", strings.TrimSpace(input.Prompts.SummaryPrompt)),
			fmt.Sprintf("Execute reproduction instructions synthesised from prompt: %s", strings.TrimSpace(input.Prompts.ReproductionPrompt)),
		}
	}
	return []string{"Review plugin evidence", "Attempt to recreate based on gathered artefacts"}
}

func scoreConfidence(plugins map[string]struct{}, findings []NormalisedFinding) (float64, string) {
	uniquePlugins := len(plugins)
	totalFindings := len(findings)
	if totalFindings == 0 {
		return 0, "no findings"
	}
	base := 0.35 + 0.2*float64(uniquePlugins-1)
	if base < 0.2 {
		base = 0.2
	}
	if base > 0.9 {
		base = 0.9
	}
	// Reward corroborating evidence from the same plugin without exceeding 1.0.
	corroboration := 0.05 * float64(totalFindings-uniquePlugins)
	score := base + corroboration
	if score > 1.0 {
		score = 1.0
	}
	log := fmt.Sprintf("%d plugin(s), %d finding(s)", uniquePlugins, totalFindings)
	return score, log
}

func scoreRisk(severity findings.Severity) float64 {
	switch severity {
	case findings.SeverityCritical:
		return 9.5
	case findings.SeverityHigh:
		return 8.0
	case findings.SeverityMedium:
		return 5.5
	case findings.SeverityLow:
		return 3.0
	default:
		return 1.0
	}
}
