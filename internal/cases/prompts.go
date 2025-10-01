package cases

import (
	"bytes"
	"fmt"
	"strings"
)

// PromptSet contains the LLM-ready prompts generated for a case.
type PromptSet struct {
	SummaryPrompt      string `json:"summary_prompt"`
	ReproductionPrompt string `json:"reproduction_prompt"`
}

// BuildPrompts generates deterministic prompts that can be fed to an LLM for richer summaries.
func BuildPrompts(proto Case, findings []NormalisedFinding) PromptSet {
	summary := buildSummaryPrompt(proto, findings)
	repro := buildReproductionPrompt(proto, findings)
	return PromptSet{SummaryPrompt: summary, ReproductionPrompt: repro}
}

func buildSummaryPrompt(proto Case, findings []NormalisedFinding) string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "You are an AI security analyst. Summarise why the following signals combine into a single case.\n")
	fmt.Fprintf(&buf, "Asset: %s (%s)\n", proto.Asset.Identifier, proto.Asset.Kind)
	fmt.Fprintf(&buf, "Attack vector: %s", proto.Vector.Kind)
	if proto.Vector.Value != "" {
		fmt.Fprintf(&buf, " (%s)", proto.Vector.Value)
	}
	buf.WriteString("\nEvidence:\n")
	for _, f := range findings {
		fmt.Fprintf(&buf, "- Plugin=%s Severity=%s Message=%s\n", f.Plugin, strings.ToUpper(string(f.Severity)), f.Message)
	}
	buf.WriteString("Provide a concise narrative and highlight overlapping evidence.\n")
	return buf.String()
}

func buildReproductionPrompt(proto Case, findings []NormalisedFinding) string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "Synthesize deterministic reproduction steps for asset %s (%s).\n", proto.Asset.Identifier, proto.Asset.Kind)
	buf.WriteString("Use at most 4 steps. Incorporate plugin observations:\n")
	for _, f := range findings {
		if strings.TrimSpace(f.Evidence) != "" {
			fmt.Fprintf(&buf, "- %s evidence: %s\n", strings.Title(f.Plugin), truncate(f.Evidence, 200))
		} else {
			fmt.Fprintf(&buf, "- %s observed: %s\n", strings.Title(f.Plugin), f.Message)
		}
	}
	buf.WriteString("Return concise imperative steps.")
	return buf.String()
}

func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}
