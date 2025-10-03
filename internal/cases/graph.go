package cases

import (
	"fmt"
	"strings"
)

func buildExploitGraph(c Case, summary SummaryOutput) ExploitGraph {
	preconditions := fmt.Sprintf("Asset: %s", safeGraphText(c.Asset.Identifier))
	if c.Vector.Kind != "" {
		vector := c.Vector.Kind
		if c.Vector.Value != "" {
			vector = fmt.Sprintf("%s (%s)", vector, c.Vector.Value)
		}
		preconditions = preconditions + "\\nVector: " + safeGraphText(vector)
	}

	action := "Follow synthesised reproduction"
	if len(summary.ReproductionSteps) > 0 {
		action = summary.ReproductionSteps[0]
	} else if summary.ProofSummary != "" {
		action = summary.ProofSummary
	}

	post := fmt.Sprintf("Impact: %s", strings.ToUpper(string(summary.RiskSeverity)))
	if summary.RiskRationale != "" {
		post = post + "\\n" + summary.RiskRationale
	}

	dot := fmt.Sprintf(`digraph ExploitPath {
    rankdir=LR;
    node [shape=box];
    pre [label="%s"];
    act [label="%s"];
    post [label="%s"];
    pre -> act -> post;
}`, escapeDOT(preconditions), escapeDOT(action), escapeDOT(post))

	mermaid := fmt.Sprintf(`graph TD
    pre["%s"] --> act["%s"] --> post["%s"]
`, escapeMermaid(preconditions), escapeMermaid(action), escapeMermaid(post))

	return ExploitGraph{DOT: dot, Mermaid: mermaid}
}

func safeGraphText(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unspecified"
	}
	return s
}

func escapeDOT(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}

func escapeMermaid(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "<br/>")
	return s
}
