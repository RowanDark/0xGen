package cases

import (
	"fmt"
	"sort"
	"strings"
)

func buildExploitGraph(c Case, summary SummaryOutput, chain attackChain) ExploitGraph {
	if len(chain.Steps) == 0 {
		return buildFallbackExploitGraph(c, summary)
	}

	dot := buildChainDOT(chain)
	mermaid := buildChainMermaid(chain)

	orderedSteps := make([]ChainStep, len(chain.Steps))
	copy(orderedSteps, chain.Steps)
	sort.SliceStable(orderedSteps, func(i, j int) bool {
		return orderedSteps[i].Stage < orderedSteps[j].Stage
	})

	return ExploitGraph{
		DOT:        dot,
		Mermaid:    mermaid,
		Summary:    chain.Summary,
		AttackPath: orderedSteps,
	}
}

func buildFallbackExploitGraph(c Case, summary SummaryOutput) ExploitGraph {
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

func buildChainDOT(chain attackChain) string {
	var b strings.Builder
	b.WriteString("digraph AttackChain {\n")
	b.WriteString("    rankdir=LR;\n")
	b.WriteString("    node [shape=box];\n")

	nodeIDs := make(map[string]string, len(chain.Nodes))
	for i, node := range chain.Nodes {
		id := fmt.Sprintf("n%d", i)
		nodeIDs[node] = id
		fmt.Fprintf(&b, "    %s [label=\"%s\"];\n", id, escapeDOT(node))
	}

	for _, step := range chain.Steps {
		fromID := nodeIDs[step.From]
		toID := nodeIDs[step.To]
		if fromID == "" || toID == "" {
			continue
		}
		label := fmt.Sprintf("S%d: %s (%s)", step.Stage, safeGraphText(step.Description), step.Plugin)
		attrs := fmt.Sprintf("label=\"%s\"", escapeDOT(label))
		if step.WeakLink {
			attrs += ", color=\"orange\", style=\"dashed\""
		}
		fmt.Fprintf(&b, "    %s -> %s [%s];\n", fromID, toID, attrs)
	}
	b.WriteString("}\n")
	return b.String()
}

func buildChainMermaid(chain attackChain) string {
	var b strings.Builder
	b.WriteString("graph TD\n")
	for _, step := range chain.Steps {
		connector := "-->"
		if step.WeakLink {
			connector = "-.->"
		}
		label := fmt.Sprintf("S%d: %s (%s)", step.Stage, safeGraphText(step.Description), step.Plugin)
		fmt.Fprintf(&b, "    %s[\"%s\"] %s %s[\"%s\"] |%s|\n",
			sanitizeMermaidID(step.From), escapeMermaid(step.From), connector,
			sanitizeMermaidID(step.To), escapeMermaid(step.To), escapeMermaid(label))
	}
	return b.String()
}

func sanitizeMermaidID(label string) string {
	cleaned := strings.NewReplacer(" ", "_", "-", "_", ".", "_", "/", "_", "(", "_", ")", "_").Replace(strings.ToLower(label))
	cleaned = strings.Trim(cleaned, "_")
	if cleaned == "" {
		return "node"
	}
	return cleaned
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
