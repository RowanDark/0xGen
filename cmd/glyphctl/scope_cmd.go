package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/RowanDark/Glyph/internal/scope"
)

func runScope(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "scope subcommand required")
		return 2
	}

	switch args[0] {
	case "derive":
		return runScopeDerive(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown scope subcommand: %s\n", args[0])
		return 2
	}
}

func runScopeDerive(args []string) int {
	fs := flag.NewFlagSet("scope derive", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	inputPath := fs.String("input", "-", "path to bounty scope text (or - for stdin)")
	outputPath := fs.String("out", "scope.yaml", "path to write the generated scope policy")
	writeOut := fs.Bool("write", false, "write the generated policy to --out")
	autoYes := fs.Bool("yes", false, "apply changes without prompting (requires --write)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if fs.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "unexpected argument: %s\n", fs.Arg(0))
		return 2
	}

	if *writeOut && *inputPath == "-" && !*autoYes {
		fmt.Fprintln(os.Stderr, "cannot prompt for confirmation when reading scope text from stdin; rerun with --yes or --input path")
		return 2
	}

	scopeText, err := readScopeSource(*inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	policy := scope.ParsePolicyFromText(scopeText)
	policy.Normalise()

	summary := scope.Summarize(policy)
	summaryWriter := os.Stdout
	if !*writeOut {
		summaryWriter = os.Stderr
	}
	printPolicySummary(summaryWriter, summary)
	if summaryWriter == os.Stdout {
		fmt.Fprintln(os.Stdout)
	}

	rendered, err := encodePolicy(policy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "render scope policy: %v\n", err)
		return 1
	}

	if !*writeOut {
		os.Stdout.Write(rendered)
		if len(rendered) == 0 || rendered[len(rendered)-1] != '\n' {
			fmt.Fprintln(os.Stdout)
		}
		return 0
	}

	existing, err := os.ReadFile(*outputPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "read existing policy: %v\n", err)
			return 1
		}
		existing = nil
	}

	diff, err := previewDiff(existing, rendered, *outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "preview diff: %v\n", err)
		return 1
	}

	if diff == "" {
		fmt.Fprintln(os.Stdout, "scope policy unchanged; no updates written")
		return 0
	}

	fmt.Fprint(os.Stdout, diff)

	if !*autoYes {
		ok, err := promptConfirmation(os.Stdin, os.Stdout, fmt.Sprintf("Apply changes to %s? [y/N]: ", *outputPath))
		if err != nil {
			fmt.Fprintf(os.Stderr, "confirm update: %v\n", err)
			return 1
		}
		if !ok {
			fmt.Fprintln(os.Stdout, "aborted")
			return 1
		}
	}

	if err := writePolicyFile(*outputPath, rendered); err != nil {
		fmt.Fprintf(os.Stderr, "write scope policy: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stdout, "wrote %s\n", *outputPath)
	return 0
}

func readScopeSource(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("input path must not be empty")
	}
	if path == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("read scope text from stdin: %w", err)
		}
		return string(data), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read scope text %s: %w", path, err)
	}
	return string(data), nil
}

func encodePolicy(policy scope.Policy) ([]byte, error) {
	var builder strings.Builder
	builder.WriteString("version: 1\n")
	writeRuleSection(&builder, "allow", policy.Allow)
	writeRuleSection(&builder, "deny", policy.Deny)

	if policy.PrivateNetworks != scope.PrivateNetworksUnspecified {
		builder.WriteString("private_networks: ")
		builder.WriteString(yamlQuote(policy.PrivateNetworks))
		builder.WriteByte('\n')
	}

	if policy.PIIMode != scope.PIIModeUnspecified {
		builder.WriteString("pii: ")
		builder.WriteString(yamlQuote(policy.PIIMode))
		builder.WriteByte('\n')
	}

	builder.WriteByte('\n')
	return []byte(builder.String()), nil
}

func writeRuleSection(builder *strings.Builder, name string, rules []scope.Rule) {
	builder.WriteString(name)
	builder.WriteString(":\n")
	if len(rules) == 0 {
		builder.WriteString("  []\n")
		return
	}
	for _, rule := range rules {
		builder.WriteString("  - type: ")
		builder.WriteString(yamlQuote(rule.Type))
		builder.WriteByte('\n')
		builder.WriteString("    value: ")
		builder.WriteString(yamlQuote(rule.Value))
		builder.WriteByte('\n')
		if strings.TrimSpace(rule.Notes) != "" {
			builder.WriteString("    notes: ")
			builder.WriteString(yamlQuote(rule.Notes))
			builder.WriteByte('\n')
		}
	}
}

func yamlQuote(value string) string {
	var buf strings.Builder
	buf.WriteByte('"')
	for _, r := range value {
		switch r {
		case '\\', '"':
			buf.WriteByte('\\')
			buf.WriteRune(r)
		case '\n':
			buf.WriteString("\\n")
		case '\r':
			buf.WriteString("\\r")
		case '\t':
			buf.WriteString("\\t")
		default:
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
	return buf.String()
}

func previewDiff(oldContent, newContent []byte, outPath string) (string, error) {
	oldFile, err := os.CreateTemp("", "scope-old-*.yaml")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(oldFile.Name())
	defer oldFile.Close()

	if _, err := oldFile.Write(oldContent); err != nil {
		return "", fmt.Errorf("write temp old policy: %w", err)
	}

	newFile, err := os.CreateTemp("", "scope-new-*.yaml")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(newFile.Name())
	defer newFile.Close()

	if _, err := newFile.Write(newContent); err != nil {
		return "", fmt.Errorf("write temp new policy: %w", err)
	}

	labels := []string{
		fmt.Sprintf("%s (current)", filepath.Base(outPath)),
		fmt.Sprintf("%s (generated)", filepath.Base(outPath)),
	}

	cmd := exec.Command("diff", "-u", "--label", labels[0], "--label", labels[1], oldFile.Name(), newFile.Name())
	diffOut, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if exitErr.ExitCode() == 1 {
				return string(diffOut), nil
			}
		}
		if errors.Is(err, exec.ErrNotFound) {
			return simpleDiff(oldContent, newContent, outPath), nil
		}
		return "", fmt.Errorf("run diff command: %w", err)
	}

	if len(diffOut) == 0 {
		return "", nil
	}

	return string(diffOut), nil
}

func simpleDiff(oldContent, newContent []byte, outPath string) string {
	var buf strings.Builder
	buf.WriteString("--- old\n")
	buf.WriteString("+++ new\n")
	buf.WriteString(strings.TrimSpace(string(newContent)))
	buf.WriteString("\n")
	return buf.String()
}

func promptConfirmation(in io.Reader, out io.Writer, prompt string) (bool, error) {
	if _, err := fmt.Fprint(out, prompt); err != nil {
		return false, err
	}
	reader := bufio.NewReader(in)
	response, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	trimmed := strings.TrimSpace(strings.ToLower(response))
	return trimmed == "y" || trimmed == "yes", nil
}

func writePolicyFile(path string, content []byte) error {
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create policy directory: %w", err)
		}
	}
	return os.WriteFile(path, content, 0o600)
}

func printPolicySummary(out io.Writer, summary scope.Summary) {
	if out == nil {
		return
	}
	fmt.Fprintln(out, "Extracted scope policy:")
	fmt.Fprintf(out, "  Private networks: %s\n", summary.PrivateNetworks)
	if summary.PIIMode != scope.PIIModeUnspecified {
		fmt.Fprintf(out, "  PII mode: %s\n", summary.PIIMode)
	}
	printRuleGroup(out, "Allow", summary.Allow)
	printRuleGroup(out, "Deny", summary.Deny)
	fmt.Fprintln(out)
}

func printRuleGroup(out io.Writer, label string, group map[string][]string) {
	total := 0
	for _, values := range group {
		total += len(values)
	}
	if total == 0 {
		fmt.Fprintf(out, "  %s rules: none\n", label)
		return
	}
	fmt.Fprintf(out, "  %s rules:\n", label)
	for _, key := range orderedRuleTypes(group) {
		values := group[key]
		fmt.Fprintf(out, "    - %s (%d)\n", key, len(values))
		for _, value := range values {
			fmt.Fprintf(out, "        • %s\n", value)
		}
	}
}

func orderedRuleTypes(group map[string][]string) []string {
	predefined := []string{
		scope.RuleTypeDomain,
		scope.RuleTypeWildcard,
		scope.RuleTypeURL,
		scope.RuleTypePrefix,
		scope.RuleTypePath,
		scope.RuleTypeCIDR,
		scope.RuleTypeIP,
		scope.RuleTypePattern,
	}
	seen := make(map[string]struct{}, len(group))
	var order []string
	for _, typ := range predefined {
		if _, ok := group[typ]; ok {
			order = append(order, typ)
			seen[typ] = struct{}{}
		}
	}
	var rest []string
	for typ := range group {
		if _, ok := seen[typ]; ok {
			continue
		}
		rest = append(rest, typ)
	}
	sort.Strings(rest)
	order = append(order, rest...)
	return order
}
