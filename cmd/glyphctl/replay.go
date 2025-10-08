package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/RowanDark/Glyph/internal/cases"
	"github.com/RowanDark/Glyph/internal/replay"
	"github.com/RowanDark/Glyph/internal/reporter"
)

func runReplay(args []string) int {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	outDir := fs.String("out", "", "directory to write replay outputs (defaults to ${GLYPH_OUT:-.}/replay)")
	verifyOnly := fs.Bool("verify-only", false, "only verify recorded cases without writing outputs")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: glyphctl replay [--out dir] <artifact>")
		return 2
	}

	artefactPath := strings.TrimSpace(fs.Arg(0))
	if artefactPath == "" {
		fmt.Fprintln(os.Stderr, "artifact path is required")
		return 2
	}
	if _, err := os.Stat(artefactPath); err != nil {
		fmt.Fprintf(os.Stderr, "open artifact: %v\n", err)
		return 1
	}

	dest := strings.TrimSpace(*outDir)
	if dest == "" {
		if env := strings.TrimSpace(os.Getenv("GLYPH_OUT")); env != "" {
			dest = filepath.Join(env, "replay")
		} else {
			cwd, err := os.Getwd()
			if err != nil {
				fmt.Fprintf(os.Stderr, "determine working directory: %v\n", err)
				return 1
			}
			dest = filepath.Join(cwd, "replay")
		}
	}

	tmpDir, err := os.MkdirTemp("", "glyph-replay-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create temp dir: %v\n", err)
		return 1
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	manifest, err := replay.ExtractArtifact(artefactPath, tmpDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "extract artifact: %v\n", err)
		return 1
	}

	findingsPath := filepath.Join(tmpDir, filepath.FromSlash(manifest.FindingsFile))
	findingsList, err := reporter.ReadJSONL(findingsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load findings: %v\n", err)
		return 1
	}

	builder := configureCaseBuilder(manifest)
	builtCases, err := builder.Build(context.Background(), findingsList)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build cases: %v\n", err)
		return 1
	}

	expectedCasesPath := filepath.Join(tmpDir, filepath.FromSlash(manifest.CasesFile))
	expectedCases, err := replay.LoadCases(expectedCasesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load recorded cases: %v\n", err)
		return 1
	}

	if !replay.CasesEqual(builtCases, expectedCases) {
		fmt.Fprintln(os.Stderr, "replayed cases diverged from recorded output")
		return 1
	}

	var flowRecords []replay.FlowRecord
	if strings.TrimSpace(manifest.FlowsFile) != "" {
		flowsPath := filepath.Join(tmpDir, filepath.FromSlash(manifest.FlowsFile))
		flowRecords, err = replay.LoadFlows(flowsPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load flows: %v\n", err)
			return 1
		}
	}

	if *verifyOnly {
		fmt.Fprintf(os.Stdout, "verified %d cases from %s\n", len(builtCases), artefactPath)
		return 0
	}

	if err := os.MkdirAll(dest, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "create output directory: %v\n", err)
		return 1
	}

	outputCasesPath := filepath.Join(dest, "cases.replay.json")
	if err := replay.WriteCases(outputCasesPath, builtCases); err != nil {
		fmt.Fprintf(os.Stderr, "write replay cases: %v\n", err)
		return 1
	}

	if len(flowRecords) > 0 {
		flowsOutput := filepath.Join(dest, "flows.replay.jsonl")
		if err := replay.WriteFlows(flowsOutput, flowRecords); err != nil {
			fmt.Fprintf(os.Stderr, "write flows: %v\n", err)
			return 1
		}
	}

	if err := exportSupplemental(manifest, tmpDir, dest); err != nil {
		fmt.Fprintf(os.Stderr, "export supplemental data: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stdout, "replayed %d cases to %s\n", len(builtCases), outputCasesPath)
	return 0
}

func configureCaseBuilder(manifest replay.Manifest) *cases.Builder {
	var opts []cases.Option
	if manifest.CaseTimestamp.IsZero() {
		manifest.CaseTimestamp = time.Now().UTC()
	}
	opts = append(opts, cases.WithClock(func() time.Time { return manifest.CaseTimestamp }))
	if seed, ok := manifest.Seeds["cases"]; ok {
		opts = append(opts, cases.WithDeterministicMode(seed))
	}
	return cases.NewBuilder(opts...)
}

func exportSupplemental(manifest replay.Manifest, root, dest string) error {
	if len(manifest.Responses) == 0 && len(manifest.Robots) == 0 {
		return nil
	}
	copyFile := func(relPath, targetDir string) error {
		if strings.TrimSpace(relPath) == "" {
			return nil
		}
		src := filepath.Join(root, filepath.FromSlash(relPath))
		if _, err := os.Stat(src); err != nil {
			return fmt.Errorf("missing supplemental file %s: %w", relPath, err)
		}
		if err := os.MkdirAll(targetDir, 0o755); err != nil {
			return fmt.Errorf("create supplemental directory: %w", err)
		}
		dst := filepath.Join(targetDir, filepath.Base(relPath))
		data, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("read supplemental file %s: %w", relPath, err)
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return fmt.Errorf("write supplemental file %s: %w", relPath, err)
		}
		return nil
	}

	responsesDir := filepath.Join(dest, "responses")
	for _, resp := range manifest.Responses {
		if err := copyFile(resp.BodyFile, responsesDir); err != nil {
			return err
		}
	}
	robotsDir := filepath.Join(dest, "robots")
	for _, rob := range manifest.Robots {
		if err := copyFile(rob.BodyFile, robotsDir); err != nil {
			return err
		}
	}
	return nil
}
