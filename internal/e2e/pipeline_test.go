package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/findings"
	"github.com/RowanDark/0xgen/internal/reporter"
)

type goldenFinding struct {
	Plugin   string            `json:"plugin"`
	Type     string            `json:"type"`
	Message  string            `json:"message"`
	Severity findings.Severity `json:"severity"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

func TestPipelinePassiveHeaderScanGolden(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping pipeline golden test in short mode")
	}

	target := newPassiveTargetServer(t)
	defer target.Close()

	// Sanity check the deterministic response used by the pipeline.
	resp, err := target.Client().Get(target.URL + "/security")
	if err != nil {
		t.Fatalf("failed to query test target: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected test target status: %d", resp.StatusCode)
	}
	for _, header := range []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Content-Type-Options",
		"X-Frame-Options",
	} {
		if resp.Header.Get(header) != "" {
			t.Fatalf("expected %s header to be empty", header)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	root := repoRoot(t)
	glyphdBin := buildGlyphd(ctx, t, root)
	glyphctlBin := buildGlyphctl(ctx, t, root)

	outDir := t.TempDir()
	findingsPath := filepath.Join(outDir, "findings.jsonl")

	listenAddr, dialAddr := resolveAddresses(t)
	cmdCtx, cmdCancel := context.WithCancel(ctx)
	glyphd := exec.CommandContext(cmdCtx, glyphdBin, "--addr", listenAddr, "--token", "test-token")
	glyphd.Dir = root
	glyphd.Env = append(os.Environ(), "0XGEN_OUT="+outDir)

	var stdout, stderr bytes.Buffer
	glyphd.Stdout = &stdout
	glyphd.Stderr = &stderr

	if err := glyphd.Start(); err != nil {
		t.Fatalf("failed to start glyphd: %v", err)
	}

	done := make(chan struct{})
	var glyphdErr error
	go func() {
		glyphdErr = glyphd.Wait()
		close(done)
	}()

	t.Cleanup(func() {
		cmdCancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("glyphd did not exit after cancellation")
		}
	})

	if err := waitForListener(cmdCtx, dialAddr, done, func() error { return glyphdErr }); err != nil {
		t.Fatalf("glyphd did not become ready: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	pluginCmd := exec.CommandContext(ctx, glyphctlBin, "plugin", "run", "--sample", "passive-header-scan", "--server", dialAddr, "--token", "test-token", "--duration", "6s")
	pluginCmd.Dir = root
	pluginCmd.Env = append(os.Environ(), "0XGEN_OUT="+outDir)
	var pluginOut, pluginErr bytes.Buffer
	pluginCmd.Stdout = &pluginOut
	pluginCmd.Stderr = &pluginErr

	if err := pluginCmd.Run(); err != nil {
		t.Fatalf("glyphctl plugin run failed: %v\nstdout:\n%s\nstderr:\n%s", err, pluginOut.String(), pluginErr.String())
	}

	findingsList := waitForFindings(t, findingsPath, 4, 10*time.Second)
	comparable := normaliseFindings(findingsList)
	sort.SliceStable(comparable, func(i, j int) bool {
		left := comparable[i]
		right := comparable[j]
		leftHeader := ""
		rightHeader := ""
		if left.Metadata != nil {
			leftHeader = left.Metadata["header"]
		}
		if right.Metadata != nil {
			rightHeader = right.Metadata["header"]
		}
		if leftHeader == rightHeader {
			return left.Message < right.Message
		}
		return leftHeader < rightHeader
	})

	goldenPath := filepath.Join(root, "internal", "e2e", "testdata", "passive_header_scan_golden.json")
	golden := loadGoldenFindings(t, goldenPath)

	if !reflect.DeepEqual(comparable, golden) {
		encoded, err := json.MarshalIndent(comparable, "", "  ")
		if err != nil {
			t.Fatalf("failed to encode comparable findings: %v", err)
		}
		t.Fatalf("pipeline findings did not match golden file\nwant: %s\n got: %s", mustJSON(golden), string(encoded))
	}
}

func newPassiveTargetServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/security", func(w http.ResponseWriter, r *http.Request) {
		// Deliberately omit the security headers the passive scan plugin expects.
		w.Header().Set("Server", "glyph-e2e")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/security", http.StatusFound)
	})
	return httptest.NewServer(mux)
}

func waitForFindings(t *testing.T, path string, minCount int, timeout time.Duration) []findings.Finding {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for {
		findingsList, err := reporter.ReadJSONL(path)
		if err != nil {
			t.Fatalf("read findings: %v", err)
		}
		if len(findingsList) >= minCount {
			return findingsList
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	findingsList, err := reporter.ReadJSONL(path)
	if err != nil {
		t.Fatalf("read findings after timeout: %v", err)
	}
	if len(findingsList) < minCount {
		t.Fatalf("expected at least %d findings, got %d", minCount, len(findingsList))
	}
	return findingsList
}

func normaliseFindings(input []findings.Finding) []goldenFinding {
	byHeader := make(map[string]goldenFinding)
	for _, finding := range input {
		if finding.Type != "missing-security-header" {
			continue
		}
		header := finding.Metadata["header"]
		if header == "" {
			continue
		}
		if _, exists := byHeader[header]; exists {
			continue
		}
		basePlugin := normalisePluginID(finding.Plugin)
		metadata := make(map[string]string, len(finding.Metadata))
		for k, v := range finding.Metadata {
			metadata[k] = v
		}
		byHeader[header] = goldenFinding{
			Plugin:   basePlugin,
			Type:     finding.Type,
			Message:  finding.Message,
			Severity: finding.Severity,
			Metadata: metadata,
		}
	}
	comparable := make([]goldenFinding, 0, len(byHeader))
	for _, gf := range byHeader {
		comparable = append(comparable, gf)
	}
	return comparable
}

func normalisePluginID(id string) string {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return trimmed
	}
	idx := strings.LastIndex(trimmed, "-")
	if idx == -1 {
		return trimmed
	}
	suffix := trimmed[idx+1:]
	if _, err := strconv.Atoi(suffix); err == nil {
		return trimmed[:idx]
	}
	return trimmed
}

func loadGoldenFindings(t *testing.T, path string) []goldenFinding {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden file: %v", err)
	}
	var golden []goldenFinding
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatalf("decode golden file: %v", err)
	}
	return golden
}

func mustJSON(v any) string {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(data)
}
