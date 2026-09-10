package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/findings"
	"github.com/RowanDark/0xgen/internal/ranker"
	"github.com/RowanDark/0xgen/internal/testutil"
)

func TestExecuteDemoFastPathDisclosesInProcessScan(t *testing.T) {
	t.Parallel()

	outDir := filepath.Join(t.TempDir(), "demo-out")
	var log strings.Builder
	progress := demoProgress{Writer: &log}

	if _, err := executeDemo(outDir, false, false, progress); err != nil {
		t.Fatalf("executeDemo: %v", err)
	}

	out := log.String()
	if !strings.Contains(out, "in-process detector") {
		t.Fatalf("expected fast-path disclosure in output, got:\n%s", out)
	}
	if !strings.Contains(out, "--full") {
		t.Fatalf("expected fast-path output to point at --full, got:\n%s", out)
	}
}

// TestExecuteDemoFullPathUsesRealLauncher exercises the --full path end to
// end: the seer plugin is built, allowlist- and (deliberately, since the
// checked-in signature cannot be verified without the private key)
// signature-checked, granted capabilities, and run inside the sandbox,
// connected over a real gRPC plugin bus. It requires a privileged sandbox
// (chroot) and is skipped in short mode like the other launcher-backed e2e
// tests.
func TestExecuteDemoFullPathUsesRealLauncher(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full plugin-path demo test in short mode")
	}
	t.Parallel()

	outDir := filepath.Join(t.TempDir(), "demo-out")
	var log strings.Builder
	progress := demoProgress{Writer: &log}

	result, err := executeDemo(outDir, false, true, progress)
	if err != nil {
		t.Fatalf("executeDemo --full: %v", err)
	}

	out := log.String()
	if !strings.Contains(out, "real plugin path") {
		t.Fatalf("expected --full output to describe the real plugin path, got:\n%s", out)
	}

	var sawRealPluginFinding bool
	for _, f := range result.Findings {
		if strings.HasPrefix(f.Plugin, "seer-") {
			sawRealPluginFinding = true
			break
		}
	}
	if !sawRealPluginFinding {
		t.Fatalf("expected at least one finding emitted by the sandboxed seer plugin, got: %+v", result.Findings)
	}
}

func TestFileURLFromPath(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		path string
		want string
	}{
		{name: "unix", path: "/tmp/demo/report.html", want: "file:///tmp/demo/report.html"},
		{name: "windows drive", path: `C:\\Users\\demo\\report.html`, want: "file:///C:/Users/demo/report.html"},
		{name: "unc", path: `\\\\server\\share\\report.html`, want: "file://server/share/report.html"},
		{name: "empty", path: "", want: ""},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := fileURLFromPath(tc.path)
			if got != tc.want {
				t.Fatalf("fileURLFromPath(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestFormatDuration(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   time.Duration
		want string
	}{
		{name: "zero", in: 0, want: "0s"},
		{name: "microseconds", in: 500 * time.Microsecond, want: "500µs"},
		{name: "milliseconds", in: 42 * time.Millisecond, want: "42ms"},
		{name: "seconds", in: 1500 * time.Millisecond, want: "1.5s"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := formatDuration(tc.in); got != tc.want {
				t.Fatalf("formatDuration(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestDiscoverLinks(t *testing.T) {
	t.Parallel()

	html := `
                <a href="/dashboard">Dashboard</a>
                <a href="/cases">Cases</a>
                <a href="https://example.com/login">External Login</a>
                <a href="http://127.0.0.1:4000/settings">Settings</a>
                <a href="mailto:alerts@example.com">Email</a>
                <a href="javascript:alert('xss')">Script</a>
                <a href="data:text/plain;base64,Zm9v">Data</a>
                <a href="vbscript:msgbox('hi')">VBScript</a>
                <a href="/cases">Duplicate</a>
        `

	internal, external := discoverLinks("http://127.0.0.1:4000", []byte(html))
	if internal != 3 {
		t.Fatalf("discoverLinks internal count = %d, want 3", internal)
	}
	if external != 1 {
		t.Fatalf("discoverLinks external count = %d, want 1", external)
	}
}

func TestSeverityLabel(t *testing.T) {
	t.Parallel()

	cases := map[findings.Severity]string{
		findings.SeverityCritical: "Critical",
		findings.SeverityHigh:     "High",
		findings.SeverityMedium:   "Medium",
		findings.SeverityLow:      "Low",
		findings.SeverityInfo:     "Informational",
	}

	for input, want := range cases {
		if got := severityLabel(input); got != want {
			t.Fatalf("severityLabel(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestPrintCasePreview(t *testing.T) {
	t.Parallel()

	detected := time.Date(2024, time.March, 14, 15, 9, 26, 0, time.UTC)
	finding := ranker.ScoredFinding{
		Finding: findings.Finding{
			Message:    "Captured login preview containing a session token",
			Severity:   findings.SeverityMedium,
			Target:     "http://127.0.0.1:4000/login",
			DetectedAt: findings.NewTimestamp(detected),
			Metadata: map[string]string{
				"oxg.case_owner": testutil.BrandSuffix("Demo"),
				"oxg.case_note":  "Auto-generated by 0xgenctl demo",
				"poc":            "curl demo",
				"session_token":  "demo-token",
				"thumbnail":      "data:image/svg+xml;base64,abc",
			},
		},
		Score:        65,
		ExposureHint: "public",
		Primary:      true,
	}

	var buf strings.Builder
	printCasePreview(&buf, finding)
	out := buf.String()
	expectedOwner := "Case owner: " + testutil.BrandSuffix("Demo")
	for _, want := range []string{
		"Case preview",
		"Captured login preview containing a session token",
		"Medium",
		"Proof of concept: curl demo",
		expectedOwner,
		"Score: 65 (primary, exposure: public)",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("printCasePreview output missing %q:\n%s", want, out)
		}
	}
}
