package e2e

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/findings"
)

//go:embed testdata/passive_header_scenarios.json
var passiveHeaderScenarioData []byte

type passiveHeaderScenario struct {
	Name        string            `json:"name"`
	App         string            `json:"app"`
	Description string            `json:"description"`
	Path        string            `json:"path"`
	Status      int               `json:"status"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
}

func TestPassiveHeaderRealWorldScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping passive header scenarios in short mode")
	}

	scenarios := loadPassiveHeaderScenarios(t)
	for _, scenario := range scenarios {
		scenario := scenario
		t.Run(scenario.Name, func(t *testing.T) {
			runPassiveHeaderScenario(t, scenario)
		})
	}
}

func runPassiveHeaderScenario(t *testing.T, scenario passiveHeaderScenario) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	target := newScenarioServer(t, scenario)
	defer target.Close()

	root := repoRoot(t)
	daemonBin := buildDaemon(ctx, t, root)
	cliBin := buildCli(ctx, t, root)

	outDir := filepath.Join(t.TempDir(), scenario.Name)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("create scenario output dir: %v", err)
	}
	findingsPath := filepath.Join(outDir, "findings.jsonl")
	reportPath := filepath.Join(outDir, "report.md")
	historyPath := filepath.Join(outDir, fmt.Sprintf("%s_history.jsonl", scenario.Name))

	daemonListen, daemonDial := resolveAddresses(t)
	proxyListen, proxyDial := resolveAddresses(t)

	cmdCtx, cmdCancel := context.WithCancel(ctx)
	daemon := exec.CommandContext(cmdCtx, daemonBin,
		"--addr", daemonListen,
		"--token", "scenario-token",
		"--enable-proxy",
		"--proxy-addr", proxyListen,
		"--proxy-history", historyPath,
	)
	daemon.Dir = root
	daemon.Env = append(os.Environ(),
		"0XGEN_OUT="+outDir,
		"0XGEN_SYNC_WRITES=1",
		"0XGEN_DISABLE_EVENT_GENERATOR=1",
	)

	var daemonStdout, daemonStderr bytes.Buffer
	daemon.Stdout = &daemonStdout
	daemon.Stderr = &daemonStderr

	if err := daemon.Start(); err != nil {
		t.Fatalf("failed to start 0xgend: %v", err)
	}

	done := make(chan struct{})
	var daemonErr error
	go func() {
		daemonErr = daemon.Wait()
		close(done)
	}()

	t.Cleanup(func() {
		cmdCancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("0xgend did not exit after cancellation\nstdout:\n%s\nstderr:\n%s", daemonStdout.String(), daemonStderr.String())
		}
	})

	if err := waitForListener(cmdCtx, daemonDial, done, func() error { return daemonErr }); err != nil {
		t.Fatalf("0xgend gRPC listener not ready: %v\nstdout:\n%s\nstderr:\n%s", err, daemonStdout.String(), daemonStderr.String())
	}
	if err := waitForListener(cmdCtx, proxyDial, done, func() error { return daemonErr }); err != nil {
		t.Fatalf("galdr proxy listener not ready: %v\nstdout:\n%s\nstderr:\n%s", err, daemonStdout.String(), daemonStderr.String())
	}

	pluginCmd := exec.CommandContext(ctx, cliBin,
		"plugin", "run",
		"--sample", "passive-header-scan",
		"--server", daemonDial,
		"--token", "scenario-token",
		"--duration", "15s",
	)
	pluginCmd.Dir = root
	pluginCmd.Env = append(os.Environ(),
		"0XGEN_OUT="+outDir,
		"0XGEN_SYNC_WRITES=1",
	)

	var pluginStdout, pluginStderr bytes.Buffer
	pluginCmd.Stdout = &pluginStdout
	pluginCmd.Stderr = &pluginStderr

	if err := pluginCmd.Start(); err != nil {
		t.Fatalf("start plugin: %v", err)
	}
	pluginDone := make(chan error, 1)
	go func() {
		pluginDone <- pluginCmd.Wait()
	}()

	proxyURL, err := url.Parse("http://" + proxyDial)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	requestCtx, requestCancel := context.WithCancel(ctx)
	defer requestCancel()

	requestURL := target.URL + scenario.Path

	sendRequest := func(parent context.Context) error {
		req, err := http.NewRequestWithContext(parent, http.MethodGet, requestURL, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if resp.StatusCode != scenario.statusCode() {
			return fmt.Errorf("unexpected status code %d", resp.StatusCode)
		}
		return nil
	}

	go func() {
		ticker := time.NewTicker(400 * time.Millisecond)
		defer ticker.Stop()
		// Fire an immediate request before waiting on the ticker to reduce startup latency.
		_ = sendRequest(requestCtx)
		for {
			select {
			case <-requestCtx.Done():
				return
			case <-ticker.C:
				_ = sendRequest(requestCtx)
			}
		}
	}()

	expected := expectedScenarioFindings(scenario)
	findings := waitForFindings(t, findingsPath, len(expected), 10*time.Second)
	comparable := normaliseFindings(findings)
	sort.SliceStable(comparable, func(i, j int) bool {
		return comparable[i].Message < comparable[j].Message
	})
	sort.SliceStable(expected, func(i, j int) bool {
		return expected[i].Message < expected[j].Message
	})

	if len(comparable) != len(expected) {
		t.Fatalf("unexpected number of findings: got %d want %d\nstdout:\n%s\nstderr:\n%s", len(comparable), len(expected), pluginStdout.String(), pluginStderr.String())
	}
	for i := range expected {
		if !reflect.DeepEqual(comparable[i], expected[i]) {
			t.Fatalf("scenario findings mismatch at index %d\nwant: %s\n got: %s", i, mustJSON(expected[i]), mustJSON(comparable[i]))
		}
	}

	requestCancel()

	select {
	case err := <-pluginDone:
		if err != nil {
			t.Fatalf("plugin execution failed: %v\nstdout:\n%s\nstderr:\n%s", err, pluginStdout.String(), pluginStderr.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("plugin did not exit within timeout\nstdout:\n%s\nstderr:\n%s", pluginStdout.String(), pluginStderr.String())
	}

	if daemon.Process != nil {
		_ = daemon.Process.Signal(os.Interrupt)
	}

	if _, err := os.Stat(historyPath); err != nil {
		t.Fatalf("proxy history missing: %v", err)
	}
	historyData, err := os.ReadFile(historyPath)
	if err != nil {
		t.Fatalf("read proxy history: %v", err)
	}
	if strings.TrimSpace(string(historyData)) == "" {
		t.Fatal("proxy history empty")
	}

	if err := runCliReport(ctx, root, cliBin, findingsPath, reportPath); err != nil {
		t.Fatalf("0xgenctl report failed: %v", err)
	}
	if info, err := os.Stat(reportPath); err != nil {
		t.Fatalf("report missing: %v", err)
	} else if info.Size() == 0 {
		t.Fatal("report file empty")
	}

	t.Logf("scenario %s artifacts stored in %s", scenario.Name, outDir)
}

func loadPassiveHeaderScenarios(t *testing.T) []passiveHeaderScenario {
	t.Helper()

	var scenarios []passiveHeaderScenario
	if err := json.Unmarshal(passiveHeaderScenarioData, &scenarios); err != nil {
		t.Fatalf("decode passive header scenarios: %v", err)
	}
	if len(scenarios) == 0 {
		t.Fatal("no passive header scenarios defined")
	}
	return scenarios
}

func newScenarioServer(t *testing.T, scenario passiveHeaderScenario) *httptest.Server {
	t.Helper()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for header, value := range scenario.Headers {
			if value == "" {
				continue
			}
			w.Header().Set(header, value)
		}
		status := scenario.statusCode()
		w.WriteHeader(status)
		if _, err := w.Write([]byte(scenario.Body)); err != nil {
			t.Fatalf("write scenario body: %v", err)
		}
	})
	server := httptest.NewServer(handler)
	return server
}

func (s passiveHeaderScenario) statusCode() int {
	if s.Status <= 0 {
		return http.StatusOK
	}
	return s.Status
}

func expectedScenarioFindings(scenario passiveHeaderScenario) []goldenFinding {
	recommendations := map[string]string{
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Content-Security-Policy":   "default-src 'none'",
	}

	expected := make([]goldenFinding, 0, len(recommendations))
	for header, recommendation := range recommendations {
		if value, ok := scenario.Headers[header]; ok && strings.TrimSpace(value) != "" {
			continue
		}
		expected = append(expected, goldenFinding{
			Plugin:   "passive-header-scan",
			Type:     "missing-security-header",
			Message:  fmt.Sprintf("response missing %s header", header),
			Severity: findings.SeverityMedium,
			Metadata: map[string]string{
				"header":         header,
				"recommendation": recommendation,
			},
		})
	}
	return expected
}

func runCliReport(ctx context.Context, root, cliBin, findingsPath, reportPath string) error {
	reportCmd := exec.CommandContext(ctx, cliBin, "report", "--input", findingsPath, "--out", reportPath)
	reportCmd.Dir = root
	reportCmd.Env = append(os.Environ(), "0XGEN_OUT="+filepath.Dir(reportPath))
	output, err := reportCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("0xgenctl report: %w\n%s", err, string(output))
	}
	return nil
}
