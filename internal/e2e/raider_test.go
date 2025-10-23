package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/raider"
)

func TestCliRaiderRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping raider e2e in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var (
		mu   sync.Mutex
		hits []time.Time
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		payload, _ := io.ReadAll(r.Body)
		mu.Lock()
		hits = append(hits, time.Now())
		mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	reqTemplate := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: text/plain\r\n\r\nbody={{seed}}\r\n", srv.URL, srv.Listener.Addr().String())

	tempDir := t.TempDir()
	reqPath := filepath.Join(tempDir, "request.http")
	if err := os.WriteFile(reqPath, []byte(reqTemplate), 0o600); err != nil {
		t.Fatalf("write request template: %v", err)
	}

	payloads := []string{"alpha", "beta", "gamma"}
	payloadPath := filepath.Join(tempDir, "payloads.txt")
	if err := os.WriteFile(payloadPath, []byte(strings.Join(payloads, "\n")), 0o600); err != nil {
		t.Fatalf("write payload file: %v", err)
	}

	root := repoRoot(t)
	cliPath := buildCli(ctx, t, root)

	cmd := exec.CommandContext(ctx, cliPath, "raider", "run", "--req", reqPath, "--positions", "{{}}", "--payload", payloadPath, "--concurrency", "3", "--rate", "2/s")
	cmd.Dir = root
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	if err := cmd.Run(); err != nil {
		t.Fatalf("0xgenctl raider run failed: %v\nstderr:\n%s", err, stderr.String())
	}
	duration := time.Since(start)

	decoder := json.NewDecoder(&stdout)
	var results []raider.Result
	for decoder.More() {
		var res raider.Result
		if err := decoder.Decode(&res); err != nil {
			t.Fatalf("decode result: %v", err)
		}
		results = append(results, res)
	}

	if len(results) != len(payloads) {
		t.Fatalf("expected %d results, got %d", len(payloads), len(results))
	}

	if len(hits) != len(payloads) {
		t.Fatalf("expected %d requests, got %d", len(payloads), len(hits))
	}

	counts := make(map[string]int, len(results))
	for i, res := range results {
		counts[res.Payload]++
		if res.Status == "" {
			t.Errorf("result %d missing status", i)
		}
	}
	for _, payload := range payloads {
		if counts[payload] == 0 {
			t.Fatalf("missing payload %q in results", payload)
		}
	}

	if len(hits) >= 2 {
		total := hits[len(hits)-1].Sub(hits[0])
		expected := time.Duration(float64(len(hits)-1) / 2.0 * float64(time.Second))
		if total+150*time.Millisecond < expected {
			t.Fatalf("requests completed too quickly (duration %v, expected at least %v)", total, expected)
		}
	}

	if duration < 500*time.Millisecond {
		t.Fatalf("run completed suspiciously fast: %v", duration)
	}
}
