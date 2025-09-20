package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/Glyph/internal/proxy"
)

type addressCaptureHandler struct {
	ch chan string
}

func (h *addressCaptureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *addressCaptureHandler) Handle(_ context.Context, record slog.Record) error {
	var address string
	record.Attrs(func(attr slog.Attr) bool {
		if attr.Key == "address" {
			address = attr.Value.String()
		}
		return true
	})
	if address != "" {
		select {
		case h.ch <- address:
		default:
		}
	}
	return nil
}

func (h *addressCaptureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *addressCaptureHandler) WithGroup(string) slog.Handler { return h }

func TestProxyEndToEndHTTPFlow(t *testing.T) {
	outDir := t.TempDir()
	t.Setenv("GLYPH_OUT", outDir)

	received := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headerCopy := r.Header.Clone()
		select {
		case received <- headerCopy:
		default:
		}
		w.Header().Set("Server", "upstream")
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(upstream.Close)

	rulesPath := filepath.Join(outDir, "rules.json")
	rules := `[{"name":"demo-rule","match":{"url_contains":"/demo"},"request":{"add_headers":{"X-Glyph":"on"}},"response":{"add_headers":{"X-Glyph-Proxy":"active"},"remove_headers":["Server"]}}]`
	if err := os.WriteFile(rulesPath, []byte(rules), 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	historyPath := filepath.Join(outDir, "proxy_history.jsonl")
	capture := &addressCaptureHandler{ch: make(chan string, 1)}

	cfg := config{
		addr:  "127.0.0.1:0",
		token: "test-token",
		proxy: proxy.Config{
			Addr:        "127.0.0.1:0",
			RulesPath:   rulesPath,
			HistoryPath: historyPath,
			CACertPath:  filepath.Join(outDir, "proxy_ca.pem"),
			CAKeyPath:   filepath.Join(outDir, "proxy_ca.key"),
			Logger:      slog.New(capture),
		},
		enableProxy: true,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx, cfg)
	}()

	var proxyAddr string
	select {
	case proxyAddr = <-capture.ch:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not report an address")
	}

	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("parse proxy address: %v", err)
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	targetURL := upstream.URL + "/demo"
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("send request via proxy: %v", err)
	}
	_ = resp.Body.Close()

	if got := resp.Header.Get("X-Glyph-Proxy"); got != "active" {
		t.Fatalf("expected response header to be rewritten, got %q", got)
	}
	if resp.Header.Get("Server") != "" {
		t.Fatal("expected Server header to be stripped")
	}

	select {
	case hdr := <-received:
		if hdr.Get("X-Glyph") != "on" {
			t.Fatalf("upstream request missing injected header: %#v", hdr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream request not observed")
	}

	cancel()

	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("glyphd did not shut down")
	}

	deadline := time.Now().Add(3 * time.Second)
	var entry proxy.HistoryEntry
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(historyPath)
		if err != nil {
			if os.IsNotExist(err) {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			t.Fatalf("read history: %v", err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) == 0 {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		last := strings.TrimSpace(lines[len(lines)-1])
		if last == "" {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if err := json.Unmarshal([]byte(last), &entry); err != nil {
			t.Fatalf("decode history entry: %v", err)
		}
		if entry.URL == targetURL {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if entry.URL != targetURL {
		t.Fatalf("history entry missing target URL, got %q", entry.URL)
	}
	if len(entry.MatchedRules) == 0 || entry.MatchedRules[0] != "demo-rule" {
		t.Fatalf("history missing rule reference: %#v", entry.MatchedRules)
	}
	if values := entry.RequestHeaders["X-Glyph"]; len(values) == 0 || values[0] != "on" {
		t.Fatalf("history missing request header injection: %#v", entry.RequestHeaders)
	}
	if _, ok := entry.ResponseHeaders["Server"]; ok {
		t.Fatalf("history still contains stripped Server header: %#v", entry.ResponseHeaders)
	}
}
