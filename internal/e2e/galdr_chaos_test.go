package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/proxy"
)

func TestGaldrProxyUpstreamFailureReports502(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatalf("upstream does not support hijacking")
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack upstream connection: %v", err)
		}
		defer conn.Close()

		_, _ = buf.WriteString("HTTP/1.1 503 Service Unavailable\r\n")
		_, _ = buf.WriteString("Content-Length: 10\r\n")
		_, _ = buf.WriteString("Content-Type: text/plain\r\n\r\n")
		_, _ = buf.WriteString("fail")
		_ = buf.Flush()
	}))
	t.Cleanup(upstream.Close)

	tempDir := t.TempDir()
	cfg := proxy.Config{
		Addr:        "127.0.0.1:0",
		RulesPath:   writeTempFile(t, tempDir, "rules.json", "[]"),
		HistoryPath: filepath.Join(tempDir, "history.jsonl"),
		CACertPath:  filepath.Join(tempDir, "ca.pem"),
		CAKeyPath:   filepath.Join(tempDir, "ca.key"),
	}

	p, logs, stop := startProxyForChaos(t, cfg)
	defer stop()

	proxyURL, _ := url.Parse("http://" + p.Addr())
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	defer transport.CloseIdleConnections()

	resp, err := client.Get(upstream.URL + "/chaos")
	if err != nil {
		t.Fatalf("request via proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status code = %d, want 502. body: %s", resp.StatusCode, string(body))
	}

	entries := parseJSONLogs(t, logs.Bytes())
	assertProxyErrorLog(t, entries, "/chaos", "")
}

func TestGaldrProxyTimeoutsReturnBadGateway(t *testing.T) {
	t.Parallel()

	t.Run("SlowHeadersHTTP2", func(t *testing.T) {
		t.Parallel()

		upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(2 * time.Second)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}))
		upstream.EnableHTTP2 = true
		upstream.StartTLS()
		t.Cleanup(upstream.Close)

		cert := upstream.Certificate()
		if cert == nil {
			t.Fatal("upstream certificate missing")
		}
		pool := x509.NewCertPool()
		pool.AddCert(cert)

		tempDir := t.TempDir()
		cfg := proxy.Config{
			Addr:        "127.0.0.1:0",
			RulesPath:   writeTempFile(t, tempDir, "rules.json", "[]"),
			HistoryPath: filepath.Join(tempDir, "history.jsonl"),
			CACertPath:  filepath.Join(tempDir, "ca.pem"),
			CAKeyPath:   filepath.Join(tempDir, "ca.key"),
			Transport: &http.Transport{
				TLSClientConfig:       &tls.Config{RootCAs: pool},
				ResponseHeaderTimeout: 200 * time.Millisecond,
			},
		}

		p, logs, stop := startProxyForChaos(t, cfg)
		defer stop()

		proxyURL, _ := url.Parse("http://" + p.Addr())
		caPool := x509PoolFromPEM(p.CACertificatePEM(), t)
		transport := &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool},
		}
		client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		defer transport.CloseIdleConnections()

		resp, err := client.Get(upstream.URL + "/slow")
		if err != nil {
			t.Fatalf("request via proxy: %v", err)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("status code = %d, want 502", resp.StatusCode)
		}

		entries := parseJSONLogs(t, logs.Bytes())
		assertProxyErrorLog(t, entries, "/slow", "")
	})

	t.Run("SlowBody", func(t *testing.T) {
		t.Parallel()

		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			time.Sleep(500 * time.Millisecond)
			_, _ = w.Write([]byte("late"))
		}))
		t.Cleanup(upstream.Close)

		tempDir := t.TempDir()
		cfg := proxy.Config{
			Addr:        "127.0.0.1:0",
			RulesPath:   writeTempFile(t, tempDir, "rules.json", "[]"),
			HistoryPath: filepath.Join(tempDir, "history.jsonl"),
			CACertPath:  filepath.Join(tempDir, "ca.pem"),
			CAKeyPath:   filepath.Join(tempDir, "ca.key"),
			Transport:   newTimeoutTransport(150 * time.Millisecond),
		}

		p, logs, stop := startProxyForChaos(t, cfg)
		defer stop()

		proxyURL, _ := url.Parse("http://" + p.Addr())
		transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
		client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		defer transport.CloseIdleConnections()

		resp, err := client.Get(upstream.URL + "/slow-body")
		if err != nil {
			t.Fatalf("request via proxy: %v", err)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("status code = %d, want 502", resp.StatusCode)
		}

		entries := parseJSONLogs(t, logs.Bytes())
		assertProxyErrorLog(t, entries, "/slow-body", "")
	})
}

func TestGaldrProxyModifyResponseFailureIncludesRule(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	rules := `[{"name":"chaos-rule","match":{"url_contains":"/modify"}}]`
	cfg := proxy.Config{
		Addr:        "127.0.0.1:0",
		RulesPath:   writeTempFile(t, tempDir, "rules.json", rules),
		HistoryPath: filepath.Join(tempDir, "history.jsonl"),
		CACertPath:  filepath.Join(tempDir, "ca.pem"),
		CAKeyPath:   filepath.Join(tempDir, "ca.key"),
		Transport:   &ruleErrorTransport{ruleName: "chaos-rule"},
	}

	p, logs, stop := startProxyForChaos(t, cfg)
	defer stop()

	proxyURL, _ := url.Parse("http://" + p.Addr())
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	defer transport.CloseIdleConnections()

	resp, err := client.Get("http://example.com/modify")
	if err != nil {
		t.Fatalf("request via proxy: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status code = %d, want 502", resp.StatusCode)
	}

	entries := parseJSONLogs(t, logs.Bytes())
	assertProxyErrorLog(t, entries, "/modify", "chaos-rule")
}

type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logBuffer) Bytes() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]byte(nil), l.buf.Bytes()...)
}

func startProxyForChaos(t *testing.T, cfg proxy.Config) (*proxy.Proxy, *logBuffer, func()) {
	t.Helper()

	logs := &logBuffer{}
	cfg.Logger = slog.New(slog.NewJSONHandler(logs, nil))

	p, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- p.Run(ctx)
	}()

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readyCancel()
	if err := p.WaitUntilReady(readyCtx); err != nil {
		cancel()
		select {
		case runErr := <-errCh:
			if runErr != nil && runErr != context.Canceled {
				t.Fatalf("proxy run failed: %v", runErr)
			}
		default:
		}
		t.Fatalf("proxy not ready: %v", err)
	}

	stop := func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil && err != context.Canceled {
				t.Fatalf("proxy exited with error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout waiting for proxy shutdown")
		}
	}

	return p, logs, stop
}

func parseJSONLogs(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	var entries []map[string]any
	for {
		var entry map[string]any
		if err := decoder.Decode(&entry); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("decode log entry: %v\nlogs: %s", err, string(data))
		}
		entries = append(entries, entry)
	}
	return entries
}

func assertProxyErrorLog(t *testing.T, entries []map[string]any, pathFragment, expectedRule string) {
	t.Helper()
	for _, entry := range entries {
		msg, _ := entry["msg"].(string)
		if msg != "reverse proxy error" {
			continue
		}
		urlVal, _ := entry["url"].(string)
		if !strings.Contains(urlVal, pathFragment) {
			continue
		}
		component, _ := entry["component"].(string)
		if component != "galdr" {
			t.Fatalf("component = %q, want galdr", component)
		}
		event, _ := entry["event"].(string)
		if event != "proxy_error" {
			t.Fatalf("event = %q, want proxy_error", event)
		}
		rule, ok := entry["rule"].(string)
		if !ok {
			t.Fatalf("rule field missing in entry: %#v", entry)
		}
		if rule != expectedRule {
			t.Fatalf("rule = %q, want %q", rule, expectedRule)
		}
		if _, ok := entry["err"].(string); !ok {
			t.Fatalf("err field missing in entry: %#v", entry)
		}
		return
	}
	t.Fatalf("reverse proxy error log not found for %s", pathFragment)
}

type timeoutTransport struct {
	*http.Transport
	limit time.Duration
}

func newTimeoutTransport(limit time.Duration) *timeoutTransport {
	base, _ := http.DefaultTransport.(*http.Transport)
	transport := base.Clone()
	transport.Proxy = nil
	transport.ProxyConnectHeader = nil
	return &timeoutTransport{Transport: transport, limit: limit}
}

func (t *timeoutTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(req.Context(), t.limit)
	outReq := req.Clone(ctx)
	resp, err := t.Transport.RoundTrip(outReq)
	if err != nil {
		cancel()
		return nil, err
	}
	resp.Body = &cancelOnCloseReadCloser{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

type cancelOnCloseReadCloser struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnCloseReadCloser) Close() error {
	c.cancel()
	return c.ReadCloser.Close()
}

type ruleErrorTransport struct {
	ruleName string
}

func (r *ruleErrorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body := &ruleErrorBody{rule: r.ruleName}
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Status:        http.StatusText(http.StatusOK),
		Header:        make(http.Header),
		Body:          body,
		ContentLength: -1,
		Request:       req,
	}
	return resp, nil
}

type ruleErrorBody struct {
	rule string
}

func (b *ruleErrorBody) Read([]byte) (int, error) {
	return 0, &proxy.RuleError{RuleID: b.rule, Err: errors.New("modify response failure")}
}

func (b *ruleErrorBody) Close() error { return nil }
