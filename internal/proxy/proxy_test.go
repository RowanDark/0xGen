package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"log/slog"

	"github.com/RowanDark/0xgen/internal/flows"
	"github.com/RowanDark/0xgen/internal/scope"
	"github.com/RowanDark/0xgen/internal/testutil"
	pb "github.com/RowanDark/0xgen/proto/gen/go/proto/glyph"
)

type recordedRequest struct {
	Header http.Header
	Body   []byte
}

type recordedFlow struct {
	ID                string
	Sequence          uint64
	Timestamp         time.Time
	Type              pb.FlowEvent_Type
	Sanitized         []byte
	Raw               []byte
	RawBodySize       int
	RawBodyCaptured   int
	SanitizedRedacted bool
}

type recordingPublisher struct {
	mu     sync.Mutex
	events []recordedFlow
}

func (r *recordingPublisher) PublishFlowEvent(ctx context.Context, event flows.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := recordedFlow{
		ID:                event.ID,
		Sequence:          event.Sequence,
		Timestamp:         event.Timestamp,
		Type:              event.Type,
		RawBodySize:       event.RawBodySize,
		RawBodyCaptured:   event.RawBodyCaptured,
		SanitizedRedacted: event.SanitizedRedacted,
	}
	if len(event.Sanitized) > 0 {
		entry.Sanitized = append([]byte(nil), event.Sanitized...)
	}
	if len(event.Raw) > 0 {
		entry.Raw = append([]byte(nil), event.Raw...)
	}
	r.events = append(r.events, entry)
	return nil
}

func (r *recordingPublisher) snapshot() []recordedFlow {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]recordedFlow, len(r.events))
	copy(out, r.events)
	return out
}

type logCaptureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *logCaptureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *logCaptureHandler) Handle(_ context.Context, record slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, record.Clone())
	return nil
}

func (h *logCaptureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *logCaptureHandler) WithGroup(string) slog.Handler { return h }

func (h *logCaptureHandler) contains(level slog.Level, substr string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, rec := range h.records {
		if rec.Level == level && strings.Contains(rec.Message, substr) {
			return true
		}
	}
	return false
}

func expectedRedactedBody(body string) string {
	sum := sha256.Sum256([]byte(body))
	return fmt.Sprintf("[REDACTED body length=%d sha256=%s]", len(body), hex.EncodeToString(sum[:]))
}

func expectedTruncationHeader(body string) string {
	sum := sha256.Sum256([]byte(body))
	return fmt.Sprintf("%s: %d;sha256=%s", rawBodyTruncatedHeader, len(body), hex.EncodeToString(sum[:]))
}

type filteringScope struct {
	block string
}

func (f filteringScope) Evaluate(candidate string) scope.Decision {
	if strings.Contains(candidate, f.block) {
		return scope.Decision{Allowed: false, Reason: scope.DecisionDeniedByRule}
	}
	return scope.Decision{Allowed: true, Reason: scope.DecisionAllowed}
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func waitErr(t *testing.T, ch <-chan error) {
	t.Helper()
	select {
	case err := <-ch:
		if err != nil {
			t.Fatalf("proxy exited with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for proxy shutdown")
	}
}

func TestProxyEndToEndHeaderRewrite(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "upstream-demo")
		_, _ = w.Write([]byte("demo"))
	}))
	t.Cleanup(upstream.Close)

	tempDir := t.TempDir()
	rules := `[{"name":"demo-rewrite","match":{"url_contains":"/"},"response":{"add_headers":{"X-0xgen":"on","Content-Security-Policy":"default-src 'self'"},"remove_headers":["Server"]}}]`
	rulesPath := filepath.Join(tempDir, "rules.json")
	if err := os.WriteFile(rulesPath, []byte(rules), 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	historyPath := filepath.Join(tempDir, "history.jsonl")
	cfg := Config{
		Addr:        "127.0.0.1:0",
		RulesPath:   rulesPath,
		HistoryPath: historyPath,
		CACertPath:  filepath.Join(tempDir, "ca.pem"),
		CAKeyPath:   filepath.Join(tempDir, "ca.key"),
		Logger:      newTestLogger(),
	}

	proxy, err := New(cfg)
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.Run(ctx)
	}()

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readyCancel()
	if err := proxy.WaitUntilReady(readyCtx); err != nil {
		t.Fatalf("proxy not ready: %v", err)
	}

	proxyURL, _ := url.Parse("http://" + proxy.Addr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("http request via proxy: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	testutil.RequireModernHeader(t, resp.Header, "X-0xgen", "on")
	if got := resp.Header.Get("Content-Security-Policy"); got != "default-src 'self'" {
		t.Fatalf("csp header = %q", got)
	}
	if got := resp.Header.Get("Server"); got != "" {
		t.Fatalf("expected server header stripped, got %q", got)
	}

	cancel()
	waitErr(t, errCh)

	data, err := os.ReadFile(historyPath)
	if err != nil {
		t.Fatalf("read history: %v", err)
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		t.Fatal("history file empty")
	}
	lines := strings.Split(trimmed, "\n")
	if len(lines) != 1 {
		t.Fatalf("expected single history entry, got %d", len(lines))
	}

	var entry HistoryEntry
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("decode history: %v", err)
	}
	if entry.StatusCode != http.StatusOK {
		t.Fatalf("history status = %d", entry.StatusCode)
	}
	if !contains(entry.MatchedRules, "demo-rewrite") {
		t.Fatalf("history missing rule reference: %#v", entry.MatchedRules)
	}
	testutil.RequireModernHeaderMap(t, entry.ResponseHeaders, "X-0xgen", "on")
	if _, exists := entry.ResponseHeaders["Server"]; exists {
		t.Fatal("history should not include stripped server header")
	}
}

func TestProxyIgnoresLegacyHeaders(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(upstream.Close)

	tempDir := t.TempDir()
	rules := `[{"name":"legacy","match":{"url_contains":"/"},"response":{"add_headers":{"X-Glyph-Proxy":"legacy"}}}]`
	rulesPath := filepath.Join(tempDir, "rules.json")
	if err := os.WriteFile(rulesPath, []byte(rules), 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	historyPath := filepath.Join(tempDir, "history.jsonl")
	handler := &logCaptureHandler{}
	cfg := Config{
		Addr:        "127.0.0.1:0",
		RulesPath:   rulesPath,
		HistoryPath: historyPath,
		CACertPath:  filepath.Join(tempDir, "ca.pem"),
		CAKeyPath:   filepath.Join(tempDir, "ca.key"),
		Logger:      slog.New(handler),
	}

	proxy, err := New(cfg)
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.Run(ctx)
	}()

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readyCancel()
	if err := proxy.WaitUntilReady(readyCtx); err != nil {
		t.Fatalf("proxy not ready: %v", err)
	}

	proxyURL, _ := url.Parse("http://" + proxy.Addr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("http request via proxy: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if got := resp.Header.Get("X-0xgen-Proxy"); got != "" {
		t.Fatalf("expected X-0xgen-Proxy header to be absent, got %q", got)
	}
	if legacy := resp.Header.Get("X-Glyph-Proxy"); legacy != "" {
		t.Fatalf("expected legacy header to be absent, got %q", legacy)
	}

	cancel()
	waitErr(t, errCh)

	data, err := os.ReadFile(historyPath)
	if err != nil {
		t.Fatalf("read history: %v", err)
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		t.Fatal("history file empty")
	}
	var entry HistoryEntry
	if err := json.Unmarshal([]byte(trimmed), &entry); err != nil {
		t.Fatalf("decode history: %v", err)
	}
	if _, exists := entry.ResponseHeaders["X-0xgen-Proxy"]; exists {
		t.Fatal("expected modern header to be absent in history")
	}
	if _, exists := entry.ResponseHeaders["X-Glyph-Proxy"]; exists {
		t.Fatal("expected legacy header to be absent in history")
	}
	if handler.contains(slog.LevelWarn, "legacy") {
		t.Fatal("unexpected legacy header warning")
	}
}

func TestProxyHTTPModificationAndHistory(t *testing.T) {
	t.Parallel()

	received := make(chan recordedRequest, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		received <- recordedRequest{Header: r.Header.Clone(), Body: body}
		w.Header().Set("X-Origin", "upstream")
		_, _ = w.Write([]byte("origin"))
	}))
	t.Cleanup(upstream.Close)

	tempDir := t.TempDir()
	target := upstream.URL + "/test"

	rules := `[{
        "name": "modify-http",
        "match": {"url_contains": "/test"},
        "request": {"add_headers": {"X-Galdr-Request": "yes"}},
        "response": {"add_headers": {"X-Galdr-Response": "added"}, "body": {"set": "rewritten"}}
    }]`
	rulesPath := filepath.Join(tempDir, "rules.json")
	if err := os.WriteFile(rulesPath, []byte(rules), 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	historyPath := filepath.Join(tempDir, "history.jsonl")
	cfg := Config{
		Addr:        "127.0.0.1:0",
		RulesPath:   rulesPath,
		HistoryPath: historyPath,
		CACertPath:  filepath.Join(tempDir, "ca.pem"),
		CAKeyPath:   filepath.Join(tempDir, "ca.key"),
		Logger:      newTestLogger(),
	}

	proxy, err := New(cfg)
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.Run(ctx)
	}()

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readyCancel()
	if err := proxy.WaitUntilReady(readyCtx); err != nil {
		t.Fatalf("proxy not ready: %v", err)
	}

	proxyURL, _ := url.Parse("http://" + proxy.Addr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("http get via proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if got, want := resp.Header.Get("X-Galdr-Response"), "added"; got != want {
		t.Fatalf("response header = %q, want %q", got, want)
	}
	if got, want := string(body), "rewritten"; got != want {
		t.Fatalf("response body = %q, want %q", got, want)
	}

	select {
	case req := <-received:
		if got := req.Header.Get("X-Galdr-Request"); got != "yes" {
			t.Fatalf("upstream header missing, got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for upstream request")
	}

	cancel()
	waitErr(t, errCh)

	data, err := os.ReadFile(historyPath)
	if err != nil {
		t.Fatalf("read history: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 {
		t.Fatalf("no history entries")
	}

	var entry HistoryEntry
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &entry); err != nil {
		t.Fatalf("decode history: %v", err)
	}
	if entry.Method != "GET" {
		t.Fatalf("history method = %q", entry.Method)
	}
	if !contains(entry.MatchedRules, "modify-http") {
		t.Fatalf("history missing rule reference: %#v", entry.MatchedRules)
	}
	if headers := entry.RequestHeaders["X-Galdr-Request"]; len(headers) == 0 || headers[0] != "yes" {
		t.Fatalf("history missing request header")
	}
	if headers := entry.ResponseHeaders["X-Galdr-Response"]; len(headers) == 0 || headers[0] != "added" {
		t.Fatalf("history missing response header")
	}
}

func TestProxyPublishesFlowEvents(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
		w.Header().Set("X-Upstream", "ok")
		w.Header().Add("Set-Cookie", "session=raw-token; HttpOnly")
		_, _ = w.Write([]byte("payload"))
	}))
	t.Cleanup(upstream.Close)

	tempDir := t.TempDir()
	publisher := &recordingPublisher{}

	cfg := Config{
		Addr:          "127.0.0.1:0",
		RulesPath:     filepath.Join(tempDir, "rules.json"),
		HistoryPath:   filepath.Join(tempDir, "history.jsonl"),
		CACertPath:    filepath.Join(tempDir, "ca.pem"),
		CAKeyPath:     filepath.Join(tempDir, "ca.key"),
		Logger:        newTestLogger(),
		FlowPublisher: publisher,
	}

	proxy, err := New(cfg)
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.Run(ctx)
	}()

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readyCancel()
	if err := proxy.WaitUntilReady(readyCtx); err != nil {
		t.Fatalf("proxy not ready: %v", err)
	}

	proxyURL, _ := url.Parse("http://" + proxy.Addr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, err := http.NewRequest(http.MethodPost, upstream.URL+"/flow", strings.NewReader("sensitive-body"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer demo-secret")
	req.Header.Set("Cookie", "session=abc; theme=dark")
	req.Header.Set("X-API-KEY", "key-123")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("http request via proxy: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	cancel()
	waitErr(t, errCh)

	events := publisher.snapshot()
	if len(events) != 2 {
		t.Fatalf("expected 2 flow events, got %d", len(events))
	}

	if events[0].Type != pb.FlowEvent_FLOW_REQUEST {
		t.Fatalf("first event type = %v, want FLOW_REQUEST", events[0].Type)
	}
	if events[0].ID == "" {
		t.Fatal("request event missing id")
	}
	if events[0].Sequence == 0 {
		t.Fatal("request event missing sequence")
	}
	if events[0].Timestamp.IsZero() {
		t.Fatal("request event timestamp not set")
	}
	if events[0].RawBodySize != len("sensitive-body") {
		t.Fatalf("request raw size = %d", events[0].RawBodySize)
	}
	if events[0].RawBodyCaptured != events[0].RawBodySize {
		t.Fatalf("request raw captured = %d", events[0].RawBodyCaptured)
	}
	if !events[0].SanitizedRedacted {
		t.Fatal("request event should mark sanitized redaction")
	}
	if len(events[0].Raw) == 0 || len(events[0].Sanitized) == 0 {
		t.Fatalf("request event missing raw or sanitized payload")
	}
	rawReq := string(events[0].Raw)
	if !strings.Contains(rawReq, "Authorization: Bearer demo-secret") {
		t.Fatalf("raw request missing authorization header: %q", rawReq)
	}
	if !strings.Contains(rawReq, "Cookie: session=abc; theme=dark") {
		t.Fatalf("raw request missing cookie header: %q", rawReq)
	}
	if strings.Contains(rawReq, rawBodyTruncatedHeader) {
		t.Fatalf("raw request unexpectedly flagged as truncated: %q", rawReq)
	}
	sanitizedReq := string(events[0].Sanitized)
	if !strings.Contains(sanitizedReq, "Authorization: Bearer [REDACTED]") {
		t.Fatalf("sanitized request missing authorization redaction: %q", sanitizedReq)
	}
	if strings.Contains(sanitizedReq, "demo-secret") {
		t.Fatalf("sanitized request leaked secret: %q", sanitizedReq)
	}
	if !strings.Contains(sanitizedReq, "Cookie: session=<redacted>; theme=<redacted>") {
		t.Fatalf("sanitized request cookie not redacted: %q", sanitizedReq)
	}
	if !strings.Contains(sanitizedReq, "X-Api-Key: [REDACTED]") && !strings.Contains(sanitizedReq, "X-API-KEY: [REDACTED]") {
		t.Fatalf("sanitized request api key not redacted: %q", sanitizedReq)
	}
	if !strings.Contains(sanitizedReq, "X-0xgen-Body-Redacted: 14") {
		t.Fatalf("sanitized request missing body metadata: %q", sanitizedReq)
	}
	if strings.Contains(sanitizedReq, "X-Glyph-Body-Redacted") {
		t.Fatalf("sanitized request still includes legacy header: %q", sanitizedReq)
	}
	if !strings.Contains(sanitizedReq, expectedRedactedBody("sensitive-body")) {
		t.Fatalf("sanitized request body placeholder missing: %q", sanitizedReq)
	}

	if events[1].Type != pb.FlowEvent_FLOW_RESPONSE {
		t.Fatalf("second event type = %v, want FLOW_RESPONSE", events[1].Type)
	}
	if events[1].Sequence <= events[0].Sequence {
		t.Fatalf("response sequence %d should be greater than request %d", events[1].Sequence, events[0].Sequence)
	}
	if events[1].RawBodySize != len("payload") {
		t.Fatalf("response raw size = %d", events[1].RawBodySize)
	}
	if events[1].RawBodyCaptured != events[1].RawBodySize {
		t.Fatalf("response raw captured = %d", events[1].RawBodyCaptured)
	}
	if !events[1].SanitizedRedacted {
		t.Fatal("response event should mark sanitized redaction")
	}
	if len(events[1].Raw) == 0 || len(events[1].Sanitized) == 0 {
		t.Fatalf("response event missing raw or sanitized payload")
	}
	rawResp := string(events[1].Raw)
	if !strings.Contains(rawResp, "Set-Cookie: session=raw-token; HttpOnly") {
		t.Fatalf("raw response missing set-cookie header: %q", rawResp)
	}
	sanitizedResp := string(events[1].Sanitized)
	if strings.Contains(sanitizedResp, "raw-token") {
		t.Fatalf("sanitized response leaked cookie token: %q", sanitizedResp)
	}
	if !strings.Contains(sanitizedResp, "Set-Cookie: session=<redacted>; HttpOnly") {
		t.Fatalf("sanitized response cookie not redacted: %q", sanitizedResp)
	}
	if !strings.Contains(sanitizedResp, "X-0xgen-Body-Redacted: 7") {
		t.Fatalf("sanitized response missing body metadata: %q", sanitizedResp)
	}
	if strings.Contains(sanitizedResp, "X-Glyph-Body-Redacted") {
		t.Fatalf("sanitized response still includes legacy header: %q", sanitizedResp)
	}
	if !strings.Contains(sanitizedResp, expectedRedactedBody("payload")) {
		t.Fatalf("sanitized response body placeholder missing: %q", sanitizedResp)
	}
}

func TestProxyFlowSamplingDisabled(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	tempDir := t.TempDir()
	publisher := &recordingPublisher{}

	cfg := Config{
		Addr:          "127.0.0.1:0",
		RulesPath:     filepath.Join(tempDir, "rules.json"),
		HistoryPath:   filepath.Join(tempDir, "history.jsonl"),
		CACertPath:    filepath.Join(tempDir, "ca.pem"),
		CAKeyPath:     filepath.Join(tempDir, "ca.key"),
		Logger:        newTestLogger(),
		FlowPublisher: publisher,
		Flow: FlowCaptureConfig{
			Enabled:    true,
			SampleRate: 0,
		},
	}

	proxy, err := New(cfg)
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.Run(ctx)
	}()

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readyCancel()
	if err := proxy.WaitUntilReady(readyCtx); err != nil {
		t.Fatalf("proxy not ready: %v", err)
	}

	proxyURL, _ := url.Parse("http://" + proxy.Addr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("http request via proxy: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	cancel()
	waitErr(t, errCh)

	if events := publisher.snapshot(); len(events) != 0 {
		t.Fatalf("expected 0 events when sampling disabled, got %d", len(events))
	}
}

func TestProxyRawBodyLimitTruncates(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	tempDir := t.TempDir()
	publisher := &recordingPublisher{}

	cfg := Config{
		Addr:          "127.0.0.1:0",
		RulesPath:     filepath.Join(tempDir, "rules.json"),
		HistoryPath:   filepath.Join(tempDir, "history.jsonl"),
		CACertPath:    filepath.Join(tempDir, "ca.pem"),
		CAKeyPath:     filepath.Join(tempDir, "ca.key"),
		Logger:        newTestLogger(),
		FlowPublisher: publisher,
		Flow: FlowCaptureConfig{
			Enabled:      true,
			SampleRate:   1,
			MaxBodyBytes: 5,
		},
	}

	proxy, err := New(cfg)
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.Run(ctx)
	}()

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readyCancel()
	if err := proxy.WaitUntilReady(readyCtx); err != nil {
		t.Fatalf("proxy not ready: %v", err)
	}

	proxyURL, _ := url.Parse("http://" + proxy.Addr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, err := http.NewRequest(http.MethodPost, upstream.URL+"/truncate", strings.NewReader("sensitive-body"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("http request via proxy: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	cancel()
	waitErr(t, errCh)

	events := publisher.snapshot()
	if len(events) == 0 {
		t.Fatal("expected at least one flow event")
	}
	request := events[0]
	if request.RawBodyCaptured != 5 {
		t.Fatalf("expected captured raw body 5, got %d", request.RawBodyCaptured)
	}
	if request.RawBodySize != len("sensitive-body") {
		t.Fatalf("raw body size = %d", request.RawBodySize)
	}
	raw := string(request.Raw)
	if !strings.Contains(raw, expectedTruncationHeader("sensitive-body")) {
		t.Fatalf("expected raw payload to note truncation: %q", raw)
	}
	sanitized := string(request.Sanitized)
	if !strings.Contains(sanitized, expectedRedactedBody("sensitive-body")) {
		t.Fatalf("sanitized body placeholder missing from truncated request")
	}
}

func TestProxySuppressesOutOfScopeFlows(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(upstream.Close)

	tempDir := t.TempDir()
	publisher := &recordingPublisher{}

	cfg := Config{
		Addr:          "127.0.0.1:0",
		RulesPath:     filepath.Join(tempDir, "rules.json"),
		HistoryPath:   filepath.Join(tempDir, "history.jsonl"),
		CACertPath:    filepath.Join(tempDir, "ca.pem"),
		CAKeyPath:     filepath.Join(tempDir, "ca.key"),
		Logger:        newTestLogger(),
		FlowPublisher: publisher,
		Scope:         filteringScope{block: "/blocked"},
	}

	proxy, err := New(cfg)
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.Run(ctx)
	}()

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readyCancel()
	if err := proxy.WaitUntilReady(readyCtx); err != nil {
		t.Fatalf("proxy not ready: %v", err)
	}

	proxyURL, _ := url.Parse("http://" + proxy.Addr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(upstream.URL + "/blocked")
	if err != nil {
		t.Fatalf("http request via proxy: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	cancel()
	waitErr(t, errCh)

	events := publisher.snapshot()
	if len(events) != 0 {
		t.Fatalf("expected 0 flow events for out-of-scope request, got %d", len(events))
	}
}

func TestBuildRequestEventHandlesEmptyState(t *testing.T) {
	t.Parallel()

	state := &proxyFlowState{}
	cfg := FlowCaptureConfig{Enabled: true, SampleRate: 1, MaxBodyBytes: -1}
	event := buildRequestEvent(state, cfg)
	if event == nil {
		t.Fatal("expected event for empty state")
	}
	if len(event.Raw) == 0 {
		t.Fatal("raw payload should not be empty")
	}
	if len(event.Sanitized) == 0 {
		t.Fatal("sanitized payload should not be empty")
	}
	if event.RawBodySize != 0 {
		t.Fatalf("expected raw body size 0, got %d", event.RawBodySize)
	}
}

func TestProxyHTTPSInterception(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin", "https")
		_, _ = w.Write([]byte("secure"))
	}))
	t.Cleanup(upstream.Close)

	pool := x509.NewCertPool()
	cert := upstream.Certificate()
	if cert == nil {
		t.Fatal("upstream certificate missing")
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatal("failed to append upstream certificate")
	}

	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}

	tempDir := t.TempDir()
	rules := `[{
        "name": "https-rule",
        "match": {"url_contains": "https"},
        "response": {"add_headers": {"X-Proxy-Injected": "true"}}
    }]`
	rulesPath := filepath.Join(tempDir, "rules.json")
	if err := os.WriteFile(rulesPath, []byte(rules), 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	cfg := Config{
		Addr:        "127.0.0.1:0",
		RulesPath:   rulesPath,
		HistoryPath: filepath.Join(tempDir, "history.jsonl"),
		CACertPath:  filepath.Join(tempDir, "ca.pem"),
		CAKeyPath:   filepath.Join(tempDir, "ca.key"),
		Logger:      newTestLogger(),
		Transport:   transport,
	}

	proxy, err := New(cfg)
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.Run(ctx)
	}()

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readyCancel()
	if err := proxy.WaitUntilReady(readyCtx); err != nil {
		t.Fatalf("proxy not ready: %v", err)
	}

	proxyURL, _ := url.Parse("http://" + proxy.Addr())
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(proxy.CACertificatePEM()) {
		t.Fatal("failed to append proxy CA")
	}

	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: caPool},
	}}

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("https request via proxy: %v", err)
	}
	_ = resp.Body.Close()

	if got := resp.Header.Get("X-Proxy-Injected"); got != "true" {
		t.Fatalf("expected injected header, got %q", got)
	}

	cancel()
	waitErr(t, errCh)

	data, err := os.ReadFile(cfg.HistoryPath)
	if err != nil {
		t.Fatalf("read history: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 {
		t.Fatalf("missing history entries")
	}
	var entry HistoryEntry
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &entry); err != nil {
		t.Fatalf("decode history: %v", err)
	}
	if entry.Protocol != "HTTPS" {
		t.Fatalf("history protocol = %q", entry.Protocol)
	}
	if !contains(entry.MatchedRules, "https-rule") {
		t.Fatalf("https rule missing from history")
	}
	if headers := entry.ResponseHeaders["X-Proxy-Injected"]; len(headers) == 0 || headers[0] != "true" {
		t.Fatalf("history missing injected header")
	}
}

func contains(list []string, needle string) bool {
	for _, item := range list {
		if item == needle {
			return true
		}
	}
	return false
}
