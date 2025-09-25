package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestProxyErrorSurface(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))

	proxy := &Proxy{transport: http.DefaultTransport, logger: logger}

	originalModifier := proxyResponseModifier
	proxyResponseModifier = func(pxy *Proxy, resp *http.Response, state *proxyFlowState) error {
		if resp.Request.URL.Path == "/boom" {
			return &RuleError{RuleID: "strip-server", Err: errors.New("demo failure")}
		}
		return defaultProxyResponseModifier(pxy, resp, state)
	}
	t.Cleanup(func() {
		proxyResponseModifier = originalModifier
	})

	handler := func(w http.ResponseWriter, r *http.Request) {
		target := copyURL(r.URL)
		target.Scheme = upstreamURL.Scheme
		target.Host = upstreamURL.Host

		state := &proxyFlowState{
			applyRules:     true,
			requestHeaders: r.Header.Clone(),
			url:            target.String(),
			protocol:       target.Scheme,
			host:           target.Host,
		}
		rp := proxy.newReverseProxy(target, state)
		rp.ServeHTTP(w, r)
	}

	server := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(server.Close)

	resOK, err := http.Get(server.URL + "/ok")
	if err != nil {
		t.Fatalf("request ok: %v", err)
	}
	_, _ = io.ReadAll(resOK.Body)
	_ = resOK.Body.Close()
	if resOK.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for ok path, got %d", resOK.StatusCode)
	}

	resFail, err := http.Get(server.URL + "/boom")
	if err != nil {
		t.Fatalf("request boom: %v", err)
	}
	_, _ = io.ReadAll(resFail.Body)
	_ = resFail.Body.Close()
	if resFail.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 for boom path, got %d", resFail.StatusCode)
	}

	decoder := json.NewDecoder(&logBuf)
	var found bool
	for decoder.More() {
		var entry map[string]any
		if err := decoder.Decode(&entry); err != nil {
			t.Fatalf("decode structured log: %v", err)
		}
		msg, _ := entry["msg"].(string)
		if msg != "reverse proxy error" {
			continue
		}
		component, ok := entry["component"].(string)
		if !ok || component != "galdr" {
			t.Fatalf("expected galdr component, got %#v", entry["component"])
		}
		rule, ok := entry["rule"].(string)
		if !ok || rule != "strip-server" {
			t.Fatalf("expected strip-server rule, got %#v", entry["rule"])
		}
		urlVal, ok := entry["url"].(string)
		if !ok || !strings.Contains(urlVal, "/boom") {
			t.Fatalf("expected boom url fragment, got %#v", entry["url"])
		}
		found = true
		break
	}
	if !found {
		t.Fatal("expected reverse proxy error log entry")
	}
}
