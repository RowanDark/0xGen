package netgate

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	oxghttp3 "github.com/RowanDark/0xgen/internal/netgate/http3"
)

func TestRoundTripHTTP3Success(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "ok")
		_, _ = io.WriteString(w, "world")
	})
	addr, shutdown, err := oxghttp3.StartTestServer(handler)
	if err != nil {
		t.Fatalf("start http3 server: %v", err)
	}
	t.Cleanup(func() {
		_ = shutdown()
	})

	gate := New(dummyDialer{})
	lt := &layeredTransport{
		gate:    gate,
		primary: &http.Transport{TLSClientConfig: insecureTLSConfig()},
		baseTLS: insecureTLSConfig(),
	}
	lt.h3attempt = lt.roundTripHTTP3

	url := fmt.Sprintf("https://localhost:%s/hello", addr[strings.LastIndex(addr, ":")+1:])
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := lt.tryHTTP3(req)
	if err != nil {
		t.Fatalf("roundTripHTTP3: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Test"); got != "ok" {
		t.Fatalf("unexpected header: %q", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "world" {
		t.Fatalf("unexpected body: %q", string(body))
	}
}

func BenchmarkLayeredTransportHTTP3(b *testing.B) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	addr, shutdown, err := oxghttp3.StartTestServer(handler)
	if err != nil {
		b.Fatalf("start http3 server: %v", err)
	}
	defer shutdown()

	gate := New(dummyDialer{}, WithTimeout(2*time.Second))
	lt := &layeredTransport{
		gate:    gate,
		primary: &http.Transport{TLSClientConfig: insecureTLSConfig()},
		baseTLS: insecureTLSConfig(),
	}
	lt.h3attempt = lt.roundTripHTTP3

	url := fmt.Sprintf("https://localhost:%s/bench", addr[strings.LastIndex(addr, ":")+1:])
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		b.Fatalf("new request: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := lt.tryHTTP3(req.Clone(context.Background()))
		if err != nil {
			b.Fatalf("roundTripHTTP3: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func insecureTLSConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}
