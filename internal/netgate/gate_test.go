package netgate

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestGateDeniesMissingCapability(t *testing.T) {
	gate := New(nil)
	gate.Register("plugin", nil)

	if _, err := gate.DialContext(context.Background(), "plugin", capHTTPActive, "tcp", "198.51.100.1:1"); err == nil {
		t.Fatal("expected dial to be denied without capability")
	}
}

func TestGateAllowsWithCapability(t *testing.T) {
	gate := New(dummyDialer{}, WithTimeout(100*time.Millisecond))
	gate.Register("plugin", []string{capHTTPActive})

	conn, err := gate.DialContext(context.Background(), "plugin", capHTTPActive, "tcp", "198.51.100.10:443")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close connection: %v", err)
	}
}

func TestGateHTTPClientRequiresCapability(t *testing.T) {
	gate := New(nil)
	gate.Register("plugin", []string{})

	if _, err := gate.HTTPClient("plugin", capHTTPActive); err == nil {
		t.Fatal("expected error for missing capability")
	}
}

func TestGateDialBlocksRawNetwork(t *testing.T) {
	gate := New(dummyDialer{})
	gate.Register("plugin", []string{capHTTPActive})

	if _, err := gate.DialContext(context.Background(), "plugin", capHTTPActive, "ip4:1", "198.51.100.1:80"); err == nil {
		t.Fatal("expected raw network to be blocked")
	}
}

func TestGateDialBlocksLoopback(t *testing.T) {
	gate := New(dummyDialer{})
	gate.Register("plugin", []string{capHTTPActive})

	if _, err := gate.DialContext(context.Background(), "plugin", capHTTPActive, "tcp", "127.0.0.1:80"); err == nil {
		t.Fatal("expected loopback dial to be blocked")
	}
}

func TestGateHTTPClientPerformsRequests(t *testing.T) {
	gate := New(httpPipeDialer{response: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"}, WithRequestBudget(2))
	gate.Register("plugin", []string{capHTTPActive})

	client, err := gate.HTTPClient("plugin", capHTTPActive)
	if err != nil {
		t.Fatalf("http client: %v", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/resource", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close response body: %v", err)
	}
}

func TestGateHTTPClientBlocksLoopback(t *testing.T) {
	gate := New(httpPipeDialer{})
	gate.Register("plugin", []string{capHTTPActive})

	client, err := gate.HTTPClient("plugin", capHTTPActive)
	if err != nil {
		t.Fatalf("http client: %v", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1/", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if _, err := client.Do(req); err == nil {
		t.Fatal("expected loopback request to be denied")
	}
}

func TestGateHTTPClientBlocksPrivate(t *testing.T) {
	gate := New(httpPipeDialer{})
	gate.Register("plugin", []string{capHTTPActive})

	client, err := gate.HTTPClient("plugin", capHTTPActive)
	if err != nil {
		t.Fatalf("http client: %v", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://10.0.0.5/resource", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if _, err := client.Do(req); err == nil {
		t.Fatal("expected private range to be denied")
	}
}

func TestGateHTTPClientBlocksFileScheme(t *testing.T) {
	gate := New(httpPipeDialer{})
	gate.Register("plugin", []string{capHTTPActive})

	client, err := gate.HTTPClient("plugin", capHTTPActive)
	if err != nil {
		t.Fatalf("http client: %v", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "file:///etc/passwd", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if _, err := client.Do(req); err == nil {
		t.Fatal("expected file scheme to be denied")
	}
}

func TestGateHTTPClientBlocksDataScheme(t *testing.T) {
	gate := New(httpPipeDialer{})
	gate.Register("plugin", []string{capHTTPActive})

	client, err := gate.HTTPClient("plugin", capHTTPActive)
	if err != nil {
		t.Fatalf("http client: %v", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "data:text/plain;base64,SGVsbG8=", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if _, err := client.Do(req); err == nil {
		t.Fatal("expected data scheme to be denied")
	}
}

func TestGateTimeoutEnforced(t *testing.T) {
	slow := slowDialer{delay: 200 * time.Millisecond}
	gate := New(slow, WithTimeout(50*time.Millisecond))
	gate.Register("plugin", []string{capHTTPActive})

	start := time.Now()
	_, err := gate.DialContext(context.Background(), "plugin", capHTTPActive, "tcp", "198.51.100.2:1")
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 150*time.Millisecond {
		t.Fatalf("timeout not enforced quickly, took %v", elapsed)
	}
}

func TestGateBudgetExhaustion(t *testing.T) {
	gate := New(dummyDialer{}, WithRequestBudget(1))
	gate.Register("plugin", []string{capHTTPActive})

	conn, err := gate.DialContext(context.Background(), "plugin", capHTTPActive, "tcp", "198.51.100.3:1")
	if err != nil {
		t.Fatalf("unexpected error on first dial: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close connection: %v", err)
	}

	if _, err := gate.DialContext(context.Background(), "plugin", capHTTPActive, "tcp", "198.51.100.3:1"); err == nil {
		t.Fatal("expected error once budget exhausted")
	}
}

type slowDialer struct {
	delay time.Duration
}

func (s slowDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	select {
	case <-time.After(s.delay):
		return nil, errors.New("dial should have timed out")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type dummyDialer struct{}

func (dummyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c1, c2 := net.Pipe()
	go func() {
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Millisecond):
		}
		_ = c2.Close()
	}()
	return c1, nil
}

type httpPipeDialer struct {
	response string
}

func (d httpPipeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c1, c2 := net.Pipe()
	go func() {
		defer c2.Close()
		buf := make([]byte, 0, 512)
		tmp := make([]byte, 256)
		for {
			n, err := c2.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
				if bytes.Contains(buf, []byte("\r\n\r\n")) {
					break
				}
			}
			if err != nil {
				return
			}
		}
		if _, err := io.WriteString(c2, d.response); err != nil {
			return
		}
	}()
	return c1, nil
}
