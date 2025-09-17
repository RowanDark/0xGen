package netgate

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGateDeniesMissingCapability(t *testing.T) {
	gate := New(nil)
	gate.Register("plugin", nil)

	if _, err := gate.DialContext(context.Background(), "plugin", capHTTPActive, "tcp", "127.0.0.1:1"); err == nil {
		t.Fatal("expected dial to be denied without capability")
	}
}

func TestGateAllowsWithCapability(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() {
		_ = ln.Close()
	}()

	gate := New(&net.Dialer{Timeout: 100 * time.Millisecond})
	gate.Register("plugin", []string{capHTTPActive})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
		close(done)
	}()

	conn, err := gate.DialContext(ctx, "plugin", capHTTPActive, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	func() {
		if err := conn.Close(); err != nil {
			t.Fatalf("close connection: %v", err)
		}
	}()
	<-done
}

func TestGateHTTPClientRequiresCapability(t *testing.T) {
	gate := New(nil)
	gate.Register("plugin", []string{})

	if _, err := gate.HTTPClient("plugin", capHTTPActive); err == nil {
		t.Fatal("expected error for missing capability")
	}
}

func TestGateHTTPClientPerformsRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	gate := New(nil, WithRequestBudget(2))
	gate.Register("plugin", []string{capHTTPActive})

	client, err := gate.HTTPClient("plugin", capHTTPActive)
	if err != nil {
		t.Fatalf("http client: %v", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
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

func TestGateTimeoutEnforced(t *testing.T) {
	slow := slowDialer{delay: 200 * time.Millisecond}
	gate := New(slow, WithTimeout(50*time.Millisecond))
	gate.Register("plugin", []string{capHTTPActive})

	start := time.Now()
	_, err := gate.DialContext(context.Background(), "plugin", capHTTPActive, "tcp", "127.0.0.1:1")
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

	conn, err := gate.DialContext(context.Background(), "plugin", capHTTPActive, "tcp", "127.0.0.1:1")
	if err != nil {
		t.Fatalf("unexpected error on first dial: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close connection: %v", err)
	}

	if _, err := gate.DialContext(context.Background(), "plugin", capHTTPActive, "tcp", "127.0.0.1:1"); err == nil {
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
