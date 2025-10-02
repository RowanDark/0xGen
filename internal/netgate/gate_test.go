package netgate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/Glyph/internal/logging"
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

func TestGateHTTPClientRequiresCapabilityAudited(t *testing.T) {
	audit, buf := newAuditRecorder(t)
	gate := New(nil, WithAuditLogger(audit))
	gate.Register("plugin", []string{})

	if _, err := gate.HTTPClient("plugin", capHTTPActive); err == nil {
		t.Fatal("expected error for missing capability")
	}

	events := decodeAuditEvents(t, buf)
	if len(events) == 0 {
		t.Fatal("expected audit entry for missing capability")
	}
	event := events[len(events)-1]
	if event.Metadata["capability"] != capHTTPActive {
		t.Fatalf("unexpected capability metadata: %v", event.Metadata["capability"])
	}
	if !strings.Contains(event.Reason, "missing capability") {
		t.Fatalf("unexpected reason: %s", event.Reason)
	}
}

func TestGateDialBlocksRawNetwork(t *testing.T) {
	gate := New(dummyDialer{})
	gate.Register("plugin", []string{capHTTPActive})

	if _, err := gate.DialContext(context.Background(), "plugin", capHTTPActive, "ip4:1", "198.51.100.1:80"); err == nil {
		t.Fatal("expected raw network to be blocked")
	}
}

func TestGateDialBlocksRawNetworkAudited(t *testing.T) {
	audit, buf := newAuditRecorder(t)
	gate := New(dummyDialer{}, WithAuditLogger(audit))
	gate.Register("plugin", []string{capHTTPActive})

	if _, err := gate.DialContext(context.Background(), "plugin", capHTTPActive, "ip4:1", "198.51.100.1:80"); err == nil {
		t.Fatal("expected raw network to be blocked")
	}

	events := decodeAuditEvents(t, buf)
	if len(events) == 0 {
		t.Fatal("expected audit entry for denied dial")
	}
	event := events[len(events)-1]
	if event.EventType != logging.EventNetworkDenied {
		t.Fatalf("unexpected event type: %s", event.EventType)
	}
	if event.PluginID != "plugin" {
		t.Fatalf("unexpected plugin id: %s", event.PluginID)
	}
	if capName := event.Metadata["capability"]; capName != capHTTPActive {
		t.Fatalf("unexpected capability metadata: %v", capName)
	}
	if network := event.Metadata["network"]; network != "ip4:1" {
		t.Fatalf("unexpected network metadata: %v", network)
	}
	if addr := event.Metadata["address"]; addr != "198.51.100.1:80" {
		t.Fatalf("unexpected address metadata: %v", addr)
	}
	if !strings.Contains(event.Reason, "not permitted") {
		t.Fatalf("unexpected reason: %s", event.Reason)
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

func TestGateHTTPClientBlocksLoopbackAudited(t *testing.T) {
	audit, buf := newAuditRecorder(t)
	gate := New(httpPipeDialer{}, WithAuditLogger(audit))
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

	events := decodeAuditEvents(t, buf)
	if len(events) == 0 {
		t.Fatal("expected audit entry for loopback request")
	}
	event := events[len(events)-1]
	if event.EventType != logging.EventNetworkDenied {
		t.Fatalf("unexpected event type: %s", event.EventType)
	}
	if event.Metadata["url"] != "http://127.0.0.1/" {
		t.Fatalf("unexpected url metadata: %v", event.Metadata["url"])
	}
	if event.Metadata["capability"] != capHTTPActive {
		t.Fatalf("unexpected capability metadata: %v", event.Metadata["capability"])
	}
	if !strings.Contains(event.Reason, "loopback") {
		t.Fatalf("unexpected reason: %s", event.Reason)
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

func TestGateHTTPClientBlocksFileSchemeAudited(t *testing.T) {
	audit, buf := newAuditRecorder(t)
	gate := New(httpPipeDialer{}, WithAuditLogger(audit))
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

	events := decodeAuditEvents(t, buf)
	if len(events) == 0 {
		t.Fatal("expected audit entry for file scheme request")
	}
	event := events[len(events)-1]
	if event.Metadata["url"] != "file:///etc/passwd" {
		t.Fatalf("unexpected url metadata: %v", event.Metadata["url"])
	}
	if !strings.Contains(event.Reason, "not permitted") {
		t.Fatalf("unexpected reason: %s", event.Reason)
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

func TestGateHTTPClientBlocksDataSchemeAudited(t *testing.T) {
	audit, buf := newAuditRecorder(t)
	gate := New(httpPipeDialer{}, WithAuditLogger(audit))
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

	events := decodeAuditEvents(t, buf)
	if len(events) == 0 {
		t.Fatal("expected audit entry for data scheme request")
	}
	event := events[len(events)-1]
	if event.Metadata["url"] != "data:text/plain;base64,SGVsbG8=" {
		t.Fatalf("unexpected url metadata: %v", event.Metadata["url"])
	}
	if !strings.Contains(event.Reason, "not permitted") {
		t.Fatalf("unexpected reason: %s", event.Reason)
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

func newAuditRecorder(t *testing.T) (*logging.AuditLogger, *bytes.Buffer) {
	t.Helper()
	buf := &bytes.Buffer{}
	logger, err := logging.NewAuditLogger("netgate_test", logging.WithoutStdout(), logging.WithWriter(buf))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	t.Cleanup(func() {
		_ = logger.Close()
	})
	return logger, buf
}

func decodeAuditEvents(t *testing.T, buf *bytes.Buffer) []logging.AuditEvent {
	t.Helper()
	raw := bytes.TrimSpace(buf.Bytes())
	if len(raw) == 0 {
		return nil
	}
	lines := bytes.Split(raw, []byte("\n"))
	events := make([]logging.AuditEvent, 0, len(lines))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var event logging.AuditEvent
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatalf("decode audit event: %v", err)
		}
		events = append(events, event)
	}
	return events
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
