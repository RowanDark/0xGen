package e2e

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/proxy"
	"github.com/RowanDark/0xgen/internal/testutil"
)

func TestGaldrProxyHTTP2HeaderRewrite(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("expected HTTP/2 request, got %s", r.Proto)
		}
		w.Header().Set("Server", "h2-upstream")
		_, _ = w.Write([]byte("ok"))
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	t.Cleanup(upstream.Close)

	cert := upstream.Certificate()
	if cert == nil {
		t.Fatal("upstream certificate missing")
	}
	pool := x509PoolFromCert(cert)

	tempDir := t.TempDir()
	rulesPath := writeTempFile(t, tempDir, "rules.json", `[{"name":"h2-rewrite","match":{"url_contains":"/"},"response":{"add_headers":{"X-0xgen":"on"},"remove_headers":["Server"]}}]`)

	cfg := proxy.Config{
		Addr:        "127.0.0.1:0",
		RulesPath:   rulesPath,
		HistoryPath: tempDir + "/history.jsonl",
		CACertPath:  tempDir + "/ca.pem",
		CAKeyPath:   tempDir + "/ca.key",
		Logger:      newTestLogger(),
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}

	p, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- p.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil && err != context.Canceled {
				t.Fatalf("proxy exited with error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout waiting for proxy shutdown")
		}
	})

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readyCancel()
	if err := p.WaitUntilReady(readyCtx); err != nil {
		t.Fatalf("proxy not ready: %v", err)
	}

	proxyURL, _ := url.Parse("http://" + p.Addr())
	caPool := x509PoolFromPEM(p.CACertificatePEM(), t)
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: caPool},
	}, Timeout: 5 * time.Second}

	resp, err := client.Get(upstream.URL + "/h2")
	if err != nil {
		t.Fatalf("request via proxy: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	testutil.RequireModernHeader(t, resp.Header, "X-0xgen", "on")
	if resp.Header.Get("Server") != "" {
		t.Fatalf("expected server header stripped, got %q", resp.Header.Get("Server"))
	}
}

func TestGaldrProxyWebSocketPassthrough(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(webSocketEchoHandler(t)))
	t.Cleanup(upstream.Close)

	tempDir := t.TempDir()
	cfg := proxy.Config{
		Addr:        "127.0.0.1:0",
		HistoryPath: tempDir + "/history.jsonl",
		CACertPath:  tempDir + "/ca.pem",
		CAKeyPath:   tempDir + "/ca.key",
		Logger:      newTestLogger(),
	}

	p, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- p.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil && err != context.Canceled {
				t.Fatalf("proxy exited with error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout waiting for proxy shutdown")
		}
	})

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readyCancel()
	if err := p.WaitUntilReady(readyCtx); err != nil {
		t.Fatalf("proxy not ready: %v", err)
	}

	conn, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	wsURL := upstream.URL + "/echo"
	parsed, err := url.Parse(wsURL)
	if err != nil {
		t.Fatalf("parse websocket url: %v", err)
	}

	key := generateWebSocketKey(t)
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nOrigin: http://example.com\r\n\r\n", wsURL, parsed.Host, key)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write handshake: %v", err)
	}

	reader := bufio.NewReader(conn)
	status, headers, err := readHTTPResponse(reader)
	if err != nil {
		t.Fatalf("read handshake response: %v", err)
	}
	if status != "101" {
		t.Fatalf("unexpected status code %s", status)
	}
	expectedAccept := computeAcceptKey(key)
	if headers.Get("Sec-WebSocket-Accept") != expectedAccept {
		t.Fatalf("unexpected accept key %q", headers.Get("Sec-WebSocket-Accept"))
	}

	message := []byte("glyph")
	if err := writeWebSocketFrame(conn, message); err != nil {
		t.Fatalf("write websocket frame: %v", err)
	}

	echoed, err := readWebSocketFrame(reader)
	if err != nil {
		t.Fatalf("read websocket frame: %v", err)
	}
	if string(echoed) != string(message) {
		t.Fatalf("echo mismatch: got %q want %q", string(echoed), string(message))
	}
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func writeTempFile(t *testing.T, dir, name, contents string) string {
	t.Helper()
	path := dir + "/" + name
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func x509PoolFromCert(cert *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}

func x509PoolFromPEM(pemBytes []byte, t *testing.T) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatal("failed to append certificate")
	}
	return pool
}

func generateWebSocketKey(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("generate websocket key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func computeAcceptKey(key string) string {
	h := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h[:])
}

func readHTTPResponse(r *bufio.Reader) (string, http.Header, error) {
	statusLine, err := r.ReadString('\n')
	if err != nil {
		return "", nil, err
	}
	statusLine = strings.TrimSpace(statusLine)
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 {
		return "", nil, fmt.Errorf("malformed status line: %q", statusLine)
	}
	status := parts[1]
	headers := http.Header{}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return "", nil, err
		}
		if line == "\r\n" {
			break
		}
		line = strings.TrimSuffix(line, "\r\n")
		headerParts := strings.SplitN(line, ":", 2)
		if len(headerParts) != 2 {
			return "", nil, fmt.Errorf("parse header line: %q", line)
		}
		key := headerParts[0]
		value := strings.TrimSpace(headerParts[1])
		headers.Add(key, value)
	}
	return status, headers, nil
}

func writeWebSocketFrame(conn net.Conn, payload []byte) error {
	mask := make([]byte, 4)
	if _, err := rand.Read(mask); err != nil {
		return fmt.Errorf("generate mask: %w", err)
	}
	frame := []byte{0x81, byte(0x80 | len(payload))}
	frame = append(frame, mask...)
	masked := make([]byte, len(payload))
	for i, b := range payload {
		masked[i] = b ^ mask[i%4]
	}
	frame = append(frame, masked...)
	_, err := conn.Write(frame)
	return err
}

func readWebSocketFrame(r *bufio.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("read frame header: %w", err)
	}
	if header[0]&0x0f != 0x1 {
		return nil, fmt.Errorf("unexpected opcode: %x", header[0])
	}
	if header[1]&0x80 != 0 {
		return nil, fmt.Errorf("server frames must be unmasked")
	}
	length := int(header[1] & 0x7f)
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}
	return payload, nil
}

func readMaskedClientFrame(r *bufio.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("read masked frame header: %w", err)
	}
	if header[0]&0x0f != 0x1 {
		return nil, fmt.Errorf("unexpected opcode: %x", header[0])
	}
	if header[1]&0x80 == 0 {
		return nil, fmt.Errorf("client frames must be masked")
	}
	length := int(header[1] & 0x7f)
	if length > 125 {
		return nil, fmt.Errorf("client frame too large: %d", length)
	}
	mask := make([]byte, 4)
	if _, err := io.ReadFull(r, mask); err != nil {
		return nil, fmt.Errorf("read mask: %w", err)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	return payload, nil
}

func webSocketEchoHandler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isWebSocketUpgrade(r) {
			http.Error(w, "upgrade required", http.StatusBadRequest)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijacking not supported", http.StatusInternalServerError)
			return
		}
		conn, buf, err := hijacker.Hijack()
		if err != nil {
			http.Error(w, "hijack failed", http.StatusInternalServerError)
			return
		}
		key := r.Header.Get("Sec-WebSocket-Key")
		if key == "" {
			_ = conn.Close()
			return
		}
		accept := computeAcceptKey(key)
		response := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
		if _, err := buf.WriteString(response); err != nil {
			_ = conn.Close()
			return
		}
		if err := buf.Flush(); err != nil {
			_ = conn.Close()
			return
		}
		reader := bufio.NewReader(conn)
		payload, err := readMaskedClientFrame(reader)
		if err != nil {
			_ = conn.Close()
			return
		}
		frame := append([]byte{0x81, byte(len(payload))}, payload...)
		if _, err := conn.Write(frame); err != nil {
			t.Logf("write echo: %v", err)
		}
		_ = conn.Close()
	}
}

func isWebSocketUpgrade(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}
