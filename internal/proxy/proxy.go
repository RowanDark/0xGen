package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultHistoryName = "proxy_history.jsonl"
)

// Config controls proxy behaviour.
type Config struct {
	Addr           string
	RulesPath      string
	HistoryPath    string
	CACertPath     string
	CAKeyPath      string
	Logger         *slog.Logger
	ReloadInterval time.Duration
	Transport      http.RoundTripper
}

// Proxy intercepts HTTP traffic for inspection and modification.
type Proxy struct {
	cfg        Config
	logger     *slog.Logger
	server     *http.Server
	transport  http.RoundTripper
	ca         *caStore
	history    *historyWriter
	rules      *ruleStore
	ready      chan struct{}
	readyOnce  sync.Once
	addr       atomic.Value
	shutdownMu sync.Mutex
	closed     bool
}

// New creates a proxy using the provided configuration.
func New(cfg Config) (*Proxy, error) {
	cfg = applyDefaults(cfg)

	ca, err := newCAStore(cfg.CACertPath, cfg.CAKeyPath)
	if err != nil {
		return nil, fmt.Errorf("initialise CA store: %w", err)
	}

	history, err := newHistoryWriter(cfg.HistoryPath)
	if err != nil {
		return nil, fmt.Errorf("initialise history writer: %w", err)
	}

	transport := cfg.Transport
	if transport == nil {
		transport = defaultTransport()
	}

	p := &Proxy{
		cfg:       cfg,
		logger:    cfg.Logger,
		transport: transport,
		ca:        ca,
		history:   history,
		rules:     newRuleStore(cfg.RulesPath, cfg.ReloadInterval),
		ready:     make(chan struct{}),
	}

	p.server = &http.Server{
		Handler:           p,
		ReadHeaderTimeout: 15 * time.Second,
	}
	return p, nil
}

func applyDefaults(cfg Config) Config {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(os.Stdout, nil))
	}
	addr := strings.TrimSpace(cfg.Addr)
	if addr == "" {
		addr = ":8080"
	}
	if !strings.Contains(addr, ":") {
		addr = ":" + addr
	}
	if strings.HasPrefix(addr, ":") {
		addr = "0.0.0.0" + addr
	}
	cfg.Addr = addr
	cfg.HistoryPath = ensureHistoryPath(cfg.HistoryPath)
	cfg.RulesPath = ensureRulesPath(cfg.RulesPath)
	return cfg
}

func ensureHistoryPath(path string) string {
	path = strings.TrimSpace(path)
	if path != "" {
		return path
	}
	dir := defaultOutputDir()
	return filepath.Join(dir, defaultHistoryName)
}

func defaultTransport() http.RoundTripper {
	base := http.DefaultTransport
	transport, ok := base.(*http.Transport)
	if !ok {
		transport = &http.Transport{}
	} else {
		transport = transport.Clone()
	}
	transport.Proxy = nil
	transport.ProxyConnectHeader = nil
	transport.ForceAttemptHTTP2 = false
	return transport
}

func defaultOutputDir() string {
	if custom := strings.TrimSpace(os.Getenv("GLYPH_OUT")); custom != "" {
		return custom
	}
	return "/out"
}

// Run starts the proxy server and blocks until the context is cancelled or the server stops.
func (p *Proxy) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", p.cfg.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", p.cfg.Addr, err)
	}
	p.addr.Store(listener.Addr().String())
	p.signalReady()
	p.logger.Info("galdr proxy listening", "address", listener.Addr().String(), "history", p.history.Path(), "rules", p.cfg.RulesPath)

	errCh := make(chan error, 1)
	go func() {
		errCh <- p.server.Serve(listener)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := p.Shutdown(shutdownCtx); err != nil {
			p.logger.Warn("proxy shutdown error", "error", err)
		}
		err := <-errCh
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

// Shutdown gracefully stops the proxy server and flushes history.
func (p *Proxy) Shutdown(ctx context.Context) error {
	p.shutdownMu.Lock()
	if p.closed {
		p.shutdownMu.Unlock()
		return nil
	}
	p.closed = true
	p.shutdownMu.Unlock()

	if err := p.server.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	if closer, ok := p.transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
	return p.history.Close()
}

// WaitUntilReady blocks until the proxy listener is active or the context is cancelled.
func (p *Proxy) WaitUntilReady(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.ready:
		return nil
	}
}

func (p *Proxy) signalReady() {
	p.readyOnce.Do(func() {
		close(p.ready)
	})
}

// Addr returns the bound address for the running proxy.
func (p *Proxy) Addr() string {
	if v := p.addr.Load(); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// CACertificatePEM exposes the PEM encoded root certificate used by the proxy.
func (p *Proxy) CACertificatePEM() []byte {
	return p.ca.certificatePEM()
}

// ServeHTTP implements http.Handler.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.EqualFold(r.Method, http.MethodConnect):
		p.handleConnect(w, r)
		return
	case isWebSocketRequest(r):
		p.handleWebSocket(w, r)
		return
	default:
		p.handleHTTP(w, r)
	}
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()

	targetURL := copyURL(r.URL)
	if targetURL.Scheme == "" {
		targetURL.Scheme = "http"
	}
	if targetURL.Host == "" {
		targetURL.Host = r.Host
	}

	reqHeaders := cloneHeader(r.Header)
	resp, err := p.dispatchRequest(r.Context(), proxyRequest{
		Method:     r.Method,
		URL:        targetURL,
		Header:     reqHeaders,
		Body:       body,
		Protocol:   targetURL.Scheme,
		ClientAddr: r.RemoteAddr,
		Host:       targetURL.Host,
	})
	if err != nil {
		p.logger.Warn("proxy dispatch failed", "error", err)
		http.Error(w, "proxy error", http.StatusBadGateway)
		return
	}

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if len(resp.Body) > 0 {
		if _, err := w.Write(resp.Body); err != nil {
			p.logger.Warn("failed to write response to client", "error", err)
		}
	}
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "connect not supported", http.StatusInternalServerError)
		return
	}

	clientConn, rw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "failed to hijack connection", http.StatusInternalServerError)
		return
	}

	host := r.Host
	_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if err := rw.Flush(); err != nil {
		_ = clientConn.Close()
		return
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := chi.ServerName
			if name == "" {
				name = host
			}
			return p.ca.certificateForHost(name)
		},
	}

	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		p.logger.Warn("TLS handshake with client failed", "error", err)
		_ = tlsConn.Close()
		return
	}

	p.serveTLS(tlsConn, host, r.RemoteAddr)
}

func (p *Proxy) serveTLS(conn net.Conn, host, clientAddr string) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				p.logger.Warn("failed to read tls request", "error", err)
			}
			return
		}

		body, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			p.logger.Warn("failed to read tls request body", "error", err)
			return
		}

		targetURL := copyURL(req.URL)
		targetURL.Scheme = "https"
		if targetURL.Host == "" {
			targetURL.Host = host
		}

		resp, err := p.dispatchRequest(context.Background(), proxyRequest{
			Method:     req.Method,
			URL:        targetURL,
			Header:     cloneHeader(req.Header),
			Body:       body,
			Protocol:   "https",
			ClientAddr: clientAddr,
			Host:       targetURL.Host,
		})
		if err != nil {
			p.logger.Warn("proxy dispatch failed", "error", err)
			return
		}

		response := &http.Response{
			StatusCode: resp.StatusCode,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     cloneHeader(resp.Header),
			Body:       io.NopCloser(bytes.NewReader(resp.Body)),
		}
		response.ContentLength = int64(len(resp.Body))
		if len(resp.Body) == 0 {
			response.Body = http.NoBody
		}
		if err := response.Write(writer); err != nil {
			p.logger.Warn("failed to write tls response", "error", err)
			return
		}
		if err := writer.Flush(); err != nil {
			p.logger.Warn("failed to flush tls response", "error", err)
			return
		}
	}
}

func (p *Proxy) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket not supported", http.StatusInternalServerError)
		return
	}

	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "failed to hijack websocket", http.StatusInternalServerError)
		return
	}

	targetHost := r.Host
	if !strings.Contains(targetHost, ":") {
		targetHost = net.JoinHostPort(targetHost, "80")
	}

	upstream, err := net.Dial("tcp", targetHost)
	if err != nil {
		_, _ = clientBuf.WriteString("HTTP/1.1 502 Bad Gateway\r\n\r\n")
		_ = clientBuf.Flush()
		_ = clientConn.Close()
		return
	}

	if err := r.Write(upstream); err != nil {
		_ = upstream.Close()
		_ = clientConn.Close()
		return
	}

	upstreamReader := bufio.NewReader(upstream)
	resp, err := http.ReadResponse(upstreamReader, r)
	if err != nil {
		_ = upstream.Close()
		_ = clientConn.Close()
		return
	}

	if err := resp.Write(clientBuf); err != nil {
		_ = upstream.Close()
		_ = clientConn.Close()
		return
	}
	if err := clientBuf.Flush(); err != nil {
		_ = upstream.Close()
		_ = clientConn.Close()
		return
	}

	if resp.StatusCode == http.StatusSwitchingProtocols {
		go func() {
			_, _ = io.Copy(upstream, clientConn)
			_ = upstream.Close()
		}()
		_, _ = io.Copy(clientConn, upstream)
	}

	_ = upstream.Close()
	_ = clientConn.Close()
}

type proxyRequest struct {
	Method     string
	URL        *url.URL
	Header     http.Header
	Body       []byte
	Protocol   string
	ClientAddr string
	Host       string
}

type proxyResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

func (p *Proxy) dispatchRequest(ctx context.Context, req proxyRequest) (*proxyResponse, error) {
	matched, names := p.rules.match(req.Method, req.URL.String())

	headers := cloneHeader(req.Header)
	body := append([]byte(nil), req.Body...)

	for _, rule := range matched {
		applyHeaderAdds(headers, rule.Request.AddHeaders)
		applyHeaderRemovals(headers, rule.Request.RemoveHeaders)
		if rule.Request.Body != nil {
			body = []byte(rule.Request.Body.Set)
		}
	}

	sanitizeProxyHeaders(headers)

	outboundReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build outbound request: %w", err)
	}
	outboundReq.Header = headers
	outboundReq.Host = req.Host
	outboundReq.ContentLength = int64(len(body))
	if len(body) == 0 {
		outboundReq.Body = http.NoBody
	}

	start := time.Now()
	resp, err := p.transport.RoundTrip(outboundReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read upstream response: %w", err)
	}

	respHeaders := cloneHeader(resp.Header)
	for _, rule := range matched {
		applyHeaderAdds(respHeaders, rule.Response.AddHeaders)
		applyHeaderRemovals(respHeaders, rule.Response.RemoveHeaders)
		if rule.Response.Body != nil {
			respBody = []byte(rule.Response.Body.Set)
		}
	}

	respHeaders.Del("Content-Length")
	respHeaders.Del("Transfer-Encoding")
	if len(respBody) > 0 {
		respHeaders.Set("Content-Length", strconv.Itoa(len(respBody)))
	} else {
		respHeaders.Set("Content-Length", "0")
	}

	entry := HistoryEntry{
		Timestamp:       time.Now().UTC(),
		ClientIP:        clientIP(req.ClientAddr),
		Protocol:        strings.ToUpper(req.Protocol),
		Method:          strings.ToUpper(req.Method),
		URL:             req.URL.String(),
		StatusCode:      resp.StatusCode,
		LatencyMillis:   time.Since(start).Milliseconds(),
		RequestSize:     len(body),
		ResponseSize:    len(respBody),
		RequestHeaders:  headerToMap(headers),
		ResponseHeaders: headerToMap(respHeaders),
		MatchedRules:    names,
	}
	if err := p.history.Write(entry); err != nil {
		p.logger.Warn("failed to persist history", "error", err)
	}

	return &proxyResponse{
		StatusCode: resp.StatusCode,
		Header:     respHeaders,
		Body:       respBody,
	}, nil
}

func sanitizeProxyHeaders(h http.Header) {
	h.Del("Proxy-Connection")
	h.Del("Proxy-Authenticate")
	h.Del("Proxy-Authorization")
}

func headerToMap(h http.Header) map[string][]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string][]string, len(h))
	for k, values := range h {
		copied := make([]string, len(values))
		copy(copied, values)
		out[k] = copied
	}
	return out
}

func copyHeaders(dst, src http.Header) {
	for k := range dst {
		dst.Del(k)
	}
	for k, values := range src {
		for _, v := range values {
			dst.Add(k, v)
		}
	}
}

func cloneHeader(h http.Header) http.Header {
	cloned := make(http.Header, len(h))
	for k, values := range h {
		copied := make([]string, len(values))
		copy(copied, values)
		cloned[k] = copied
	}
	return cloned
}

func copyURL(u *url.URL) *url.URL {
	if u == nil {
		return &url.URL{}
	}
	copied := *u
	return &copied
}

func applyHeaderAdds(header http.Header, additions map[string]string) {
	for k, v := range additions {
		if strings.TrimSpace(k) == "" {
			continue
		}
		header.Set(k, v)
	}
}

func applyHeaderRemovals(header http.Header, removals []string) {
	for _, key := range removals {
		header.Del(key)
	}
}

func isWebSocketRequest(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	connection := strings.ToLower(r.Header.Get("Connection"))
	return strings.Contains(connection, "upgrade")
}

func clientIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
