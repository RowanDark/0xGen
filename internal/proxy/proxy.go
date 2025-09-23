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
	"net/http/httputil"
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
	if err := configureHTTP2Transport(transport); err != nil {
		return nil, fmt.Errorf("configure http2 transport: %w", err)
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
	transport.ForceAttemptHTTP2 = true
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
	meta := connectionMetadataFromContext(r.Context())
	scheme := ""
	host := ""
	clientAddr := r.RemoteAddr
	if meta != nil {
		scheme = meta.scheme
		if meta.host != "" {
			host = meta.host
		}
		if meta.clientAddr != "" {
			clientAddr = meta.clientAddr
		}
	}

	p.serveProxyRequest(w, r, scheme, host, clientAddr, true, true)
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
	if strings.TrimSpace(host) == "" {
		host = r.URL.Host
	}

	_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if err := rw.Flush(); err != nil {
		_ = clientConn.Close()
		return
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
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

	metadata := &connMetadata{scheme: "https", host: host, clientAddr: r.RemoteAddr}
	switch tlsConn.ConnectionState().NegotiatedProtocol {
	case "h2":
		p.serveHTTP2(tlsConn, metadata)
	default:
		p.serveTLSHTTP1(tlsConn, metadata)
	}
}

func (p *Proxy) serveTLSHTTP1(conn net.Conn, meta *connMetadata) {
	hijacked := false
	defer func() {
		if !hijacked {
			_ = conn.Close()
		}
	}()

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

		ctx := context.WithValue(req.Context(), connMetadataContextKey{}, meta)
		req = req.WithContext(ctx)
		req.RemoteAddr = meta.clientAddr

		respWriter := newTLSResponseWriter(conn, reader, writer)

		switch {
		case isWebSocketRequest(req):
			p.handleWebSocket(respWriter, req)
		default:
			p.handleHTTP(respWriter, req)
		}

		if respWriter.hijacked {
			hijacked = true
			return
		}

		if err := respWriter.flush(); err != nil {
			p.logger.Warn("failed to write tls response", "error", err)
			return
		}
	}
}

type tlsResponseWriter struct {
	conn        net.Conn
	reader      *bufio.Reader
	writer      *bufio.Writer
	header      http.Header
	status      int
	wroteHeader bool
	headersSent bool
	hijacked    bool
}

func newTLSResponseWriter(conn net.Conn, reader *bufio.Reader, writer *bufio.Writer) *tlsResponseWriter {
	return &tlsResponseWriter{
		conn:   conn,
		reader: reader,
		writer: writer,
		header: make(http.Header),
	}
}

func (w *tlsResponseWriter) Header() http.Header {
	return w.header
}

func (w *tlsResponseWriter) WriteHeader(status int) {
	if w.headersSent {
		return
	}
	w.status = status
	w.wroteHeader = true
}

func (w *tlsResponseWriter) Write(b []byte) (int, error) {
	if err := w.writeHeaders(); err != nil {
		return 0, err
	}
	return w.writer.Write(b)
}

func (w *tlsResponseWriter) Flush() {
	_ = w.writeHeaders()
	_ = w.writer.Flush()
}

func (w *tlsResponseWriter) flush() error {
	if err := w.writeHeaders(); err != nil {
		return err
	}
	return w.writer.Flush()
}

func (w *tlsResponseWriter) writeHeaders() error {
	if w.headersSent {
		return nil
	}
	if !w.wroteHeader {
		w.status = http.StatusOK
	}
	statusText := http.StatusText(w.status)
	if statusText == "" {
		statusText = "Status"
	}
	if _, err := fmt.Fprintf(w.writer, "HTTP/1.1 %d %s\r\n", w.status, statusText); err != nil {
		return err
	}
	if err := w.header.Write(w.writer); err != nil {
		return err
	}
	if _, err := w.writer.WriteString("\r\n"); err != nil {
		return err
	}
	w.headersSent = true
	return nil
}

func (w *tlsResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if w.hijacked {
		return nil, nil, fmt.Errorf("connection already hijacked")
	}
	if err := w.writer.Flush(); err != nil {
		return nil, nil, err
	}
	w.headersSent = true
	w.hijacked = true
	return w.conn, bufio.NewReadWriter(w.reader, w.writer), nil
}

func (p *Proxy) serveProxyRequest(w http.ResponseWriter, r *http.Request, scheme, hostOverride, clientAddr string, applyRules, recordHistory bool) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()

	if clientAddr == "" {
		clientAddr = r.RemoteAddr
	}

	targetURL := copyURL(r.URL)
	if scheme != "" {
		targetURL.Scheme = scheme
	}
	if targetURL.Scheme == "" {
		targetURL.Scheme = "http"
	}
	if hostOverride != "" {
		targetURL.Host = hostOverride
	}
	if targetURL.Host == "" {
		targetURL.Host = r.Host
	}
	if strings.TrimSpace(targetURL.Host) == "" {
		http.Error(w, "missing target host", http.StatusBadRequest)
		return
	}

	matched, names := p.rules.match(r.Method, targetURL.String())

	headers := cloneHeader(r.Header)
	r.Header = headers

	state := &proxyFlowState{
		method:         r.Method,
		url:            targetURL.String(),
		protocol:       targetURL.Scheme,
		host:           targetURL.Host,
		clientAddr:     clientAddr,
		matched:        matched,
		matchedNames:   names,
		requestHeaders: headers,
		requestBody:    append([]byte(nil), body...),
		start:          time.Now(),
		applyRules:     applyRules,
		recordHistory:  recordHistory,
	}

	if len(body) == 0 {
		r.Body = http.NoBody
		r.ContentLength = 0
	} else {
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}

	proxy := p.newReverseProxy(targetURL, state)
	proxy.ServeHTTP(w, r)
}

func (p *Proxy) newReverseProxy(target *url.URL, state *proxyFlowState) *httputil.ReverseProxy {
	director := func(outReq *http.Request) {
		outReq.URL = copyURL(target)
		outReq.Host = target.Host

		headers := cloneHeader(state.requestHeaders)
		body := append([]byte(nil), state.requestBody...)

		if state.applyRules {
			for _, rule := range state.matched {
				applyHeaderAdds(headers, rule.Request.AddHeaders)
				applyHeaderRemovals(headers, rule.Request.RemoveHeaders)
				if rule.Request.Body != nil {
					body = []byte(rule.Request.Body.Set)
				}
			}
		}

		sanitizeProxyHeaders(headers)

		outReq.Header = headers
		outReq.ContentLength = int64(len(body))
		if len(body) == 0 {
			outReq.Body = http.NoBody
		} else {
			outReq.Body = io.NopCloser(bytes.NewReader(body))
		}

		state.finalRequestHeaders = cloneHeader(headers)
		state.finalRequestBody = append([]byte(nil), body...)
	}

	proxy := &httputil.ReverseProxy{
		Director:     director,
		Transport:    p.transport,
		ErrorHandler: p.reverseProxyErrorHandler,
	}
	if state.applyRules || state.recordHistory {
		proxy.ModifyResponse = p.makeModifyResponse(state)
	}
	if !state.applyRules && !state.recordHistory {
		proxy.FlushInterval = -1
	}
	return proxy
}

func (p *Proxy) makeModifyResponse(state *proxyFlowState) func(*http.Response) error {
	return func(resp *http.Response) error {
		if err := proxyResponseModifier(p, resp, state); err != nil {
			target := ""
			if resp != nil && resp.Request != nil && resp.Request.URL != nil {
				target = resp.Request.URL.String()
			}
			var ruleErr *RuleError
			if errors.As(err, &ruleErr) && ruleErr.RuleID != "" {
				return fmt.Errorf("modifyresponse failed: url=%s rule=%s: %w", target, ruleErr.RuleID, err)
			}
			return fmt.Errorf("modifyresponse failed: url=%s: %w", target, err)
		}
		return nil
	}
}

func (p *Proxy) reverseProxyErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(http.StatusBadGateway)
	_, _ = w.Write([]byte("Bad Gateway"))

	url := ""
	if r != nil && r.URL != nil {
		url = r.URL.String()
	}

	rule := ""
	var ruleErr *RuleError
	if errors.As(err, &ruleErr) && ruleErr.RuleID != "" {
		rule = ruleErr.RuleID
	}

	p.logger.Error("reverse proxy error",
		"component", "galdr",
		"event", "proxy_error",
		"url", url,
		"rule", rule,
		"err", err,
	)
}

type responseModifierFunc func(*Proxy, *http.Response, *proxyFlowState) error

var proxyResponseModifier responseModifierFunc = defaultProxyResponseModifier

func defaultProxyResponseModifier(p *Proxy, resp *http.Response, state *proxyFlowState) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		_ = resp.Body.Close()
		return err
	}
	_ = resp.Body.Close()

	headers := cloneHeader(resp.Header)
	if state.applyRules {
		for _, rule := range state.matched {
			applyHeaderAdds(headers, rule.Response.AddHeaders)
			applyHeaderRemovals(headers, rule.Response.RemoveHeaders)
			if rule.Response.Body != nil {
				body = []byte(rule.Response.Body.Set)
			}
		}
	}

	headers.Del("Content-Length")
	headers.Del("Transfer-Encoding")
	if len(body) > 0 {
		headers.Set("Content-Length", strconv.Itoa(len(body)))
		resp.Body = io.NopCloser(bytes.NewReader(body))
	} else {
		headers.Set("Content-Length", "0")
		resp.Body = http.NoBody
	}
	resp.ContentLength = int64(len(body))
	copyHeaders(resp.Header, headers)

	state.responseHeaders = cloneHeader(headers)
	state.responseBody = append([]byte(nil), body...)
	state.statusCode = resp.StatusCode

	if state.recordHistory {
		p.recordHistory(state)
	}
	return nil
}

// RuleError carries the rule that failed during modification.
type RuleError struct {
	RuleID string
	Err    error
}

// Error exposes the underlying error message.
func (e *RuleError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

// Unwrap returns the wrapped error for errors.Is/As support.
func (e *RuleError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (p *Proxy) recordHistory(state *proxyFlowState) {
	entry := HistoryEntry{
		Timestamp:       time.Now().UTC(),
		ClientIP:        clientIP(state.clientAddr),
		Protocol:        strings.ToUpper(state.protocol),
		Method:          strings.ToUpper(state.method),
		URL:             state.url,
		StatusCode:      state.statusCode,
		LatencyMillis:   time.Since(state.start).Milliseconds(),
		RequestSize:     len(state.finalRequestBody),
		ResponseSize:    len(state.responseBody),
		RequestHeaders:  headerToMap(state.finalRequestHeaders),
		ResponseHeaders: headerToMap(state.responseHeaders),
		MatchedRules:    state.matchedNames,
	}
	if err := p.history.Write(entry); err != nil {
		p.logger.Warn("failed to persist history", "error", err)
	}
}

type connMetadata struct {
	scheme     string
	host       string
	clientAddr string
}

type connMetadataContextKey struct{}

func connectionMetadataFromContext(ctx context.Context) *connMetadata {
	if ctx == nil {
		return nil
	}
	if v := ctx.Value(connMetadataContextKey{}); v != nil {
		if meta, ok := v.(*connMetadata); ok {
			return meta
		}
	}
	return nil
}

type proxyFlowState struct {
	method              string
	url                 string
	protocol            string
	host                string
	clientAddr          string
	matched             []Rule
	matchedNames        []string
	requestHeaders      http.Header
	requestBody         []byte
	finalRequestHeaders http.Header
	finalRequestBody    []byte
	responseHeaders     http.Header
	responseBody        []byte
	statusCode          int
	start               time.Time
	applyRules          bool
	recordHistory       bool
}

type singleConnListener struct {
	conn net.Conn
	addr net.Addr
	mu   sync.Mutex
	used bool
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	return &singleConnListener{conn: conn, addr: conn.LocalAddr()}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.used {
		return nil, io.EOF
	}
	l.used = true
	return l.conn, nil
}

func (l *singleConnListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.used {
		return nil
	}
	l.used = true
	return l.conn.Close()
}

func (l *singleConnListener) Addr() net.Addr {
	return l.addr
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
