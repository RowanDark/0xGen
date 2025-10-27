package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RowanDark/0xgen/internal/env"
	"github.com/RowanDark/0xgen/internal/flows"
	obsmetrics "github.com/RowanDark/0xgen/internal/observability/metrics"
	"github.com/RowanDark/0xgen/internal/observability/tracing"
	"github.com/RowanDark/0xgen/internal/scope"
	pb "github.com/RowanDark/0xgen/proto/gen/go/proto/oxg"
)

const (
	defaultHistoryName      = "proxy_history.jsonl"
	modernProxyHeaderRoot   = "X-0xgen"
	modernProxyHeaderPrefix = modernProxyHeaderRoot + "-"
	bodyRedactedHeader      = modernProxyHeaderPrefix + "Body-Redacted"
	rawBodyTruncatedHeader  = modernProxyHeaderPrefix + "Raw-Body-Truncated"
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
	FlowPublisher  FlowPublisher
	Scope          ScopeEvaluator
	Flow           FlowCaptureConfig
}

// FlowCaptureConfig governs how intercepted flows are sampled, truncated, and
// recorded for replay.
type FlowCaptureConfig struct {
	Enabled      bool
	SampleRate   float64
	MaxBodyBytes int
	Seed         int64
	LogPath      string
}

// FlowPublisher propagates captured flows to downstream consumers.
type FlowPublisher interface {
	PublishFlowEvent(ctx context.Context, event flows.Event) error
}

// ScopeEvaluator determines whether a captured flow is considered in-scope for
// publication to plugins. Implementations should be safe for concurrent use.
type ScopeEvaluator interface {
	Evaluate(candidate string) scope.Decision
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
	publisher  FlowPublisher
	scope      ScopeEvaluator
	flowCfg    FlowCaptureConfig
	flowSeed   int64
	flowIDs    atomic.Uint64
	flowSeq    atomic.Uint64
	sampler    *rand.Rand
	samplerMu  sync.Mutex
	flowLog    *flowLogWriter
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

	var flowLog *flowLogWriter
	if cfg.Flow.Enabled && strings.TrimSpace(cfg.Flow.LogPath) != "" {
		flowLog, err = newFlowLogWriter(cfg.Flow.LogPath)
		if err != nil {
			return nil, fmt.Errorf("initialise flow log: %w", err)
		}
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
		publisher: cfg.FlowPublisher,
		scope:     cfg.Scope,
		flowCfg:   cfg.Flow,
		flowSeed:  cfg.Flow.Seed,
		sampler:   rand.New(rand.NewSource(cfg.Flow.Seed)),
		flowLog:   flowLog,
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
	cfg.Flow = applyFlowDefaults(cfg.Flow, cfg.HistoryPath)
	return cfg
}

func applyFlowDefaults(cfg FlowCaptureConfig, historyPath string) FlowCaptureConfig {
	zeroConfig := !cfg.Enabled && cfg.SampleRate == 0 && cfg.MaxBodyBytes == 0 && cfg.Seed == 0 && strings.TrimSpace(cfg.LogPath) == ""
	if zeroConfig {
		cfg.Enabled = true
	}
	if cfg.SampleRate < 0 {
		cfg.SampleRate = 0
	}
	if cfg.SampleRate > 1 {
		cfg.SampleRate = 1
	}
	if zeroConfig && cfg.SampleRate == 0 {
		cfg.SampleRate = 1
	}
	if cfg.MaxBodyBytes == 0 {
		if zeroConfig {
			cfg.MaxBodyBytes = 128 * 1024
		}
	}
	if cfg.MaxBodyBytes < 0 {
		cfg.MaxBodyBytes = -1
	}
	if cfg.Seed == 0 {
		cfg.Seed = time.Now().UTC().UnixNano()
	}
	if strings.TrimSpace(cfg.LogPath) == "" {
		dir := filepath.Dir(historyPath)
		if dir == "." || strings.TrimSpace(dir) == "" {
			dir = filepath.Dir(ensureHistoryPath(historyPath))
		}
		cfg.LogPath = filepath.Join(dir, "proxy_flows.jsonl")
	}
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
	if val, ok := env.Lookup("0XGEN_OUT"); ok {
		if custom := strings.TrimSpace(val); custom != "" {
			return custom
		}
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
	if err := p.history.Close(); err != nil {
		return err
	}
	if p.flowLog != nil {
		if err := p.flowLog.Close(); err != nil {
			return err
		}
	}
	return nil
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

	p.serveProxyRequest(w, r, scheme, host, clientAddr, true, true, p.publisher != nil)
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

func (p *Proxy) serveProxyRequest(w http.ResponseWriter, r *http.Request, scheme, hostOverride, clientAddr string, applyRules, recordHistory, publishFlows bool) {
	ctx := r.Context()
	spanCtx, span := tracing.StartSpan(ctx, "proxy.capture_flow", tracing.WithSpanKind(tracing.SpanKindServer))
	status := tracing.StatusOK
	statusMsg := ""
	var state *proxyFlowState
	defer func() {
		if span == nil {
			return
		}
		if state != nil {
			if state.flowTracked {
				span.SetAttribute("oxg.flow.id", state.flowID)
			}
			if state.statusCode != 0 {
				span.SetAttribute("http.status_code", state.statusCode)
			}
		}
		span.EndWithStatus(status, statusMsg)
	}()

	r = r.WithContext(spanCtx)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		span.RecordError(fmt.Errorf("read request body: %w", err))
		status = tracing.StatusError
		statusMsg = "read request body"
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()

	if clientAddr == "" {
		clientAddr = r.RemoteAddr
	}
	span.SetAttribute("net.peer.ip", clientAddr)

	method := strings.ToUpper(strings.TrimSpace(r.Method))
	if method == "" {
		method = http.MethodGet
	}
	span.SetAttribute("http.method", method)
	r.Method = method

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
	span.SetAttribute("http.scheme", targetURL.Scheme)
	if strings.TrimSpace(targetURL.Host) == "" {
		status = tracing.StatusError
		statusMsg = "missing target host"
		span.RecordError(errors.New("missing target host"))
		http.Error(w, "missing target host", http.StatusBadRequest)
		return
	}
	span.SetAttribute("http.host", targetURL.Host)
	span.SetAttribute("http.target", targetURL.String())

	matched, names := p.rules.match(method, targetURL.String())
	span.SetAttribute("oxg.proxy.rules", len(matched))

	headers := cloneHeader(r.Header)
	r.Header = headers

	state = &proxyFlowState{
		method:         method,
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
		publishFlows:   publishFlows,
		requestProto:   r.Proto,
	}

	if state.publishFlows {
		if !p.flowCfg.Enabled || p.publisher == nil {
			state.publishFlows = false
		} else if !p.shouldPublishFlow() {
			state.publishFlows = false
		} else {
			state.flowTracked = true
			state.flowID = p.generateFlowID(p.flowIDs.Add(1))
			span.SetAttribute("oxg.flow.sampled", true)
		}
	}
	if !state.flowTracked {
		span.SetAttribute("oxg.flow.sampled", false)
	}
	span.SetAttribute("oxg.proxy.publish", state.publishFlows)

	if len(body) == 0 {
		r.Body = http.NoBody
		r.ContentLength = 0
	} else {
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}

	proxy := p.newReverseProxy(targetURL, state)
	proxy.ServeHTTP(w, r)

	if state.statusCode != 0 {
		span.SetAttribute("http.status_code", state.statusCode)
		if state.statusCode >= 500 && status != tracing.StatusError {
			status = tracing.StatusError
			statusMsg = fmt.Sprintf("upstream status %d", state.statusCode)
		}
	}
}

func (p *Proxy) newReverseProxy(target *url.URL, state *proxyFlowState) *httputil.ReverseProxy {
	director := func(outReq *http.Request) {
		outReq.URL = copyURL(target)
		outReq.Host = target.Host

		headers := cloneHeader(state.requestHeaders)
		body := append([]byte(nil), state.requestBody...)

		if state.applyRules {
			for _, rule := range state.matched {
				p.applyHeaderAdds(headers, rule.Request.AddHeaders)
				p.applyHeaderRemovals(headers, rule.Request.RemoveHeaders)
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
			p.applyHeaderAdds(headers, rule.Response.AddHeaders)
			p.applyHeaderRemovals(headers, rule.Response.RemoveHeaders)
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
	state.responseProto = resp.Proto

	if state.publishFlows {
		ctx := context.Background()
		if resp != nil && resp.Request != nil {
			ctx = resp.Request.Context()
		}
		p.publishFlowEvents(ctx, state)
	}

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
		RequestHeaders:  p.headerToMap(state.finalRequestHeaders),
		ResponseHeaders: p.headerToMap(state.responseHeaders),
		MatchedRules:    state.matchedNames,
	}
	if err := p.history.Write(entry); err != nil {
		p.logger.Warn("failed to persist history", "error", err)
	}
}

func (p *Proxy) shouldPublishFlow() bool {
	if p == nil {
		return false
	}
	if !p.flowCfg.Enabled {
		return false
	}
	rate := p.flowCfg.SampleRate
	if rate >= 1 {
		return true
	}
	if rate <= 0 {
		return false
	}
	p.samplerMu.Lock()
	defer p.samplerMu.Unlock()
	if p.sampler == nil {
		p.sampler = rand.New(rand.NewSource(p.flowSeed))
	}
	return p.sampler.Float64() < rate
}

func (p *Proxy) nextEventSequence() uint64 {
	if p == nil {
		return 0
	}
	return p.flowSeq.Add(1)
}

func (p *Proxy) generateFlowID(flowNumber uint64) string {
	var seedBuf, seqBuf [8]byte
	binary.LittleEndian.PutUint64(seedBuf[:], uint64(p.flowSeed))
	binary.LittleEndian.PutUint64(seqBuf[:], flowNumber)
	h := sha1.New()
	_, _ = h.Write(seedBuf[:])
	_, _ = h.Write(seqBuf[:])
	sum := h.Sum(nil)
	encoded := hex.EncodeToString(sum)
	if len(encoded) > 16 {
		encoded = encoded[:16]
	}
	return encoded
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
	publishFlows        bool
	requestProto        string
	responseProto       string
	flowTracked         bool
	flowID              string
}

func (p *Proxy) publishFlowEvents(ctx context.Context, state *proxyFlowState) {
	if (p.publisher == nil && p.flowLog == nil) || state == nil || !state.flowTracked {
		return
	}
	if p.scope != nil {
		decision := p.scope.Evaluate(state.url)
		if !decision.Allowed {
			p.logger.Debug("suppressing out-of-scope flow", "url", state.url, "reason", decision.Reason)
			return
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}

	if event := buildRequestEvent(state, p.flowCfg); event != nil {
		event.ID = fmt.Sprintf("%s:request", state.flowID)
		event.Sequence = p.nextEventSequence()
		event.Timestamp = state.start.UTC()
		if event.SanitizedRedacted {
			obsmetrics.RecordFlowRedaction("body")
		}
		if event.RawBodyCaptured >= 0 && event.RawBodyCaptured < event.RawBodySize {
			obsmetrics.RecordFlowRedaction("raw_truncated")
		}
		p.recordFlowEvent(event)
		p.emitFlowEvent(ctx, *event, "request")
	}
	if event := buildResponseEvent(state, p.flowCfg); event != nil {
		event.ID = fmt.Sprintf("%s:response", state.flowID)
		event.Sequence = p.nextEventSequence()
		event.Timestamp = time.Now().UTC()
		if event.SanitizedRedacted {
			obsmetrics.RecordFlowRedaction("body")
		}
		if event.RawBodyCaptured >= 0 && event.RawBodyCaptured < event.RawBodySize {
			obsmetrics.RecordFlowRedaction("raw_truncated")
		}
		p.recordFlowEvent(event)
		p.emitFlowEvent(ctx, *event, "response")
	}
}

func (p *Proxy) recordFlowEvent(event *flows.Event) {
	if p == nil || p.flowLog == nil || event == nil {
		return
	}
	if err := p.flowLog.Record(event.Clone()); err != nil {
		p.logger.Warn("failed to persist flow log", "error", err, "flow_id", event.ID)
	}
}

func (p *Proxy) emitFlowEvent(ctx context.Context, event flows.Event, phase string) {
	if p == nil || p.publisher == nil {
		return
	}
	attrs := map[string]any{
		"oxg.flow.id":            event.ID,
		"oxg.flow.sequence":      event.Sequence,
		"oxg.flow.phase":         phase,
		"oxg.flow.type":          event.Type.String(),
		"oxg.flow.has_raw":       len(event.Raw) > 0,
		"oxg.flow.has_sanitized": len(event.Sanitized) > 0,
	}
	pubCtx, span := tracing.StartSpan(ctx, "proxy.publish_flow_event", tracing.WithSpanKind(tracing.SpanKindInternal), tracing.WithAttributes(attrs))
	status := tracing.StatusOK
	statusMsg := ""
	defer func() {
		if span == nil {
			return
		}
		span.EndWithStatus(status, statusMsg)
	}()

	if err := p.publisher.PublishFlowEvent(pubCtx, event.Clone()); err != nil {
		span.RecordError(err)
		status = tracing.StatusError
		statusMsg = "publish flow event failed"
		p.logger.Warn("failed to publish flow event", "error", err, "flow_id", event.ID, "phase", phase)
	}
}

func encodeProxyRequest(state *proxyFlowState, limit int) ([]byte, int) {
	if state == nil {
		return nil, 0
	}
	method := strings.ToUpper(strings.TrimSpace(state.method))
	if method == "" {
		method = http.MethodGet
	}
	proto := strings.TrimSpace(state.requestProto)
	if proto == "" {
		proto = "HTTP/1.1"
	}
	headers := cloneHeader(state.finalRequestHeaders)
	body := append([]byte(nil), state.finalRequestBody...)
	captured := len(body)
	truncated := false
	if limit >= 0 && len(body) > limit {
		body = body[:limit]
		captured = len(body)
		truncated = true
	}
	headers = ensureHeader(headers)
	applyRawBodyHeaders(headers, body, truncated, state.finalRequestBody)
	target := requestTarget(state.url)
	payload := encodeHTTPRequest(method, target, proto, headers, body)
	return payload, captured
}

func encodeSanitizedProxyRequest(state *proxyFlowState) ([]byte, bool) {
	if state == nil {
		return nil, false
	}
	method := strings.ToUpper(strings.TrimSpace(state.method))
	if method == "" {
		method = http.MethodGet
	}
	proto := strings.TrimSpace(state.requestProto)
	if proto == "" {
		proto = "HTTP/1.1"
	}
	headers, body, redacted := sanitizeRequest(state)
	target := requestTarget(state.url)
	return encodeHTTPRequest(method, target, proto, headers, body), redacted
}

func encodeProxyResponse(state *proxyFlowState, limit int) ([]byte, int) {
	if state == nil {
		return nil, 0
	}
	proto := strings.TrimSpace(state.responseProto)
	if proto == "" {
		proto = "HTTP/1.1"
	}
	headers := cloneHeader(state.responseHeaders)
	body := append([]byte(nil), state.responseBody...)
	captured := len(body)
	truncated := false
	if limit >= 0 && len(body) > limit {
		body = body[:limit]
		captured = len(body)
		truncated = true
	}
	headers = ensureHeader(headers)
	applyRawBodyHeaders(headers, body, truncated, state.responseBody)
	status := sanitizeStatus(state.statusCode)
	payload := encodeHTTPResponse(proto, state.statusCode, headers, body, status)
	return payload, captured
}

func encodeSanitizedProxyResponse(state *proxyFlowState) ([]byte, bool) {
	if state == nil {
		return nil, false
	}
	proto := strings.TrimSpace(state.responseProto)
	if proto == "" {
		proto = "HTTP/1.1"
	}
	headers, body, redacted := sanitizeResponse(state)
	status := sanitizeStatus(state.statusCode)
	return encodeHTTPResponse(proto, state.statusCode, headers, body, status), redacted
}

func buildRequestEvent(state *proxyFlowState, cfg FlowCaptureConfig) *flows.Event {
	if state == nil {
		return nil
	}
	raw, captured := encodeProxyRequest(state, cfg.MaxBodyBytes)
	sanitized, redacted := encodeSanitizedProxyRequest(state)
	if len(raw) == 0 && len(sanitized) == 0 {
		return nil
	}
	return &flows.Event{
		Type:              pb.FlowEvent_FLOW_REQUEST,
		Sanitized:         sanitized,
		Raw:               raw,
		RawBodySize:       len(state.finalRequestBody),
		RawBodyCaptured:   captured,
		SanitizedRedacted: redacted,
	}
}

func buildResponseEvent(state *proxyFlowState, cfg FlowCaptureConfig) *flows.Event {
	if state == nil {
		return nil
	}
	raw, captured := encodeProxyResponse(state, cfg.MaxBodyBytes)
	sanitized, redacted := encodeSanitizedProxyResponse(state)
	if len(raw) == 0 && len(sanitized) == 0 {
		return nil
	}
	return &flows.Event{
		Type:              pb.FlowEvent_FLOW_RESPONSE,
		Sanitized:         sanitized,
		Raw:               raw,
		RawBodySize:       len(state.responseBody),
		RawBodyCaptured:   captured,
		SanitizedRedacted: redacted,
	}
}

func requestTarget(rawURL string) string {
	target := strings.TrimSpace(rawURL)
	if parsed, err := url.Parse(rawURL); err == nil {
		if parsed.Opaque != "" {
			target = parsed.Opaque
		} else {
			target = parsed.RequestURI()
		}
	}
	if target == "" {
		return "/"
	}
	return target
}

func encodeHTTPRequest(method, target, proto string, headers http.Header, body []byte) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %s %s\r\n", method, target, proto)
	if len(headers) > 0 {
		if err := headers.Write(&buf); err != nil {
			return nil
		}
	}
	buf.WriteString("\r\n")
	buf.Write(body)
	return buf.Bytes()
}

func encodeHTTPResponse(proto string, statusCode int, headers http.Header, body []byte, statusText string) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %d %s\r\n", proto, statusCode, statusText)
	if len(headers) > 0 {
		if err := headers.Write(&buf); err != nil {
			return nil
		}
	}
	buf.WriteString("\r\n")
	buf.Write(body)
	return buf.Bytes()
}

func sanitizeStatus(statusCode int) string {
	statusText := http.StatusText(statusCode)
	if statusText == "" {
		statusText = "Status"
	}
	return statusText
}

func sanitizeRequest(state *proxyFlowState) (http.Header, []byte, bool) {
	headers := sanitizeHeaders(state.finalRequestHeaders, true)
	body, redacted := sanitizeBody(state.finalRequestBody)
	headers = ensureHeader(headers)
	applySanitizedBodyHeaders(headers, body, redacted, len(state.finalRequestBody))
	return headers, body, redacted
}

func sanitizeResponse(state *proxyFlowState) (http.Header, []byte, bool) {
	headers := sanitizeHeaders(state.responseHeaders, false)
	body, redacted := sanitizeBody(state.responseBody)
	headers = ensureHeader(headers)
	applySanitizedBodyHeaders(headers, body, redacted, len(state.responseBody))
	return headers, body, redacted
}

const (
	redactedValue        = "[REDACTED]"
	redactedCookieValue  = "<redacted>"
	redactedBodyTemplate = "[REDACTED body length=%d sha256=%s]"
)

var (
	requestSensitiveHeaders = map[string]struct{}{
		"AUTHORIZATION":       {},
		"PROXY-AUTHORIZATION": {},
		"COOKIE":              {},
		"COOKIE2":             {},
		"X-CSRF-TOKEN":        {},
		"X-CSRFTOKEN":         {},
		"X-API-KEY":           {},
		"X-APIKEY":            {},
		"X-GITHUB-TOKEN":      {},
		"X-GITLAB-TOKEN":      {},
		"X-GOOG-API-KEY":      {},
		"X-AUTH-TOKEN":        {},
		"X-AUTHORIZATION":     {},
		"SET-COOKIE":          {},
		"SET-COOKIE2":         {},
	}
	responseSensitiveHeaders = map[string]struct{}{
		"SET-COOKIE":         {},
		"SET-COOKIE2":        {},
		"WWW-AUTHENTICATE":   {},
		"PROXY-AUTHENTICATE": {},
		"AUTHORIZATION":      {},
	}
)

func sanitizeHeaders(headers http.Header, request bool) http.Header {
	if len(headers) == 0 {
		return nil
	}
	sanitized := make(http.Header, len(headers))
	sensitive := responseSensitiveHeaders
	if request {
		sensitive = requestSensitiveHeaders
	}
	for name, values := range headers {
		canonical, _ := canonicalizeProxyHeaderName(name)
		upper := strings.ToUpper(canonical)
		if _, ok := sensitive[upper]; ok {
			sanitized[canonical] = sanitizeSensitiveHeader(upper, values)
			continue
		}
		copied := make([]string, len(values))
		copy(copied, values)
		sanitized[canonical] = copied
	}
	return sanitized
}

func sanitizeSensitiveHeader(upperName string, values []string) []string {
	switch upperName {
	case "AUTHORIZATION", "PROXY-AUTHORIZATION", "WWW-AUTHENTICATE", "PROXY-AUTHENTICATE":
		sanitized := make([]string, len(values))
		for i, value := range values {
			trimmed := strings.TrimSpace(value)
			parts := strings.SplitN(trimmed, " ", 2)
			if len(parts) == 2 {
				sanitized[i] = parts[0] + " " + redactedValue
				continue
			}
			if trimmed != "" {
				sanitized[i] = trimmed + " " + redactedValue
			} else {
				sanitized[i] = redactedValue
			}
		}
		return sanitized
	case "COOKIE", "COOKIE2":
		return sanitizeCookieValues(values)
	case "SET-COOKIE", "SET-COOKIE2":
		return sanitizeSetCookieValues(values)
	default:
		sanitized := make([]string, len(values))
		for i := range values {
			sanitized[i] = redactedValue
		}
		return sanitized
	}
}

func sanitizeCookieValues(values []string) []string {
	sanitized := make([]string, len(values))
	for i, value := range values {
		segments := strings.Split(value, ";")
		for j, segment := range segments {
			trimmed := strings.TrimSpace(segment)
			if trimmed == "" {
				segments[j] = trimmed
				continue
			}
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				segments[j] = strings.TrimSpace(parts[0]) + "=" + redactedCookieValue
			} else {
				segments[j] = trimmed
			}
		}
		sanitized[i] = strings.Join(segments, "; ")
	}
	return sanitized
}

func sanitizeSetCookieValues(values []string) []string {
	sanitized := make([]string, len(values))
	for i, value := range values {
		segments := strings.Split(value, ";")
		for j, segment := range segments {
			trimmed := strings.TrimSpace(segment)
			if trimmed == "" {
				segments[j] = trimmed
				continue
			}
			if j == 0 {
				parts := strings.SplitN(trimmed, "=", 2)
				if len(parts) == 2 {
					segments[j] = strings.TrimSpace(parts[0]) + "=" + redactedCookieValue
				} else {
					segments[j] = trimmed
				}
				continue
			}
			segments[j] = trimmed
		}
		sanitized[i] = strings.Join(segments, "; ")
	}
	return sanitized
}

func sanitizeBody(body []byte) ([]byte, bool) {
	if len(body) == 0 {
		return nil, false
	}
	sum := sha256.Sum256(body)
	placeholder := fmt.Sprintf(redactedBodyTemplate, len(body), hex.EncodeToString(sum[:]))
	return []byte(placeholder), true
}

func ensureHeader(h http.Header) http.Header {
	if h == nil {
		return http.Header{}
	}
	return h
}

func applySanitizedBodyHeaders(headers http.Header, body []byte, redacted bool, originalLen int) {
	if headers == nil {
		return
	}
	headers.Del("Transfer-Encoding")
	headers.Del("Content-Encoding")
	headers.Del("Content-Length")
	length := "0"
	if len(body) > 0 {
		length = strconv.Itoa(len(body))
	}
	headers.Set("Content-Length", length)
	if redacted {
		headers.Set(bodyRedactedHeader, strconv.Itoa(originalLen))
	} else {
		headers.Del(bodyRedactedHeader)
	}
}

func applyRawBodyHeaders(headers http.Header, body []byte, truncated bool, original []byte) {
	if headers == nil {
		return
	}
	headers.Del("Transfer-Encoding")
	headers.Del("Content-Encoding")
	headers.Del("Content-Length")
	length := "0"
	if len(body) > 0 {
		length = strconv.Itoa(len(body))
	}
	headers.Set("Content-Length", length)
	if truncated && len(original) > len(body) {
		sum := sha256.Sum256(original)
		value := fmt.Sprintf("%d;sha256=%s", len(original), hex.EncodeToString(sum[:]))
		headers.Set(rawBodyTruncatedHeader, value)
	} else {
		headers.Del(rawBodyTruncatedHeader)
	}
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

func (p *Proxy) headerToMap(h http.Header) map[string][]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string][]string, len(h))
	for k, values := range h {
		canonical := normalizeProxyHeaderName(k)
		if canonical == "" {
			continue
		}
		copied := make([]string, len(values))
		copy(copied, values)
		if existing, ok := out[canonical]; ok {
			out[canonical] = append(existing, copied...)
		} else {
			out[canonical] = copied
		}
	}
	if len(out) == 0 {
		return nil
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

func (p *Proxy) applyHeaderAdds(header http.Header, additions map[string]string) {
	if header == nil {
		return
	}
	for k, v := range additions {
		canonical := normalizeProxyHeaderName(k)
		if canonical == "" {
			continue
		}
		header.Set(canonical, v)
	}
}

func (p *Proxy) applyHeaderRemovals(header http.Header, removals []string) {
	if header == nil {
		return
	}
	for _, key := range removals {
		canonical := normalizeProxyHeaderName(key)
		if canonical == "" {
			continue
		}
		header.Del(canonical)
	}
}

func normalizeProxyHeaderName(name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return ""
	}
	return textproto.CanonicalMIMEHeaderKey(trimmed)
}

func canonicalizeProxyHeaderName(name string) (string, bool) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", false
	}
	canonical := textproto.CanonicalMIMEHeaderKey(trimmed)
	lower := strings.ToLower(canonical)
	if lower == strings.ToLower(modernProxyHeaderRoot) {
		return canonical, true
	}
	if strings.HasPrefix(lower, strings.ToLower(modernProxyHeaderPrefix)) {
		return canonical, true
	}
	return canonical, false
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
