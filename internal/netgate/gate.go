package netgate

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/RowanDark/0xgen/internal/env"
	"github.com/RowanDark/0xgen/internal/logging"
	"github.com/RowanDark/0xgen/internal/netgate/fingerprint"
	obsmetrics "github.com/RowanDark/0xgen/internal/observability/metrics"
	"github.com/RowanDark/0xgen/internal/observability/tracing"
)

const (
	capHTTPActive  = "CAP_HTTP_ACTIVE"
	capHTTPPassive = "CAP_HTTP_PASSIVE"

	envTimeout    = "GLYPH_NET_TIMEOUT"
	envBudget     = "GLYPH_NET_BUDGET"
	envTimeoutNew = "0XGEN_NET_TIMEOUT"
	envBudgetNew  = "0XGEN_NET_BUDGET"

	defaultTimeout = 5 * time.Second
	defaultBudget  = 50

	defaultRetryAttempts   = 3
	defaultRetryInitial    = 500 * time.Millisecond
	defaultRetryMax        = 10 * time.Second
	defaultRetryMultiplier = 2.0
	defaultRetryJitter     = 250 * time.Millisecond

	// maxBufferedRetryBodyBytes bounds the amount of request body data that may be
	// materialised in memory to enable retries. Requests with larger or
	// unknown bodies are executed without retries to avoid unbounded buffering.
	maxBufferedRetryBodyBytes = int64(1 << 20) // 1 MiB
)

var supportedCaps = map[string]struct{}{
	capHTTPActive:  {},
	capHTTPPassive: {},
}

var (
	jitterMu  sync.Mutex
	jitterRNG = rand.New(rand.NewSource(time.Now().UnixNano()))
)

// TransportConfig controls the negotiated HTTP protocols available to clients.
type TransportConfig struct {
	EnableHTTP2  bool
	EnableHTTP3  bool
	RequireHTTP3 bool
}

var defaultTransportConfig = TransportConfig{EnableHTTP2: true, EnableHTTP3: true}

func sanitizeTransportConfig(cfg TransportConfig) TransportConfig {
	if cfg.RequireHTTP3 {
		cfg.EnableHTTP3 = true
	}
	if !cfg.EnableHTTP2 && !cfg.EnableHTTP3 {
		cfg.EnableHTTP2 = true
	}
	return cfg
}

// Config controls the runtime limits enforced by the gate.
type Config struct {
	Timeout       time.Duration
	RequestBudget int
	PerHostRate   RateLimit
	GlobalRate    RateLimit
	Retry         RetryConfig
}

// RateLimit describes a token bucket configuration.
type RateLimit struct {
	Requests int
	Interval time.Duration
	Burst    int
}

// RetryConfig controls retry and backoff behaviour for HTTP requests.
type RetryConfig struct {
	MaxAttempts int
	Initial     time.Duration
	Max         time.Duration
	Multiplier  float64
	Jitter      time.Duration
}

// Dialer defines the subset of net.Dialer we require. net.Dialer itself
// satisfies this interface.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Option customises gate behaviour.
type Option func(*Gate)

// WithConfig replaces the default gate configuration.
func WithConfig(cfg Config) Option {
	return func(g *Gate) {
		g.config = sanitizeConfig(cfg)
	}
}

// WithTimeout overrides the request timeout enforced by the gate.
func WithTimeout(timeout time.Duration) Option {
	return func(g *Gate) {
		g.config.Timeout = timeout
	}
}

// WithRequestBudget overrides the per-plugin request budget.
func WithRequestBudget(budget int) Option {
	return func(g *Gate) {
		g.config.RequestBudget = budget
	}
}

// WithPerHostRateLimit configures the per-host rate limiter.
func WithPerHostRateLimit(limit RateLimit) Option {
	return func(g *Gate) {
		g.config.PerHostRate = limit
	}
}

// WithGlobalRateLimit configures the process-wide HTTP rate limiter.
func WithGlobalRateLimit(limit RateLimit) Option {
	return func(g *Gate) {
		g.config.GlobalRate = limit
	}
}

// WithRetryConfig overrides the default retry configuration.
func WithRetryConfig(cfg RetryConfig) Option {
	return func(g *Gate) {
		g.config.Retry = cfg
	}
}

// WithTransportConfig customises the HTTP protocol support for new clients.
func WithTransportConfig(cfg TransportConfig) Option {
	return func(g *Gate) {
		g.tcfg = sanitizeTransportConfig(cfg)
	}
}

// WithFingerprintStrategy replaces the default JA3/JA4 strategy.
func WithFingerprintStrategy(strategy *fingerprint.Strategy) Option {
	return func(g *Gate) {
		if strategy != nil {
			g.fp = strategy
		}
	}
}

// WithTLSConfig applies a base TLS configuration to all outbound clients.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(g *Gate) {
		if cfg != nil {
			g.tlsCfg = cfg.Clone()
		}
	}
}

// Gate ensures all outbound network operations performed on behalf of plugins
// respect the declared capabilities and configured limits.
type Gate struct {
	dialer        Dialer
	mu            sync.RWMutex
	perms         map[string]map[string]struct{}
	budgets       map[string]int
	config        Config
	audit         *logging.AuditLogger
	tlsCfg        *tls.Config
	fp            *fingerprint.Strategy
	tcfg          TransportConfig
	rateMu        sync.Mutex
	hostLimiters  map[string]*rateTracker
	globalLimiter *rateTracker
	retryCfg      RetryConfig
}

// New creates a gate wrapping the provided dialer. If dialer is nil a sane
// default is used.
func New(dialer Dialer, opts ...Option) *Gate {
	cfg := loadConfigFromEnv()
	g := &Gate{
		dialer:       dialer,
		perms:        make(map[string]map[string]struct{}),
		budgets:      make(map[string]int),
		config:       cfg,
		fp:           fingerprint.DefaultStrategy(),
		tcfg:         defaultTransportConfig,
		hostLimiters: make(map[string]*rateTracker),
	}
	for _, opt := range opts {
		opt(g)
	}
	g.config = sanitizeConfig(g.config)
	g.tcfg = sanitizeTransportConfig(g.tcfg)
	if g.fp == nil {
		g.fp = fingerprint.DefaultStrategy()
	}
	g.retryCfg = g.config.Retry
	if rl := g.config.GlobalRate; rateLimitEnabled(rl) {
		g.globalLimiter = newRateLimiter(rl)
	}
	if g.dialer == nil {
		g.dialer = &net.Dialer{Timeout: g.config.Timeout}
	}
	return g
}

// WithAuditLogger configures the gate to emit audit entries for denied operations.
func WithAuditLogger(logger *logging.AuditLogger) Option {
	return func(g *Gate) {
		if logger != nil {
			g.audit = logger
		}
	}
}

func loadConfigFromEnv() Config {
	cfg := Config{Timeout: defaultTimeout, RequestBudget: defaultBudget, Retry: defaultRetryConfig()}
	if raw, ok := env.Lookup(envTimeoutNew, envTimeout); ok {
		if trimmed := strings.TrimSpace(raw); trimmed != "" {
			if dur, err := time.ParseDuration(trimmed); err == nil {
				cfg.Timeout = dur
			}
		}
	}
	if raw, ok := env.Lookup(envBudgetNew, envBudget); ok {
		if trimmed := strings.TrimSpace(raw); trimmed != "" {
			if v, err := strconv.Atoi(trimmed); err == nil {
				cfg.RequestBudget = v
			}
		}
	}
	return cfg
}

func sanitizeConfig(cfg Config) Config {
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.RequestBudget < 0 {
		cfg.RequestBudget = 0
	}
	cfg.PerHostRate = sanitizeRateLimit(cfg.PerHostRate)
	cfg.GlobalRate = sanitizeRateLimit(cfg.GlobalRate)
	cfg.Retry = sanitizeRetryConfig(cfg.Retry)
	return cfg
}

func defaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts: defaultRetryAttempts,
		Initial:     defaultRetryInitial,
		Max:         defaultRetryMax,
		Multiplier:  defaultRetryMultiplier,
		Jitter:      defaultRetryJitter,
	}
}

func sanitizeRateLimit(limit RateLimit) RateLimit {
	if limit.Requests <= 0 || limit.Interval <= 0 {
		return RateLimit{}
	}
	if limit.Burst <= 0 {
		limit.Burst = limit.Requests
	}
	return limit
}

func rateLimitEnabled(limit RateLimit) bool {
	return limit.Requests > 0 && limit.Interval > 0 && limit.Burst > 0
}

func newRateLimiter(limit RateLimit) *rateTracker {
	if !rateLimitEnabled(limit) {
		return nil
	}
	return newRateTracker(limit)
}

func sanitizeRetryConfig(cfg RetryConfig) RetryConfig {
	def := defaultRetryConfig()
	if cfg.MaxAttempts < 1 {
		cfg.MaxAttempts = def.MaxAttempts
	}
	if cfg.Initial <= 0 {
		cfg.Initial = def.Initial
	}
	if cfg.Max <= 0 {
		cfg.Max = def.Max
	}
	if cfg.Multiplier < 1 {
		cfg.Multiplier = def.Multiplier
	}
	if cfg.Jitter < 0 {
		cfg.Jitter = 0
	}
	if cfg.Max < cfg.Initial {
		cfg.Max = cfg.Initial
	}
	return cfg
}

// Register stores the capabilities granted to the plugin. Passing an empty
// slice clears any prior grant.
func (g *Gate) Register(pluginID string, capabilities []string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if pluginID = strings.TrimSpace(pluginID); pluginID == "" {
		return
	}

	capSet := make(map[string]struct{}, len(capabilities))
	for _, cap := range capabilities {
		cap = strings.ToUpper(strings.TrimSpace(cap))
		if cap == "" {
			continue
		}
		capSet[cap] = struct{}{}
	}
	g.perms[pluginID] = capSet
	if g.config.RequestBudget > 0 {
		g.budgets[pluginID] = g.config.RequestBudget
	} else {
		delete(g.budgets, pluginID)
	}
}

// Unregister removes any stored capabilities for the plugin.
func (g *Gate) Unregister(pluginID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.perms, pluginID)
	delete(g.budgets, pluginID)
}

// DialContext enforces the requested capability before delegating to the
// underlying dialer.
func (g *Gate) DialContext(ctx context.Context, pluginID, capability, network, address string) (net.Conn, error) {
	metadata := dialMetadata(network, address)
	if err := g.authorize(pluginID, capability); err != nil {
		g.auditDenied(ctx, pluginID, capability, metadata, err)
		return nil, err
	}
	if err := validateDialTarget(network, address); err != nil {
		g.auditDenied(ctx, pluginID, capability, metadata, err)
		return nil, err
	}
	ctx, cancel := g.withTimeout(ctx)
	defer cancel()
	return g.dialer.DialContext(ctx, network, address)
}

// HTTPClient returns a client that performs capability and budget checks per
// request before allowing HTTP egress.
func (g *Gate) HTTPClient(pluginID, capability string) (*HTTPClient, error) {
	metadata := map[string]any{"operation": "http_client_init"}
	if err := g.ensureCapability(pluginID, capability); err != nil {
		g.auditDenied(context.Background(), pluginID, capability, metadata, err)
		return nil, err
	}
	transport, err := g.buildTransport()
	if err != nil {
		g.auditDenied(context.Background(), pluginID, capability, metadata, err)
		return nil, err
	}
	client := &http.Client{
		Transport: &gatedTransport{gate: g, pluginID: pluginID, capability: capability, transport: transport},
		Timeout:   g.config.Timeout,
	}
	return &HTTPClient{gate: g, pluginID: pluginID, capability: capability, client: client, transport: transport}, nil
}

func (g *Gate) ensureCapability(pluginID, capability string) error {
	capability = strings.ToUpper(strings.TrimSpace(capability))
	if _, ok := supportedCaps[capability]; !ok {
		return fmt.Errorf("unsupported capability check: %s", capability)
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	perms, ok := g.perms[pluginID]
	if !ok {
		return errors.New("plugin not registered with gate")
	}
	if _, ok := perms[capability]; !ok {
		return fmt.Errorf("plugin %s missing capability %s", pluginID, capability)
	}
	return nil
}

func (g *Gate) authorize(pluginID, capability string) error {
	capability = strings.ToUpper(strings.TrimSpace(capability))
	if _, ok := supportedCaps[capability]; !ok {
		return fmt.Errorf("unsupported capability check: %s", capability)
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	perms, ok := g.perms[pluginID]
	if !ok {
		return errors.New("plugin not registered with gate")
	}
	if _, ok := perms[capability]; !ok {
		return fmt.Errorf("plugin %s missing capability %s", pluginID, capability)
	}
	if g.config.RequestBudget <= 0 {
		return nil
	}
	remaining, ok := g.budgets[pluginID]
	if !ok {
		remaining = g.config.RequestBudget
	}
	if remaining <= 0 {
		return fmt.Errorf("plugin %s exhausted network budget", pluginID)
	}
	g.budgets[pluginID] = remaining - 1
	return nil
}

func (g *Gate) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if g.config.Timeout <= 0 {
		return ctx, func() {}
	}
	newCtx, cancel := context.WithTimeout(ctx, g.config.Timeout)
	return newCtx, cancel
}

func (g *Gate) validateHTTPRequest(ctx context.Context, pluginID, capability string, req *http.Request) error {
	err := validateHTTPRequest(req)
	if err != nil {
		g.auditDenied(ctx, pluginID, capability, httpMetadata(req), err)
	}
	return err
}

func (g *Gate) auditDenied(ctx context.Context, pluginID, capability string, metadata map[string]any, err error) {
	if g == nil || g.audit == nil || err == nil {
		return
	}
	md := make(map[string]any, len(metadata)+1)
	for k, v := range metadata {
		if v == nil {
			continue
		}
		md[k] = v
	}
	if capName := strings.TrimSpace(capability); capName != "" {
		md["capability"] = capName
	}
	event := logging.AuditEvent{
		EventType: logging.EventNetworkDenied,
		Decision:  logging.DecisionDeny,
		PluginID:  strings.TrimSpace(pluginID),
		Reason:    err.Error(),
		Metadata:  md,
	}
	if traceID := tracing.TraceIDFromContext(ctx); traceID != "" {
		event.TraceID = traceID
	}
	_ = g.audit.Emit(event)
}

func (g *Gate) decorateRequest(req *http.Request) {
	if req == nil || g.fp == nil {
		return
	}
	g.fp.DecorateRequest(req)
}

func dialMetadata(network, address string) map[string]any {
	md := map[string]any{"operation": "dial"}
	if netName := strings.TrimSpace(network); netName != "" {
		md["network"] = netName
	}
	if addr := strings.TrimSpace(address); addr != "" {
		md["address"] = addr
	}
	return md
}

func httpMetadata(req *http.Request) map[string]any {
	md := map[string]any{"operation": "http_request"}
	if req == nil {
		return md
	}
	if method := strings.TrimSpace(req.Method); method != "" {
		md["method"] = method
	}
	if req.URL != nil {
		md["url"] = req.URL.String()
	}
	return md
}

// HTTPClient wraps a standard http.Client with capability enforcement.
type HTTPClient struct {
	gate       *Gate
	pluginID   string
	capability string
	client     *http.Client
	transport  http.RoundTripper
}

type rateTracker struct {
	mu      sync.Mutex
	window  time.Duration
	max     int
	entries []time.Time
}

func newRateTracker(limit RateLimit) *rateTracker {
	return &rateTracker{window: limit.Interval, max: limit.Burst}
}

func (rt *rateTracker) reserve(now time.Time) (time.Duration, func()) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.pruneLocked(now)
	if len(rt.entries) < rt.max {
		rt.entries = append(rt.entries, now)
		return 0, func() {}
	}
	earliest := rt.entries[0]
	waitUntil := earliest.Add(rt.window)
	delay := waitUntil.Sub(now)
	if delay < 0 {
		delay = 0
		waitUntil = now
	}
	rt.entries = append(rt.entries, waitUntil)
	cancelled := false
	cancel := func() {
		rt.mu.Lock()
		defer rt.mu.Unlock()
		if cancelled {
			return
		}
		for i, ts := range rt.entries {
			if ts == waitUntil {
				rt.entries = append(rt.entries[:i], rt.entries[i+1:]...)
				break
			}
		}
		cancelled = true
	}
	return delay, cancel
}

func (rt *rateTracker) pruneLocked(now time.Time) {
	if rt.window <= 0 {
		rt.entries = rt.entries[:0]
		return
	}
	cutoff := now.Add(-rt.window)
	idx := 0
	for _, ts := range rt.entries {
		if ts.After(cutoff) {
			break
		}
		idx++
	}
	if idx > 0 {
		rt.entries = append(rt.entries[:0], rt.entries[idx:]...)
	}
	if len(rt.entries) > rt.max {
		rt.entries = rt.entries[len(rt.entries)-rt.max:]
	}
}

// Do dispatches the HTTP request after applying capability and timeout checks.
func (c *HTTPClient) Do(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, errors.New("request is nil")
	}
	metadata := httpMetadata(req)
	if err := c.gate.authorize(c.pluginID, c.capability); err != nil {
		c.gate.auditDenied(req.Context(), c.pluginID, c.capability, metadata, err)
		return nil, err
	}
	ctx, cancel := c.gate.withTimeout(req.Context())
	if cancel != nil {
		defer cancel()
	}
	attempts := c.gate.retryCfg.MaxAttempts
	if attempts < 1 {
		attempts = 1
	}
	cloned := req.Clone(ctx)
	if attempts > 1 {
		rewindable, err := ensureRewindableBody(cloned)
		if err != nil {
			return nil, err
		}
		if !rewindable {
			attempts = 1
		}
	}
	c.gate.decorateRequest(cloned)
	return c.executeWithRetry(cloned, attempts)
}

func (c *HTTPClient) executeWithRetry(template *http.Request, attempts int) (*http.Response, error) {
	if attempts < 1 {
		attempts = 1
	}
	for attempt := 0; attempt < attempts; attempt++ {
		req, err := cloneRequestForAttempt(template)
		if err != nil {
			return nil, err
		}
		if err := c.gate.waitForQuota(req.Context(), c.pluginID, req.URL); err != nil {
			return nil, err
		}
		start := time.Now()
		resp, err := c.client.Do(req)
		duration := time.Since(start)
		if err != nil {
			obsmetrics.ObserveHTTPClientDuration(c.pluginID, c.capability, req.Method, "error", duration)
			return nil, err
		}
		statusLabel := strconv.Itoa(resp.StatusCode)
		obsmetrics.ObserveHTTPClientDuration(c.pluginID, c.capability, req.Method, statusLabel, duration)
		if !shouldRetry(resp.StatusCode) || attempt == attempts-1 {
			return resp, nil
		}
		obsmetrics.RecordHTTPBackoff(resp.StatusCode)
		delay := c.gate.computeBackoffDelay(attempt)
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-req.Context().Done():
				if !timer.Stop() {
					<-timer.C
				}
				_ = resp.Body.Close()
				return nil, req.Context().Err()
			case <-timer.C:
			}
		}
		_ = resp.Body.Close()
	}
	return nil, errors.New("exhausted retries without response")
}

// CloseIdleConnections releases idle connections held by the underlying transport.
func (c *HTTPClient) CloseIdleConnections() {
	if closer, ok := c.transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

// Client exposes the underlying http.Client for advanced use cases.
func (c *HTTPClient) Client() *http.Client {
	return c.client
}

func ensureRewindableBody(req *http.Request) (bool, error) {
	if req == nil || req.Body == nil {
		return true, nil
	}
	if req.GetBody != nil {
		original := req.Body
		body, err := req.GetBody()
		if err != nil {
			if original != nil {
				_ = original.Close()
			}
			return false, err
		}
		if original != nil {
			if err := original.Close(); err != nil {
				_ = body.Close()
				return false, err
			}
		}
		req.Body = body
		return true, nil
	}
	if req.ContentLength < 0 {
		return false, nil
	}
	if req.ContentLength == 0 {
		if err := req.Body.Close(); err != nil {
			return false, err
		}
		req.Body = http.NoBody
		req.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
		return true, nil
	}
	if req.ContentLength > maxBufferedRetryBodyBytes {
		return false, nil
	}
	data := make([]byte, int(req.ContentLength))
	if _, err := io.ReadFull(req.Body, data); err != nil {
		return false, err
	}
	if err := req.Body.Close(); err != nil {
		return false, err
	}
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	body, err := req.GetBody()
	if err != nil {
		return false, err
	}
	req.Body = body
	return true, nil
}

func cloneRequestForAttempt(template *http.Request) (*http.Request, error) {
	if template == nil {
		return nil, errors.New("request template is nil")
	}
	clone := template.Clone(template.Context())
	if template.GetBody != nil {
		body, err := template.GetBody()
		if err != nil {
			return nil, err
		}
		clone.Body = body
	}
	return clone, nil
}

func (g *Gate) waitForQuota(ctx context.Context, pluginID string, u *url.URL) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if u == nil {
		return errors.New("request URL required")
	}
	if rateLimitEnabled(g.config.PerHostRate) {
		host := strings.ToLower(u.Hostname())
		if host != "" {
			limiter := g.limiterForHost(host)
			if err := g.waitOnLimiter(ctx, pluginID, limiter, "host", host); err != nil {
				return err
			}
		}
	}
	if g.globalLimiter != nil {
		if err := g.waitOnLimiter(ctx, pluginID, g.globalLimiter, "global", ""); err != nil {
			return err
		}
	}
	return nil
}

func (g *Gate) limiterForHost(host string) *rateTracker {
	if !rateLimitEnabled(g.config.PerHostRate) {
		return nil
	}
	key := strings.ToLower(strings.TrimSpace(host))
	if key == "" {
		return nil
	}
	g.rateMu.Lock()
	defer g.rateMu.Unlock()
	limiter, ok := g.hostLimiters[key]
	if ok {
		return limiter
	}
	limiter = newRateLimiter(g.config.PerHostRate)
	g.hostLimiters[key] = limiter
	return limiter
}

func (g *Gate) waitOnLimiter(ctx context.Context, pluginID string, limiter *rateTracker, scope, key string) error {
	if limiter == nil {
		return nil
	}
	delay, cancel := limiter.reserve(time.Now())
	if delay <= 0 {
		return nil
	}
	obsmetrics.RecordHTTPThrottle(scope)
	attrs := map[string]any{
		"glyph.plugin.id":     pluginID,
		"glyph.rate.scope":    scope,
		"glyph.rate.delay_ms": delay.Milliseconds(),
	}
	if strings.TrimSpace(key) != "" {
		attrs["glyph.rate.key"] = strings.TrimSpace(key)
	}
	spanCtx, span := tracing.StartSpan(ctx, "netgate.rate_limit_wait", tracing.WithSpanKind(tracing.SpanKindInternal), tracing.WithAttributes(attrs))
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-spanCtx.Done():
		cancel()
		err := spanCtx.Err()
		span.RecordError(err)
		span.End()
		return err
	case <-timer.C:
		span.EndWithStatus(tracing.StatusOK, "")
	}
	return nil
}

func (g *Gate) computeBackoffDelay(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	cfg := g.retryCfg
	delay := cfg.Initial
	for i := 0; i < attempt; i++ {
		next := time.Duration(float64(delay) * cfg.Multiplier)
		if next < delay {
			delay = cfg.Max
			break
		}
		delay = next
		if delay >= cfg.Max {
			delay = cfg.Max
			break
		}
	}
	if delay > cfg.Max {
		delay = cfg.Max
	}
	if cfg.Jitter > 0 {
		delay += randomJitter(cfg.Jitter)
		if delay > cfg.Max {
			delay = cfg.Max
		}
	}
	if delay < 0 {
		return cfg.Max
	}
	return delay
}

func randomJitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	jitterMu.Lock()
	defer jitterMu.Unlock()
	upper := int64(max)
	if upper <= 0 {
		return 0
	}
	n := jitterRNG.Int63n(upper + 1)
	return time.Duration(n)
}

func shouldRetry(status int) bool {
	if status == http.StatusTooManyRequests {
		return true
	}
	return status >= 500 && status < 600
}

func validateDialTarget(network, address string) error {
	netName := strings.ToLower(strings.TrimSpace(network))
	switch netName {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
	default:
		return fmt.Errorf("network %s not permitted", network)
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}
	return validateHost(host)
}

func validateHTTPRequest(req *http.Request) error {
	if req == nil || req.URL == nil {
		return errors.New("request URL required")
	}
	if err := validateURL(req.URL); err != nil {
		return err
	}
	return nil
}

func validateURL(u *url.URL) error {
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	switch scheme {
	case "http", "https":
	default:
		return fmt.Errorf("scheme %s not permitted", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("request host required")
	}
	return validateHost(host)
}

var (
	privatePrefixes = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("fc00::/7"),
	}
	linkLocalPrefixes = []netip.Prefix{
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("fe80::/10"),
	}
)

func validateHost(host string) error {
	hostname := strings.TrimSpace(host)
	if hostname == "" {
		return errors.New("host required")
	}
	if strings.EqualFold(hostname, "localhost") {
		return errors.New("loopback destinations are not permitted")
	}
	base := hostname
	if i := strings.Index(hostname, "%"); i > -1 {
		base = hostname[:i]
	}
	if addr, err := netip.ParseAddr(base); err == nil {
		if addr.IsLoopback() {
			return errors.New("loopback destinations are not permitted")
		}
		if inPrefixes(addr, privatePrefixes) {
			return errors.New("private address ranges are not permitted")
		}
		if inPrefixes(addr, linkLocalPrefixes) {
			return errors.New("link-local destinations are not permitted")
		}
	}
	return nil
}

func inPrefixes(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
