package netgate

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	capHTTPActive  = "CAP_HTTP_ACTIVE"
	capHTTPPassive = "CAP_HTTP_PASSIVE"

	envTimeout = "GLYPH_NET_TIMEOUT"
	envBudget  = "GLYPH_NET_BUDGET"

	defaultTimeout = 5 * time.Second
	defaultBudget  = 50
)

var supportedCaps = map[string]struct{}{
	capHTTPActive:  {},
	capHTTPPassive: {},
}

// Config controls the runtime limits enforced by the gate.
type Config struct {
	Timeout       time.Duration
	RequestBudget int
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

// Gate ensures all outbound network operations performed on behalf of plugins
// respect the declared capabilities and configured limits.
type Gate struct {
	dialer  Dialer
	mu      sync.RWMutex
	perms   map[string]map[string]struct{}
	budgets map[string]int
	config  Config
}

// New creates a gate wrapping the provided dialer. If dialer is nil a sane
// default is used.
func New(dialer Dialer, opts ...Option) *Gate {
	cfg := loadConfigFromEnv()
	g := &Gate{
		dialer:  dialer,
		perms:   make(map[string]map[string]struct{}),
		budgets: make(map[string]int),
		config:  cfg,
	}
	for _, opt := range opts {
		opt(g)
	}
	g.config = sanitizeConfig(g.config)
	if g.dialer == nil {
		g.dialer = &net.Dialer{Timeout: g.config.Timeout}
	}
	return g
}

func loadConfigFromEnv() Config {
	cfg := Config{Timeout: defaultTimeout, RequestBudget: defaultBudget}
	if raw := strings.TrimSpace(os.Getenv(envTimeout)); raw != "" {
		if dur, err := time.ParseDuration(raw); err == nil {
			cfg.Timeout = dur
		}
	}
	if raw := strings.TrimSpace(os.Getenv(envBudget)); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil {
			cfg.RequestBudget = v
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
	if err := g.authorize(pluginID, capability); err != nil {
		return nil, err
	}
	ctx, cancel := g.withTimeout(ctx)
	defer cancel()
	return g.dialer.DialContext(ctx, network, address)
}

// HTTPClient returns a client that performs capability and budget checks per
// request before allowing HTTP egress.
func (g *Gate) HTTPClient(pluginID, capability string) (*HTTPClient, error) {
	if err := g.ensureCapability(pluginID, capability); err != nil {
		return nil, err
	}
	base := http.DefaultTransport
	transport, ok := base.(*http.Transport)
	if !ok {
		transport = &http.Transport{}
	} else {
		transport = transport.Clone()
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		ctx, cancel := g.withTimeout(ctx)
		defer cancel()
		return g.dialer.DialContext(ctx, network, address)
	}
	client := &http.Client{Transport: transport, Timeout: g.config.Timeout}
	return &HTTPClient{gate: g, pluginID: pluginID, capability: capability, client: client}, nil
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

// HTTPClient wraps a standard http.Client with capability enforcement.
type HTTPClient struct {
	gate       *Gate
	pluginID   string
	capability string
	client     *http.Client
}

// Do dispatches the HTTP request after applying capability and timeout checks.
func (c *HTTPClient) Do(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, errors.New("request is nil")
	}
	if err := c.gate.authorize(c.pluginID, c.capability); err != nil {
		return nil, err
	}
	ctx, cancel := c.gate.withTimeout(req.Context())
	if cancel != nil {
		defer cancel()
	}
	cloned := req.Clone(ctx)
	return c.client.Do(cloned)
}

// CloseIdleConnections releases idle connections held by the underlying transport.
func (c *HTTPClient) CloseIdleConnections() {
	if closer, ok := c.client.Transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

// Client exposes the underlying http.Client for advanced use cases.
func (c *HTTPClient) Client() *http.Client {
	return c.client
}
