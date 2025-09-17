package netgate

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	capHTTPActive  = "CAP_HTTP_ACTIVE"
	capHTTPPassive = "CAP_HTTP_PASSIVE"
)

// Dialer defines the subset of net.Dialer we require. net.Dialer itself
// satisfies this interface.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Gate ensures all outbound network operations performed on behalf of plugins
// respect the declared capabilities.
type Gate struct {
	dialer Dialer
	mu     sync.RWMutex
	perms  map[string]map[string]struct{}
}

// New creates a gate wrapping the provided dialer. If dialer is nil a sane
// default is used.
func New(dialer Dialer) *Gate {
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 5 * time.Second}
	}
	return &Gate{dialer: dialer, perms: make(map[string]map[string]struct{})}
}

// Register stores the capabilities granted to the plugin. Passing an empty
// slice clears any prior grant.
func (g *Gate) Register(pluginID string, capabilities []string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if pluginID == "" {
		return
	}

	capSet := make(map[string]struct{}, len(capabilities))
	for _, cap := range capabilities {
		cap = strings.TrimSpace(cap)
		if cap == "" {
			continue
		}
		capSet[cap] = struct{}{}
	}
	g.perms[pluginID] = capSet
}

// Unregister removes any stored capabilities for the plugin.
func (g *Gate) Unregister(pluginID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.perms, pluginID)
}

// DialContext enforces the requested capability before delegating to the
// underlying dialer.
func (g *Gate) DialContext(ctx context.Context, pluginID, capability, network, address string) (net.Conn, error) {
	if err := g.check(pluginID, capability); err != nil {
		return nil, err
	}
	return g.dialer.DialContext(ctx, network, address)
}

func (g *Gate) check(pluginID, capability string) error {
	switch capability {
	case capHTTPActive, capHTTPPassive:
	default:
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
