package capabilities

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

const defaultTokenTTL = time.Minute

// Manager issues and validates short-lived capability grants for plugins.
type Manager struct {
	mu     sync.Mutex
	grants map[string]grant
	clock  func() time.Time
	ttl    time.Duration
}

type grant struct {
	plugin       string
	capabilities map[string]struct{}
	expires      time.Time
}

// Option configures the manager.
type Option func(*Manager)

// WithClock overrides the clock used for expiry calculations.
func WithClock(clock func() time.Time) Option {
	return func(m *Manager) {
		if clock != nil {
			m.clock = clock
		}
	}
}

// WithTTL overrides the duration for which issued tokens remain valid.
func WithTTL(ttl time.Duration) Option {
	return func(m *Manager) {
		if ttl > 0 {
			m.ttl = ttl
		}
	}
}

// NewManager constructs a Manager with sane defaults.
func NewManager(opts ...Option) *Manager {
	m := &Manager{
		grants: make(map[string]grant),
		clock:  time.Now,
		ttl:    defaultTokenTTL,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Issue registers the provided capability list for the plugin and returns a
// short-lived token that must be presented during the runtime handshake.
func (m *Manager) Issue(plugin string, capabilities []string) (token string, expires time.Time, err error) {
	plugin = strings.TrimSpace(plugin)
	if plugin == "" {
		return "", time.Time{}, errors.New("plugin name is required")
	}
	capSet := make(map[string]struct{}, len(capabilities))
	for _, cap := range capabilities {
		cap = strings.ToUpper(strings.TrimSpace(cap))
		if cap == "" {
			continue
		}
		capSet[cap] = struct{}{}
	}
	if len(capSet) == 0 {
		return "", time.Time{}, errors.New("at least one capability is required")
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, fmt.Errorf("generate token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw)

	expires = m.clock().Add(m.ttl)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.grants[token] = grant{plugin: plugin, capabilities: capSet, expires: expires}
	return token, expires, nil
}

// Validate consumes the token and ensures the requested capabilities are a
// subset of the issued grant. The returned slice contains the normalised
// capability names that remain valid for the session.
func (m *Manager) Validate(token, plugin string, requested []string) ([]string, error) {
	token = strings.TrimSpace(token)
	plugin = strings.TrimSpace(plugin)
	if token == "" {
		return nil, errors.New("capability token is required")
	}
	if plugin == "" {
		return nil, errors.New("plugin name is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	grant, ok := m.grants[token]
	if !ok {
		return nil, errors.New("capability token not recognised")
	}
	delete(m.grants, token)

	if grant.plugin != plugin {
		return nil, errors.New("capability token issued for different plugin")
	}
	if m.clock().After(grant.expires) {
		return nil, errors.New("capability token expired")
	}

	if len(requested) == 0 {
		return nil, errors.New("no capabilities requested")
	}

	normalised := make([]string, 0, len(requested))
	for _, cap := range requested {
		cap = strings.ToUpper(strings.TrimSpace(cap))
		if cap == "" {
			continue
		}
		if _, ok := grant.capabilities[cap]; !ok {
			return nil, fmt.Errorf("capability %s not granted", cap)
		}
		normalised = append(normalised, cap)
	}
	if len(normalised) == 0 {
		return nil, errors.New("no valid capabilities requested")
	}

	slices.Sort(normalised)
	return normalised, nil
}

// Remaining returns the number of active grants. It is intended for testing.
func (m *Manager) Remaining() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.grants)
}
