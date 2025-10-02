package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/RowanDark/Glyph/internal/logging"
)

var (
	// ErrPluginRequired indicates the plugin name was not supplied.
	ErrPluginRequired = errors.New("plugin name is required")
	// ErrSecretRequired indicates no secrets were requested.
	ErrSecretRequired = errors.New("at least one secret is required")
	// ErrSecretNotProvisioned signals the requested secret has not been provisioned.
	ErrSecretNotProvisioned = errors.New("requested secret not provisioned")
	// ErrTokenNotRecognised indicates the broker does not recognise the provided token.
	ErrTokenNotRecognised = errors.New("secrets token not recognised")
	// ErrTokenExpired indicates the token is no longer valid.
	ErrTokenExpired = errors.New("secrets token expired")
	// ErrTokenPluginMismatch indicates the token was issued for a different plugin.
	ErrTokenPluginMismatch = errors.New("secrets token issued for different plugin")
	// ErrSecretNotGranted signals the requested secret was not included in the grant.
	ErrSecretNotGranted = errors.New("secret not granted for token")
)

const defaultTokenTTL = time.Minute

type secretGrant struct {
	plugin  string
	secrets map[string]string
	expires time.Time
}

// Manager issues short-lived secrets tokens and resolves secret material when authorised.
type Manager struct {
	mu sync.Mutex

	secrets map[string]map[string]string
	grants  map[string]secretGrant
	clock   func() time.Time
	ttl     time.Duration
	audit   *logging.AuditLogger
}

// Option configures the manager.
type Option func(*Manager)

// WithClock overrides the time source used for expiry checks.
func WithClock(clock func() time.Time) Option {
	return func(m *Manager) {
		if clock != nil {
			m.clock = clock
		}
	}
}

// WithTTL overrides the lifetime of issued tokens.
func WithTTL(ttl time.Duration) Option {
	return func(m *Manager) {
		if ttl > 0 {
			m.ttl = ttl
		}
	}
}

// WithAuditLogger attaches an audit logger used to record issuance events.
func WithAuditLogger(logger *logging.AuditLogger) Option {
	return func(m *Manager) {
		if logger != nil {
			m.audit = logger
		}
	}
}

// NewManager constructs a Manager initialised with the provided secrets map.
// The input map is copied to avoid external mutation.
func NewManager(initial map[string]map[string]string, opts ...Option) *Manager {
	mgr := &Manager{
		secrets: make(map[string]map[string]string),
		grants:  make(map[string]secretGrant),
		clock:   time.Now,
		ttl:     defaultTokenTTL,
	}
	for plugin, secrets := range initial {
		mgr.setSecretsLocked(plugin, secrets)
	}
	for _, opt := range opts {
		opt(mgr)
	}
	return mgr
}

// Set registers or updates a secret value for the plugin. Empty values clear the secret.
func (m *Manager) Set(plugin, name, value string) {
	pluginKey := normalise(plugin)
	secretKey := normalise(name)
	if pluginKey == "" || secretKey == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.secrets == nil {
		m.secrets = make(map[string]map[string]string)
	}
	pluginSecrets, ok := m.secrets[pluginKey]
	if !ok {
		pluginSecrets = make(map[string]string)
		m.secrets[pluginKey] = pluginSecrets
	}
	if strings.TrimSpace(value) == "" {
		delete(pluginSecrets, secretKey)
		return
	}
	pluginSecrets[secretKey] = value
}

// Issue generates a short-lived token authorising the provided secrets for the plugin.
func (m *Manager) Issue(plugin string, requested []string) (string, time.Time, error) {
	pluginName := strings.TrimSpace(plugin)
	if pluginName == "" {
		return "", time.Time{}, ErrPluginRequired
	}
	if len(requested) == 0 {
		return "", time.Time{}, ErrSecretRequired
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock()
	m.pruneExpiredLocked(now)

	pluginKey := normalise(pluginName)
	available, ok := m.secrets[pluginKey]
	if !ok || len(available) == 0 {
		return "", time.Time{}, fmt.Errorf("%w: %s", ErrSecretNotProvisioned, pluginName)
	}

	granted := make(map[string]string)
	sanitizedNames := make([]string, 0, len(requested))
	for _, name := range requested {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			continue
		}
		canonical := normalise(trimmed)
		value, ok := available[canonical]
		if !ok {
			return "", time.Time{}, fmt.Errorf("%w: %s", ErrSecretNotProvisioned, trimmed)
		}
		granted[canonical] = value
		sanitizedNames = append(sanitizedNames, trimmed)
	}
	if len(granted) == 0 {
		return "", time.Time{}, ErrSecretRequired
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, fmt.Errorf("generate token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	expires := now.Add(m.ttl)
	if m.grants == nil {
		m.grants = make(map[string]secretGrant)
	}
	m.grants[token] = secretGrant{plugin: pluginKey, secrets: granted, expires: expires}
	if m.audit != nil {
		_ = m.audit.Emit(logging.AuditEvent{
			EventType: logging.EventSecretsToken,
			Decision:  logging.DecisionAllow,
			PluginID:  pluginName,
			Metadata: map[string]any{
				"secrets":    sanitizedNames,
				"expires_at": expires.UTC(),
			},
		})
	}
	return token, expires, nil
}

// Resolve returns the secret value authorised for the provided token.
func (m *Manager) Resolve(token, plugin, secret string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", ErrTokenNotRecognised
	}
	pluginName := strings.TrimSpace(plugin)
	if pluginName == "" {
		return "", ErrPluginRequired
	}
	secretName := strings.TrimSpace(secret)
	if secretName == "" {
		return "", ErrSecretRequired
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock()

	grant, ok := m.grants[token]
	if !ok {
		m.pruneExpiredLocked(now)
		return "", ErrTokenNotRecognised
	}
	pluginKey := normalise(pluginName)
	if grant.plugin != pluginKey {
		return "", ErrTokenPluginMismatch
	}
	if now.After(grant.expires) {
		delete(m.grants, token)
		m.pruneExpiredLocked(now)
		return "", ErrTokenExpired
	}
	value, ok := grant.secrets[normalise(secretName)]
	if !ok {
		return "", ErrSecretNotGranted
	}
	m.pruneExpiredLocked(now)
	return value, nil
}

func (m *Manager) pruneExpiredLocked(now time.Time) {
	for token, grant := range m.grants {
		if now.After(grant.expires) {
			delete(m.grants, token)
		}
	}
}

func (m *Manager) setSecretsLocked(plugin string, secrets map[string]string) {
	pluginKey := normalise(plugin)
	if pluginKey == "" {
		return
	}
	if len(secrets) == 0 {
		return
	}
	if m.secrets == nil {
		m.secrets = make(map[string]map[string]string)
	}
	copyMap := make(map[string]string, len(secrets))
	for name, value := range secrets {
		key := normalise(name)
		if key == "" || strings.TrimSpace(value) == "" {
			continue
		}
		copyMap[key] = value
	}
	if len(copyMap) > 0 {
		m.secrets[pluginKey] = copyMap
	}
}

func normalise(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
