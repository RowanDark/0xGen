package pluginsdk

import (
	"context"
	"errors"
	"net/http"
)

// ErrBrokerUnavailable is returned when a broker endpoint is not configured.
var ErrBrokerUnavailable = errors.New("broker endpoint unavailable")

// ErrNotFound signals that the requested resource was not found by the broker.
var ErrNotFound = errors.New("resource not found")

// Broker exposes sandbox-safe helpers implemented by the 0xgen broker.
type Broker interface {
	Filesystem() FilesystemBroker
	Network() NetworkBroker
	Secrets() SecretsBroker
}

// FilesystemBroker offers workspace-scoped filesystem helpers.
type FilesystemBroker interface {
	ReadFile(ctx context.Context, path string) ([]byte, error)
	WriteFile(ctx context.Context, path string, data []byte) error
	Remove(ctx context.Context, path string) error
}

// NetworkBroker mediates outbound HTTP requests through the broker.
type NetworkBroker interface {
	Do(ctx context.Context, req HTTPRequest) (HTTPResult, error)
}

// SecretsBroker retrieves secret material from the broker.
type SecretsBroker interface {
	Get(ctx context.Context, name string) (string, error)
}

// HTTPRequest models an outbound HTTP request performed by the broker.
type HTTPRequest struct {
	Method  string
	URL     string
	Headers http.Header
	Body    []byte
}

// HTTPResult captures the result of a broker-mediated HTTP request.
type HTTPResult struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

// WithCapability ensures the provided capability is available before invoking fn.
func (c *Context) WithCapability(cap Capability, fn func(Broker) error) error {
	if _, ok := c.capabilities[cap]; !ok {
		return CapabilityError{Capability: cap}
	}
	if c.broker == nil {
		return ErrBrokerUnavailable
	}
	return fn(c.broker)
}

// UseFilesystem executes fn with the filesystem broker after verifying capability.
func UseFilesystem(ctx *Context, cap Capability, fn func(FilesystemBroker) error) error {
	if cap != CapabilityWorkspaceRead && cap != CapabilityWorkspaceWrite {
		return errors.New("invalid filesystem capability")
	}
	return ctx.WithCapability(cap, func(b Broker) error {
		fs := b.Filesystem()
		if fs == nil {
			return ErrBrokerUnavailable
		}
		return fn(fs)
	})
}

// UseNetwork executes fn with the network broker after verifying CAP_NET_OUTBOUND.
func UseNetwork(ctx *Context, fn func(NetworkBroker) error) error {
	return ctx.WithCapability(CapabilityNetOutbound, func(b Broker) error {
		net := b.Network()
		if net == nil {
			return ErrBrokerUnavailable
		}
		return fn(net)
	})
}

// UseSecrets executes fn with the secrets broker after verifying CAP_SECRETS_READ.
func UseSecrets(ctx *Context, fn func(SecretsBroker) error) error {
	return ctx.WithCapability(CapabilitySecretsRead, func(b Broker) error {
		secrets := b.Secrets()
		if secrets == nil {
			return ErrBrokerUnavailable
		}
		return fn(secrets)
	})
}

// CapabilityGranted reports whether the capability is present on the context.
func (c *Context) CapabilityGranted(cap Capability) bool {
	_, ok := c.capabilities[cap]
	return ok
}

// Broker exposes the configured broker for advanced scenarios.
func (c *Context) Broker() Broker {
	return c.broker
}
