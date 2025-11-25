// Package oast provides Out-of-Application Security Testing (OAST) functionality
// for detecting blind vulnerabilities through callback interactions.
package oast

import (
	"context"
	"fmt"
	"time"

	"github.com/RowanDark/0xgen/internal/logging"
	"github.com/RowanDark/0xgen/internal/oast/local"
)

// Mode represents the OAST operating mode.
type Mode string

const (
	// ModeDisabled disables OAST functionality.
	ModeDisabled Mode = "disabled"
	// ModeLocal runs a local OAST server.
	ModeLocal Mode = "local"
	// ModeSelfHosted uses a self-hosted OAST server (future).
	ModeSelfHosted Mode = "selfhosted"
	// ModeCloud uses a cloud OAST service (future).
	ModeCloud Mode = "cloud"
)

// Config holds configuration for the OAST client.
type Config struct {
	Mode    Mode
	Port    int    // For local mode (0 = random)
	Host    string // For local mode
	BaseURL string // For selfhosted/cloud modes
	Timeout int    // Seconds to wait for callback
}

// DefaultConfig returns the default OAST configuration.
func DefaultConfig() Config {
	return Config{
		Mode:    ModeLocal,
		Port:    0,
		Host:    "localhost",
		Timeout: 5,
	}
}

// EventBus defines the interface for publishing OAST events.
type EventBus interface {
	Publish(eventType string, data interface{})
}

// Client provides a unified interface for OAST operations.
type Client struct {
	mode    Mode
	local   *local.Server
	storage *local.Storage
	builder *local.URLBuilder
	timeout time.Duration
}

// NewClient creates a new OAST client with the specified configuration.
func NewClient(cfg Config, eventBus EventBus, logger *logging.AuditLogger) (*Client, error) {
	c := &Client{
		mode:    cfg.Mode,
		timeout: time.Duration(cfg.Timeout) * time.Second,
	}

	if c.timeout == 0 {
		c.timeout = 5 * time.Second
	}

	switch cfg.Mode {
	case ModeDisabled:
		return c, nil

	case ModeLocal:
		localCfg := local.Config{
			Port: cfg.Port,
			Host: cfg.Host,
		}
		c.local = local.New(localCfg, eventBus, logger)
		c.storage = c.local.GetStorage()
		c.builder = local.NewURLBuilder(c.local.GetBaseURL())
		return c, nil

	case ModeSelfHosted, ModeCloud:
		return nil, fmt.Errorf("mode %s not yet implemented", cfg.Mode)

	default:
		return nil, fmt.Errorf("unknown mode: %s", cfg.Mode)
	}
}

// Start starts the OAST server (for local mode).
func (c *Client) Start(ctx context.Context) error {
	if c.mode == ModeDisabled {
		return nil
	}

	if c.local != nil {
		return c.local.Start(ctx)
	}

	return nil
}

// Stop stops the OAST server.
func (c *Client) Stop(ctx context.Context) error {
	if c.local != nil {
		return c.local.Stop(ctx)
	}
	return nil
}

// IsEnabled returns true if OAST functionality is enabled.
func (c *Client) IsEnabled() bool {
	return c.mode != ModeDisabled
}

// GetMode returns the current OAST mode.
func (c *Client) GetMode() Mode {
	return c.mode
}

// GetBaseURL returns the base URL for callbacks.
func (c *Client) GetBaseURL() string {
	if c.local != nil {
		return c.local.GetBaseURL()
	}
	return ""
}

// GetPort returns the listening port (for local mode).
func (c *Client) GetPort() int {
	if c.local != nil {
		return c.local.GetPort()
	}
	return 0
}

// Callback represents a generated OAST callback.
type Callback struct {
	ID      string
	URL     string
	TestID  string
	Created time.Time
}

// GenerateCallback creates a new OAST callback URL.
func (c *Client) GenerateCallback(ctx context.Context, testID string) (*Callback, error) {
	if !c.IsEnabled() {
		return nil, fmt.Errorf("OAST is disabled")
	}

	if c.builder == nil {
		return nil, fmt.Errorf("URL builder not initialized")
	}

	callback := c.builder.Generate()

	// Register the callback with its test ID for future interactions
	if c.storage != nil && testID != "" {
		c.storage.RegisterCallback(callback.ID, testID)
	}

	return &Callback{
		ID:      callback.ID,
		URL:     callback.URL,
		TestID:  testID,
		Created: time.Now(),
	}, nil
}

// GenerateCallbackWithPath creates a callback URL with an additional path.
func (c *Client) GenerateCallbackWithPath(ctx context.Context, testID, path string) (*Callback, error) {
	if !c.IsEnabled() {
		return nil, fmt.Errorf("OAST is disabled")
	}

	if c.builder == nil {
		return nil, fmt.Errorf("URL builder not initialized")
	}

	callback := c.builder.GenerateWithPath(path)

	// Register the callback with its test ID for future interactions
	if c.storage != nil && testID != "" {
		c.storage.RegisterCallback(callback.ID, testID)
	}

	return &Callback{
		ID:      callback.ID,
		URL:     callback.URL,
		TestID:  testID,
		Created: time.Now(),
	}, nil
}

// CheckInteractions retrieves all interactions for a callback ID.
func (c *Client) CheckInteractions(ctx context.Context, callbackID string) ([]*local.Interaction, error) {
	if !c.IsEnabled() {
		return nil, fmt.Errorf("OAST is disabled")
	}

	if c.storage == nil {
		return nil, fmt.Errorf("storage not initialized")
	}

	return c.storage.GetByID(callbackID), nil
}

// HasInteraction checks if any interaction exists for a callback ID.
func (c *Client) HasInteraction(ctx context.Context, callbackID string) (bool, error) {
	if !c.IsEnabled() {
		return false, fmt.Errorf("OAST is disabled")
	}

	if c.storage == nil {
		return false, fmt.Errorf("storage not initialized")
	}

	return c.storage.HasInteraction(callbackID), nil
}

// WaitForInteraction blocks until an interaction is received or timeout.
func (c *Client) WaitForInteraction(ctx context.Context, callbackID string, timeout time.Duration) (*local.Interaction, error) {
	if !c.IsEnabled() {
		return nil, fmt.Errorf("OAST is disabled")
	}

	if c.storage == nil {
		return nil, fmt.Errorf("storage not initialized")
	}

	if timeout == 0 {
		timeout = c.timeout
	}

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()

		case <-ticker.C:
			interactions := c.storage.GetByID(callbackID)
			if len(interactions) > 0 {
				return interactions[0], nil
			}

			if time.Now().After(deadline) {
				return nil, fmt.Errorf("timeout waiting for interaction")
			}
		}
	}
}

// GetInteractionsByTestID retrieves all interactions for a test ID.
func (c *Client) GetInteractionsByTestID(ctx context.Context, testID string) ([]*local.Interaction, error) {
	if !c.IsEnabled() {
		return nil, fmt.Errorf("OAST is disabled")
	}

	if c.storage == nil {
		return nil, fmt.Errorf("storage not initialized")
	}

	return c.storage.GetByTestID(testID), nil
}

// GetStats returns statistics about stored interactions.
func (c *Client) GetStats() (*local.Stats, error) {
	if !c.IsEnabled() {
		return nil, fmt.Errorf("OAST is disabled")
	}

	if c.storage == nil {
		return nil, fmt.Errorf("storage not initialized")
	}

	stats := c.storage.GetStats()
	return &stats, nil
}

// GetStorage returns the underlying storage (for advanced use).
func (c *Client) GetStorage() *local.Storage {
	return c.storage
}

// GetURLBuilder returns the URL builder (for advanced use).
func (c *Client) GetURLBuilder() *local.URLBuilder {
	return c.builder
}
