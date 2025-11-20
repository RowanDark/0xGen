package atlas

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ModuleConfig holds configuration options for a module.
type ModuleConfig struct {
	Intensity      int           // 1-5, how aggressive
	Timeout        time.Duration // Per-request timeout
	CustomPayloads []string      // User-defined payloads
	EnableOAST     bool          // Enable out-of-band testing
}

// DefaultModuleConfig returns sensible default module configuration.
func DefaultModuleConfig() ModuleConfig {
	return ModuleConfig{
		Intensity:  3,
		Timeout:    10 * time.Second,
		EnableOAST: true,
	}
}

// ConfigurableModule extends Module with configuration support.
type ConfigurableModule interface {
	Module
	// Category returns the module category (injection, auth, config, etc.)
	Category() string
	// Configure sets the module configuration.
	Configure(config ModuleConfig) error
}

// Evidence holds proof of a vulnerability.
type Evidence struct {
	Parameter string
	Location  ParamLocation
	Request   string
	Response  string
	Payload   string
	Proof     string // Specific proof (e.g., reflected payload, OAST callback)
}

// BaseModule provides common functionality for all modules.
type BaseModule struct {
	name        string
	description string
	category    string
	severity    Severity
	config      ModuleConfig
	logger      Logger
	httpClient  *http.Client
	oastClient  OASTClient
}

// NewBaseModule creates a new base module.
func NewBaseModule(
	name, description, category string,
	severity Severity,
	logger Logger,
	oastClient OASTClient,
) *BaseModule {
	return &BaseModule{
		name:        name,
		description: description,
		category:    category,
		severity:    severity,
		logger:      logger,
		oastClient:  oastClient,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		config: DefaultModuleConfig(),
	}
}

// Name returns the module identifier.
func (m *BaseModule) Name() string { return m.name }

// Description returns a human-readable description.
func (m *BaseModule) Description() string { return m.description }

// Category returns the module category.
func (m *BaseModule) Category() string { return m.category }

// Configure sets the module configuration.
func (m *BaseModule) Configure(config ModuleConfig) error {
	m.config = config
	m.httpClient.Timeout = config.Timeout
	return nil
}

// OASTClient returns the OAST client for this module.
func (m *BaseModule) OASTClient() OASTClient {
	return m.oastClient
}

// SendRequest sends an HTTP request with error handling.
func (m *BaseModule) SendRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	req = req.WithContext(ctx)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}

// ReadBody reads the response body safely with size limits.
func (m *BaseModule) ReadBody(resp *http.Response) (string, error) {
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// CreateFinding creates a finding from evidence.
func (m *BaseModule) CreateFinding(
	target *ScanTarget,
	findingType string,
	confidence Confidence,
	evidence Evidence,
) *Finding {
	return &Finding{
		ID:          GenerateFindingID(),
		Type:        findingType,
		Severity:    m.severity,
		Confidence:  confidence,
		Title:       fmt.Sprintf("%s in %s", findingType, target.URL),
		Description: fmt.Sprintf("Detected %s vulnerability", findingType),
		URL:         target.URL,
		Method:      target.Method,
		Parameter:   evidence.Parameter,
		Location:    evidence.Location,
		Request:     evidence.Request,
		Response:    evidence.Response,
		Payload:     evidence.Payload,
		Proof:       evidence.Proof,
		DetectedBy:  m.name,
	}
}

// GenerateFindingID generates a unique finding ID.
func GenerateFindingID() string {
	return fmt.Sprintf("finding-%d", time.Now().UnixNano())
}

// FormatRequest formats an HTTP request for logging.
func FormatRequest(req *http.Request) string {
	if req == nil {
		return ""
	}
	return fmt.Sprintf("%s %s", req.Method, req.URL.String())
}

// TruncateBody truncates a body to a maximum length.
func TruncateBody(body string, maxLen int) string {
	if len(body) <= maxLen {
		return body
	}
	return body[:maxLen] + "... (truncated)"
}
