// Package atlas provides the core active vulnerability scanner infrastructure
// for 0xGen. Atlas automatically detects security issues by sending payloads
// and analyzing responses to confirm vulnerabilities.
package atlas

import (
	"context"
	"time"
)

// Scan represents a complete vulnerability scan operation.
type Scan struct {
	ID          string
	Name        string
	Target      Target
	Config      ScanConfig
	State       ScanState
	Progress    Progress
	Findings    []*Finding
	StartTime   time.Time
	EndTime     *time.Time
	Duration    time.Duration

	// Metadata
	CreatedBy   string
	WorkspaceID string
	Tags        []string
}

// Target defines what to scan.
type Target struct {
	Type    TargetType // SingleURL, URLList, Scope
	URLs    []string
	Scope   *ScopeConfig
	BaseURL string // For relative URLs
}

// TargetType specifies the type of scan target.
type TargetType string

const (
	TargetTypeSingleURL TargetType = "single_url"
	TargetTypeURLList   TargetType = "url_list"
	TargetTypeScope     TargetType = "scope"
)

// ScopeConfig defines crawling scope boundaries.
type ScopeConfig struct {
	// Include patterns (regex)
	IncludePatterns []string
	// Exclude patterns (regex)
	ExcludePatterns []string
	// Maximum crawl depth
	MaxDepth int
	// Start URLs for crawling
	StartURLs []string
}

// ScanConfig holds all configuration options for a scan.
type ScanConfig struct {
	// Module selection
	EnabledModules  []string // nil = all modules
	DisabledModules []string

	// Intensity
	Depth        int // How deep to crawl (0 = no crawl, 1-5)
	Intensity    int // How aggressive (1-5, 3 = default)
	Thoroughness int // How thorough (1-5, 3 = default)

	// Performance
	MaxConcurrency int           // Max parallel requests
	RateLimit      int           // Requests per second
	Timeout        time.Duration // Per-request timeout

	// OAST
	EnableOAST  bool
	OASTTimeout time.Duration

	// Authentication
	AuthConfig *AuthConfig

	// Advanced
	FollowRedirects bool
	VerifySSL       bool
	CustomHeaders   map[string]string
	CustomCookies   map[string]string
	UserAgent       string
}

// AuthType specifies the authentication method.
type AuthType string

const (
	AuthTypeBasic         AuthType = "basic"
	AuthTypeBearer        AuthType = "bearer"
	AuthTypeSessionCookie AuthType = "session_cookie"
	AuthTypeCustom        AuthType = "custom"
)

// AuthConfig holds authentication credentials.
type AuthConfig struct {
	Type     AuthType // BasicAuth, BearerToken, SessionCookie, Custom
	Username string
	Password string
	Token    string
	Cookies  map[string]string
	Headers  map[string]string
}

// ScanState represents the current state of a scan.
type ScanState string

const (
	ScanStatePending   ScanState = "pending"
	ScanStateRunning   ScanState = "running"
	ScanStatePaused    ScanState = "paused"
	ScanStateCompleted ScanState = "completed"
	ScanStateFailed    ScanState = "failed"
	ScanStateCancelled ScanState = "cancelled"
)

// Progress tracks scan execution progress.
type Progress struct {
	Phase                  string  // "discovery", "analysis", "exploitation"
	CurrentModule          string
	URLsDiscovered         int
	URLsTested             int
	URLsRemaining          int
	RequestsSent           int
	FindingsFound          int
	PercentComplete        float64
	EstimatedTimeRemaining time.Duration
}

// Finding represents a discovered vulnerability.
type Finding struct {
	ID          string
	ScanID      string
	Type        string // "SQLi", "XSS", "SSRF", etc.
	Severity    Severity
	Confidence  Confidence
	Title       string
	Description string

	// Location
	URL       string
	Method    string
	Parameter string
	Location  ParamLocation // Query, Body, Header, Cookie, Path

	// Evidence
	Request  string // Full HTTP request
	Response string // Full HTTP response
	Payload  string
	Proof    string // Specific evidence (e.g., OAST callback)

	// Classification
	CWE   string
	OWASP string
	CVSS  float64

	// Remediation
	Remediation string
	References  []string

	// Metadata
	DetectedBy    string // Module name
	DetectedAt    time.Time
	Verified      bool
	FalsePositive bool
}

// Severity represents the impact level of a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Confidence represents how certain we are about a finding.
type Confidence string

const (
	ConfidenceConfirmed Confidence = "confirmed"
	ConfidenceFirm      Confidence = "firm"
	ConfidenceTentative Confidence = "tentative"
)

// ParamLocation indicates where a vulnerable parameter is located.
type ParamLocation string

const (
	ParamLocationQuery  ParamLocation = "query"
	ParamLocationBody   ParamLocation = "body"
	ParamLocationHeader ParamLocation = "header"
	ParamLocationCookie ParamLocation = "cookie"
	ParamLocationPath   ParamLocation = "path"
)

// ScanTarget represents a single target for module scanning.
type ScanTarget struct {
	URL        string
	Method     string
	Parameters map[string]string
	Headers    map[string]string
	Body       string
}

// Module represents a vulnerability detection module.
type Module interface {
	// Name returns the module identifier.
	Name() string
	// Description returns a human-readable description.
	Description() string
	// Scan performs vulnerability detection on the target.
	Scan(ctx context.Context, target *ScanTarget) ([]*Finding, error)
	// SupportsTarget checks if the module can scan this target.
	SupportsTarget(target *ScanTarget) bool
}

// Storage defines the interface for scan persistence.
type Storage interface {
	// StoreScan persists a scan to storage.
	StoreScan(ctx context.Context, scan *Scan) error
	// GetScan retrieves a scan by ID.
	GetScan(ctx context.Context, scanID string) (*Scan, error)
	// ListScans returns scans matching the filter.
	ListScans(ctx context.Context, filter ScanFilter) ([]*Scan, error)
	// UpdateScan updates an existing scan.
	UpdateScan(ctx context.Context, scan *Scan) error
	// DeleteScan removes a scan from storage.
	DeleteScan(ctx context.Context, scanID string) error

	// StoreFinding persists a finding to storage.
	StoreFinding(ctx context.Context, finding *Finding) error
	// GetFinding retrieves a finding by ID.
	GetFinding(ctx context.Context, findingID string) (*Finding, error)
	// ListFindings returns findings matching the filter.
	ListFindings(ctx context.Context, filter FindingFilter) ([]*Finding, error)
}

// ScanFilter specifies criteria for listing scans.
type ScanFilter struct {
	WorkspaceID string
	State       ScanState
	Tags        []string
	Limit       int
	Offset      int
}

// FindingFilter specifies criteria for listing findings.
type FindingFilter struct {
	ScanID     string
	Type       string
	Severity   Severity
	Confidence Confidence
	Limit      int
	Offset     int
}

// OASTClient defines the interface for OAST integration.
type OASTClient interface {
	// GeneratePayload creates a new OAST payload URL.
	GeneratePayload(ctx context.Context, testID string) (string, error)
	// CheckInteractions polls for OAST callbacks.
	CheckInteractions(ctx context.Context, testID string) ([]OASTInteraction, error)
}

// OASTInteraction represents an OAST callback.
type OASTInteraction struct {
	ID          string
	TestID      string
	Type        string // DNS, HTTP, SMTP
	RemoteAddr  string
	Timestamp   time.Time
	RawRequest  string
	RawResponse string
}

// EventBus provides pub/sub for scan events.
type EventBus interface {
	// Publish emits an event to all subscribers.
	Publish(topic string, data interface{})
	// Subscribe returns a channel for receiving events on a topic.
	Subscribe(ctx context.Context, topic string) <-chan Event
}

// Event represents a scan-related event.
type Event struct {
	Topic     string
	Timestamp time.Time
	Data      interface{}
}

// Crawler discovers URLs within a scope.
type Crawler interface {
	// Crawl discovers targets within the scope.
	Crawl(ctx context.Context, scope *ScopeConfig) ([]*ScanTarget, error)
}

// DefaultScanConfig returns a sensible default configuration.
func DefaultScanConfig() ScanConfig {
	return ScanConfig{
		Depth:           1,
		Intensity:       3,
		Thoroughness:    3,
		MaxConcurrency:  10,
		RateLimit:       100,
		Timeout:         30 * time.Second,
		EnableOAST:      true,
		OASTTimeout:     30 * time.Second,
		FollowRedirects: true,
		VerifySSL:       true,
		UserAgent:       "0xGen-Atlas/1.0",
	}
}
