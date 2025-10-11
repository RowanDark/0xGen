package wizard

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/RowanDark/Glyph/internal/logging"
)

// RiskLevel is a coarse indicator that the UI can translate into colour coded banners.
type RiskLevel string

const (
	RiskLow    RiskLevel = "low"
	RiskMedium RiskLevel = "medium"
	RiskHigh   RiskLevel = "high"
)

// CapabilitySummary captures the human-readable risk metadata for a capability.
type CapabilitySummary struct {
	Capability   string
	Title        string
	Description  string
	Risks        []string
	Mitigations  []string
	RiskLevel    RiskLevel
	HighRisk     bool
	Dependencies []string
}

var capabilityLibrary = map[string]CapabilitySummary{
	"CAP_EMIT_FINDINGS": {
		Capability:  "CAP_EMIT_FINDINGS",
		Title:       "Emit findings",
		Description: "Allows the plugin to publish findings and annotations back to Glyph.",
		Risks: []string{
			"Malicious or buggy plugins can flood the case timeline with noise.",
			"Findings emitted by untrusted publishers could mislead analysts.",
		},
		Mitigations: []string{
			"Only grant to publishers that are vetted by the team.",
			"Revoke when a plugin should operate in observation-only mode.",
		},
		RiskLevel: RiskMedium,
	},
	"CAP_HTTP_ACTIVE": {
		Capability:  "CAP_HTTP_ACTIVE",
		Title:       "Active HTTP egress",
		Description: "Permits outbound HTTP requests through the managed netgate.",
		Risks: []string{
			"Allows active scanning of in-scope targets and potential lateral movement.",
			"Improper scoping may trigger scanners or touch production systems.",
		},
		Mitigations: []string{
			"Scope requests via allowlists and per-run configuration.",
			"Monitor the audit log for unexpected destinations.",
		},
		RiskLevel: RiskHigh,
		HighRisk:  true,
	},
	"CAP_HTTP_PASSIVE": {
		Capability:  "CAP_HTTP_PASSIVE",
		Title:       "Passive HTTP capture",
		Description: "Grants access to sanitized HTTP request/response bodies.",
		Risks: []string{
			"Provides visibility into user traffic including potentially sensitive metadata.",
		},
		Mitigations: []string{
			"Secrets are redacted unless raw access is also granted.",
		},
		RiskLevel: RiskMedium,
	},
	"CAP_FLOW_INSPECT": {
		Capability:  "CAP_FLOW_INSPECT",
		Title:       "Sanitized flow inspection",
		Description: "Allows inspection of flows with sensitive values redacted.",
		Risks: []string{
			"Exposes metadata and sanitized payloads that could include business data.",
		},
		Mitigations: []string{
			"All secrets remain redacted unless CAP_FLOW_INSPECT_RAW is approved.",
		},
		RiskLevel: RiskMedium,
	},
	"CAP_FLOW_INSPECT_RAW": {
		Capability:  "CAP_FLOW_INSPECT_RAW",
		Title:       "Raw flow inspection",
		Description: "Provides unredacted access to captured payloads and headers.",
		Risks:       []string{"Secrets, credentials, and personal data are visible in full."},
		Mitigations: []string{
			"Grant alongside CAP_FLOW_INSPECT only when absolutely necessary.",
			"Pair with run-scoped allowlists to minimise blast radius.",
		},
		RiskLevel:    RiskHigh,
		HighRisk:     true,
		Dependencies: []string{"CAP_FLOW_INSPECT"},
	},
	"CAP_WS": {
		Capability:  "CAP_WS",
		Title:       "WebSocket egress",
		Description: "Allows initiating outbound WebSocket connections.",
		Risks: []string{
			"Plugins can maintain long-lived connections to external services.",
		},
		Mitigations: []string{
			"Restrict destinations via the global allowlist.",
			"Monitor the audit log for abnormal connection volume.",
		},
		RiskLevel: RiskHigh,
		HighRisk:  true,
	},
	"CAP_SPIDER": {
		Capability:  "CAP_SPIDER",
		Title:       "Crawler control",
		Description: "Allows manipulating the internal reconnaissance spider.",
		Risks: []string{
			"Misuse can lead to excessive crawling or touching out-of-scope content.",
		},
		Mitigations: []string{
			"Combine with scoped entry points and monitor crawl output.",
		},
		RiskLevel: RiskMedium,
	},
	"CAP_REPORT": {
		Capability:  "CAP_REPORT",
		Title:       "Reporting & export",
		Description: "Provides ability to export findings and generate external reports.",
		Risks: []string{
			"Data can leave Glyph-managed storage and be shared externally.",
		},
		Mitigations: []string{
			"Grant only to trusted publishers and rotate reports regularly.",
		},
		RiskLevel: RiskHigh,
		HighRisk:  true,
	},
	"CAP_STORAGE": {
		Capability:  "CAP_STORAGE",
		Title:       "Managed storage access",
		Description: "Allows reading and writing artefacts to Glyph-managed buckets.",
		Risks: []string{
			"Plugins can exfiltrate artefacts or inject malicious binaries.",
		},
		Mitigations: []string{
			"Use bucket-level ACLs and revoke when no longer required.",
		},
		RiskLevel: RiskHigh,
		HighRisk:  true,
	},
}

// DescribeCapabilities converts a capability list into detailed wizard summaries.
func DescribeCapabilities(capabilities []string) ([]CapabilitySummary, error) {
	if len(capabilities) == 0 {
		return nil, errors.New("at least one capability is required")
	}
	summaries := make([]CapabilitySummary, 0, len(capabilities))
	seen := make(map[string]struct{}, len(capabilities))
	for _, cap := range capabilities {
		cap = strings.ToUpper(strings.TrimSpace(cap))
		if cap == "" {
			return nil, errors.New("capability name cannot be empty")
		}
		if _, dup := seen[cap]; dup {
			continue
		}
		seen[cap] = struct{}{}
		summary, ok := capabilityLibrary[cap]
		if !ok {
			return nil, fmt.Errorf("unknown capability %s", cap)
		}
		summaries = append(summaries, summary)
	}
	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].HighRisk == summaries[j].HighRisk {
			return summaries[i].Capability < summaries[j].Capability
		}
		return summaries[i].HighRisk
	})
	return summaries, nil
}

// AccessMatrixRow describes how a capability affects redaction semantics.
type AccessMatrixRow struct {
	DataSource       string
	SanitizedSummary string
	RawSummary       string
	SanitizedAllowed bool
	RawAllowed       bool
	SanitizedCaps    []string
	RawCaps          []string
}

// BuildAccessMatrix produces the wizard's redaction/secret access matrix.
func BuildAccessMatrix(granted map[string]bool) []AccessMatrixRow {
	has := func(cap string) bool {
		return granted[strings.ToUpper(strings.TrimSpace(cap))]
	}
	rows := []AccessMatrixRow{
		{
			DataSource:       "HTTP request bodies",
			SanitizedSummary: "Secrets are redacted and authorization headers removed.",
			RawSummary:       "Unredacted payloads including headers and body digests.",
			SanitizedAllowed: has("CAP_FLOW_INSPECT") || has("CAP_HTTP_PASSIVE"),
			RawAllowed:       has("CAP_FLOW_INSPECT_RAW"),
			SanitizedCaps:    []string{"CAP_FLOW_INSPECT", "CAP_HTTP_PASSIVE"},
			RawCaps:          []string{"CAP_FLOW_INSPECT_RAW"},
		},
		{
			DataSource:       "Findings history",
			SanitizedSummary: "Read-only correlation of prior findings.",
			RawSummary:       "Export and mutation via reporting helpers.",
			SanitizedAllowed: has("CAP_EMIT_FINDINGS"),
			RawAllowed:       has("CAP_REPORT"),
			SanitizedCaps:    []string{"CAP_EMIT_FINDINGS"},
			RawCaps:          []string{"CAP_REPORT"},
		},
		{
			DataSource:       "Storage buckets",
			SanitizedSummary: "No direct access.",
			RawSummary:       "Read/write to managed artefact buckets.",
			SanitizedAllowed: false,
			RawAllowed:       has("CAP_STORAGE"),
			SanitizedCaps:    nil,
			RawCaps:          []string{"CAP_STORAGE"},
		},
		{
			DataSource:       "HTTP egress",
			SanitizedSummary: "Blocked entirely without explicit grant.",
			RawSummary:       "Outbound HTTP/WebSocket requests proxied with observability.",
			SanitizedAllowed: false,
			RawAllowed:       has("CAP_HTTP_ACTIVE") || has("CAP_WS"),
			SanitizedCaps:    nil,
			RawCaps:          []string{"CAP_HTTP_ACTIVE", "CAP_WS"},
		},
	}
	return rows
}

// Grant encapsulates the persisted wizard decision for a plugin.
type Grant struct {
	Plugin       string
	Capabilities []string
	GrantedBy    string
	GrantedAt    time.Time
	AuditID      string
}

// Registrar mirrors the subset of the netgate.Gate API required by the wizard.
type Registrar interface {
	Register(pluginID string, capabilities []string)
	Unregister(pluginID string)
}

// GrantStore tracks approved grants and handles revocations.
type GrantStore struct {
	mu     sync.RWMutex
	grants map[string]Grant
	audit  *logging.AuditLogger
	gate   Registrar
	clock  func() time.Time
	idGen  func() string
}

// GrantOption customises the GrantStore.
type GrantOption func(*GrantStore)

// WithClock injects a deterministic clock for testing.
func WithClock(clock func() time.Time) GrantOption {
	return func(gs *GrantStore) {
		if clock != nil {
			gs.clock = clock
		}
	}
}

// WithIDGenerator injects a deterministic ID generator for testing.
func WithIDGenerator(gen func() string) GrantOption {
	return func(gs *GrantStore) {
		if gen != nil {
			gs.idGen = gen
		}
	}
}

// NewGrantStore constructs a GrantStore bound to the provided registrar and audit logger.
func NewGrantStore(audit *logging.AuditLogger, registrar Registrar, opts ...GrantOption) (*GrantStore, error) {
	if registrar == nil {
		return nil, errors.New("registrar is required")
	}
	gs := &GrantStore{
		grants: make(map[string]Grant),
		audit:  audit,
		gate:   registrar,
		clock:  time.Now,
		idGen: func() string {
			return fmt.Sprintf("audit-%d", time.Now().UnixNano())
		},
	}
	for _, opt := range opts {
		opt(gs)
	}
	return gs, nil
}

// Install registers a plugin's capabilities and records an audit entry.
func (gs *GrantStore) Install(plugin string, capabilities []string, grantedBy string) (Grant, error) {
	plugin = strings.TrimSpace(plugin)
	if plugin == "" {
		return Grant{}, errors.New("plugin name is required")
	}
	if len(capabilities) == 0 {
		return Grant{}, errors.New("at least one capability must be granted")
	}
	normalized := normaliseCaps(capabilities)
	gs.gate.Register(plugin, normalized)

	gs.mu.Lock()
	defer gs.mu.Unlock()
	grant := Grant{
		Plugin:       plugin,
		Capabilities: slices.Clone(normalized),
		GrantedBy:    strings.TrimSpace(grantedBy),
		GrantedAt:    gs.clock().UTC(),
	}
	grant.AuditID = gs.emitAudit(logging.AuditEvent{
		EventType: logging.EventCapabilityGrant,
		Decision:  logging.DecisionAllow,
		PluginID:  plugin,
		Metadata: map[string]any{
			"capabilities": grant.Capabilities,
			"granted_by":   grant.GrantedBy,
		},
	})
	gs.grants[plugin] = grant
	return grant, nil
}

// Revoke removes the capability from the plugin and emits an audit entry.
func (gs *GrantStore) Revoke(plugin string, capability string, reason string) (Grant, error) {
	plugin = strings.TrimSpace(plugin)
	capability = strings.ToUpper(strings.TrimSpace(capability))
	if plugin == "" {
		return Grant{}, errors.New("plugin name is required")
	}
	if capability == "" {
		return Grant{}, errors.New("capability is required")
	}

	gs.mu.Lock()
	defer gs.mu.Unlock()
	current, ok := gs.grants[plugin]
	if !ok {
		return Grant{}, fmt.Errorf("plugin %s has no grant", plugin)
	}
	filtered := current.Capabilities[:0]
	removed := false
	for _, cap := range current.Capabilities {
		if cap == capability {
			removed = true
			continue
		}
		filtered = append(filtered, cap)
	}
	if !removed {
		return Grant{}, fmt.Errorf("plugin %s was not granted %s", plugin, capability)
	}
	current.Capabilities = slices.Clone(filtered)
	if len(current.Capabilities) == 0 {
		gs.gate.Unregister(plugin)
	} else {
		gs.gate.Register(plugin, current.Capabilities)
	}
	current.AuditID = gs.emitAudit(logging.AuditEvent{
		EventType: logging.EventCapabilityDenied,
		Decision:  logging.DecisionDeny,
		PluginID:  plugin,
		Reason:    reason,
		Metadata: map[string]any{
			"revoked_capability": capability,
			"remaining":          current.Capabilities,
		},
	})
	gs.grants[plugin] = current
	return current, nil
}

// RevokeAll strips all capabilities from the plugin.
func (gs *GrantStore) RevokeAll(plugin string, reason string) error {
	plugin = strings.TrimSpace(plugin)
	if plugin == "" {
		return errors.New("plugin name is required")
	}
	gs.mu.Lock()
	defer gs.mu.Unlock()
	if _, ok := gs.grants[plugin]; !ok {
		return fmt.Errorf("plugin %s has no grant", plugin)
	}
	gs.gate.Unregister(plugin)
	gs.emitAudit(logging.AuditEvent{
		EventType: logging.EventCapabilityDenied,
		Decision:  logging.DecisionDeny,
		PluginID:  plugin,
		Reason:    reason,
		Metadata: map[string]any{
			"revoked_all": true,
		},
	})
	delete(gs.grants, plugin)
	return nil
}

// List returns a copy of the current grants.
func (gs *GrantStore) List() []Grant {
	gs.mu.RLock()
	defer gs.mu.RUnlock()
	out := make([]Grant, 0, len(gs.grants))
	for _, grant := range gs.grants {
		clone := grant
		clone.Capabilities = slices.Clone(grant.Capabilities)
		out = append(out, clone)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Plugin < out[j].Plugin
	})
	return out
}

func (gs *GrantStore) emitAudit(event logging.AuditEvent) string {
	if gs.audit == nil {
		return ""
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = gs.clock().UTC()
	}
	if event.Metadata == nil {
		event.Metadata = make(map[string]any)
	}
	if event.Metadata["audit_id"] == nil {
		event.Metadata["audit_id"] = gs.idGen()
	}
	id, _ := event.Metadata["audit_id"].(string)
	if err := gs.audit.Emit(event); err != nil {
		return id
	}
	return id
}

func normaliseCaps(caps []string) []string {
	set := make(map[string]struct{}, len(caps))
	for _, cap := range caps {
		cap = strings.ToUpper(strings.TrimSpace(cap))
		if cap == "" {
			continue
		}
		set[cap] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for cap := range set {
		out = append(out, cap)
	}
	sort.Strings(out)
	return out
}
