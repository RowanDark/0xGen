package replay

import (
	"errors"
	"fmt"
	"runtime"
	"time"
)

// ManifestVersion captures the schema version for replay artefact manifests.
const ManifestVersion = "1.0"

// Manifest describes the metadata captured for a replayable pipeline run.
type Manifest struct {
	Version       string            `json:"version"`
	CreatedAt     time.Time         `json:"created_at"`
	Seeds         map[string]int64  `json:"seeds,omitempty"`
	DNS           []DNSRecord       `json:"dns,omitempty"`
	Robots        []RobotsRecord    `json:"robots,omitempty"`
	RateLimits    []RateLimitRecord `json:"rate_limits,omitempty"`
	Cookies       []CookieRecord    `json:"cookies,omitempty"`
	Responses     []ResponseRecord  `json:"responses,omitempty"`
	Runner        RunnerInfo        `json:"runner"`
	Plugins       []PluginInfo      `json:"plugins"`
	FindingsFile  string            `json:"findings_file"`
	CasesFile     string            `json:"cases_file"`
	CaseTimestamp time.Time         `json:"case_timestamp"`
}

// DNSRecord records resolved addresses for a host.
type DNSRecord struct {
	Host      string   `json:"host"`
	Addresses []string `json:"addresses"`
}

// RobotsRecord stores the contents of robots.txt for a host.
type RobotsRecord struct {
	Host     string `json:"host"`
	BodyFile string `json:"body_file"`
}

// RateLimitRecord captures observed rate limiting headers.
type RateLimitRecord struct {
	Host   string `json:"host"`
	Policy string `json:"policy"`
}

// CookieRecord stores sanitised cookie values observed during the run.
type CookieRecord struct {
	Domain string `json:"domain"`
	Name   string `json:"name"`
	Value  string `json:"value"`
}

// ResponseRecord references a sanitised HTTP response body.
type ResponseRecord struct {
	RequestURL string              `json:"request_url"`
	Method     string              `json:"method"`
	Status     int                 `json:"status"`
	Headers    map[string][]string `json:"headers,omitempty"`
	BodyFile   string              `json:"body_file,omitempty"`
}

// RunnerInfo records the versions of the primary executables.
type RunnerInfo struct {
	GlyphctlVersion string `json:"glyphctl_version"`
	GlyphdVersion   string `json:"glyphd_version"`
	GoVersion       string `json:"go_version,omitempty"`
	OS              string `json:"os,omitempty"`
	Arch            string `json:"arch,omitempty"`
}

// PluginInfo stores the manifest and signature metadata for a plugin.
type PluginInfo struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	ManifestPath string `json:"manifest_path"`
	Signature    string `json:"signature"`
	SHA256       string `json:"sha256"`
}

// DefaultRunnerInfo returns a baseline RunnerInfo populated from the runtime.
func DefaultRunnerInfo() RunnerInfo {
	return RunnerInfo{
		GlyphctlVersion: "dev",
		GlyphdVersion:   "dev",
		GoVersion:       runtime.Version(),
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
	}
}

// Validate ensures the manifest is structurally sound before packaging.
func (m Manifest) Validate() error {
	if m.Version == "" {
		return errors.New("manifest version is required")
	}
	if m.FindingsFile == "" {
		return errors.New("findings_file must reference a file within the artefact")
	}
	if m.CasesFile == "" {
		return errors.New("cases_file must reference a file within the artefact")
	}
	if m.Runner.GlyphctlVersion == "" && m.Runner.GlyphdVersion == "" {
		return errors.New("runner info must include at least one version")
	}
	if err := validateResponses(m.Responses); err != nil {
		return err
	}
	return nil
}

func validateResponses(responses []ResponseRecord) error {
	for i, resp := range responses {
		if stringsTrim(resp.RequestURL) == "" {
			return fmt.Errorf("response[%d] missing request_url", i)
		}
		if resp.Status < 100 || resp.Status > 599 {
			return fmt.Errorf("response[%d] has invalid status %d", i, resp.Status)
		}
	}
	return nil
}

func stringsTrim(s string) string {
	if len(s) == 0 {
		return s
	}
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\n' || s[start] == '\t' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\n' || s[end-1] == '\t' || s[end-1] == '\r') {
		end--
	}
	if start == 0 && end == len(s) {
		return s
	}
	return s[start:end]
}
