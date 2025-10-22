package replay

import (
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"
)

// ManifestVersion captures the schema version for replay artefact manifests.
const ManifestVersion = "1.1"

// Manifest describes the metadata captured for a replayable pipeline run.
type Manifest struct {
	Version       string            `json:"version"`
	CreatedAt     time.Time         `json:"created_at"`
	Seeds         map[string]int64  `json:"seeds,omitempty"`
	DNS           []DNSRecord       `json:"dns,omitempty"`
	TLS           []TLSRecord       `json:"tls,omitempty"`
	Robots        []RobotsRecord    `json:"robots,omitempty"`
	RateLimits    []RateLimitRecord `json:"rate_limits,omitempty"`
	Cookies       []CookieRecord    `json:"cookies,omitempty"`
	Responses     []ResponseRecord  `json:"responses,omitempty"`
	FlowsFile     string            `json:"flows_file,omitempty"`
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

// TLSRecord stores observed TLS fingerprinting and ALPN negotiation metadata.
type TLSRecord struct {
	Host           string   `json:"host"`
	JA3            string   `json:"ja3,omitempty"`
	JA3Hash        string   `json:"ja3_hash,omitempty"`
	NegotiatedALPN string   `json:"negotiated_alpn,omitempty"`
	OfferedALPN    []string `json:"offered_alpn,omitempty"`
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
	if strings.TrimSpace(m.FlowsFile) != "" && !strings.HasPrefix(m.FlowsFile, filesDir+"/") {
		return errors.New("flows_file must reside under files/")
	}
	if m.Runner.GlyphctlVersion == "" && m.Runner.GlyphdVersion == "" {
		return errors.New("runner info must include at least one version")
	}
	if err := validateResponses(m.Responses); err != nil {
		return err
	}
	if err := validateTLSRecords(m.TLS); err != nil {
		return err
	}
	return nil
}

// Normalize enforces deterministic ordering across manifest collections so
// that serialised artefacts remain stable for replay comparisons.
func (m *Manifest) Normalize() {
	if m == nil {
		return
	}
	normalizeDNSRecords(m.DNS)
	normalizeTLSRecords(m.TLS)
	normalizeRobotsRecords(m.Robots)
	normalizeRateLimitRecords(m.RateLimits)
	normalizeCookieRecords(m.Cookies)
	normalizeResponseRecords(m.Responses)
	normalizePluginInfo(m.Plugins)
}

func normalizeDNSRecords(records []DNSRecord) {
	for i := range records {
		records[i].Host = strings.TrimSpace(strings.ToLower(records[i].Host))
		records[i].Addresses = normalizeStrings(records[i].Addresses, true)
	}
	sort.SliceStable(records, func(i, j int) bool {
		return records[i].Host < records[j].Host
	})
}

func normalizeTLSRecords(records []TLSRecord) {
	for i := range records {
		records[i].Host = strings.TrimSpace(strings.ToLower(records[i].Host))
		records[i].NegotiatedALPN = strings.TrimSpace(records[i].NegotiatedALPN)
		records[i].JA3 = strings.TrimSpace(records[i].JA3)
		records[i].JA3Hash = strings.TrimSpace(records[i].JA3Hash)
		records[i].OfferedALPN = normalizeStrings(records[i].OfferedALPN, false)
	}
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].Host == records[j].Host {
			if records[i].JA3 == records[j].JA3 {
				if records[i].JA3Hash == records[j].JA3Hash {
					if records[i].NegotiatedALPN == records[j].NegotiatedALPN {
						return strings.Join(records[i].OfferedALPN, ",") < strings.Join(records[j].OfferedALPN, ",")
					}
					return records[i].NegotiatedALPN < records[j].NegotiatedALPN
				}
				return records[i].JA3Hash < records[j].JA3Hash
			}
			return records[i].JA3 < records[j].JA3
		}
		return records[i].Host < records[j].Host
	})
}

func normalizeRobotsRecords(records []RobotsRecord) {
	for i := range records {
		records[i].Host = strings.TrimSpace(strings.ToLower(records[i].Host))
	}
	sort.SliceStable(records, func(i, j int) bool {
		return records[i].Host < records[j].Host
	})
}

func normalizeRateLimitRecords(records []RateLimitRecord) {
	for i := range records {
		records[i].Host = strings.TrimSpace(strings.ToLower(records[i].Host))
		records[i].Policy = strings.TrimSpace(records[i].Policy)
	}
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].Host == records[j].Host {
			return records[i].Policy < records[j].Policy
		}
		return records[i].Host < records[j].Host
	})
}

func normalizeCookieRecords(records []CookieRecord) {
	for i := range records {
		records[i].Domain = strings.TrimSpace(strings.ToLower(records[i].Domain))
		records[i].Name = strings.TrimSpace(records[i].Name)
	}
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].Domain == records[j].Domain {
			return records[i].Name < records[j].Name
		}
		return records[i].Domain < records[j].Domain
	})
}

func normalizeResponseRecords(records []ResponseRecord) {
	for i := range records {
		records[i].RequestURL = strings.TrimSpace(records[i].RequestURL)
		records[i].Method = strings.TrimSpace(strings.ToUpper(records[i].Method))
	}
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].RequestURL == records[j].RequestURL {
			if records[i].Method == records[j].Method {
				if records[i].Status == records[j].Status {
					return records[i].BodyFile < records[j].BodyFile
				}
				return records[i].Status < records[j].Status
			}
			return records[i].Method < records[j].Method
		}
		return records[i].RequestURL < records[j].RequestURL
	})
}

func normalizePluginInfo(records []PluginInfo) {
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].Name == records[j].Name {
			return records[i].Version < records[j].Version
		}
		return records[i].Name < records[j].Name
	})
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

func validateTLSRecords(records []TLSRecord) error {
	for i, rec := range records {
		if stringsTrim(rec.Host) == "" {
			return fmt.Errorf("tls[%d] missing host", i)
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

func normalizeStrings(values []string, lower bool) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if lower {
			v = strings.ToLower(v)
		}
		if _, exists := seen[v]; exists {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}
