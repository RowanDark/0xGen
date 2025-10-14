package cases

import (
	"bytes"
	"encoding/json"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/RowanDark/0xgen/internal/findings"
)

var severityOrder = map[findings.Severity]int{
	findings.SeverityCritical: 5,
	findings.SeverityHigh:     4,
	findings.SeverityMedium:   3,
	findings.SeverityLow:      2,
	findings.SeverityInfo:     1,
}

func selectDominantFinding(fs []findings.Finding) findings.Finding {
	if len(fs) == 0 {
		return findings.Finding{}
	}
	dominant := fs[0]
	for _, f := range fs[1:] {
		if severityOrder[f.Severity] > severityOrder[dominant.Severity] {
			dominant = f
			continue
		}
		if severityOrder[f.Severity] == severityOrder[dominant.Severity] {
			if strings.Compare(f.Message, dominant.Message) < 0 {
				dominant = f
			}
		}
	}
	return dominant
}

func normaliseAsset(f findings.Finding) Asset {
	target := strings.TrimSpace(f.Target)
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			host := strings.ToLower(u.Host)
			if h, _, err := net.SplitHostPort(host); err == nil && h != "" {
				host = h
			}
			details := strings.TrimSpace(f.Metadata["asset_detail"])
			if details == "" {
				details = u.String()
			}
			return Asset{Kind: "web", Identifier: host, Details: details}
		}
	}

	kind := strings.TrimSpace(f.Metadata["asset_kind"])
	identifier := strings.TrimSpace(f.Metadata["asset_id"])
	details := strings.TrimSpace(f.Metadata["asset_detail"])

	if kind != "" && identifier != "" {
		return Asset{Kind: strings.ToLower(kind), Identifier: identifier, Details: details}
	}

	if target == "" {
		return Asset{Kind: "generic", Identifier: f.Plugin}
	}

	if strings.Contains(target, "@") && !strings.Contains(target, " ") {
		return Asset{Kind: "account", Identifier: strings.ToLower(target)}
	}

	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		if len(parts) > 1 {
			return Asset{Kind: strings.ToLower(parts[0]), Identifier: strings.Join(parts[1:], ":")}
		}
	}

	return Asset{Kind: "generic", Identifier: strings.ToLower(target)}
}

func normaliseVector(fs []findings.Finding) AttackVector {
	if len(fs) == 0 {
		return AttackVector{Kind: "unknown"}
	}
	vectorCounts := make(map[string]int)
	for _, f := range fs {
		vector := extractVectorFromFinding(f)
		if vector == "" {
			vector = "unknown"
		}
		vectorCounts[vector]++
	}
	type vectorCount struct {
		key   string
		count int
	}
	ranking := make([]vectorCount, 0, len(vectorCounts))
	for k, v := range vectorCounts {
		ranking = append(ranking, vectorCount{key: k, count: v})
	}
	sort.SliceStable(ranking, func(i, j int) bool {
		if ranking[i].count == ranking[j].count {
			return ranking[i].key < ranking[j].key
		}
		return ranking[i].count > ranking[j].count
	})
	top := ranking[0]
	parts := strings.SplitN(top.key, "|", 2)
	kind := parts[0]
	value := ""
	if len(parts) > 1 {
		value = parts[1]
	}
	if kind == "" {
		kind = "unknown"
	}
	return AttackVector{Kind: kind, Value: value}
}

func extractVectorFromFinding(f findings.Finding) string {
	vector := strings.TrimSpace(f.Metadata["vector"])
	if vector != "" {
		return strings.ToLower(vector)
	}
	switch strings.ToLower(f.Plugin) {
	case "seer":
		return "source_code"
	case "excavator":
		return "web_crawl"
	case "proxy", "galdr":
		return "http_proxy"
	default:
		return "unknown"
	}
}

func canonicalTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			host := strings.ToLower(u.Host)
			if h, _, err := net.SplitHostPort(host); err == nil && h != "" {
				host = h
			}
			return host
		}
	}
	return strings.ToLower(raw)
}

// NormalisedFinding represents a plugin finding prepared for summarisation.
type NormalisedFinding struct {
	Plugin   string            `json:"plugin"`
	Type     string            `json:"type"`
	Message  string            `json:"message"`
	Evidence string            `json:"evidence,omitempty"`
	Severity findings.Severity `json:"severity"`
	Metadata orderedStringMap  `json:"metadata,omitempty"`
}

func normaliseFinding(f findings.Finding) NormalisedFinding {
	return NormalisedFinding{
		Plugin:   f.Plugin,
		Type:     f.Type,
		Message:  f.Message,
		Evidence: f.Evidence,
		Severity: f.Severity,
		Metadata: orderedStringMap(cloneMetadata(f.Metadata)),
	}
}

type orderedStringMap map[string]string

func (m orderedStringMap) MarshalJSON() ([]byte, error) {
	if m == nil {
		return []byte("null"), nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		keyBytes, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		valueBytes, err := json.Marshal(m[k])
		if err != nil {
			return nil, err
		}
		buf.Write(keyBytes)
		buf.WriteByte(':')
		buf.Write(valueBytes)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}
