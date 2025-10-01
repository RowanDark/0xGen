package scope

import (
	"sort"
	"strings"
)

// RuleType enumerates the supported scope rule kinds.
const (
	RuleTypeDomain   = "domain"
	RuleTypeWildcard = "wildcard"
	RuleTypeURL      = "url"
	RuleTypePrefix   = "url_prefix"
	RuleTypePath     = "path"
	RuleTypeCIDR     = "cidr"
	RuleTypeIP       = "ip"
	RuleTypePattern  = "pattern"
)

// Private network handling modes.
const (
	PrivateNetworksBlock       = "block"
	PrivateNetworksAllow       = "allow"
	PrivateNetworksUnspecified = "unspecified"
)

// PIIMode describes how the crawler should handle personally identifiable information.
const (
	PIIModeUnspecified = "unspecified"
	PIIModeForbid      = "forbid"
	PIIModeAllow       = "allow"
)

// Rule captures a single allow/deny statement within a scope policy.
type Rule struct {
	Type  string `yaml:"type" json:"type"`
	Value string `yaml:"value" json:"value"`
	Notes string `yaml:"notes,omitempty" json:"notes,omitempty"`
}

// Policy represents a normalised scope policy derived from a textual program scope.
type Policy struct {
	Version         int    `yaml:"version" json:"version"`
	Allow           []Rule `yaml:"allow" json:"allow"`
	Deny            []Rule `yaml:"deny" json:"deny"`
	PrivateNetworks string `yaml:"private_networks,omitempty" json:"private_networks,omitempty"`
	PIIMode         string `yaml:"pii,omitempty" json:"pii,omitempty"`
}

// Normalise ensures policy fields use canonical casing/order and removes duplicates.
func (p *Policy) Normalise() {
	p.Version = 1
	p.Allow = dedupeAndSort(p.Allow)
	p.Deny = dedupeAndSort(p.Deny)

	if p.PrivateNetworks == "" {
		p.PrivateNetworks = PrivateNetworksUnspecified
	} else {
		p.PrivateNetworks = strings.ToLower(strings.TrimSpace(p.PrivateNetworks))
	}

	if p.PIIMode == "" {
		p.PIIMode = PIIModeUnspecified
	} else {
		p.PIIMode = strings.ToLower(strings.TrimSpace(p.PIIMode))
	}
}

func dedupeAndSort(rules []Rule) []Rule {
	if len(rules) == 0 {
		return nil
	}

	seen := make(map[string]Rule, len(rules))
	for _, rule := range rules {
		if rule.Value == "" {
			continue
		}
		rule.Type = strings.ToLower(strings.TrimSpace(rule.Type))
		rule.Value = normaliseValue(rule.Type, rule.Value)
		key := ruleKey(rule)
		if existing, ok := seen[key]; ok {
			// Preserve the first non-empty notes field for readability.
			if existing.Notes == "" && rule.Notes != "" {
				existing.Notes = strings.TrimSpace(rule.Notes)
				seen[key] = existing
			}
			continue
		}
		if rule.Notes != "" {
			rule.Notes = strings.TrimSpace(rule.Notes)
		}
		seen[key] = rule
	}

	if len(seen) == 0 {
		return nil
	}

	out := make([]Rule, 0, len(seen))
	for _, rule := range seen {
		out = append(out, rule)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type == out[j].Type {
			return out[i].Value < out[j].Value
		}
		return out[i].Type < out[j].Type
	})
	return out
}

func ruleKey(rule Rule) string {
	return rule.Type + "\n" + rule.Value
}

func normaliseValue(kind, value string) string {
	trimmed := strings.TrimSpace(value)
	switch kind {
	case RuleTypeDomain, RuleTypeWildcard, RuleTypeCIDR, RuleTypeIP:
		trimmed = strings.ToLower(trimmed)
	case RuleTypePattern:
		// leave as-is
	default:
		trimmed = strings.TrimSuffix(trimmed, "/")
	}
	return trimmed
}
