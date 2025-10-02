package scope

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// DecisionReason captures the outcome of a scope evaluation.
type DecisionReason string

const (
	// DecisionAllowed indicates the candidate satisfied the policy allowlist.
	DecisionAllowed DecisionReason = "allowed"
	// DecisionNotAllowlisted indicates no allowlist entry matched the candidate.
	DecisionNotAllowlisted DecisionReason = "not_allowlisted"
	// DecisionDeniedByRule indicates an explicit deny rule matched the candidate.
	DecisionDeniedByRule DecisionReason = "denied_by_rule"
	// DecisionPrivateBlocked indicates private network access was blocked.
	DecisionPrivateBlocked DecisionReason = "private_network_blocked"
	// DecisionInvalidCandidate indicates the input URL was invalid.
	DecisionInvalidCandidate DecisionReason = "invalid_candidate"
)

// Decision describes the result of evaluating a candidate against a policy.
type Decision struct {
	Allowed bool
	Reason  DecisionReason
	Rule    *Rule
}

// Enforcer evaluates URLs against a compiled scope policy.
type Enforcer struct {
	allowRules []*compiledRule
	denyRules  []*compiledRule
	allowEmpty bool
	private    string
}

type compiledRule struct {
	original Rule
	match    func(*url.URL, string) bool
}

// Option customises enforcer behaviour.
type Option func(*Enforcer)

// WithAllowEmpty controls the behaviour when no allow rules are present. When
// true, candidates are allowed unless denied by an explicit rule. The default
// behaviour denies candidates when the allowlist is empty.
func WithAllowEmpty(allow bool) Option {
	return func(e *Enforcer) {
		e.allowEmpty = allow
	}
}

// Compile constructs a new Enforcer for the provided policy.
func Compile(policy Policy, opts ...Option) (*Enforcer, error) {
	policy.Normalise()

	enforcer := &Enforcer{private: policy.PrivateNetworks}
	for _, opt := range opts {
		opt(enforcer)
	}

	for _, rule := range policy.Allow {
		compiled, err := compileRule(rule)
		if err != nil {
			return nil, fmt.Errorf("compile allow rule %s %q: %w", rule.Type, rule.Value, err)
		}
		enforcer.allowRules = append(enforcer.allowRules, compiled)
	}
	for _, rule := range policy.Deny {
		compiled, err := compileRule(rule)
		if err != nil {
			return nil, fmt.Errorf("compile deny rule %s %q: %w", rule.Type, rule.Value, err)
		}
		enforcer.denyRules = append(enforcer.denyRules, compiled)
	}

	return enforcer, nil
}

// Evaluate determines whether the provided URL is permitted by the policy.
func (e *Enforcer) Evaluate(candidate string) Decision {
	trimmed := strings.TrimSpace(candidate)
	if trimmed == "" {
		return Decision{Allowed: false, Reason: DecisionInvalidCandidate}
	}

	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return Decision{Allowed: false, Reason: DecisionInvalidCandidate}
	}

	serialised := parsed.String()

	if e.private != PrivateNetworksAllow && isPrivateHost(parsed.Hostname()) {
		return Decision{Allowed: false, Reason: DecisionPrivateBlocked}
	}

	for _, rule := range e.denyRules {
		if rule.match(parsed, serialised) {
			return Decision{Allowed: false, Reason: DecisionDeniedByRule, Rule: &rule.original}
		}
	}

	if len(e.allowRules) == 0 {
		if e.allowEmpty {
			return Decision{Allowed: true, Reason: DecisionAllowed}
		}
		return Decision{Allowed: false, Reason: DecisionNotAllowlisted}
	}

	for _, rule := range e.allowRules {
		if rule.match(parsed, serialised) {
			return Decision{Allowed: true, Reason: DecisionAllowed, Rule: &rule.original}
		}
	}

	return Decision{Allowed: false, Reason: DecisionNotAllowlisted}
}

func compileRule(rule Rule) (*compiledRule, error) {
	switch rule.Type {
	case RuleTypeDomain:
		value := strings.ToLower(rule.Value)
		return &compiledRule{
			original: rule,
			match: func(u *url.URL, _ string) bool {
				return hostMatchesDomain(strings.ToLower(u.Hostname()), value)
			},
		}, nil
	case RuleTypeWildcard:
		regex, err := wildcardToRegexp(rule.Value)
		if err != nil {
			return nil, err
		}
		return &compiledRule{
			original: rule,
			match: func(u *url.URL, _ string) bool {
				return regex.MatchString(strings.ToLower(u.Hostname()))
			},
		}, nil
	case RuleTypeURL:
		value := rule.Value
		return &compiledRule{
			original: rule,
			match: func(_ *url.URL, serialised string) bool {
				return serialised == value
			},
		}, nil
	case RuleTypePrefix:
		value := rule.Value
		return &compiledRule{
			original: rule,
			match: func(_ *url.URL, serialised string) bool {
				return strings.HasPrefix(serialised, value)
			},
		}, nil
	case RuleTypePath:
		needle := rule.Value
		if !strings.HasPrefix(needle, "/") {
			needle = "/" + needle
		}
		return &compiledRule{
			original: Rule{Type: rule.Type, Value: needle, Notes: rule.Notes},
			match: func(u *url.URL, _ string) bool {
				return strings.HasPrefix(u.Path, needle)
			},
		}, nil
	case RuleTypeCIDR:
		prefix, err := parseCIDR(rule.Value)
		if err != nil {
			return nil, err
		}
		return &compiledRule{
			original: rule,
			match: func(u *url.URL, _ string) bool {
				return cidrContains(prefix, u.Hostname())
			},
		}, nil
	case RuleTypeIP:
		target := strings.ToLower(rule.Value)
		return &compiledRule{
			original: rule,
			match: func(u *url.URL, _ string) bool {
				return strings.ToLower(u.Hostname()) == target
			},
		}, nil
	case RuleTypePattern:
		expr, err := regexp.Compile(rule.Value)
		if err != nil {
			return nil, err
		}
		return &compiledRule{
			original: rule,
			match: func(_ *url.URL, serialised string) bool {
				return expr.MatchString(serialised)
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported rule type %q", rule.Type)
	}
}

func wildcardToRegexp(pattern string) (*regexp.Regexp, error) {
	trimmed := strings.TrimSpace(pattern)
	if trimmed == "" {
		return nil, errors.New("empty wildcard pattern")
	}
	escaped := regexp.QuoteMeta(trimmed)
	regex := "^" + strings.ReplaceAll(escaped, "\\*", ".*") + "$"
	return regexp.Compile(strings.ToLower(regex))
}

func hostMatchesDomain(host, domain string) bool {
	if host == "" || domain == "" {
		return false
	}
	if host == domain {
		return true
	}
	return strings.HasSuffix(host, "."+domain)
}

func parseCIDR(value string) (netip.Prefix, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return netip.Prefix{}, errors.New("empty cidr")
	}
	prefix, err := netip.ParsePrefix(trimmed)
	if err == nil {
		return prefix, nil
	}
	// Attempt to unwrap IPv6 literals like [::1]/128
	if strings.HasPrefix(trimmed, "[") && strings.Contains(trimmed, "]/") {
		closing := strings.Index(trimmed, "]/")
		if closing > 0 {
			addr := trimmed[1:closing]
			suffix := trimmed[closing+2:]
			return netip.ParsePrefix(addr + "/" + suffix)
		}
	}
	return netip.Prefix{}, err
}

func cidrContains(prefix netip.Prefix, host string) bool {
	addr, ok := parseHostAddr(host)
	if !ok {
		return false
	}
	return prefix.Contains(addr)
}

func parseHostAddr(host string) (netip.Addr, bool) {
	trimmed := strings.TrimSpace(host)
	if trimmed == "" {
		return netip.Addr{}, false
	}
	if strings.EqualFold(trimmed, "localhost") {
		return netip.AddrFrom4([4]byte{127, 0, 0, 1}), true
	}
	unwrapped := trimmed
	if strings.HasPrefix(unwrapped, "[") && strings.HasSuffix(unwrapped, "]") {
		unwrapped = unwrapped[1 : len(unwrapped)-1]
	}
	addr, err := netip.ParseAddr(unwrapped)
	if err != nil && strings.HasPrefix(strings.ToLower(unwrapped), "::ffff:") {
		mapped := unwrapped[7:]
		if parsed, err := netip.ParseAddr(mapped); err == nil {
			addr = parsed
		}
	}
	if err != nil {
		return netip.Addr{}, false
	}
	return addr, true
}

func isPrivateHost(host string) bool {
	addr, ok := parseHostAddr(host)
	if !ok {
		return false
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() {
		return true
	}
	return false
}

// Summary captures a human-readable view of the policy contents.
type Summary struct {
	Allow           map[string][]string
	Deny            map[string][]string
	PrivateNetworks string
	PIIMode         string
}

// Summarize groups policy rules by type for presentation.
func Summarize(policy Policy) Summary {
	policy.Normalise()
	summary := Summary{
		Allow:           make(map[string][]string),
		Deny:            make(map[string][]string),
		PrivateNetworks: policy.PrivateNetworks,
		PIIMode:         policy.PIIMode,
	}

	for _, rule := range policy.Allow {
		summary.Allow[rule.Type] = append(summary.Allow[rule.Type], rule.Value)
	}
	for _, rule := range policy.Deny {
		summary.Deny[rule.Type] = append(summary.Deny[rule.Type], rule.Value)
	}

	for _, bucket := range []map[string][]string{summary.Allow, summary.Deny} {
		for key, values := range bucket {
			clone := append([]string(nil), values...)
			sort.Strings(clone)
			bucket[key] = clone
		}
	}

	return summary
}
