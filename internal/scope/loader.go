package scope

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// LoadPolicyFromFile reads a scope policy from disk and normalises it for enforcement.
func LoadPolicyFromFile(path string) (Policy, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return Policy{}, fmt.Errorf("scope policy path is required")
	}
	data, err := os.ReadFile(trimmed)
	if err != nil {
		return Policy{}, fmt.Errorf("read scope policy: %w", err)
	}
	if policy, err := parsePolicyJSON(data); err == nil {
		return policy, nil
	}
	policy, err := parsePolicyYAML(string(data))
	if err != nil {
		return Policy{}, err
	}
	return policy, nil
}

// LoadEnforcerFromFile loads and compiles a scope policy into an Enforcer ready for evaluation.
func LoadEnforcerFromFile(path string, opts ...Option) (*Enforcer, error) {
	policy, err := LoadPolicyFromFile(path)
	if err != nil {
		return nil, err
	}
	return Compile(policy, opts...)
}

func parsePolicyJSON(data []byte) (Policy, error) {
	var policy Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		return Policy{}, err
	}
	policy.Normalise()
	return policy, nil
}

func parsePolicyYAML(contents string) (Policy, error) {
	var policy Policy
	var section string
	lines := strings.Split(contents, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasSuffix(line, ":") && !strings.HasPrefix(line, "-") {
			section = strings.TrimSuffix(line, ":")
			continue
		}
		if strings.HasPrefix(line, "-") {
			rule, consumed, err := parseRule(lines, i)
			if err != nil {
				return Policy{}, err
			}
			if section == "allow" {
				policy.Allow = append(policy.Allow, rule)
			} else if section == "deny" {
				policy.Deny = append(policy.Deny, rule)
			} else {
				return Policy{}, fmt.Errorf("unexpected list entry outside allow/deny: %q", line)
			}
			i += consumed
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return Policy{}, fmt.Errorf("invalid scope policy line: %q", line)
		}
		key := strings.TrimSpace(parts[0])
		value := trimScalar(parts[1])
		switch key {
		case "version":
			// ignore explicit version, Normalise() sets it to 1
		case "private_networks":
			policy.PrivateNetworks = value
		case "pii":
			policy.PIIMode = value
		default:
			return Policy{}, fmt.Errorf("unknown scope policy key %q", key)
		}
	}
	policy.Normalise()
	return policy, nil
}

func parseRule(lines []string, index int) (Rule, int, error) {
	line := strings.TrimSpace(lines[index])
	rule := Rule{}
	consumed := 0
	// handle inline "- key: value"
	if inline := strings.TrimSpace(strings.TrimPrefix(line, "-")); inline != "" {
		parts := strings.SplitN(inline, ":", 2)
		if len(parts) == 2 {
			assignRuleField(&rule, strings.TrimSpace(parts[0]), trimScalar(parts[1]))
		}
	}
	for i := index + 1; i < len(lines); i++ {
		raw := lines[i]
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			consumed++
			continue
		}
		if !strings.HasPrefix(raw, " ") && !strings.HasPrefix(raw, "\t") {
			break
		}
		consumed++
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			return Rule{}, 0, fmt.Errorf("invalid rule line: %q", trimmed)
		}
		assignRuleField(&rule, strings.TrimSpace(parts[0]), trimScalar(parts[1]))
	}
	if strings.TrimSpace(rule.Type) == "" || strings.TrimSpace(rule.Value) == "" {
		return Rule{}, 0, fmt.Errorf("scope rule requires type and value")
	}
	return rule, consumed, nil
}

func assignRuleField(rule *Rule, key, value string) {
	switch strings.ToLower(key) {
	case "type":
		rule.Type = value
	case "value":
		rule.Value = value
	case "notes":
		rule.Notes = value
	}
}

func trimScalar(value string) string {
	trimmed := strings.TrimSpace(value)
	trimmed = strings.Trim(trimmed, "\"'")
	return trimmed
}
