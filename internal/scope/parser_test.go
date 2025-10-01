package scope

import "testing"

func containsRule(rules []Rule, kind, value string) bool {
	for _, rule := range rules {
		if rule.Type == kind && rule.Value == value {
			return true
		}
	}
	return false
}

func TestParsePolicyFromText(t *testing.T) {
	text := `In Scope:
- https://app.example.com
- *.example.org
- api.example.net/login

Out of Scope:
- admin.example.com
- 10.0.0.0/8

Private IP ranges are out of scope.
Do not submit PII.`

	policy := ParsePolicyFromText(text)

	if policy.Version != 1 {
		t.Fatalf("expected version 1, got %d", policy.Version)
	}

	if !containsRule(policy.Allow, RuleTypePrefix, "https://app.example.com") {
		t.Fatalf("missing https://app.example.com allow rule: %+v", policy.Allow)
	}
	if !containsRule(policy.Allow, RuleTypeDomain, "example.org") {
		t.Fatalf("missing example.org allow rule: %+v", policy.Allow)
	}
	if !containsRule(policy.Allow, RuleTypeDomain, "api.example.net") {
		t.Fatalf("missing api.example.net allow rule: %+v", policy.Allow)
	}
	if !containsRule(policy.Allow, RuleTypePath, "/login") {
		t.Fatalf("missing /login allow rule: %+v", policy.Allow)
	}

	if !containsRule(policy.Deny, RuleTypeDomain, "admin.example.com") {
		t.Fatalf("missing admin.example.com deny rule: %+v", policy.Deny)
	}
	if !containsRule(policy.Deny, RuleTypeCIDR, "10.0.0.0/8") {
		t.Fatalf("missing CIDR deny rule: %+v", policy.Deny)
	}

	if policy.PrivateNetworks != PrivateNetworksBlock {
		t.Fatalf("expected private network posture block, got %s", policy.PrivateNetworks)
	}

	if policy.PIIMode != PIIModeForbid {
		t.Fatalf("expected PII mode forbid, got %s", policy.PIIMode)
	}
}
