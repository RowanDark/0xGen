package scope

import "testing"

func TestCompileAndEvaluate(t *testing.T) {
	text := `### Program Scope

Eligible targets:
- app.acme.test
- https://portal.acme.test/login
- *.acme.org/api

Out of scope targets:
- admin.acme.test
- api.acme.net/internal
- 192.168.0.0/16

Private subnets are out of scope.`

	derived := ParsePolicyFromText(text)
	manual := Policy{Version: 1, PrivateNetworks: PrivateNetworksBlock}
	manual.Allow = []Rule{
		{Type: RuleTypeDomain, Value: "app.acme.test"},
		{Type: RuleTypePrefix, Value: "https://portal.acme.test/login"},
		{Type: RuleTypeWildcard, Value: "*.acme.org"},
		{Type: RuleTypePath, Value: "/api"},
	}
	manual.Deny = []Rule{
		{Type: RuleTypeDomain, Value: "admin.acme.test"},
		{Type: RuleTypeDomain, Value: "api.acme.net"},
		{Type: RuleTypePath, Value: "/internal"},
		{Type: RuleTypeCIDR, Value: "192.168.0.0/16"},
	}

	derived.Normalise()
	manual.Normalise()

	derivedEnforcer, err := Compile(derived)
	if err != nil {
		t.Fatalf("compile derived policy: %v", err)
	}
	manualEnforcer, err := Compile(manual)
	if err != nil {
		t.Fatalf("compile manual policy: %v", err)
	}

	cases := map[string]DecisionReason{
		"https://app.acme.test/dashboard":      DecisionAllowed,
		"https://portal.acme.test/login":       DecisionAllowed,
		"https://portal.acme.test/login/reset": DecisionAllowed,
		"https://portal.acme.test/logout":      DecisionNotAllowlisted,
		"https://admin.acme.test/":             DecisionDeniedByRule,
		"https://api.acme.net/internal/status": DecisionDeniedByRule,
		"https://api.acme.org/api/list":        DecisionAllowed,
		"https://api.acme.org/health":          DecisionAllowed,
		"https://public.acme.net":              DecisionNotAllowlisted,
		"http://192.168.1.10/status":           DecisionPrivateBlocked,
		"https://10.0.0.5":                     DecisionPrivateBlocked,
		"https://[::1]/":                       DecisionPrivateBlocked,
		"":                                     DecisionInvalidCandidate,
		"not a url":                            DecisionInvalidCandidate,
	}

	for candidate, expected := range cases {
		d := derivedEnforcer.Evaluate(candidate)
		m := manualEnforcer.Evaluate(candidate)
		if d.Reason != m.Reason {
			t.Errorf("decision mismatch for %q: derived=%s manual=%s", candidate, d.Reason, m.Reason)
		}
		if d.Reason != expected {
			t.Errorf("unexpected derived decision for %q: got %s want %s", candidate, d.Reason, expected)
		}
	}
}

func TestSummarize(t *testing.T) {
	policy := Policy{
		Allow: []Rule{
			{Type: RuleTypeDomain, Value: "app.test"},
			{Type: RuleTypeDomain, Value: "api.test"},
		},
		Deny: []Rule{{Type: RuleTypeCIDR, Value: "10.0.0.0/8"}},
	}
	policy.Normalise()
	summary := Summarize(policy)

	if summary.PrivateNetworks != PrivateNetworksUnspecified {
		t.Fatalf("unexpected private network mode: %s", summary.PrivateNetworks)
	}
	allowDomains := summary.Allow[RuleTypeDomain]
	if len(allowDomains) != 2 || allowDomains[0] != "api.test" || allowDomains[1] != "app.test" {
		t.Fatalf("unexpected allow domain summary: %#v", allowDomains)
	}
	denyCIDR := summary.Deny[RuleTypeCIDR]
	if len(denyCIDR) != 1 || denyCIDR[0] != "10.0.0.0/8" {
		t.Fatalf("unexpected deny cidr summary: %#v", denyCIDR)
	}
}
