package scope

import (
	"bufio"
	"regexp"
	"strings"
)

type section int

const (
	sectionUnknown section = iota
	sectionAllow
	sectionDeny
)

var (
	urlPattern    = regexp.MustCompile(`https?://[^\s,;]+`)
	cidrPattern   = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b`)
	ipPattern     = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	domainPattern = regexp.MustCompile(`(?i)(?:\*?[_a-z0-9-]+\.)+[a-z]{2,}`)
	pathPattern   = regexp.MustCompile(`(?:^|[\s,])(/[^\s,;]+)`) // captures leading slash tokens
)

// ParsePolicyFromText extracts an enforceable scope policy from bounty program prose.
func ParsePolicyFromText(input string) Policy {
	policy := Policy{
		Version:         1,
		PrivateNetworks: inferPrivateNetworks(input),
		PIIMode:         inferPIIMode(input),
	}

	scanner := bufio.NewScanner(strings.NewReader(input))
	sectionState := sectionUnknown

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)

		if heading, remainder := detectHeading(lower, trimmed); heading != sectionUnknown {
			sectionState = heading
			if remainder == "" {
				continue
			}
			trimmed = remainder
			lower = strings.ToLower(trimmed)
		}

		rules := extractRules(trimmed)
		if len(rules) == 0 {
			continue
		}

		switch sectionState {
		case sectionAllow:
			policy.Allow = append(policy.Allow, rules...)
		case sectionDeny:
			policy.Deny = append(policy.Deny, rules...)
		default:
			if strings.Contains(lower, "out of scope") || strings.Contains(lower, "forbidden") || strings.Contains(lower, "prohibited") {
				policy.Deny = append(policy.Deny, rules...)
			} else {
				policy.Allow = append(policy.Allow, rules...)
			}
		}
	}

	policy.Normalise()
	return policy
}

func detectHeading(lower, original string) (section, string) {
	allowKeywords := []string{"in scope", "scope includes", "eligible", "targets", "permitted"}
	denyKeywords := []string{"out of scope", "not in scope", "excluded", "forbidden", "prohibited"}

	for _, kw := range denyKeywords {
		if strings.Contains(lower, kw) {
			remainder := extractRemainder(original, kw)
			return sectionDeny, remainder
		}
	}
	for _, kw := range allowKeywords {
		if strings.Contains(lower, kw) {
			remainder := extractRemainder(original, kw)
			return sectionAllow, remainder
		}
	}
	return sectionUnknown, ""
}

func extractRemainder(original, keyword string) string {
	idx := strings.Index(strings.ToLower(original), keyword)
	if idx == -1 {
		return ""
	}
	remainder := strings.TrimSpace(original[idx+len(keyword):])
	if strings.HasPrefix(remainder, ":") {
		remainder = strings.TrimSpace(remainder[1:])
	}
	return remainder
}

func extractRules(line string) []Rule {
	cleaned := strings.TrimSpace(strings.TrimLeft(line, "-•0123456789.()"))
	if cleaned == "" {
		return nil
	}

	var rules []Rule
	seen := make(map[string]struct{})

	addRule := func(r Rule) {
		r.Type = strings.ToLower(strings.TrimSpace(r.Type))
		r.Value = cleanToken(r.Value)
		if r.Value == "" {
			return
		}
		key := r.Type + "|" + strings.ToLower(r.Value)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		rules = append(rules, r)
	}

	for _, match := range urlPattern.FindAllString(cleaned, -1) {
		addRule(Rule{Type: RuleTypePrefix, Value: match})
	}

	for _, match := range cidrPattern.FindAllString(cleaned, -1) {
		addRule(Rule{Type: RuleTypeCIDR, Value: match})
	}

	ipMatches := ipPattern.FindAllString(cleaned, -1)
	for _, match := range ipMatches {
		if cidrPattern.MatchString(match) {
			continue
		}
		addRule(Rule{Type: RuleTypeIP, Value: match})
	}

	cleanedLower := strings.ToLower(cleaned)

	for _, match := range domainPattern.FindAllString(cleaned, -1) {
		token := strings.ToLower(cleanToken(match))
		if strings.Contains(token, "@") {
			continue
		}
		if ipPattern.MatchString(token) {
			continue
		}
		if strings.Contains(cleanedLower, "://"+token) {
			continue
		}
		if strings.Contains(token, "*") {
			addRule(Rule{Type: RuleTypeWildcard, Value: token})
		} else {
			addRule(Rule{Type: RuleTypeDomain, Value: token})
		}
	}

	pathMatches := pathPattern.FindAllStringSubmatch(cleaned, -1)
	for _, groups := range pathMatches {
		if len(groups) < 2 {
			continue
		}
		token := strings.TrimSpace(groups[1])
		if token == "" || token == "/" {
			continue
		}
		addRule(Rule{Type: RuleTypePath, Value: token})
	}

	if strings.Contains(cleaned, "/") && !strings.Contains(cleaned, "://") {
		slashIdx := strings.Index(cleaned, "/")
		if slashIdx >= 0 {
			pathToken := strings.TrimSpace(cleaned[slashIdx:])
			if pathToken != "" && pathToken != "/" {
				addRule(Rule{Type: RuleTypePath, Value: pathToken})
			}
		}
	}

	return rules
}

func inferPrivateNetworks(input string) string {
	lower := strings.ToLower(input)
	sentences := strings.FieldsFunc(lower, func(r rune) bool {
		return r == '.' || r == '!' || r == '?' || r == '\n'
	})

	for _, sentence := range sentences {
		trimmed := strings.TrimSpace(sentence)
		if trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, "private") || strings.Contains(trimmed, "internal") {
			if strings.Contains(trimmed, "out of scope") || strings.Contains(trimmed, "forbidden") || strings.Contains(trimmed, "not allowed") || strings.Contains(trimmed, "prohibited") {
				return PrivateNetworksBlock
			}
			if strings.Contains(trimmed, "in scope") || strings.Contains(trimmed, "allowed") || strings.Contains(trimmed, "permitted") {
				return PrivateNetworksAllow
			}
		}
	}

	if strings.Contains(lower, "private") && strings.Contains(lower, "out of scope") {
		return PrivateNetworksBlock
	}

	return PrivateNetworksBlock
}

func inferPIIMode(input string) string {
	lower := strings.ToLower(input)
	if !(strings.Contains(lower, "pii") || strings.Contains(lower, "personally identifiable") || strings.Contains(lower, "personal data")) {
		return PIIModeUnspecified
	}

	negative := []string{"no pii", "avoid pii", "pii is out of scope", "pii is forbidden", "do not submit pii", "pii is not allowed"}
	positive := []string{"pii is allowed", "pii allowed", "pii in scope", "pii may be submitted"}

	for _, kw := range negative {
		if strings.Contains(lower, kw) {
			return PIIModeForbid
		}
	}
	for _, kw := range positive {
		if strings.Contains(lower, kw) {
			return PIIModeAllow
		}
	}

	return PIIModeForbid
}

func cleanToken(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	const punctuation = "[]{}<>.,;'\""
	trimmed = strings.Trim(trimmed, punctuation)
	trimmed = strings.Trim(trimmed, "()")
	trimmed = strings.Trim(trimmed, punctuation)
	return strings.TrimSpace(trimmed)
}
