package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Rule describes how an intercepted flow should be modified.
type Rule struct {
	Name     string     `json:"name"`
	Match    RuleMatch  `json:"match"`
	Request  RuleAction `json:"request"`
	Response RuleAction `json:"response"`
}

// RuleMatch controls when a rule is applied.
type RuleMatch struct {
	URLContains string   `json:"url_contains"`
	Methods     []string `json:"methods"`
}

// RuleAction applies header and body mutations to a flow.
type RuleAction struct {
	AddHeaders    map[string]string `json:"add_headers"`
	RemoveHeaders []string          `json:"remove_headers"`
	Body          *RuleBody         `json:"body"`
}

// RuleBody replaces the payload of a request or response.
type RuleBody struct {
	Set string `json:"set"`
}

type ruleStore struct {
	path           string
	mu             sync.Mutex
	cached         []Rule
	lastMod        time.Time
	lastChecked    time.Time
	reloadInterval time.Duration
}

func newRuleStore(path string, reloadInterval time.Duration) *ruleStore {
	if reloadInterval <= 0 {
		reloadInterval = time.Second
	}
	return &ruleStore{path: strings.TrimSpace(path), reloadInterval: reloadInterval}
}

func (r *ruleStore) rules() []Rule {
	if r.path == "" {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	if now.Sub(r.lastChecked) < r.reloadInterval && r.cached != nil {
		return cloneRules(r.cached)
	}
	r.lastChecked = now

	info, err := os.Stat(r.path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return cloneRules(r.cached)
		}
		r.cached = nil
		r.lastMod = time.Time{}
		return nil
	}

	if info.ModTime().Equal(r.lastMod) && r.cached != nil {
		return cloneRules(r.cached)
	}

	data, err := os.ReadFile(r.path)
	if err != nil {
		return cloneRules(r.cached)
	}

	var parsed []Rule
	if err := json.Unmarshal(data, &parsed); err != nil {
		return cloneRules(r.cached)
	}

	if err := validateRules(parsed); err != nil {
		return cloneRules(r.cached)
	}

	r.cached = parsed
	r.lastMod = info.ModTime()
	return cloneRules(r.cached)
}

func (r *ruleStore) match(method, url string) ([]Rule, []string) {
	method = strings.ToUpper(strings.TrimSpace(method))
	url = strings.TrimSpace(url)
	rules := r.rules()
	if len(rules) == 0 {
		return nil, nil
	}
	matched := make([]Rule, 0, len(rules))
	names := make([]string, 0, len(rules))
	for _, rule := range rules {
		if rule.Match.matches(method, url) {
			matched = append(matched, rule)
			if strings.TrimSpace(rule.Name) != "" {
				names = append(names, rule.Name)
			}
		}
	}
	return matched, names
}

func (m RuleMatch) matches(method, url string) bool {
	if m.URLContains != "" && !strings.Contains(url, m.URLContains) {
		return false
	}
	if len(m.Methods) == 0 {
		return true
	}
	upper := strings.ToUpper(method)
	for _, candidate := range m.Methods {
		if strings.ToUpper(candidate) == upper {
			return true
		}
	}
	return false
}

func validateRules(rules []Rule) error {
	seen := make(map[string]struct{})
	for _, rule := range rules {
		if strings.TrimSpace(rule.Name) != "" {
			if _, ok := seen[rule.Name]; ok {
				return fmt.Errorf("duplicate rule name %q", rule.Name)
			}
			seen[rule.Name] = struct{}{}
		}
	}
	return nil
}

func cloneRules(rules []Rule) []Rule {
	if len(rules) == 0 {
		return nil
	}
	out := make([]Rule, len(rules))
	copy(out, rules)
	return out
}

func ensureRulesPath(path string) string {
	path = strings.TrimSpace(path)
	if path != "" {
		return path
	}
	dir := defaultOutputDir()
	return filepath.Join(dir, "proxy_rules.json")
}
