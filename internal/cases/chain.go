package cases

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/RowanDark/0xgen/internal/findings"
)

type attackChain struct {
	Nodes   []string
	Steps   []ChainStep
	Summary string
}

func buildAttackChain(fs []findings.Finding) attackChain {
	if len(fs) == 0 {
		return attackChain{}
	}

	type occurrence struct {
		Node        string
		Host        string
		FindingIdx  int
		Description string
	}

	paramBuckets := make(map[string][]occurrence)
	paramNames := make(map[string]string)
	tokenBuckets := make(map[string][]occurrence)
	cookieBuckets := make(map[string][]occurrence)

	steps := make([]ChainStep, 0)

	addStep := func(from, to, description string, f findings.Finding) {
		from = strings.TrimSpace(from)
		to = strings.TrimSpace(to)
		if from == "" || to == "" || from == to {
			return
		}
		step := ChainStep{
			Stage:       len(steps) + 1,
			From:        from,
			To:          to,
			Description: description,
			Plugin:      f.Plugin,
			Type:        f.Type,
			FindingID:   f.ID,
			Severity:    f.Severity,
			WeakLink:    isWeakLink(f.Severity),
		}
		steps = append(steps, step)
	}

	for idx, f := range fs {
		feature := extractChainFeature(f)

		for _, seq := range feature.Redirects {
			if len(seq) < 2 {
				continue
			}
			for i := 1; i < len(seq); i++ {
				prev := seq[i-1]
				next := seq[i]
				desc := "Redirect observed between nodes"
				if prev.Node != "" && next.Node != "" {
					desc = "Redirect from " + prev.Node + " to " + next.Node
				}
				addStep(prev.Node, next.Node, desc, f)
			}
		}

		for _, p := range feature.Parameters {
			key := strings.ToLower(p.Name) + "|" + strings.ToLower(p.Value)
			if p.Name == "" || p.Value == "" {
				continue
			}
			bucket := occurrence{Node: feature.Node, Host: feature.Host, FindingIdx: idx}
			paramBuckets[key] = append(paramBuckets[key], bucket)
			if _, ok := paramNames[key]; !ok {
				paramNames[key] = p.Name
			}
		}

		for _, domain := range feature.TokenDomains {
			domain = strings.TrimSpace(strings.ToLower(domain))
			if domain == "" {
				continue
			}
			tokenBuckets[domain] = append(tokenBuckets[domain], occurrence{Node: feature.Node, Host: feature.Host, FindingIdx: idx})
		}

		for _, scope := range feature.CookieScopes {
			key := scope.Domain + "|" + scope.Path
			cookieBuckets[key] = append(cookieBuckets[key], occurrence{Node: feature.Node, Host: feature.Host, FindingIdx: idx, Description: scope.Path})
		}
	}

	addSequentialSteps := func(bucket []occurrence, descriptor func() string, stageFinding func(int) findings.Finding, fromLabel func(occurrence) string, toLabel func(occurrence) string) {
		if len(bucket) < 2 {
			return
		}
		sort.SliceStable(bucket, func(i, j int) bool {
			return bucket[i].FindingIdx < bucket[j].FindingIdx
		})
		for i := 1; i < len(bucket); i++ {
			from := bucket[i-1]
			to := bucket[i]
			f := stageFinding(to.FindingIdx)
			addStep(fromLabel(from), toLabel(to), descriptor(), f)
		}
	}

	for key, bucket := range paramBuckets {
		name := paramNames[key]
		descriptor := func() string {
			return "Parameter " + name + " reused across hosts"
		}
		addSequentialSteps(bucket, descriptor, func(i int) findings.Finding { return fs[i] }, func(o occurrence) string { return o.Node }, func(o occurrence) string { return o.Node })
	}

	for domain, bucket := range tokenBuckets {
		descriptor := func() string {
			return "Shared token domain " + domain
		}
		addSequentialSteps(bucket, descriptor, func(i int) findings.Finding { return fs[i] }, func(o occurrence) string { return o.Node }, func(o occurrence) string { return o.Node })
	}

	for key, bucket := range cookieBuckets {
		parts := strings.SplitN(key, "|", 2)
		domain := parts[0]
		path := ""
		if len(parts) > 1 {
			path = parts[1]
		}
		descriptor := func() string {
			return "Cookie scope " + domain + path + " reused"
		}
		addSequentialSteps(bucket, descriptor, func(i int) findings.Finding { return fs[i] }, func(o occurrence) string { return o.Node }, func(o occurrence) string { return o.Node })
	}

	if len(steps) == 0 {
		return attackChain{}
	}

	orderedNodes := deriveChainNodes(steps)
	summary := buildChainSummary(steps, orderedNodes)

	return attackChain{Nodes: orderedNodes, Steps: steps, Summary: summary}
}

type chainFeature struct {
	Node         string
	Host         string
	Redirects    [][]chainLocation
	Parameters   []chainParam
	TokenDomains []string
	CookieScopes []cookieScope
}

type chainParam struct {
	Name  string
	Value string
}

type chainLocation struct {
	Host string
	Path string
	Node string
}

type cookieScope struct {
	Domain string
	Path   string
}

func extractChainFeature(f findings.Finding) chainFeature {
	host, path := parseTargetURL(f.Target)
	node := buildNodeLabel(host, path, f)

	params := parseParameterMetadata(f.Metadata)
	tokenDomains := parseTokenDomains(f.Metadata)
	redirects := parseRedirectChains(f.Metadata, host, path)
	cookieScopes := parseCookieScopes(f.Metadata, host)

	return chainFeature{
		Node:         node,
		Host:         host,
		Redirects:    redirects,
		Parameters:   params,
		TokenDomains: tokenDomains,
		CookieScopes: cookieScopes,
	}
}

func parseTargetURL(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		if u, err := url.Parse(raw); err == nil {
			host := strings.ToLower(u.Host)
			if h, _, err := net.SplitHostPort(host); err == nil && h != "" {
				host = h
			}
			path := strings.TrimSpace(u.Path)
			if path == "" {
				path = "/"
			}
			return host, path
		}
	}
	return strings.ToLower(raw), ""
}

func buildNodeLabel(host, path string, f findings.Finding) string {
	host = strings.TrimSpace(host)
	path = strings.TrimSpace(path)
	switch {
	case host != "" && path != "":
		return host + " " + path
	case host != "":
		return host
	case strings.TrimSpace(f.Target) != "":
		return strings.TrimSpace(f.Target)
	default:
		return strings.TrimSpace(f.Plugin)
	}
}

func parseParameterMetadata(metadata map[string]string) []chainParam {
	params := make([]chainParam, 0)
	for k, v := range metadata {
		key := strings.ToLower(strings.TrimSpace(k))
		value := strings.TrimSpace(v)
		switch {
		case strings.HasPrefix(key, "param:"):
			name := strings.TrimSpace(strings.TrimPrefix(key, "param:"))
			if name != "" && value != "" {
				params = append(params, chainParam{Name: name, Value: value})
			}
		case key == "shared_param" || key == "shared_params" || strings.Contains(key, "param_leak"):
			for _, token := range splitCorrelationValues(value) {
				name, val, ok := splitParamToken(token)
				if ok {
					params = append(params, chainParam{Name: name, Value: val})
				}
			}
		}
	}
	return params
}

func splitParamToken(token string) (string, string, bool) {
	parts := strings.SplitN(token, "=", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	name := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])
	if name == "" || value == "" {
		return "", "", false
	}
	return strings.ToLower(name), value, true
}

func parseTokenDomains(metadata map[string]string) []string {
	domains := make([]string, 0)
	for k, v := range metadata {
		key := strings.ToLower(strings.TrimSpace(k))
		if !(strings.Contains(key, "token") && strings.Contains(key, "domain")) {
			continue
		}
		for _, token := range splitCorrelationValues(v) {
			if token != "" {
				domains = append(domains, strings.TrimPrefix(token, "."))
			}
		}
	}
	return domains
}

func parseRedirectChains(metadata map[string]string, fallbackHost, fallbackPath string) [][]chainLocation {
	sequences := make([][]chainLocation, 0)
	for k, v := range metadata {
		key := strings.ToLower(strings.TrimSpace(k))
		if key != "redirect_chain" && key != "redirects" {
			continue
		}
		rawSequence := strings.Split(v, "->")
		seq := make([]chainLocation, 0, len(rawSequence))
		for _, raw := range rawSequence {
			trimmed := strings.TrimSpace(raw)
			if trimmed == "" {
				continue
			}
			host, path := parseTargetURL(trimmed)
			if host == "" {
				host = fallbackHost
			}
			if path == "" {
				path = fallbackPath
			}
			seq = append(seq, chainLocation{Host: host, Path: path, Node: buildNodeLabel(host, path, findings.Finding{Target: trimmed})})
		}
		if len(seq) > 0 {
			sequences = append(sequences, dedupeSequentialLocations(seq))
		}
	}
	return sequences
}

func dedupeSequentialLocations(seq []chainLocation) []chainLocation {
	if len(seq) < 2 {
		return seq
	}
	out := make([]chainLocation, 0, len(seq))
	var last string
	for _, loc := range seq {
		if loc.Node == "" {
			continue
		}
		if loc.Node == last {
			continue
		}
		out = append(out, loc)
		last = loc.Node
	}
	return out
}

func parseCookieScopes(metadata map[string]string, fallbackHost string) []cookieScope {
	domains := make(map[string]struct{})
	paths := make(map[string]struct{})

	for k, v := range metadata {
		key := strings.ToLower(strings.TrimSpace(k))
		value := strings.TrimSpace(v)
		switch {
		case key == "cookie_domain" || key == "cookie_domains" || strings.Contains(key, "cookie_domain"):
			for _, token := range splitCorrelationValues(value) {
				if token == "" {
					continue
				}
				domains[strings.TrimPrefix(token, ".")] = struct{}{}
			}
		case key == "cookie_path" || key == "cookie_paths" || strings.Contains(key, "cookie_path"):
			for _, token := range splitCorrelationValuesPreserveSlash(value) {
				if token == "" {
					continue
				}
				paths[normaliseCookiePath(token)] = struct{}{}
			}
		case strings.HasPrefix(key, "cookie:"):
			for _, token := range parseCookieAttributeString(value) {
				switch token.Kind {
				case "domain":
					if token.Value != "" {
						domains[strings.TrimPrefix(strings.ToLower(token.Value), ".")] = struct{}{}
					}
				case "path":
					if token.Value != "" {
						paths[normaliseCookiePath(token.Value)] = struct{}{}
					}
				}
			}
		}
	}

	if len(paths) == 0 {
		return nil
	}
	if len(domains) == 0 && fallbackHost != "" {
		domains[fallbackHost] = struct{}{}
	}

	scopes := make([]cookieScope, 0, len(domains)*len(paths))
	for domain := range domains {
		for path := range paths {
			scopes = append(scopes, cookieScope{Domain: domain, Path: path})
		}
	}
	return scopes
}

type cookieAttribute struct {
	Kind  string
	Value string
}

func parseCookieAttributeString(raw string) []cookieAttribute {
	parts := strings.Split(raw, ";")
	out := make([]cookieAttribute, 0, len(parts))
	for _, part := range parts {
		cleaned := strings.TrimSpace(part)
		if cleaned == "" {
			continue
		}
		pieces := strings.SplitN(cleaned, "=", 2)
		if len(pieces) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(pieces[0]))
		value := strings.TrimSpace(pieces[1])
		switch key {
		case "domain":
			out = append(out, cookieAttribute{Kind: "domain", Value: value})
		case "path":
			out = append(out, cookieAttribute{Kind: "path", Value: value})
		}
	}
	return out
}

func splitCorrelationValuesPreserveSlash(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	replacer := strings.NewReplacer("->", " ", ",", " ", ";", " ", "|", " ", "\n", " ", "\t", " ")
	normalized := replacer.Replace(raw)
	fields := strings.Fields(normalized)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		token := strings.TrimSpace(f)
		if token != "" {
			out = append(out, token)
		}
	}
	return out
}

func normaliseCookiePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func deriveChainNodes(steps []ChainStep) []string {
	ordered := make([]string, 0)
	seen := make(map[string]struct{})
	for _, step := range steps {
		if _, ok := seen[step.From]; !ok && step.From != "" {
			ordered = append(ordered, step.From)
			seen[step.From] = struct{}{}
		}
		if _, ok := seen[step.To]; !ok && step.To != "" {
			ordered = append(ordered, step.To)
			seen[step.To] = struct{}{}
		}
	}
	return ordered
}

func buildChainSummary(steps []ChainStep, nodes []string) string {
	if len(steps) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("Correlated attack path spans ")
	b.WriteString(fmtCount(len(steps), "step"))
	b.WriteString(" across ")
	b.WriteString(fmtCount(len(nodes), "node"))
	b.WriteString(": ")
	b.WriteString(strings.Join(nodes, " -> "))
	b.WriteString(". Contributors: ")
	parts := make([]string, len(steps))
	for i, step := range steps {
		parts[i] = fmt.Sprintf("step %d by %s (%s)", step.Stage, step.Plugin, step.Type)
	}
	b.WriteString(strings.Join(parts, "; "))
	weak := make([]string, 0)
	for _, step := range steps {
		if step.WeakLink {
			weak = append(weak, fmt.Sprintf("step %d", step.Stage))
		}
	}
	if len(weak) > 0 {
		b.WriteString(". Potential weak links: ")
		b.WriteString(strings.Join(weak, ", "))
		b.WriteString(".")
	}
	return b.String()
}

func fmtCount(n int, label string) string {
	if n == 1 {
		return "1 " + label
	}
	return fmt.Sprintf("%d %ss", n, label)
}

func isWeakLink(severity findings.Severity) bool {
	return severityOrder[severity] <= severityOrder[findings.SeverityLow]
}
