package cases

import (
	"net"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/RowanDark/0xgen/internal/findings"
)

func (b *Builder) clusterFindings(fs []findings.Finding) [][]findings.Finding {
	if len(fs) == 0 {
		return nil
	}
	uf := newUnionFind(len(fs))
	indexByKey := make(map[string]int)
	for i, f := range fs {
		keys := b.correlationKeys(f)
		if len(keys) == 0 {
			keys = []string{strings.ToLower(strings.TrimSpace(b.groupKey(f)))}
		}
		for _, key := range keys {
			if key == "" {
				continue
			}
			if prev, ok := indexByKey[key]; ok {
				uf.union(i, prev)
			} else {
				indexByKey[key] = i
			}
		}
	}

	grouped := make(map[int][]findings.Finding)
	for i, f := range fs {
		root := uf.find(i)
		grouped[root] = append(grouped[root], f)
	}

	out := make([][]findings.Finding, 0, len(grouped))
	for _, group := range grouped {
		out = append(out, group)
	}
	return out
}

func (b *Builder) componentOrderKey(fs []findings.Finding) string {
	if len(fs) == 0 {
		return ""
	}
	keys := make([]string, len(fs))
	for i, f := range fs {
		keys[i] = strings.ToLower(strings.TrimSpace(b.groupKey(f)))
	}
	sort.Strings(keys)
	return keys[0]
}

func (b *Builder) correlationKeys(f findings.Finding) []string {
	seen := make(map[string]struct{})
	add := func(prefix, raw string) {
		raw = strings.TrimSpace(strings.ToLower(raw))
		if raw == "" {
			return
		}
		key := prefix + raw
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
	}

	primary := strings.ToLower(strings.TrimSpace(b.groupKey(f)))
	if primary != "" {
		add("primary:", primary)
	}

	if explicit := strings.TrimSpace(f.Metadata["case_key"]); explicit != "" {
		add("case:", explicit)
	}

	if host := canonicalTarget(f.Target); host != "" {
		add("host:", host)
		if domain := registrableDomain(host); domain != "" {
			add("domain:", domain)
		}
	}

	asset := normaliseAsset(f)
	if asset.Identifier != "" {
		add("asset:", asset.Kind+"|"+strings.ToLower(asset.Identifier))
	}

	for k, v := range f.Metadata {
		key := strings.ToLower(strings.TrimSpace(k))
		value := strings.TrimSpace(v)
		switch {
		case key == "case_key" || strings.HasPrefix(key, "label:"):
			continue
		case key == "cookie_domain" || key == "cookie_domains":
			for _, token := range splitCorrelationValues(value) {
				token = strings.TrimPrefix(token, ".")
				add("domain:", token)
			}
		case strings.HasPrefix(key, "cookie:"):
			for _, token := range splitCorrelationValues(value) {
				token = strings.TrimPrefix(token, ".")
				add("domain:", token)
			}
		case key == "redirect_chain" || key == "redirects":
			for _, token := range splitCorrelationValues(value) {
				if strings.HasPrefix(token, "http://") || strings.HasPrefix(token, "https://") {
					if u, err := url.Parse(token); err == nil && u.Host != "" {
						host := strings.ToLower(u.Host)
						if h, _, err := net.SplitHostPort(host); err == nil && h != "" {
							host = h
						}
						add("host:", host)
						if domain := registrableDomain(host); domain != "" {
							add("domain:", domain)
						}
					}
				} else {
					add("host:", token)
				}
			}
		case strings.HasPrefix(key, "param:"):
			name := strings.TrimPrefix(key, "param:")
			if name == "" {
				continue
			}
			add("param:", name+"="+strings.ToLower(value))
		case key == "shared_param" || key == "shared_params":
			for _, token := range splitCorrelationValues(value) {
				parts := strings.SplitN(token, "=", 2)
				if len(parts) == 2 {
					add("param:", strings.ToLower(strings.TrimSpace(parts[0]))+"="+strings.ToLower(strings.TrimSpace(parts[1])))
				}
			}
		case strings.HasPrefix(key, "correlate:"):
			label := strings.TrimPrefix(key, "correlate:")
			for _, token := range splitCorrelationValues(value) {
				add(label+":", token)
			}
		}
	}

	if len(seen) == 0 {
		add("fallback:", primary)
	}

	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func splitCorrelationValues(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	replacer := strings.NewReplacer("->", " ", ",", " ", ";", " ", "|", " ", "\n", " ", "\t", " ")
	normalized := replacer.Replace(raw)
	fields := strings.Fields(normalized)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(strings.ToLower(strings.TrimPrefix(f, ".")))
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func registrableDomain(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil {
		return host
	}
	if strings.HasSuffix(host, ".") {
		host = strings.TrimSuffix(host, ".")
	}
	if host == "" {
		return ""
	}
	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	return domain
}

type unionFind struct {
	parent []int
	rank   []int
}

func newUnionFind(n int) *unionFind {
	parent := make([]int, n)
	rank := make([]int, n)
	for i := range parent {
		parent[i] = i
	}
	return &unionFind{parent: parent, rank: rank}
}

func (u *unionFind) find(x int) int {
	if u.parent[x] != x {
		u.parent[x] = u.find(u.parent[x])
	}
	return u.parent[x]
}

func (u *unionFind) union(a, b int) {
	ra := u.find(a)
	rb := u.find(b)
	if ra == rb {
		return
	}
	if u.rank[ra] < u.rank[rb] {
		u.parent[ra] = rb
	} else if u.rank[rb] < u.rank[ra] {
		u.parent[rb] = ra
	} else {
		u.parent[rb] = ra
		u.rank[ra]++
	}
}
