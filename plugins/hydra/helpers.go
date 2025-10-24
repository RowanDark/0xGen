package main

import (
	"net/url"
	"strconv"
	"strings"
)

func parseStatusCode(statusLine string) int {
	fields := strings.Fields(statusLine)
	if len(fields) < 2 {
		return 0
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}
	return code
}

func deriveTarget(headers map[string][]string) (string, string) {
	if headers == nil {
		return "", ""
	}
	get := func(key string) string {
		values := headers[key]
		if len(values) == 0 {
			return ""
		}
		return strings.TrimSpace(values[0])
	}

	var targetURL string
	candidates := []string{
		"X-OXG-Request-URL",
		"X-Request-Url",
		"X-Original-Url",
		"Request-Url",
		"X-Forwarded-Url",
		"Content-Location",
	}
	for _, key := range candidates {
		if value := get(key); value != "" {
			targetURL = value
			break
		}
	}

	host := ""
	if targetURL != "" {
		parsed, err := url.Parse(targetURL)
		if err == nil && parsed.Host != "" {
			targetURL = parsed.String()
			host = strings.ToLower(parsed.Host)
		}
	}

	if host == "" {
		for _, key := range []string{"X-Forwarded-Host", "X-Request-Host", "Host"} {
			if candidate := get(key); candidate != "" {
				host = candidate
				break
			}
		}
	}

	host = normalizeHost(host)

	if targetURL == "" && host != "" {
		scheme := strings.ToLower(strings.TrimSpace(get("X-Forwarded-Proto")))
		if scheme == "" {
			scheme = "https"
		}
		path := strings.TrimSpace(get("X-Forwarded-Uri"))
		if path == "" {
			path = "/"
		} else if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		targetURL = scheme + "://" + host + path
	}

	if strings.Contains(host, "://") {
		if parsed, err := url.Parse(host); err == nil && parsed.Host != "" {
			host = strings.ToLower(parsed.Host)
		}
	}

	return targetURL, host
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return ""
	}
	if parsed, err := url.Parse("//" + host); err == nil && parsed.Host != "" {
		if parsed.Hostname() != "" && parsed.Port() != "" {
			return strings.ToLower(parsed.Hostname() + ":" + parsed.Port())
		}
		return strings.ToLower(parsed.Hostname())
	}
	return host
}

func clampConfidence(conf float64) float64 {
	if conf < 0 {
		return 0
	}
	if conf > 1 {
		return 1
	}
	return conf
}

func snippetAround(body string, index, indicatorLen int) string {
	if index < 0 {
		return ""
	}
	if indicatorLen <= 0 {
		indicatorLen = 1
	}
	start := index - 40
	if start < 0 {
		start = 0
	}
	end := index + indicatorLen + 40
	if end > len(body) {
		end = len(body)
	}
	snippet := body[start:end]
	snippet = strings.ReplaceAll(snippet, "\n", " ")
	snippet = strings.ReplaceAll(snippet, "\r", " ")
	snippet = strings.TrimSpace(snippet)
	if len(snippet) > 160 {
		snippet = snippet[:160]
	}
	return snippet
}
