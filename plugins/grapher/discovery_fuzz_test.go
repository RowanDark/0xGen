package main

import "testing"

func FuzzNormalizeURL(f *testing.F) {
	seeds := []string{
		"https://example.com",
		"example.com/path",
		" http://example.com ",
		"",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = normalizeBaseURL(raw)
	})
}
