package netgate

import (
	"net/url"
	"testing"
)

func FuzzValidateURL(f *testing.F) {
	seeds := []string{
		"http://example.com",
		"https://127.0.0.1",
		"http://[::1]",
		"data:text/plain,hello",
		"",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		u, err := url.Parse(raw)
		if err != nil {
			return
		}
		_ = validateURL(u)
	})
}

func FuzzValidateDialTarget(f *testing.F) {
	seeds := [][2]string{
		{"tcp", "example.com:80"},
		{"tcp4", "192.0.2.1:443"},
		{"udp6", "[2001:db8::1]:53"},
		{"unix", "/tmp/socket"},
		{"", ""},
	}
	for _, seed := range seeds {
		f.Add(seed[0], seed[1])
	}

	f.Fuzz(func(t *testing.T, network, address string) {
		_ = validateDialTarget(network, address)
	})
}
