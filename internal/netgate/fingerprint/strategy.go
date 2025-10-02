package fingerprint

import (
	"context"
	"crypto/tls"
	"hash/crc32"
	"net"
	"net/http"
	"strings"
)

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type TLSProfile struct {
	MinVersion       uint16
	MaxVersion       uint16
	CipherSuites     []uint16
	CurvePreferences []tls.CurveID
	NextProtos       []string
}

type Profile struct {
	Name      string
	JA3       string
	JA3Hash   string
	JA4       string
	UserAgent string
	Headers   map[string]string
	TLS       TLSProfile
}

type Strategy struct {
	defaultProfile Profile
	rotation       []Profile
	rotate         bool
}

func DefaultStrategy() *Strategy {
	chrome := chromeProfile()
	firefox := firefoxProfile()
	return &Strategy{
		defaultProfile: chrome,
		rotation:       []Profile{chrome, firefox},
	}
}

func (s *Strategy) EnableRotation(enable bool) {
	s.rotate = enable
}

func (s *Strategy) SetRotationProfiles(profiles []Profile) {
	if len(profiles) == 0 {
		return
	}
	s.rotation = append([]Profile(nil), profiles...)
}

func (s *Strategy) RotationProfiles() []Profile {
	return append([]Profile(nil), s.rotation...)
}

func (s *Strategy) DialTLS(ctx context.Context, dialer Dialer, network, address string, base *tls.Config) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	cfg := s.TLSConfigForHost(host, base)
	rawConn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(rawConn, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	return conn, nil
}

func (s *Strategy) TLSConfigForHost(host string, base *tls.Config) *tls.Config {
	cfg := cloneTLS(base)
	profile := s.profileForHost(host)
	applyTLSProfile(cfg, profile.TLS)
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	return cfg
}

func (s *Strategy) DecorateRequest(req *http.Request) {
	if req == nil || req.URL == nil {
		return
	}
	profile := s.profileForHost(req.URL.Hostname())
	if profile.UserAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", profile.UserAgent)
	}
	for key, value := range profile.Headers {
		if value == "" {
			continue
		}
		if req.Header.Get(key) == "" {
			req.Header.Set(key, value)
		}
	}
}

func (s *Strategy) profileForHost(host string) Profile {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return s.defaultProfile
	}
	if !s.rotate || len(s.rotation) == 0 {
		return s.defaultProfile
	}
	idx := int(crc32.ChecksumIEEE([]byte(host))) % len(s.rotation)
	return s.rotation[idx]
}

func cloneTLS(base *tls.Config) *tls.Config {
	if base == nil {
		return &tls.Config{}
	}
	return base.Clone()
}

func applyTLSProfile(cfg *tls.Config, profile TLSProfile) {
	if cfg == nil {
		cfg = &tls.Config{}
	}
	if profile.MinVersion != 0 {
		cfg.MinVersion = profile.MinVersion
	}
	if profile.MaxVersion != 0 {
		cfg.MaxVersion = profile.MaxVersion
	}
	if len(profile.CipherSuites) > 0 {
		cfg.CipherSuites = append([]uint16(nil), profile.CipherSuites...)
	}
	if len(profile.CurvePreferences) > 0 {
		cfg.CurvePreferences = append([]tls.CurveID(nil), profile.CurvePreferences...)
	}
	if len(profile.NextProtos) > 0 {
		cfg.NextProtos = ensureProtocols(cfg.NextProtos, profile.NextProtos...)
	}
	if len(cfg.NextProtos) == 0 {
		cfg.NextProtos = []string{"h2", "http/1.1"}
	}
	if cfg.MinVersion == 0 {
		cfg.MinVersion = tls.VersionTLS12
	}
	if cfg.MaxVersion == 0 {
		cfg.MaxVersion = tls.VersionTLS13
	}
}

func ensureProtocols(existing []string, required ...string) []string {
	present := make(map[string]struct{}, len(existing))
	for _, proto := range existing {
		present[proto] = struct{}{}
	}
	for _, proto := range required {
		if _, ok := present[proto]; ok {
			continue
		}
		existing = append(existing, proto)
		present[proto] = struct{}{}
	}
	return existing
}

func chromeProfile() Profile {
	return Profile{
		Name:      "chrome-124",
		JA3:       "771,4866-4867-4865-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53-255,0-23-65281-10-11-35-16-5-18-51-45-43,29-23-24,0",
		JA3Hash:   "e7d705a3286e19ea42f587b344ee6865",
		JA4:       "t13d8d8d16h2_29h3_29",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Accept-Language":           "en-US,en;q=0.9",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-User":            "?1",
			"Upgrade-Insecure-Requests": "1",
			"Sec-CH-UA":                 "\"Chromium\";v=\"124\", \"Not:A-Brand\";v=\"99\"",
			"Sec-CH-UA-Mobile":          "?0",
			"Sec-CH-UA-Platform":        "\"Windows\"",
		},
		TLS: TLSProfile{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
			CipherSuites: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
			},
			NextProtos: []string{"h2", "http/1.1"},
		},
	}
}

func firefoxProfile() Profile {
	return Profile{
		Name:      "firefox-126",
		JA3:       "771,4867-4865-4866-49196-49195-49200-49188-49192-49162-49172-49187-49191-49161-49171-52392-52393-159-158-107-103-57-51-157-156-61-60-53-47-255,0-23-65281-10-11-13-16-5-18-51-45-43-27,29-23-24,0",
		JA3Hash:   "cd08e31494f7c6c1cf5a39b0e84e0842",
		JA4:       "t13d8d8d15h2_29h3_29",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
		Headers: map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			"Accept-Language":           "en-US,en;q=0.9",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-Site":            "none",
			"Upgrade-Insecure-Requests": "1",
		},
		TLS: TLSProfile{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
			CipherSuites: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			},
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
			},
			NextProtos: []string{"h2", "http/1.1"},
		},
	}
}
