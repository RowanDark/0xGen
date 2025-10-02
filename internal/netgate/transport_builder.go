package netgate

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/RowanDark/Glyph/internal/netgate/fingerprint"
	"golang.org/x/net/http2"
)

func (g *Gate) buildTransport() (http.RoundTripper, error) {
	base := http.DefaultTransport
	transport, ok := base.(*http.Transport)
	if !ok {
		transport = &http.Transport{}
	} else {
		transport = transport.Clone()
	}
	transport.Proxy = http.ProxyFromEnvironment
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		ctx, cancel := g.withTimeout(ctx)
		defer cancel()
		return g.dialer.DialContext(ctx, network, address)
	}
	transport.TLSClientConfig = g.prepareTLSConfig(transport.TLSClientConfig)
	if g.fp != nil {
		transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			ctx, cancel := g.withTimeout(ctx)
			defer cancel()
			return g.fp.DialTLS(ctx, g.dialer, network, address, transport.TLSClientConfig)
		}
	}
	if g.tcfg.EnableHTTP2 {
		if err := http2.ConfigureTransport(transport); err != nil {
			return nil, err
		}
	}
	if !g.tcfg.EnableHTTP3 {
		return transport, nil
	}
	lt := &layeredTransport{
		gate:    g,
		primary: transport,
		fp:      g.fp,
		baseTLS: transport.TLSClientConfig,
	}
	lt.h3attempt = lt.roundTripHTTP3
	return lt, nil
}

func (g *Gate) prepareTLSConfig(base *tls.Config) *tls.Config {
	cfg := cloneTLSConfig(base)
	if g.tlsCfg != nil {
		cfg = overlayTLSConfig(cfg, g.tlsCfg)
	}
	cfg.NextProtos = ensureProtocol(cfg.NextProtos, "h2", "http/1.1")
	return cfg
}

func cloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return cfg.Clone()
}

func overlayTLSConfig(dst, src *tls.Config) *tls.Config {
	if dst == nil {
		return cloneTLSConfig(src)
	}
	if src == nil {
		return dst
	}
	if src.RootCAs != nil {
		dst.RootCAs = src.RootCAs
	}
	if src.ClientCAs != nil {
		dst.ClientCAs = src.ClientCAs
	}
	if len(src.CipherSuites) > 0 {
		dst.CipherSuites = append([]uint16(nil), src.CipherSuites...)
	}
	if len(src.CurvePreferences) > 0 {
		dst.CurvePreferences = append([]tls.CurveID(nil), src.CurvePreferences...)
	}
	if len(src.NextProtos) > 0 {
		dst.NextProtos = ensureProtocol(dst.NextProtos, src.NextProtos...)
	}
	if src.MinVersion != 0 {
		dst.MinVersion = src.MinVersion
	}
	if src.MaxVersion != 0 {
		dst.MaxVersion = src.MaxVersion
	}
	if src.ClientSessionCache != nil {
		dst.ClientSessionCache = src.ClientSessionCache
	}
	dst.InsecureSkipVerify = dst.InsecureSkipVerify || src.InsecureSkipVerify
	dst.PreferServerCipherSuites = dst.PreferServerCipherSuites || src.PreferServerCipherSuites
	dst.SessionTicketsDisabled = dst.SessionTicketsDisabled || src.SessionTicketsDisabled
	if src.ServerName != "" {
		dst.ServerName = src.ServerName
	}
	if src.GetClientCertificate != nil {
		dst.GetClientCertificate = src.GetClientCertificate
	}
	if src.GetCertificate != nil {
		dst.GetCertificate = src.GetCertificate
	}
	if src.KeyLogWriter != nil {
		dst.KeyLogWriter = src.KeyLogWriter
	}
	return dst
}

func ensureProtocol(existing []string, required ...string) []string {
	present := make(map[string]struct{}, len(existing))
	for _, proto := range existing {
		present[proto] = struct{}{}
	}
	for _, proto := range required {
		if _, ok := present[proto]; !ok {
			existing = append(existing, proto)
			present[proto] = struct{}{}
		}
	}
	return existing
}

type gatedTransport struct {
	gate       *Gate
	pluginID   string
	capability string
	transport  http.RoundTripper
}

func (gt *gatedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := gt.gate.validateHTTPRequest(gt.pluginID, gt.capability, req); err != nil {
		return nil, err
	}
	return gt.transport.RoundTrip(req)
}

func (gt *gatedTransport) CloseIdleConnections() {
	if closer, ok := gt.transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

type layeredTransport struct {
	gate      *Gate
	primary   *http.Transport
	fp        *fingerprint.Strategy
	baseTLS   *tls.Config
	h3attempt func(*http.Request, string, *tls.Config) (*http.Response, error)
}

func (lt *layeredTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL != nil && strings.EqualFold(req.URL.Scheme, "https") {
		if resp, err := lt.tryHTTP3(req); err == nil {
			return resp, nil
		} else if !lt.shouldFallback(err) {
			return nil, err
		}
	}
	return lt.primary.RoundTrip(req)
}

func (lt *layeredTransport) shouldFallback(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	return true
}

func (lt *layeredTransport) tryHTTP3(req *http.Request) (*http.Response, error) {
	if req.URL == nil {
		return nil, fmt.Errorf("http3: request URL required")
	}
	host := req.URL.Hostname()
	if host == "" {
		return nil, fmt.Errorf("http3: host required")
	}
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(host, port)
	tlsCfg := lt.prepareTLS(host)
	if lt.h3attempt == nil {
		return nil, errHTTP3Unavailable
	}
	return lt.h3attempt(req, addr, tlsCfg)
}

func (lt *layeredTransport) prepareTLS(host string) *tls.Config {
	cfg := cloneTLSConfig(lt.baseTLS)
	cfg.ServerName = host
	if lt.fp != nil {
		cfg = lt.fp.TLSConfigForHost(host, cfg)
	}
	cfg.NextProtos = ensureProtocol(cfg.NextProtos, "h3", "h2", "http/1.1")
	return cfg
}

func (lt *layeredTransport) CloseIdleConnections() {
	lt.primary.CloseIdleConnections()
}
