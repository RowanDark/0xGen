package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"golang.org/x/net/http2"
)

func configureHTTP2Transport(rt http.RoundTripper) error {
	transport, ok := rt.(*http.Transport)
	if !ok {
		return nil
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	transport.TLSClientConfig.NextProtos = ensureNextProtos(transport.TLSClientConfig.NextProtos)
	transport.ForceAttemptHTTP2 = true
	return http2.ConfigureTransport(transport)
}

func ensureNextProtos(existing []string) []string {
	hasH2 := false
	hasHTTP1 := false
	for _, proto := range existing {
		switch proto {
		case "h2":
			hasH2 = true
		case "http/1.1":
			hasHTTP1 = true
		}
	}
	if !hasH2 {
		existing = append(existing, "h2")
	}
	if !hasHTTP1 {
		existing = append(existing, "http/1.1")
	}
	return existing
}

func (p *Proxy) serveHTTP2(conn net.Conn, meta *connMetadata) {
	defer conn.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), connMetadataContextKey{}, meta)
		r = r.WithContext(ctx)
		p.ServeHTTP(w, r)
	})

	server := &http2.Server{}
	server.ServeConn(conn, &http2.ServeConnOpts{Handler: handler})
}
