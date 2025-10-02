package netgate

import (
	"crypto/tls"
	"errors"
	"net/http"
)

// errHTTP3Unavailable signals that the HTTP/3 fast path is not available and
// the caller should fall back to the standard transport. It allows tests to
// assert graceful degradation until a real implementation replaces this stub.
var errHTTP3Unavailable = errors.New("http3 not available")

func (lt *layeredTransport) roundTripHTTP3(req *http.Request, addr string, cfg *tls.Config) (*http.Response, error) {
	return nil, errHTTP3Unavailable
}
