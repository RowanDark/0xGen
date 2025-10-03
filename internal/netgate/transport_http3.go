package netgate

import (
        "crypto/tls"
        "errors"
        "net/http"
)

var errHTTP3Unavailable = errors.New("http3 not available")

func (lt *layeredTransport) roundTripHTTP3(req *http.Request, addr string, cfg *tls.Config) (*http.Response, error) {
        return nil, errHTTP3Unavailable
}
