//go:build http3

package netgate

import (
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"sync"

	xhttp3 "golang.org/x/net/http3"
)

func (lt *layeredTransport) roundTripHTTP3(req *http.Request, addr string, cfg *tls.Config) (*http.Response, error) {
	if req == nil {
		return nil, errors.New("http3: request is nil")
	}
	_ = addr
	tlsCfg := cfg
	if tlsCfg != nil {
		tlsCfg = tlsCfg.Clone()
	} else {
		tlsCfg = &tls.Config{}
	}
	ctx := req.Context()
	cancel := func() {}
	if lt.gate != nil {
		var cancelFn func()
		ctx, cancelFn = lt.gate.withTimeout(ctx)
		cancel = cancelFn
	}
	defer cancel()

	h3Req := req.WithContext(ctx)
	rt := &xhttp3.RoundTripper{
		TLSClientConfig: tlsCfg,
	}
	if lt.primary != nil {
		rt.DisableCompression = lt.primary.DisableCompression
	}

	resp, err := rt.RoundTrip(h3Req)
	if err != nil {
		_ = rt.Close()
		return nil, err
	}
	resp.Body = &http3Body{ReadCloser: resp.Body, closer: &onceCloser{fn: rt.Close}}
	return resp, nil
}

type http3Body struct {
	io.ReadCloser
	closer io.Closer
}

func (b *http3Body) Close() error {
	if b == nil {
		return nil
	}
	var err error
	if b.ReadCloser != nil {
		err = b.ReadCloser.Close()
	}
	if b.closer != nil {
		if cerr := b.closer.Close(); cerr != nil {
			if err != nil {
				err = errors.Join(err, cerr)
			} else {
				err = cerr
			}
		}
	}
	return err
}

type onceCloser struct {
	once sync.Once
	fn   func() error
	err  error
}

func (c *onceCloser) Close() error {
	if c == nil || c.fn == nil {
		return nil
	}
	c.once.Do(func() {
		c.err = c.fn()
	})
	return c.err
}
