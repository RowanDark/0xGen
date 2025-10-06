package netgate

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	glyphhttp3 "github.com/RowanDark/Glyph/internal/netgate/http3"
	"golang.org/x/net/quic"
)

var errHTTP3Unavailable = errors.New("http3 not available")

func (lt *layeredTransport) roundTripHTTP3(req *http.Request, addr string, cfg *tls.Config) (*http.Response, error) {
	if req == nil {
		return nil, errors.New("http3: request is nil")
	}
	if addr == "" {
		return nil, errors.New("http3: address required")
	}
	tlsCfg := cfg
	if tlsCfg != nil {
		tlsCfg = tlsCfg.Clone()
	} else {
		tlsCfg = &tls.Config{}
	}
	if tlsCfg.MinVersion == 0 || tlsCfg.MinVersion < tls.VersionTLS13 {
		tlsCfg.MinVersion = tls.VersionTLS13
	}
	tlsCfg.NextProtos = ensureProtocol(tlsCfg.NextProtos, "h3")

	ctx := req.Context()
	cancel := func() {}
	if lt.gate != nil {
		var cancelFn func()
		ctx, cancelFn = lt.gate.withTimeout(ctx)
		cancel = cancelFn
	}

	transport := &glyphhttp3.Transport{
		Config: &quic.Config{TLSConfig: tlsCfg},
	}

	conn, err := transport.Dial(ctx, addr)
	if err != nil {
		cancel()
		closeHTTP3Endpoint(transport.Endpoint)
		return nil, err
	}
	endpoint := transport.Endpoint
	closer := &onceCloser{fn: func() error {
		var errs error
		if cerr := conn.Close(); cerr != nil {
			errs = errors.Join(errs, cerr)
		}
		if endpoint != nil {
			if cerr := closeHTTP3Endpoint(endpoint); cerr != nil {
				errs = errors.Join(errs, cerr)
			}
			endpoint = nil
		}
		return errs
	}}

	h3Req := req.WithContext(ctx)
	resp, err := conn.RoundTrip(h3Req)
	if err != nil {
		_ = closer.Close()
		cancel()
		return nil, err
	}
	resp.Request = h3Req
	resp.Body = &http3Body{ReadCloser: resp.Body, closer: closer, cancel: cancel}
	return resp, nil
}

func closeHTTP3Endpoint(ep *quic.Endpoint) error {
	if ep == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	return ep.Close(ctx)
}

type http3Body struct {
	io.ReadCloser
	closer io.Closer
	cancel context.CancelFunc
}

func (b *http3Body) Close() error {
	if b == nil {
		return nil
	}
	if b.cancel != nil {
		b.cancel()
		b.cancel = nil
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
