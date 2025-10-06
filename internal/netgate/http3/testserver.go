//go:build go1.24

package http3

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"golang.org/x/net/quic"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// StartTestServer launches a minimal HTTP/3 server backed by the provided handler.
// The returned address is suitable for use with net/http clients. The caller is
// responsible for invoking the shutdown function to release resources.
func StartTestServer(handler http.Handler) (addr string, shutdown func() error, err error) {
	if handler == nil {
		handler = http.NewServeMux()
	}
	cert, err := generateTestCertificate()
	if err != nil {
		return "", nil, err
	}
	cfg := &quic.Config{TLSConfig: &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
		MinVersion:   tls.VersionTLS13,
	}}
	endpoint, err := quic.Listen("udp", "127.0.0.1:0", cfg)
	if err != nil {
		return "", nil, err
	}
	ts := &testServer{
		endpoint: endpoint,
		handler:  handler,
	}
	go ts.serve()
	shutdown = func() error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		return endpoint.Close(ctx)
	}
	return endpoint.LocalAddr().String(), shutdown, nil
}

type testServer struct {
	endpoint *quic.Endpoint
	handler  http.Handler
}

func (ts *testServer) serve() {
	for {
		qconn, err := ts.endpoint.Accept(context.Background())
		if err != nil {
			return
		}
		go ts.handleConn(qconn)
	}
}

func (ts *testServer) handleConn(qconn *quic.Conn) {
	sc := &testServerConn{
		handler: ts.handler,
		qconn:   qconn,
	}
	sc.enc.init()
	controlStream, err := newConnStream(context.Background(), qconn, streamTypeControl)
	if err != nil {
		_ = qconn.Close()
		return
	}
	controlStream.writeSettings(settingsQPACKMaxTableCapacity, 0, settingsQPACKBlockedStreams, 0)
	_ = controlStream.Flush()
	sc.acceptStreams(qconn, sc)
}

type testServerConn struct {
	handler http.Handler
	qconn   *quic.Conn

	genericConn
	enc qpackEncoder
	dec qpackDecoder
}

func (sc *testServerConn) handleControlStream(st *stream) error {
	return (&serverConn{qconn: sc.qconn}).handleControlStream(st)
}

func (sc *testServerConn) handleEncoderStream(*stream) error { return nil }

func (sc *testServerConn) handleDecoderStream(*stream) error { return nil }

func (sc *testServerConn) handlePushStream(*stream) error {
	return &connectionError{
		code:    errH3StreamCreationError,
		message: "client created push stream",
	}
}

func (sc *testServerConn) handleRequestStream(st *stream) error {
	if err := sc.discardRequest(st); err != nil {
		return err
	}
	rw := newTestResponseWriter(st, &sc.enc)
	sc.handler.ServeHTTP(rw, &http.Request{})
	if err := rw.finish(); err != nil {
		return err
	}
	st.stream.CloseRead()
	return nil
}

func (sc *testServerConn) abort(err error) {
	if err == nil {
		return
	}
	if e, ok := err.(*connectionError); ok {
		sc.qconn.Abort(&quic.ApplicationError{Code: uint64(e.code), Reason: e.message})
	} else {
		sc.qconn.Abort(err)
	}
}

func (sc *testServerConn) discardRequest(st *stream) error {
	ftype, err := st.readFrameHeader()
	if err != nil {
		return err
	}
	if ftype != frameTypeHeaders {
		return &connectionError{code: errH3FrameUnexpected, message: "expected headers frame"}
	}
	return st.discardFrame()
}

type testResponseWriter struct {
	st     *stream
	enc    *qpackEncoder
	header http.Header
	wrote  bool
	err    error
}

func newTestResponseWriter(st *stream, enc *qpackEncoder) *testResponseWriter {
	return &testResponseWriter{
		st:     st,
		enc:    enc,
		header: make(http.Header),
	}
}

func (rw *testResponseWriter) Header() http.Header { return rw.header }

func (rw *testResponseWriter) WriteHeader(status int) {
	if rw.wrote || rw.err != nil {
		return
	}
	if status == 0 {
		status = http.StatusOK
	}
	payload := rw.enc.encode(func(yield func(indexType, string, string)) {
		yield(mayIndex, ":status", strconv.Itoa(status))
		for k, values := range rw.header {
			name := strings.ToLower(k)
			for _, v := range values {
				yield(mayIndex, name, v)
			}
		}
	})
	rw.st.writeVarint(int64(frameTypeHeaders))
	rw.st.writeVarint(int64(len(payload)))
	if _, err := rw.st.Write(payload); err != nil {
		rw.err = err
		return
	}
	if err := rw.st.Flush(); err != nil {
		rw.err = err
		return
	}
	rw.wrote = true
}

func (rw *testResponseWriter) Write(p []byte) (int, error) {
	if rw.err != nil {
		return 0, rw.err
	}
	if !rw.wrote {
		rw.WriteHeader(http.StatusOK)
	}
	if rw.err != nil {
		return 0, rw.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	rw.st.writeVarint(int64(frameTypeData))
	rw.st.writeVarint(int64(len(p)))
	n, err := rw.st.Write(p)
	if err != nil {
		rw.err = err
		return n, err
	}
	if err := rw.st.Flush(); err != nil {
		rw.err = err
		return n, err
	}
	return n, nil
}

func (rw *testResponseWriter) finish() error {
	if !rw.wrote {
		rw.WriteHeader(http.StatusOK)
	}
	if rw.err != nil {
		return rw.err
	}
	rw.st.stream.CloseWrite()
	return nil
}

func generateTestCertificate() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return tls.X509KeyPair(certPEM, keyPEM)
}
