package proxy

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	defaultCACertName = "galdr_proxy_ca.pem"
	defaultCAKeyName  = "galdr_proxy_ca.key"

	// defaultLeafCacheSize bounds the number of generated leaf certificates
	// kept in memory. Without a bound, a long-running proxy session against a
	// large attack surface would grow the cache without limit.
	defaultLeafCacheSize = 4096
)

// DefaultCACertificatePath returns the path where the proxy root certificate is stored when no override is provided.
func DefaultCACertificatePath() string {
	return filepath.Join(defaultOutputDir(), defaultCACertName)
}

// DefaultCAKeyPath returns the path where the proxy private key is stored when no override is provided.
func DefaultCAKeyPath() string {
	return filepath.Join(defaultOutputDir(), defaultCAKeyName)
}

// EnsureRootCertificate returns the PEM-encoded proxy certificate, creating it when necessary.
func EnsureRootCertificate(certPath, keyPath string) ([]byte, error) {
	certPEM, _, err := loadOrCreateCA(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	return certPEM, nil
}

// leafCacheEntry is the value stored in caStore.cacheList, keyed by host in
// caStore.cacheIndex for O(1) lookup.
type leafCacheEntry struct {
	host string
	cert *tls.Certificate
}

type caStore struct {
	cert    *x509.Certificate
	key     *rsa.PrivateKey
	certPEM []byte
	keyPEM  []byte

	cacheMu    sync.Mutex
	cacheCap   int
	cacheIndex map[string]*list.Element
	cacheOrder *list.List // front = most recently used, back = least recently used
}

// newCAStore loads (or creates) the proxy root CA and prepares a bounded LRU
// cache for generated leaf certificates. A cacheSize <= 0 selects
// defaultLeafCacheSize.
func newCAStore(certPath, keyPath string, cacheSize int) (*caStore, error) {
	certPEM, keyPEM, err := loadOrCreateCA(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	cert, key, err := parseCA(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	if cacheSize <= 0 {
		cacheSize = defaultLeafCacheSize
	}
	return &caStore{
		cert:       cert,
		key:        key,
		certPEM:    certPEM,
		keyPEM:     keyPEM,
		cacheCap:   cacheSize,
		cacheIndex: make(map[string]*list.Element),
		cacheOrder: list.New(),
	}, nil
}

func (c *caStore) certificatePEM() []byte {
	return append([]byte(nil), c.certPEM...)
}

func (c *caStore) keyPEMBytes() []byte {
	return append([]byte(nil), c.keyPEM...)
}

func (c *caStore) certificateForHost(host string) (*tls.Certificate, error) {
	host = normalizeServerName(host)
	if host == "" {
		return nil, errors.New("host must not be empty")
	}

	if cert, ok := c.lookupCache(host); ok {
		return cert, nil
	}

	// Generate the leaf outside the cache lock: signing is the expensive
	// part, and serializing it across every concurrent new-host connection
	// would defeat the point of a fast key algorithm.
	tlsCert, err := c.generateLeafCertificate(host)
	if err != nil {
		return nil, err
	}

	return c.storeCache(host, tlsCert), nil
}

func (c *caStore) generateLeafCertificate(host string) (*tls.Certificate, error) {
	tpl := &x509.Certificate{
		SerialNumber: newSerialNumber(),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(host); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{host}
	}

	// Leaf certificates use ECDSA P-256: it is far cheaper to generate than
	// RSA-2048 and is supported by every TLS client 0xgen needs to
	// intercept. The CA itself stays RSA-3072 for maximum client
	// compatibility.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate host key: %w", err)
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, c.cert, &priv.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("create host certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal host key: %w", err)
	}

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		return nil, fmt.Errorf("load tls key pair: %w", err)
	}
	return &tlsCert, nil
}

// lookupCache returns the cached certificate for host, if any, and marks it
// most recently used.
func (c *caStore) lookupCache(host string) (*tls.Certificate, bool) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	elem, ok := c.cacheIndex[host]
	if !ok {
		return nil, false
	}
	c.cacheOrder.MoveToFront(elem)
	return elem.Value.(*leafCacheEntry).cert, true
}

// storeCache inserts cert for host, evicting the least recently used entry
// once the cache exceeds its configured capacity. If another goroutine won
// the race to populate host first, the existing cached certificate is
// returned instead so all callers converge on one certificate per host.
func (c *caStore) storeCache(host string, cert *tls.Certificate) *tls.Certificate {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	if elem, ok := c.cacheIndex[host]; ok {
		c.cacheOrder.MoveToFront(elem)
		return elem.Value.(*leafCacheEntry).cert
	}

	elem := c.cacheOrder.PushFront(&leafCacheEntry{host: host, cert: cert})
	c.cacheIndex[host] = elem

	for c.cacheOrder.Len() > c.cacheCap {
		oldest := c.cacheOrder.Back()
		if oldest == nil {
			break
		}
		c.cacheOrder.Remove(oldest)
		delete(c.cacheIndex, oldest.Value.(*leafCacheEntry).host)
	}

	return cert
}

func loadOrCreateCA(certPath, keyPath string) ([]byte, []byte, error) {
	if strings.TrimSpace(certPath) == "" || strings.TrimSpace(keyPath) == "" {
		outDir := defaultOutputDir()
		if strings.TrimSpace(certPath) == "" {
			certPath = filepath.Join(outDir, defaultCACertName)
		}
		if strings.TrimSpace(keyPath) == "" {
			keyPath = filepath.Join(outDir, defaultCAKeyName)
		}
	}

	certPEM, keyPEM, err := readCAFiles(certPath, keyPath)
	if err == nil {
		return certPEM, keyPEM, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}

	certPEM, keyPEM, err = generateCA()
	if err != nil {
		return nil, nil, err
	}

	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return nil, nil, fmt.Errorf("create CA directory: %w", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, nil, fmt.Errorf("write CA certificate: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, nil, fmt.Errorf("write CA key: %w", err)
	}
	return certPEM, keyPEM, nil
}

func readCAFiles(certPath, keyPath string) ([]byte, []byte, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
}

func generateCA() ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial := newSerialNumber()
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Galdr Proxy Root CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          randomBytes(20),
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("create CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return certPEM, keyPEM, nil
}

func parseCA(certPEM, keyPEM []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, errors.New("failed to decode CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, errors.New("failed to decode CA key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA private key: %w", err)
	}
	return cert, key, nil
}

func newSerialNumber() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return big.NewInt(time.Now().UnixNano())
	}
	return serial
}

func randomBytes(length int) []byte {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		for i := range buf {
			buf[i] = byte(time.Now().UnixNano() >> (i % 8))
		}
	}
	return buf
}

func normalizeServerName(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return host
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
