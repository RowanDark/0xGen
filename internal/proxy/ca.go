package proxy

import (
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

type caStore struct {
	cert    *x509.Certificate
	key     *rsa.PrivateKey
	certPEM []byte
	keyPEM  []byte
	cacheMu sync.Mutex
	cache   map[string]*tls.Certificate
}

func newCAStore(certPath, keyPath string) (*caStore, error) {
	certPEM, keyPEM, err := loadOrCreateCA(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	cert, key, err := parseCA(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &caStore{cert: cert, key: key, certPEM: certPEM, keyPEM: keyPEM, cache: make(map[string]*tls.Certificate)}, nil
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

	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	if cert, ok := c.cache[host]; ok {
		return cert, nil
	}

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

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate host key: %w", err)
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, c.cert, &priv.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("create host certificate: %w", err)
	}

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	tlsCert, err := tls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		return nil, fmt.Errorf("load tls key pair: %w", err)
	}
	c.cache[host] = &tlsCert
	return &tlsCert, nil
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
