package proxy

import (
	"path/filepath"
	"testing"
)

func TestCertificateForHostCachesLeaf(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "ca.pem")
	keyPath := filepath.Join(tempDir, "ca.key")

	store, err := newCAStore(certPath, keyPath)
	if err != nil {
		t.Fatalf("newCAStore: %v", err)
	}

	first, err := store.certificateForHost("example.com")
	if err != nil {
		t.Fatalf("first certificateForHost: %v", err)
	}
	if first == nil {
		t.Fatal("first certificate is nil")
	}

	second, err := store.certificateForHost("example.com")
	if err != nil {
		t.Fatalf("second certificateForHost: %v", err)
	}
	if second == nil {
		t.Fatal("second certificate is nil")
	}

	if first != second {
		t.Fatalf("expected cached certificate pointer, got different instances")
	}
}
