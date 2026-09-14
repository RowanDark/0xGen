package proxy

import (
	"fmt"
	"path/filepath"
	"testing"
)

func BenchmarkCertificateForHostNewHost(b *testing.B) {
	tempDir := b.TempDir()
	certPath := filepath.Join(tempDir, "ca.pem")
	keyPath := filepath.Join(tempDir, "ca.key")

	store, err := newCAStore(certPath, keyPath, 0)
	if err != nil {
		b.Fatalf("newCAStore: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		host := fmt.Sprintf("host-%d.example.com", i)
		if _, err := store.certificateForHost(host); err != nil {
			b.Fatalf("certificateForHost: %v", err)
		}
	}
}
