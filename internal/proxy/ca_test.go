package proxy

import (
	"crypto/ecdsa"
	"fmt"
	"path/filepath"
	"testing"
)

func TestCertificateForHostCachesLeaf(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "ca.pem")
	keyPath := filepath.Join(tempDir, "ca.key")

	store, err := newCAStore(certPath, keyPath, 0)
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

	if _, ok := first.PrivateKey.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("expected leaf private key to be ECDSA, got %T", first.PrivateKey)
	}
}

func TestCertificateForHostCacheIsBounded(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "ca.pem")
	keyPath := filepath.Join(tempDir, "ca.key")

	const cacheSize = 4
	store, err := newCAStore(certPath, keyPath, cacheSize)
	if err != nil {
		t.Fatalf("newCAStore: %v", err)
	}

	hosts := make([]string, 0, cacheSize*3)
	for i := 0; i < cacheSize*3; i++ {
		host := fmt.Sprintf("host-%d.example.com", i)
		hosts = append(hosts, host)
		if _, err := store.certificateForHost(host); err != nil {
			t.Fatalf("certificateForHost(%s): %v", host, err)
		}

		store.cacheMu.Lock()
		size := store.cacheOrder.Len()
		store.cacheMu.Unlock()
		if size > cacheSize {
			t.Fatalf("cache grew to %d entries, want at most %d", size, cacheSize)
		}
	}

	// The most recently used hosts should still be cached; the earliest
	// hosts should have been evicted.
	store.cacheMu.Lock()
	_, recentCached := store.cacheIndex[hosts[len(hosts)-1]]
	_, oldestCached := store.cacheIndex[hosts[0]]
	store.cacheMu.Unlock()

	if !recentCached {
		t.Fatal("expected most recently used host to remain cached")
	}
	if oldestCached {
		t.Fatal("expected oldest host to have been evicted")
	}
}
