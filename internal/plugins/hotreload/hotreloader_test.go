package hotreload

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RowanDark/Glyph/internal/bus"
	"github.com/RowanDark/Glyph/internal/findings"
	"github.com/RowanDark/Glyph/internal/logging"
	"github.com/RowanDark/Glyph/internal/plugins/integrity"
)

func TestReloaderLoadsAndReloadsPlugin(t *testing.T) {
	root := t.TempDir()
	pluginsDir := filepath.Join(root, "plugins")
	if err := os.MkdirAll(pluginsDir, 0o755); err != nil {
		t.Fatalf("mkdir plugins dir: %v", err)
	}

	pluginDir := filepath.Join(pluginsDir, "demo")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("mkdir plugin dir: %v", err)
	}

	artifactPath := filepath.Join(pluginDir, "plugin.bin")
	signaturePath := filepath.Join(pluginDir, "plugin.bin.sig")
	publicKeyPath := filepath.Join(pluginDir, "plugin.pub")
	manifestPath := filepath.Join(pluginDir, "manifest.json")
	allowlistPath := filepath.Join(pluginsDir, "ALLOWLIST")

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	if err := os.WriteFile(publicKeyPath, pemBytes, 0o644); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	writeVersion := func(version string, content string) string {
		if err := os.WriteFile(artifactPath, []byte(content), 0o644); err != nil {
			t.Fatalf("write artifact: %v", err)
		}
		hash, err := integrity.HashFile(artifactPath)
		if err != nil {
			t.Fatalf("hash artifact: %v", err)
		}
		digest := sha256.Sum256([]byte(content))
		sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
		if err != nil {
			t.Fatalf("sign artifact: %v", err)
		}
		if err := os.WriteFile(signaturePath, []byte(base64.StdEncoding.EncodeToString(sig)), 0o644); err != nil {
			t.Fatalf("write signature: %v", err)
		}
		manifest := fmt.Sprintf(`{"name":"demo","version":"%s","entry":"plugin.bin","artifact":"plugin.bin","capabilities":["CAP_EMIT_FINDINGS"],"signature":{"signature":"plugin.bin.sig","publicKey":"plugin.pub"}}`, version)
		if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
			t.Fatalf("write manifest: %v", err)
		}
		allowlist := fmt.Sprintf("%s demo/plugin.bin\n", hash)
		if err := os.WriteFile(allowlistPath, []byte(allowlist), 0o644); err != nil {
			t.Fatalf("write allowlist: %v", err)
		}
		return hash
	}

	firstHash := writeVersion("1.0.0", "version-one")

	busLogger, err := logging.NewAuditLogger("plugin_bus_test", logging.WithoutStdout(), logging.WithWriter(io.Discard))
	if err != nil {
		t.Fatalf("create bus audit logger: %v", err)
	}
	pluginLogger, err := logging.NewAuditLogger("plugin_manager_test", logging.WithoutStdout(), logging.WithWriter(io.Discard))
	if err != nil {
		t.Fatalf("create plugin audit logger: %v", err)
	}
	srv := bus.NewServer("token", findings.NewBus(), bus.WithAuditLogger(busLogger))

	reloader, err := New(pluginsDir, root, allowlistPath, srv, WithAuditLogger(pluginLogger), WithPollInterval(10*time.Millisecond))
	if err != nil {
		t.Fatalf("construct reloader: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go reloader.Start(ctx)

	waitFor := func(cond func(map[string]PluginState) bool) {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if cond(reloader.Plugins()) {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("condition not met before timeout")
	}

	waitFor(func(m map[string]PluginState) bool {
		st, ok := m["demo"]
		if !ok {
			return false
		}
		return st.Version == "1.0.0" && st.ArtifactHash == firstHash
	})

	secondHash := writeVersion("2.0.0", "version-two")

	waitFor(func(m map[string]PluginState) bool {
		st, ok := m["demo"]
		if !ok {
			return false
		}
		return st.Version == "2.0.0" && st.ArtifactHash == secondHash
	})

	if err := os.Remove(manifestPath); err != nil {
		t.Fatalf("remove manifest: %v", err)
	}
	waitFor(func(m map[string]PluginState) bool {
		_, ok := m["demo"]
		return !ok
	})
}
