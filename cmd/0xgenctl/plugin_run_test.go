package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/RowanDark/0xgen/internal/plugins/integrity"
)

var cwdMu sync.Mutex

func TestRunPluginRunMalformedManifest(t *testing.T) {
	root := t.TempDir()
	pluginDir := filepath.Join(root, "plugins", "samples", "broken")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("mkdir plugin dir: %v", err)
	}
	manifestPath := filepath.Join(pluginDir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte("{\"name\":\"broken\""), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	cwdMu.Lock()
	cwd, err := os.Getwd()
	if err != nil {
		cwdMu.Unlock()
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(root); err != nil {
		cwdMu.Unlock()
		t.Fatalf("chdir: %v", err)
	}
	defer func() {
		_ = os.Chdir(cwd)
		cwdMu.Unlock()
	}()

	if code := runPluginRun([]string{"--sample", "broken"}); code != 1 {
		t.Fatalf("expected exit code 1 for malformed manifest, got %d", code)
	}
}

func TestRunPluginRunInvalidSignature(t *testing.T) {
	root := t.TempDir()
	pluginDir := filepath.Join(root, "plugins", "samples", "badsign")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("mkdir plugin dir: %v", err)
	}

	artifactPath := filepath.Join(pluginDir, "artifact.bin")
	if err := os.WriteFile(artifactPath, []byte("payload"), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	hash, err := integrity.HashFile(artifactPath)
	if err != nil {
		t.Fatalf("hash artifact: %v", err)
	}

	allowlistDir := filepath.Join(root, "plugins")
	if err := os.MkdirAll(allowlistDir, 0o755); err != nil {
		t.Fatalf("mkdir allowlist dir: %v", err)
	}
	allowlistPath := filepath.Join(allowlistDir, "ALLOWLIST")
	entry := fmt.Sprintf("%s samples/badsign/artifact.bin\n", hash)
	if err := os.WriteFile(allowlistPath, []byte(entry), 0o644); err != nil {
		t.Fatalf("write allowlist: %v", err)
	}

	manifest := `{
  "name": "bad-sign",
  "version": "1.0.0",
  "entry": "main.go",
  "artifact": "plugins/samples/badsign/artifact.bin",
  "capabilities": ["CAP_HTTP_PASSIVE"],
  "signature": {
    "signature": "missing.sig",
    "publicKey": "missing.pub"
  }
}`
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	cwdMu.Lock()
	cwd, err := os.Getwd()
	if err != nil {
		cwdMu.Unlock()
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(root); err != nil {
		cwdMu.Unlock()
		t.Fatalf("chdir: %v", err)
	}
	defer func() {
		_ = os.Chdir(cwd)
		cwdMu.Unlock()
	}()

	if code := runPluginRun([]string{"--sample", "badsign"}); code != 1 {
		t.Fatalf("expected exit code 1 for invalid signature, got %d", code)
	}
}
