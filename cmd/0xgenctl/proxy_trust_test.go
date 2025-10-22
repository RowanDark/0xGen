package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestProxyTrustRequiresAction(t *testing.T) {
	t.Setenv("0XGEN_OUT", t.TempDir())
	if code := runProxyTrust(nil); code != 2 {
		t.Fatalf("expected exit code 2 when no action is provided, got %d", code)
	}
}

func TestProxyTrustExportToFile(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("0XGEN_OUT", tempDir)
	out := filepath.Join(tempDir, "proxy-ca.pem")
	if code := runProxyTrust([]string{"--out", out}); code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read exported certificate: %v", err)
	}
	if !strings.Contains(string(data), "BEGIN CERTIFICATE") {
		t.Fatalf("expected PEM-encoded certificate, got %q", string(data))
	}
}

func TestProxyTrustInstallUnsupportedOnNonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("installation path tested elsewhere")
	}
	t.Setenv("0XGEN_OUT", t.TempDir())
	if code := runProxyTrust([]string{"--install"}); code != 1 {
		t.Fatalf("expected exit code 1 when installation is unsupported, got %d", code)
	}
}
