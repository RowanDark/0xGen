package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RowanDark/0xgen/internal/config"
)

func TestPrintResolvedConfig(t *testing.T) {
	cfg := config.Config{
		ServerAddr: "1.2.3.4:1111",
		AuthToken:  "token",
		OutputDir:  "/somewhere",
		Proxy: config.ProxyConfig{
			Enable:      true,
			Addr:        "proxy:1234",
			RulesPath:   "rules.yaml",
			HistoryPath: "history.jsonl",
			CACertPath:  "ca.pem",
			CAKeyPath:   "ca.key",
		},
	}

	var buf bytes.Buffer
	printResolvedConfig(&buf, cfg)

	output := buf.String()
	expected := []string{
		"server_addr: 1.2.3.4:1111",
		"auth_token: token",
		"output_dir: /somewhere",
		"proxy:",
		"  enable: true",
		"  addr: proxy:1234",
		"  rules_path: rules.yaml",
		"  history_path: history.jsonl",
		"  ca_cert_path: ca.pem",
		"  ca_key_path: ca.key",
	}
	for _, line := range expected {
		if !strings.Contains(output, line) {
			t.Fatalf("expected line %q in output: %s", line, output)
		}
	}
}

func TestRunConfigRequiresSubcommand(t *testing.T) {
	if code := runConfig(nil); code != 2 {
		t.Fatalf("expected exit code 2 for missing subcommand, got %d", code)
	}
	if code := runConfig([]string{"unknown"}); code != 2 {
		t.Fatalf("expected exit code 2 for unknown subcommand, got %d", code)
	}
}

func TestRunConfigMigrateCopiesLegacyConfig(t *testing.T) {
	tempDir := t.TempDir()
	homeDir := filepath.Join(tempDir, "home")
	if err := os.Mkdir(homeDir, 0o755); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}
	t.Setenv("HOME", homeDir)

	glyphDir := filepath.Join(homeDir, ".glyph")
	if err := os.Mkdir(glyphDir, 0o755); err != nil {
		t.Fatalf("mkdir legacy dir: %v", err)
	}
	legacyContent := []byte("server_addr = \"1.2.3.4:5000\"\n")
	if err := os.WriteFile(filepath.Join(glyphDir, "config.toml"), legacyContent, 0o600); err != nil {
		t.Fatalf("write legacy config: %v", err)
	}

	if code := runConfig([]string{"migrate"}); code != 0 {
		t.Fatalf("expected migrate to succeed, got exit code %d", code)
	}

	migratedPath := filepath.Join(homeDir, ".0xgen", "config.toml")
	data, err := os.ReadFile(migratedPath)
	if err != nil {
		t.Fatalf("read migrated config: %v", err)
	}
	if !bytes.Equal(data, legacyContent) {
		t.Fatalf("expected migrated config to match legacy content: %q", data)
	}
}

func TestRunConfigMigrateRequiresLegacySource(t *testing.T) {
	t.Setenv("HOME", filepath.Join(t.TempDir(), "home"))

	if code := runConfig([]string{"migrate"}); code != 2 {
		t.Fatalf("expected exit code 2 when legacy config missing, got %d", code)
	}
}
