package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPrecedence(t *testing.T) {
	tempDir := t.TempDir()

	// Configure HOME to a temp directory containing only the legacy ~/.glyph/config.toml.
	homeDir := filepath.Join(tempDir, "home")
	if err := os.Mkdir(homeDir, 0o755); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}
	t.Setenv("HOME", homeDir)

	glyphDir := filepath.Join(homeDir, ".glyph")
	if err := os.Mkdir(glyphDir, 0o755); err != nil {
		t.Fatalf("mkdir .glyph: %v", err)
	}
	tomlPath := filepath.Join(glyphDir, "config.toml")
	tomlConfig := []byte(`server_addr = "0.0.0.0:1111"
output_dir = "/custom"
[proxy]
addr = "proxy-home:8080"
`)
	if err := os.WriteFile(tomlPath, tomlConfig, 0o644); err != nil {
		t.Fatalf("write toml config: %v", err)
	}

	// Provide a local YAML config overriding the TOML file.
	workDir := filepath.Join(tempDir, "work")
	if err := os.Mkdir(workDir, 0o755); err != nil {
		t.Fatalf("mkdir work: %v", err)
	}
	yamlPath := filepath.Join(workDir, "glyph.yml")
	yamlConfig := []byte(`server_addr: 127.0.0.1:6500
proxy:
  enable: true
  addr: proxy-local:9090
`)
	if err := os.WriteFile(yamlPath, yamlConfig, 0o644); err != nil {
		t.Fatalf("write yaml config: %v", err)
	}

	// Ensure env overrides beat file configuration.
	t.Setenv("GLYPH_PROXY_ADDR", "proxy-env:5555")
	t.Setenv("GLYPH_AUTH_TOKEN", "env-token")

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer func() {
		_ = os.Chdir(cwd)
	}()
	if err := os.Chdir(workDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.ServerAddr != "127.0.0.1:6500" {
		t.Fatalf("unexpected server addr: %s", cfg.ServerAddr)
	}
	if !cfg.Proxy.Enable {
		t.Fatalf("expected proxy enable from YAML override")
	}
	if cfg.Proxy.Addr != "proxy-env:5555" {
		t.Fatalf("expected env override for proxy addr, got %s", cfg.Proxy.Addr)
	}
	if cfg.OutputDir != "/custom" {
		t.Fatalf("expected TOML output dir, got %s", cfg.OutputDir)
	}
	if cfg.AuthToken != "env-token" {
		t.Fatalf("expected env token override, got %s", cfg.AuthToken)
	}
}

func TestLoadDefaults(t *testing.T) {
	t.Setenv("HOME", filepath.Join(t.TempDir(), "home"))

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	defaults := Default()
	if cfg != defaults {
		t.Fatalf("expected defaults, got %#v", cfg)
	}
}

func TestLoadPrefers0xgenConfig(t *testing.T) {
	tempDir := t.TempDir()

	homeDir := filepath.Join(tempDir, "home")
	if err := os.Mkdir(homeDir, 0o755); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}
	t.Setenv("HOME", homeDir)

	legacyDir := filepath.Join(homeDir, ".glyph")
	if err := os.Mkdir(legacyDir, 0o755); err != nil {
		t.Fatalf("mkdir legacy dir: %v", err)
	}
	legacyConfig := []byte(`output_dir = "/legacy"`)
	if err := os.WriteFile(filepath.Join(legacyDir, "config.toml"), legacyConfig, 0o644); err != nil {
		t.Fatalf("write legacy config: %v", err)
	}

	modernDir := filepath.Join(homeDir, ".0xgen")
	if err := os.Mkdir(modernDir, 0o755); err != nil {
		t.Fatalf("mkdir modern dir: %v", err)
	}
	modernConfig := []byte(`output_dir = "/modern"`)
	if err := os.WriteFile(filepath.Join(modernDir, "config.toml"), modernConfig, 0o644); err != nil {
		t.Fatalf("write modern config: %v", err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.OutputDir != "/modern" {
		t.Fatalf("expected modern config to take precedence, got %s", cfg.OutputDir)
	}
}
