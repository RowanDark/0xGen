package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPrecedence(t *testing.T) {
	tempDir := t.TempDir()

	// Configure HOME to a temp directory containing ~/.0xgen/config.toml.
	homeDir := filepath.Join(tempDir, "home")
	if err := os.Mkdir(homeDir, 0o755); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}
	t.Setenv("HOME", homeDir)

	configDir := filepath.Join(homeDir, ".0xgen")
	if err := os.Mkdir(configDir, 0o755); err != nil {
		t.Fatalf("mkdir .0xgen: %v", err)
	}
	tomlPath := filepath.Join(configDir, "config.toml")
	tomlConfig := []byte(`server_addr = "0.0.0.0:1111"
output_dir = "/custom"
api_endpoint = "https://api.home"
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
	yamlPath := filepath.Join(workDir, "0xgen.yml")
	yamlConfig := []byte(`server_addr: 127.0.0.1:6500
proxy:
  enable: true
  addr: proxy-local:9090
`)
	if err := os.WriteFile(yamlPath, yamlConfig, 0o644); err != nil {
		t.Fatalf("write yaml config: %v", err)
	}

	// Ensure env overrides beat file configuration.
	t.Setenv("0XGEN_PROXY_ADDR", "proxy-env:5555")
	t.Setenv("0XGEN_AUTH_TOKEN", "env-token")
	t.Setenv("0XGEN_API_ENDPOINT", "https://api.env")

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
	if cfg.APIEndpoint != "https://api.env" {
		t.Fatalf("expected API endpoint override, got %s", cfg.APIEndpoint)
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

func TestLoadPrefersHomeConfig(t *testing.T) {
	tempDir := t.TempDir()

	homeDir := filepath.Join(tempDir, "home")
	if err := os.Mkdir(homeDir, 0o755); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}
	t.Setenv("HOME", homeDir)

	configDir := filepath.Join(homeDir, ".0xgen")
	if err := os.Mkdir(configDir, 0o755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	homeConfig := []byte(`output_dir = "/home"`)
	if err := os.WriteFile(filepath.Join(configDir, "config.toml"), homeConfig, 0o644); err != nil {
		t.Fatalf("write home config: %v", err)
	}

	workDir := filepath.Join(tempDir, "work")
	if err := os.Mkdir(workDir, 0o755); err != nil {
		t.Fatalf("mkdir work: %v", err)
	}
	yamlPath := filepath.Join(workDir, "0xgen.yml")
	yamlConfig := []byte("output_dir: /work")
	if err := os.WriteFile(yamlPath, yamlConfig, 0o644); err != nil {
		t.Fatalf("write work config: %v", err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer func() { _ = os.Chdir(cwd) }()
	if err := os.Chdir(workDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.OutputDir != "/home" {
		t.Fatalf("expected home config to take precedence, got %s", cfg.OutputDir)
	}
}
