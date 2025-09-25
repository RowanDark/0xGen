package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/RowanDark/Glyph/internal/config"
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
