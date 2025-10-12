package config

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config captures the Glyph configuration resolved from defaults, optional files,
// and environment overrides.
type Config struct {
	ServerAddr string      `yaml:"server_addr" toml:"server_addr"`
	AuthToken  string      `yaml:"auth_token" toml:"auth_token"`
	OutputDir  string      `yaml:"output_dir" toml:"output_dir"`
	Proxy      ProxyConfig `yaml:"proxy" toml:"proxy"`
}

// ProxyConfig controls proxy-related behaviour for glyphd.
type ProxyConfig struct {
	Enable      bool   `yaml:"enable" toml:"enable"`
	Addr        string `yaml:"addr" toml:"addr"`
	RulesPath   string `yaml:"rules_path" toml:"rules_path"`
	HistoryPath string `yaml:"history_path" toml:"history_path"`
	CACertPath  string `yaml:"ca_cert_path" toml:"ca_cert_path"`
	CAKeyPath   string `yaml:"ca_key_path" toml:"ca_key_path"`
}

// Default returns the built-in Glyph configuration.
func Default() Config {
	return Config{
		ServerAddr: "127.0.0.1:50051",
		AuthToken:  "supersecrettoken",
		OutputDir:  "/out",
		Proxy: ProxyConfig{
			Enable:      false,
			Addr:        "",
			RulesPath:   "",
			HistoryPath: "",
			CACertPath:  "",
			CAKeyPath:   "",
		},
	}
}

// Load resolves the Glyph configuration using defaults, configuration files, and
// environment overrides. The lookup order for configuration files is:
//  1. ./glyph.yml (YAML)
//  2. ~/.0xgen/config.toml (TOML)
//  3. ~/.glyph/config.toml (TOML, legacy)
//
// Environment variables prefixed with GLYPH_ have the highest precedence.
func Load() (Config, error) {
	cfg := Default()

	if err := loadHomeConfig(&cfg); err != nil {
		return Config{}, err
	}
	if err := loadLocalConfig(&cfg); err != nil {
		return Config{}, err
	}

	applyEnvOverrides(&cfg)

	return cfg, nil
}

func loadHomeConfig(cfg *Config) error {
	home, err := os.UserHomeDir()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("determine home directory: %w", err)
	}

	newPath := filepath.Join(home, ".0xgen", "config.toml")
	data, err := os.ReadFile(newPath)
	if err == nil {
		if err := applyFileConfig(cfg, data, "toml"); err != nil {
			return fmt.Errorf("parse config %s: %w", newPath, err)
		}
		return nil
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read config %s: %w", newPath, err)
	}

	legacyPath := filepath.Join(home, ".glyph", "config.toml")
	data, err = os.ReadFile(legacyPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read config %s: %w", legacyPath, err)
	}
	log.Println("Using legacy Glyph config")
	if err := applyFileConfig(cfg, data, "toml"); err != nil {
		return fmt.Errorf("parse config %s: %w", legacyPath, err)
	}
	return nil
}

func loadLocalConfig(cfg *Config) error {
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("determine working directory: %w", err)
	}
	path := filepath.Join(wd, "glyph.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read config %s: %w", path, err)
	}
	if err := applyFileConfig(cfg, data, "yaml"); err != nil {
		return fmt.Errorf("parse config %s: %w", path, err)
	}
	return nil
}

type fileConfig struct {
	ServerAddr *string          `yaml:"server_addr" toml:"server_addr"`
	AuthToken  *string          `yaml:"auth_token" toml:"auth_token"`
	OutputDir  *string          `yaml:"output_dir" toml:"output_dir"`
	Proxy      *fileProxyConfig `yaml:"proxy" toml:"proxy"`
}

type fileProxyConfig struct {
	Enable      *bool   `yaml:"enable" toml:"enable"`
	Addr        *string `yaml:"addr" toml:"addr"`
	RulesPath   *string `yaml:"rules_path" toml:"rules_path"`
	HistoryPath *string `yaml:"history_path" toml:"history_path"`
	CACertPath  *string `yaml:"ca_cert_path" toml:"ca_cert_path"`
	CAKeyPath   *string `yaml:"ca_key_path" toml:"ca_key_path"`
}

func applyFileConfig(cfg *Config, data []byte, format string) error {
	var fc fileConfig
	var err error
	switch format {
	case "yaml":
		fc, err = parseYAML(data)
	case "toml":
		fc, err = parseTOML(data)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
	if err != nil {
		return err
	}

	if fc.ServerAddr != nil {
		cfg.ServerAddr = strings.TrimSpace(*fc.ServerAddr)
	}
	if fc.AuthToken != nil {
		cfg.AuthToken = strings.TrimSpace(*fc.AuthToken)
	}
	if fc.OutputDir != nil {
		cfg.OutputDir = strings.TrimSpace(*fc.OutputDir)
	}
	if fc.Proxy != nil {
		if fc.Proxy.Enable != nil {
			cfg.Proxy.Enable = *fc.Proxy.Enable
		}
		if fc.Proxy.Addr != nil {
			cfg.Proxy.Addr = strings.TrimSpace(*fc.Proxy.Addr)
		}
		if fc.Proxy.RulesPath != nil {
			cfg.Proxy.RulesPath = strings.TrimSpace(*fc.Proxy.RulesPath)
		}
		if fc.Proxy.HistoryPath != nil {
			cfg.Proxy.HistoryPath = strings.TrimSpace(*fc.Proxy.HistoryPath)
		}
		if fc.Proxy.CACertPath != nil {
			cfg.Proxy.CACertPath = strings.TrimSpace(*fc.Proxy.CACertPath)
		}
		if fc.Proxy.CAKeyPath != nil {
			cfg.Proxy.CAKeyPath = strings.TrimSpace(*fc.Proxy.CAKeyPath)
		}
	}

	return nil
}

func applyEnvOverrides(cfg *Config) {
	if val := strings.TrimSpace(os.Getenv("GLYPH_SERVER")); val != "" {
		cfg.ServerAddr = val
	}
	if val := strings.TrimSpace(os.Getenv("GLYPH_AUTH_TOKEN")); val != "" {
		cfg.AuthToken = val
	}
	if val := strings.TrimSpace(os.Getenv("GLYPH_OUT")); val != "" {
		cfg.OutputDir = val
	}
	if val := strings.TrimSpace(os.Getenv("GLYPH_PROXY_ENABLE")); val != "" {
		if parsed, err := strconv.ParseBool(val); err == nil {
			cfg.Proxy.Enable = parsed
		}
	}
	if val := strings.TrimSpace(os.Getenv("GLYPH_ENABLE_PROXY")); val != "" {
		if parsed, err := strconv.ParseBool(val); err == nil {
			cfg.Proxy.Enable = parsed
		}
	}
	if val := strings.TrimSpace(os.Getenv("GLYPH_PROXY_ADDR")); val != "" {
		cfg.Proxy.Addr = val
	}
	if val := strings.TrimSpace(os.Getenv("GLYPH_PROXY_RULES")); val != "" {
		cfg.Proxy.RulesPath = val
	}
	if val := strings.TrimSpace(os.Getenv("GLYPH_PROXY_HISTORY")); val != "" {
		cfg.Proxy.HistoryPath = val
	}
	if val := strings.TrimSpace(os.Getenv("GLYPH_PROXY_CA_CERT")); val != "" {
		cfg.Proxy.CACertPath = val
	}
	if val := strings.TrimSpace(os.Getenv("GLYPH_PROXY_CA_KEY")); val != "" {
		cfg.Proxy.CAKeyPath = val
	}
}

func parseYAML(data []byte) (fileConfig, error) {
	lines := strings.Split(string(data), "\n")
	var fc fileConfig
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasSuffix(trimmed, ":") {
			key := strings.TrimSuffix(trimmed, ":")
			if key == "proxy" {
				proxy := &fileProxyConfig{}
				for j := i + 1; j < len(lines); j++ {
					nestedLine := lines[j]
					if indentation(nestedLine) == 0 {
						break
					}
					trimmedNested := strings.TrimSpace(nestedLine)
					if trimmedNested == "" || strings.HasPrefix(trimmedNested, "#") {
						continue
					}
					parts := strings.SplitN(trimmedNested, ":", 2)
					if len(parts) != 2 {
						return fileConfig{}, fmt.Errorf("invalid proxy entry: %q", trimmedNested)
					}
					key := strings.TrimSpace(parts[0])
					value := trimQuotes(strings.TrimSpace(parts[1]))
					switch key {
					case "enable":
						parsed, err := parseBool(value)
						if err != nil {
							return fileConfig{}, err
						}
						proxy.Enable = &parsed
					case "addr":
						proxy.Addr = &value
					case "rules_path":
						proxy.RulesPath = &value
					case "history_path":
						proxy.HistoryPath = &value
					case "ca_cert_path":
						proxy.CACertPath = &value
					case "ca_key_path":
						proxy.CAKeyPath = &value
					}
					i = j
				}
				fc.Proxy = proxy
			}
			continue
		}
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			return fileConfig{}, fmt.Errorf("invalid yaml line: %q", trimmed)
		}
		key := strings.TrimSpace(parts[0])
		value := trimQuotes(strings.TrimSpace(parts[1]))
		switch key {
		case "server_addr":
			fc.ServerAddr = &value
		case "auth_token":
			fc.AuthToken = &value
		case "output_dir":
			fc.OutputDir = &value
		default:
			// ignore unknown keys
		}
	}
	return fc, nil
}

func parseTOML(data []byte) (fileConfig, error) {
	lines := strings.Split(string(data), "\n")
	var fc fileConfig
	section := ""
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") { // # comment
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.TrimSuffix(strings.TrimPrefix(trimmed, "["), "]")
			continue
		}
		parts := strings.SplitN(trimmed, "=", 2)
		if len(parts) != 2 {
			return fileConfig{}, fmt.Errorf("invalid toml line: %q", trimmed)
		}
		key := strings.TrimSpace(parts[0])
		value := trimQuotes(strings.TrimSpace(parts[1]))
		switch section {
		case "":
			switch key {
			case "server_addr":
				fc.ServerAddr = &value
			case "auth_token":
				fc.AuthToken = &value
			case "output_dir":
				fc.OutputDir = &value
			}
		case "proxy":
			if fc.Proxy == nil {
				fc.Proxy = &fileProxyConfig{}
			}
			switch key {
			case "enable":
				parsed, err := parseBool(value)
				if err != nil {
					return fileConfig{}, err
				}
				fc.Proxy.Enable = &parsed
			case "addr":
				fc.Proxy.Addr = &value
			case "rules_path":
				fc.Proxy.RulesPath = &value
			case "history_path":
				fc.Proxy.HistoryPath = &value
			case "ca_cert_path":
				fc.Proxy.CACertPath = &value
			case "ca_key_path":
				fc.Proxy.CAKeyPath = &value
			}
		}
	}
	return fc, nil
}

func parseBool(val string) (bool, error) {
	v := strings.TrimSpace(strings.ToLower(val))
	switch v {
	case "true", "1", "yes", "on":
		return true, nil
	case "false", "0", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean: %s", val)
	}
}

func trimQuotes(val string) string {
	if len(val) >= 2 {
		if (strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\"")) ||
			(strings.HasPrefix(val, "'") && strings.HasSuffix(val, "'")) {
			return val[1 : len(val)-1]
		}
	}
	return val
}

func indentation(line string) int {
	count := 0
	for _, r := range line {
		switch r {
		case ' ':
			count++
		case '\t':
			count++
		default:
			return count
		}
	}
	return count
}
