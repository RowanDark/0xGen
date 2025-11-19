package tracing

import (
	"crypto/tls"
	"os"
	"testing"
)

func TestGetTLSConfig_Production(t *testing.T) {
	// Ensure environment variable is not set
	os.Unsetenv("0XGEN_DEV_MODE")

	cfg := &Config{
		DevelopmentMode: false,
		SkipTLSVerify:   true, // Even if set, should be ignored in production
	}

	tlsConfig := cfg.GetTLSConfig()

	if tlsConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify must be false in production")
	}

	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion should be TLS 1.2, got %d", tlsConfig.MinVersion)
	}
}

func TestGetTLSConfig_DevelopmentMode(t *testing.T) {
	// Ensure environment variable is not set
	os.Unsetenv("0XGEN_DEV_MODE")

	cfg := &Config{
		DevelopmentMode: true,
		SkipTLSVerify:   true,
	}

	tlsConfig := cfg.GetTLSConfig()

	if !tlsConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify should be true in development mode with SkipTLSVerify enabled")
	}

	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion should be TLS 1.2, got %d", tlsConfig.MinVersion)
	}
}

func TestGetTLSConfig_DevelopmentModeWithoutSkipTLS(t *testing.T) {
	// Ensure environment variable is not set
	os.Unsetenv("0XGEN_DEV_MODE")

	cfg := &Config{
		DevelopmentMode: true,
		SkipTLSVerify:   false, // Dev mode but SkipTLSVerify not enabled
	}

	tlsConfig := cfg.GetTLSConfig()

	if tlsConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify should be false when SkipTLSVerify is not set")
	}

	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion should be TLS 1.2, got %d", tlsConfig.MinVersion)
	}
}

func TestIsDevelopmentMode_EnvVariable(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected bool
	}{
		{"true lowercase", "true", true},
		{"TRUE uppercase", "TRUE", true},
		{"1", "1", true},
		{"yes", "yes", true},
		{"false", "false", false},
		{"0", "0", false},
		{"no", "no", false},
		{"empty", "", false},
		{"random", "random", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{DevelopmentMode: false}

			if tt.envValue == "" {
				os.Unsetenv("0XGEN_DEV_MODE")
			} else {
				os.Setenv("0XGEN_DEV_MODE", tt.envValue)
				defer os.Unsetenv("0XGEN_DEV_MODE")
			}

			result := cfg.IsDevelopmentMode()
			if result != tt.expected {
				t.Errorf("IsDevelopmentMode() = %v, want %v for env value %q", result, tt.expected, tt.envValue)
			}
		})
	}
}

func TestIsDevelopmentMode_ConfigTakesPrecedence(t *testing.T) {
	// Even if env var is false, config DevelopmentMode: true should return true
	os.Setenv("0XGEN_DEV_MODE", "false")
	defer os.Unsetenv("0XGEN_DEV_MODE")

	cfg := &Config{DevelopmentMode: true}

	if !cfg.IsDevelopmentMode() {
		t.Fatal("Config DevelopmentMode: true should take precedence over environment variable")
	}
}

func TestGetTLSConfig_EnvVariableDevMode(t *testing.T) {
	os.Setenv("0XGEN_DEV_MODE", "true")
	defer os.Unsetenv("0XGEN_DEV_MODE")

	cfg := &Config{
		DevelopmentMode: false, // Config says production
		SkipTLSVerify:   true,  // But env var enables dev mode
	}

	tlsConfig := cfg.GetTLSConfig()

	if !tlsConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify should be true when 0XGEN_DEV_MODE env var is set")
	}

	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion should be TLS 1.2, got %d", tlsConfig.MinVersion)
	}
}

func TestGetTLSConfig_AlwaysHasMinVersion(t *testing.T) {
	tests := []struct {
		name            string
		developmentMode bool
		skipTLSVerify   bool
	}{
		{"production", false, false},
		{"production with skip", false, true},
		{"development", true, false},
		{"development with skip", true, true},
	}

	os.Unsetenv("0XGEN_DEV_MODE")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				DevelopmentMode: tt.developmentMode,
				SkipTLSVerify:   tt.skipTLSVerify,
			}

			tlsConfig := cfg.GetTLSConfig()

			if tlsConfig.MinVersion != tls.VersionTLS12 {
				t.Errorf("MinVersion should always be TLS 1.2, got %d", tlsConfig.MinVersion)
			}
		})
	}
}
