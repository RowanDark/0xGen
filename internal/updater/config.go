package updater

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// ChannelStable is the default release channel.
	ChannelStable = "stable"
	// ChannelBeta exposes prerelease builds.
	ChannelBeta = "beta"
)

var validChannels = map[string]struct{}{
	ChannelStable: {},
	ChannelBeta:   {},
}

// Config captures persisted updater preferences and bookkeeping data used for
// rollback.
//
// Additional fields may be added without breaking backwards compatibility so
// long as they remain optional when unmarshalling existing config files.
type Config struct {
	Channel            string    `json:"channel"`
	LastAppliedVersion string    `json:"last_applied_version,omitempty"`
	PreviousVersion    string    `json:"previous_version,omitempty"`
	BackupPath         string    `json:"backup_path,omitempty"`
	LastAppliedAt      time.Time `json:"last_applied_at,omitempty"`
}

// Store manages reading and writing the updater configuration.
type Store struct {
	dir     string
	path    string
	mu      sync.Mutex
	written bool
}

// DefaultConfigDir returns the platform specific configuration directory for
// glyphctl's updater metadata.
func DefaultConfigDir() (string, error) {
	// Honour GLYPH_UPDATER_CONFIG_DIR if present so tests can override the
	// location without polluting the real user config.
	if override := strings.TrimSpace(os.Getenv("GLYPH_UPDATER_CONFIG_DIR")); override != "" {
		return override, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve config dir: %w", err)
	}
	return filepath.Join(dir, "glyphctl"), nil
}

// NewStore constructs a Store rooted at dir. If dir is empty the default
// configuration directory is used.
func NewStore(dir string) (*Store, error) {
	var err error
	if strings.TrimSpace(dir) == "" {
		dir, err = DefaultConfigDir()
		if err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("ensure config dir %s: %w", dir, err)
	}
	return &Store{dir: dir, path: filepath.Join(dir, "updater.json")}, nil
}

// Dir returns the directory that backs the store.
func (s *Store) Dir() string {
	if s == nil {
		return ""
	}
	return s.dir
}

// Path exposes the full path to the updater configuration file.
func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Load returns the persisted configuration or the default configuration if the
// file is absent.
func (s *Store) Load() (Config, error) {
	if s == nil {
		return Config{}, errors.New("nil store")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) {
			return Config{Channel: ChannelStable}, nil
		}
		return Config{}, fmt.Errorf("read updater config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse updater config: %w", err)
	}
	if cfg.Channel == "" {
		cfg.Channel = ChannelStable
	}
	if _, ok := validChannels[cfg.Channel]; !ok {
		cfg.Channel = ChannelStable
	}
	return cfg, nil
}

// Save persists cfg atomically.
func (s *Store) Save(cfg Config) error {
	if s == nil {
		return errors.New("nil store")
	}
	if cfg.Channel == "" {
		cfg.Channel = ChannelStable
	}
	if _, ok := validChannels[cfg.Channel]; !ok {
		return fmt.Errorf("unknown channel %q", cfg.Channel)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tmp, err := os.CreateTemp(s.dir, "updater-*.json")
	if err != nil {
		return fmt.Errorf("create temp updater config: %w", err)
	}
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return fmt.Errorf("encode updater config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("close temp updater config: %w", err)
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("persist updater config: %w", err)
	}
	s.written = true
	return nil
}

// NormalizeChannel returns the canonical lowercase representation of the
// provided channel name.
func NormalizeChannel(channel string) (string, error) {
	c := strings.TrimSpace(strings.ToLower(channel))
	if c == "" {
		return ChannelStable, nil
	}
	if _, ok := validChannels[c]; !ok {
		return "", fmt.Errorf("unknown channel %q", channel)
	}
	return c, nil
}
