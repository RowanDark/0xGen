package updater

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStoreLoadDefault(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Channel != ChannelStable {
		t.Fatalf("expected default channel %q, got %q", ChannelStable, cfg.Channel)
	}
}

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	cfg := Config{
		Channel:            ChannelBeta,
		LastAppliedVersion: "1.2.3",
		PreviousVersion:    "1.2.2",
		BackupPath:         filepath.Join(dir, "glyphctl.old"),
	}
	if err := store.Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Channel != ChannelBeta {
		t.Fatalf("expected channel %q, got %q", ChannelBeta, loaded.Channel)
	}
	if loaded.LastAppliedVersion != cfg.LastAppliedVersion {
		t.Fatalf("expected last version %q, got %q", cfg.LastAppliedVersion, loaded.LastAppliedVersion)
	}
	if loaded.PreviousVersion != cfg.PreviousVersion {
		t.Fatalf("expected previous version %q, got %q", cfg.PreviousVersion, loaded.PreviousVersion)
	}
	if loaded.BackupPath != cfg.BackupPath {
		t.Fatalf("expected backup path %q, got %q", cfg.BackupPath, loaded.BackupPath)
	}
}

func TestNormalizeChannel(t *testing.T) {
	cases := map[string]string{
		"":       ChannelStable,
		"Stable": ChannelStable,
		"BETA":   ChannelBeta,
		"beta":   ChannelBeta,
		"stable": ChannelStable,
	}
	for input, want := range cases {
		got, err := NormalizeChannel(input)
		if err != nil {
			t.Fatalf("NormalizeChannel(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("NormalizeChannel(%q)=%q, want %q", input, got, want)
		}
	}
	if _, err := NormalizeChannel("nightly"); err == nil {
		t.Fatalf("expected error for unknown channel")
	}
}

func TestDefaultConfigDirOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("0XGEN_UPDATER_CONFIG_DIR", dir)
	got, err := DefaultConfigDir()
	if err != nil {
		t.Fatalf("DefaultConfigDir: %v", err)
	}
	if got != dir {
		t.Fatalf("DefaultConfigDir=%q, want %q", got, dir)
	}
}

func TestNewStoreCreatesDir(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "child")
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("expected %s to not exist before NewStore", dir)
	}
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if _, err := os.Stat(store.Dir()); err != nil {
		t.Fatalf("expected config dir to exist: %v", err)
	}
}
