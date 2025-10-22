package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunPluginVerifyMatch(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.bin")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	hash := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if code := runPluginVerify([]string{"--hash", hash, path}); code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
}

func TestRunPluginVerifyMismatch(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.bin")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	if code := runPluginVerify([]string{"--hash", "deadbeef", path}); code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestRunPluginVerifyMissingArgs(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	if code := runPluginVerify([]string{}); code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}
