//go:build !windows

package runner

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestCreateSandboxCommandDirectoryOwnership(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	plugin := filepath.Join(dir, "plugin.sh")
	if err := os.WriteFile(plugin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write plugin stub: %v", err)
	}
	sandbox := filepath.Join(dir, "sandbox.sh")
	if err := os.WriteFile(sandbox, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write sandbox stub: %v", err)
	}

	cmd, _, cleanup, err := createSandboxCommand(ctx, Config{Binary: plugin, SandboxBinary: sandbox})
	if err != nil {
		t.Fatalf("create sandbox command: %v", err)
	}
	t.Cleanup(cleanup)

	root := cmd.SysProcAttr.Chroot
	if root == "" {
		t.Fatal("expected sandbox root to be configured")
	}

	check := func(path string) {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatalf("unexpected stat type for %s", path)
		}
		if stat.Uid != sandboxUserID {
			t.Fatalf("%s uid = %d, want %d", path, stat.Uid, sandboxUserID)
		}
		if stat.Gid != sandboxGroupID {
			t.Fatalf("%s gid = %d, want %d", path, stat.Gid, sandboxGroupID)
		}
		if info.Mode().Perm()&0o200 == 0 {
			t.Fatalf("%s is not writable by owner", path)
		}
	}

	check(filepath.Join(root, "home", "plugin"))
	check(filepath.Join(root, "workspace"))
}
