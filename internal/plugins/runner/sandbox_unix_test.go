//go:build !windows

package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// rootCheckSubprocessEnv, when set to "1", tells this test binary to run as
// the subprocess side of TestCreateSandboxCommandRequiresRoot rather than as
// the top-level test.
const rootCheckSubprocessEnv = "0XGEN_TEST_SANDBOX_ROOT_CHECK_SUBPROCESS"

// TestCreateSandboxCommandRequiresRoot verifies that a non-root caller gets
// a clear, actionable error instead of chroot/chown failing deep inside
// createSandboxCommand (or cmd.Start() failing later with a raw EPERM).
func TestCreateSandboxCommandRequiresRoot(t *testing.T) {
	if os.Getenv(rootCheckSubprocessEnv) == "1" {
		if err := syscall.Seteuid(sandboxUserID); err != nil {
			fmt.Fprintf(os.Stderr, "seteuid: %v\n", err)
			os.Exit(2)
		}
		_, _, _, err := createSandboxCommand(context.Background(), Config{Binary: "/bin/true", SandboxBinary: "/bin/true"})
		if err == nil {
			fmt.Fprintln(os.Stderr, "expected an error when not running as root")
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, err.Error())
		os.Exit(0)
	}

	if os.Geteuid() != 0 {
		t.Skip("test needs to start as root in order to drop to a non-root euid")
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestCreateSandboxCommandRequiresRoot$")
	cmd.Env = append(os.Environ(), rootCheckSubprocessEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed: %v output=%s", err, out)
	}
	if !strings.Contains(string(out), "requires the 0xgen daemon to run as root") {
		t.Fatalf("expected a clear root-requirement error, got: %s", out)
	}
}

func TestCreateSandboxCommandTmpDirIsPrivate(t *testing.T) {
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

	tmpDir := filepath.Join(cmd.SysProcAttr.Chroot, "tmp")
	info, err := os.Stat(tmpDir)
	if err != nil {
		t.Fatalf("stat %s: %v", tmpDir, err)
	}
	// tmpDir used to be created 0o777 (world-writable), letting any other
	// process sharing the sandbox uid read or tamper with a plugin's temp
	// files. It must now be private to the sandbox user.
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("tmp dir perm = %o, want 0700", perm)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("unexpected stat type for %s", tmpDir)
	}
	if stat.Uid != sandboxUserID || stat.Gid != sandboxGroupID {
		t.Fatalf("tmp dir owner = %d:%d, want %d:%d", stat.Uid, stat.Gid, sandboxUserID, sandboxGroupID)
	}
}

func TestCreateSandboxCommandStagesDeviceNodes(t *testing.T) {
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
	for _, name := range []string{"null", "urandom"} {
		path := filepath.Join(root, "dev", name)
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("stat /dev/%s: %v", name, err)
		}
		if info.Mode()&os.ModeCharDevice == 0 {
			t.Fatalf("/dev/%s is not a character device: mode=%v", name, info.Mode())
		}
	}
}

func TestCreateSandboxCommandStagesNetworkFiles(t *testing.T) {
	if _, err := os.Stat("/etc/resolv.conf"); err != nil {
		t.Skip("host has no /etc/resolv.conf to stage")
	}

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
	want, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		t.Fatalf("read host resolv.conf: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(root, "etc", "resolv.conf"))
	if err != nil {
		t.Fatalf("read staged resolv.conf: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("staged resolv.conf does not match host copy")
	}
}
