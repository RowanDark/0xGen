//go:build !windows

package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	sandboxUserID  = 65534
	sandboxGroupID = 65534
)

func createSandboxCommand(ctx context.Context, cfg Config) (*exec.Cmd, sandboxEnv, func(), error) {
	if strings.TrimSpace(cfg.SandboxBinary) == "" {
		return nil, sandboxEnv{}, nil, errors.New("sandbox binary is required")
	}

	root, err := os.MkdirTemp("", "0xgen-sandbox-")
	if err != nil {
		return nil, sandboxEnv{}, nil, fmt.Errorf("create sandbox root: %w", err)
	}
	cleanup := func() {
		_ = os.RemoveAll(root)
	}

	if err := os.Chmod(root, 0o755); err != nil {
		cleanup()
		return nil, sandboxEnv{}, nil, fmt.Errorf("configure sandbox root permissions: %w", err)
	}

	binDir := filepath.Join(root, "bin")
	homeDir := filepath.Join(root, "home", "plugin")
	workDir := filepath.Join(root, "workspace")
	tmpDir := filepath.Join(root, "tmp")
	for _, dir := range []struct {
		path  string
		perm  os.FileMode
		chown bool
	}{
		{binDir, 0o755, false},
		{homeDir, 0o755, true},
		{workDir, 0o755, true},
	} {
		if err := os.MkdirAll(dir.path, dir.perm); err != nil {
			cleanup()
			return nil, sandboxEnv{}, nil, fmt.Errorf("create sandbox dir %q: %w", dir.path, err)
		}
		if dir.chown {
			if err := os.Chown(dir.path, sandboxUserID, sandboxGroupID); err != nil {
				cleanup()
				return nil, sandboxEnv{}, nil, fmt.Errorf("set sandbox dir ownership %q: %w", dir.path, err)
			}
		}
	}
	if err := os.MkdirAll(tmpDir, 0o777); err != nil {
		cleanup()
		return nil, sandboxEnv{}, nil, fmt.Errorf("create sandbox tmp dir: %w", err)
	}

	pluginDst := filepath.Join(binDir, "plugin")
	if err := copyExecutable(cfg.Binary, pluginDst, 0o755); err != nil {
		cleanup()
		return nil, sandboxEnv{}, nil, fmt.Errorf("stage plugin binary: %w", err)
	}
	sandboxDst := filepath.Join(binDir, "sandbox")
	if err := copyExecutable(cfg.SandboxBinary, sandboxDst, 0o755); err != nil {
		cleanup()
		return nil, sandboxEnv{}, nil, fmt.Errorf("stage sandbox binary: %w", err)
	}

	args := append([]string{"/bin/plugin"}, cfg.Args...)
	cmd := exec.CommandContext(ctx, "/bin/sandbox", args...)
	cmd.Dir = "/workspace"
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Chroot:  root,
		Setpgid: true,
	}

	env := sandboxEnv{
		Path: "/bin",
		Home: "/home/plugin",
		Tmp:  "/tmp",
	}

	return cmd, env, cleanup, nil
}
