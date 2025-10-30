//go:build windows

package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func createSandboxCommand(ctx context.Context, cfg Config) (*exec.Cmd, sandboxEnv, func(), error) {
	tmpDir, err := os.MkdirTemp("", "0xgen-plugin-")
	if err != nil {
		return nil, sandboxEnv{}, nil, fmt.Errorf("create temp dir: %w", err)
	}
	cleanup := func() {
		_ = os.RemoveAll(tmpDir)
	}

	cmd := exec.CommandContext(ctx, cfg.Binary, cfg.Args...)
	cmd.Dir = tmpDir

	env := sandboxEnv{
		Path: os.Getenv("PATH"),
		Home: tmpDir,
		Tmp:  filepath.Clean(tmpDir),
	}

	return cmd, env, cleanup, nil
}
