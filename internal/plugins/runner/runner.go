package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Limits configures the sandbox applied to plugin subprocesses.
type Limits struct {
	CPUSeconds  uint64
	MemoryBytes uint64
	WallTime    time.Duration
}

// Config describes a plugin invocation.
type Config struct {
	Binary string
	Args   []string
	Env    map[string]string
	Stdout io.Writer
	Stderr io.Writer
	Limits Limits
}

// Run executes the plugin binary with the provided configuration. The caller
// should supply a cancellable context to terminate the plugin early.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Binary == "" {
		return errors.New("binary path is required")
	}

	if ctx == nil {
		ctx = context.Background()
	}

	wallCtx := ctx
	var cancel context.CancelFunc
	if cfg.Limits.WallTime > 0 {
		wallCtx, cancel = context.WithTimeout(ctx, cfg.Limits.WallTime)
		defer cancel()
	}

	tmpDir, err := os.MkdirTemp("", "glyph-plugin-")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	cmd := exec.CommandContext(wallCtx, cfg.Binary, cfg.Args...)
	cmd.Dir = tmpDir
	configureSysProc(cmd)

	if cfg.Stdout != nil {
		cmd.Stdout = cfg.Stdout
	}
	if cfg.Stderr != nil {
		cmd.Stderr = cfg.Stderr
	}

	cmd.Env = buildEnv(tmpDir, cfg.Env)

	if err := startWithLimits(cmd, cfg.Limits); err != nil {
		return err
	}

	result := make(chan error, 1)
	go func() {
		result <- cmd.Wait()
	}()

	select {
	case err := <-result:
		return err
	case <-wallCtx.Done():
		killProcessGroup(cmd)
		<-result
		return wallCtx.Err()
	}
}

func buildEnv(workDir string, overrides map[string]string) []string {
	base := map[string]string{
		"PATH":   os.Getenv("PATH"),
		"HOME":   workDir,
		"TMPDIR": workDir,
	}
	if runtime.GOOS == "windows" {
		base["TEMP"] = workDir
		base["TMP"] = workDir
	}
	for k, v := range overrides {
		base[k] = v
	}
	env := make([]string, 0, len(base))
	for k, v := range base {
		if strings.TrimSpace(k) == "" {
			continue
		}
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	return env
}
