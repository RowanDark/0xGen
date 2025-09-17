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
	"sync"
	"syscall"
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
	defer os.RemoveAll(tmpDir)

	cmd := exec.CommandContext(wallCtx, cfg.Binary, cfg.Args...)
	cmd.Dir = tmpDir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

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

var limitMu sync.Mutex

func startWithLimits(cmd *exec.Cmd, lim Limits) error {
	limitMu.Lock()
	defer limitMu.Unlock()

	var (
		cpuOrig syscall.Rlimit
		memOrig syscall.Rlimit
		cpuSet  bool
		memSet  bool
	)

	if lim.CPUSeconds > 0 {
		if err := syscall.Getrlimit(syscall.RLIMIT_CPU, &cpuOrig); err != nil {
			return fmt.Errorf("get cpu limit: %w", err)
		}
		newLimit := syscall.Rlimit{Cur: lim.CPUSeconds, Max: lim.CPUSeconds}
		if err := syscall.Setrlimit(syscall.RLIMIT_CPU, &newLimit); err != nil {
			return fmt.Errorf("set cpu limit: %w", err)
		}
		cpuSet = true
	}

	if lim.MemoryBytes > 0 {
		if err := syscall.Getrlimit(syscall.RLIMIT_AS, &memOrig); err != nil {
			return fmt.Errorf("get memory limit: %w", err)
		}
		newLimit := syscall.Rlimit{Cur: lim.MemoryBytes, Max: lim.MemoryBytes}
		if err := syscall.Setrlimit(syscall.RLIMIT_AS, &newLimit); err != nil {
			return fmt.Errorf("set memory limit: %w", err)
		}
		memSet = true
	}

	startErr := cmd.Start()

	if cpuSet {
		_ = syscall.Setrlimit(syscall.RLIMIT_CPU, &cpuOrig)
	}
	if memSet {
		_ = syscall.Setrlimit(syscall.RLIMIT_AS, &memOrig)
	}

	return startErr
}

func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	pid := cmd.Process.Pid
	if runtime.GOOS == "windows" {
		_ = cmd.Process.Kill()
		return
	}
	// Negative PID targets the process group.
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}
