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

	"github.com/RowanDark/0xgen/internal/observability/tracing"
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

	spanAttrs := map[string]any{
		"glyph.runner.binary":  cfg.Binary,
		"glyph.runner.arg_len": len(cfg.Args),
	}
	if cfg.Limits.CPUSeconds > 0 {
		spanAttrs["glyph.runner.cpu_seconds"] = cfg.Limits.CPUSeconds
	}
	if cfg.Limits.MemoryBytes > 0 {
		spanAttrs["glyph.runner.memory_bytes"] = cfg.Limits.MemoryBytes
	}
	if cfg.Limits.WallTime > 0 {
		spanAttrs["glyph.runner.wall_time"] = cfg.Limits.WallTime.String()
	}
	spanCtx, span := tracing.StartSpan(ctx, "plugin.runner.exec", tracing.WithSpanKind(tracing.SpanKindInternal), tracing.WithAttributes(spanAttrs))
	status := tracing.StatusOK
	statusMsg := ""
	defer func() {
		if span == nil {
			return
		}
		span.EndWithStatus(status, statusMsg)
	}()
	ctx = spanCtx

	wallCtx := ctx
	var cancel context.CancelFunc
	if cfg.Limits.WallTime > 0 {
		wallCtx, cancel = context.WithTimeout(ctx, cfg.Limits.WallTime)
		defer cancel()
	}

	tmpDir, err := os.MkdirTemp("", "glyph-plugin-")
	if err != nil {
		span.RecordError(err)
		status = tracing.StatusError
		statusMsg = "create temp dir"
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
		span.RecordError(err)
		status = tracing.StatusError
		statusMsg = "start plugin"
		return err
	}

	result := make(chan error, 1)
	go func() {
		result <- cmd.Wait()
	}()

	select {
	case err := <-result:
		if err != nil {
			span.RecordError(err)
			status = tracing.StatusError
			statusMsg = "plugin exit"
		}
		return err
	case <-wallCtx.Done():
		killProcessGroup(cmd)
		<-result
		err := wallCtx.Err()
		if err != nil {
			span.RecordError(err)
			status = tracing.StatusError
			statusMsg = "wall timeout"
		}
		return err
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
