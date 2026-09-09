package launcher

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"io"

	"github.com/RowanDark/0xgen/internal/env"
	"github.com/RowanDark/0xgen/internal/plugins"
	"github.com/RowanDark/0xgen/internal/plugins/integrity"
	"github.com/RowanDark/0xgen/internal/plugins/runner"
)

// Config captures the parameters required to execute a plugin against a 0xgend
// instance.
type Config struct {
	// ManifestPath points to the plugin manifest describing the executable
	// artifact.
	ManifestPath string
	// AllowlistPath points to the integrity allowlist file for verifying
	// plugin artifacts.
	AllowlistPath string
	// RepoRoot identifies the repository root used to resolve signature
	// metadata. Optional but recommended when manifests reference relative
	// paths outside their directory.
	RepoRoot string
	// SkipSignatureVerification disables the cosign signature check. This is
	// intended for development scenarios where sample plugins are unsigned.
	SkipSignatureVerification bool
	// ServerAddr is the gRPC endpoint for the 0xgend instance.
	ServerAddr string
	// AuthToken is the static authentication token required by 0xgend.
	AuthToken string
	// Duration bounds the wall clock execution time for the plugin. If zero
	// a conservative default is applied.
	Duration time.Duration
	// Stdout receives the plugin standard output stream.
	Stdout io.Writer
	// Stderr receives the plugin standard error stream.
	Stderr io.Writer
	// ExtraEnv propagates additional environment overrides for the plugin
	// process.
	ExtraEnv map[string]string
}

// Result captures the outcome of a plugin execution.
type Result struct {
	Manifest *plugins.Manifest
}

// Run builds and executes the plugin described by the manifest. It performs the
// same verification steps as the interactive CLI, ensuring artifacts are
// allowlisted and signed before invocation.
func Run(ctx context.Context, cfg Config) (Result, error) {
	if strings.TrimSpace(cfg.ManifestPath) == "" {
		return Result{}, errors.New("manifest path is required")
	}
	if strings.TrimSpace(cfg.ServerAddr) == "" {
		return Result{}, errors.New("server address is required")
	}
	if strings.TrimSpace(cfg.AuthToken) == "" {
		return Result{}, errors.New("auth token is required")
	}
	manifest, err := plugins.LoadManifest(cfg.ManifestPath)
	if err != nil {
		return Result{}, fmt.Errorf("load manifest: %w", err)
	}

	manifestDir := filepath.Dir(cfg.ManifestPath)

	repoRoot, err := determineRepoRoot(manifestDir, cfg.RepoRoot)
	if err != nil {
		return Result{}, err
	}

	artifactPath, err := resolveArtifactPath(manifest.Artifact, manifestDir, repoRoot)
	if err != nil {
		return Result{}, err
	}

	allowlistPath := strings.TrimSpace(cfg.AllowlistPath)
	if allowlistPath == "" {
		allowlistPath = findAllowlist(manifestDir)
	}
	if allowlistPath == "" {
		return Result{}, errors.New("allowlist path could not be determined")
	}
	allowlist, err := integrity.LoadAllowlist(allowlistPath)
	if err != nil {
		return Result{}, fmt.Errorf("load allowlist: %w", err)
	}
	if err := allowlist.Verify(artifactPath); err != nil {
		return Result{}, fmt.Errorf("artifact verification failed: %w", err)
	}

	skipSignature := cfg.SkipSignatureVerification
	if !skipSignature {
		if val, ok := env.Lookup("0XGEN_SKIP_SIGNATURE_VERIFY"); ok {
			lowered := strings.ToLower(strings.TrimSpace(val))
			skipSignature = lowered == "1" || lowered == "true" || lowered == "yes"
		}
	}
	if skipSignature && !manifest.Trusted {
		skipSignature = false
		if cfg.Stderr != nil {
			fmt.Fprintln(cfg.Stderr, "warning: signature verification enforced for untrusted plugin")
		}
	}

	if skipSignature {
		if cfg.Stderr != nil {
			fmt.Fprintln(cfg.Stderr, "warning: skipping signature verification")
		}
	} else {
		if err := integrity.VerifySignature(artifactPath, manifestDir, repoRoot, manifest.Signature); err != nil {
			return Result{}, fmt.Errorf("artifact signature verification failed: %w", err)
		}
	}

	binaryDir, err := os.MkdirTemp("", "0xgen-plugin-build-")
	if err != nil {
		return Result{}, fmt.Errorf("create build dir: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(binaryDir)
	}()
	binaryPath := filepath.Join(binaryDir, manifest.Entry)

	if err := buildGoBinary(manifestDir, ".", binaryPath, cfg.Stdout, cfg.Stderr); err != nil {
		return Result{}, fmt.Errorf("build plugin: %w", err)
	}

	sandboxPath := filepath.Join(binaryDir, "sandbox")
	if err := buildGoBinary(repoRoot, "./internal/plugins/runner/sandboxcmd", sandboxPath, cfg.Stdout, cfg.Stderr); err != nil {
		return Result{}, fmt.Errorf("build sandbox: %w", err)
	}

	capToken, err := requestCapabilityGrant(ctx, cfg.ServerAddr, cfg.AuthToken, manifest)
	if err != nil {
		return Result{}, err
	}

	limits := runner.Limits{
		CPUSeconds: 60,
		WallTime:   cfg.Duration,
	}
	if limits.WallTime <= 0 {
		limits.WallTime = 5 * time.Second
	}

	envVars := map[string]string{}
	for k, v := range cfg.ExtraEnv {
		envVars[k] = v
	}
	if val, ok := env.Lookup("0XGEN_OUT"); ok {
		if trimmed := strings.TrimSpace(val); trimmed != "" {
			envVars["0XGEN_OUT"] = trimmed
		}
	}
	if val, ok := env.Lookup("0XGEN_E2E_SMOKE"); ok {
		if trimmed := strings.TrimSpace(val); trimmed != "" {
			envVars["0XGEN_E2E_SMOKE"] = trimmed
		}
	}
	envVars["0XGEN_CAPABILITY_TOKEN"] = capToken

	runCfg := runner.Config{
		Binary:        binaryPath,
		SandboxBinary: sandboxPath,
		Args:          []string{"--server", cfg.ServerAddr, "--token", cfg.AuthToken},
		Env:           envVars,
		Stdout:        cfg.Stdout,
		Stderr:        cfg.Stderr,
		Limits:        limits,
	}

	if err := runner.Run(ctx, runCfg); err != nil {
		return Result{}, err
	}
	return Result{Manifest: manifest}, nil
}

// buildGoBinary compiles the Go package at pkg (relative to dir) into out
// with cgo disabled, then verifies the result is statically linked. Plugin
// and sandbox binaries run inside a chroot with no dynamic loader or libc
// staged into it, so a cgo-enabled build produces a binary that fails with
// an opaque ENOENT at execve time rather than a clear build error.
func buildGoBinary(dir, pkg, out string, stdout, stderr io.Writer) error {
	build := exec.Command("go", "build", "-o", out, pkg)
	build.Dir = dir
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	build.Stdout = stdout
	build.Stderr = stderr
	if err := build.Run(); err != nil {
		return err
	}
	return assertStaticBinary(out)
}

// assertStaticBinary verifies that the ELF binary at path has no PT_INTERP
// program header, i.e. it is statically linked and requires no dynamic
// loader. A dynamically linked plugin or sandbox binary produces an
// unreadable "exec: no such file or directory" error when launched inside
// the chroot, since the loader and libc are never staged there. This check
// only applies on Linux, where the sandbox uses a chroot; other platforms
// produce non-ELF binaries and are skipped.
func assertStaticBinary(path string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	f, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("inspect binary %q: %w", path, err)
	}
	defer f.Close()

	for _, prog := range f.Progs {
		if prog.Type == elf.PT_INTERP {
			return fmt.Errorf("binary %q is dynamically linked; rebuild with CGO_ENABLED=0 (cgo produces a dynamically linked binary that cannot run inside the sandbox chroot)", path)
		}
	}
	return nil
}

func findAllowlist(start string) string {
	dir := start
	for i := 0; i < 5; i++ {
		candidate := filepath.Join(dir, "ALLOWLIST")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

func resolveArtifactPath(artifact, manifestDir, repoRoot string) (string, error) {
	artifact = strings.TrimSpace(artifact)
	if artifact == "" {
		return "", errors.New("manifest does not declare an artifact")
	}
	if filepath.IsAbs(artifact) {
		return filepath.Clean(artifact), nil
	}

	candidates := []string{}
	if manifestDir != "" {
		candidates = append(candidates, filepath.Join(manifestDir, artifact))
	}
	trimmedRoot := strings.TrimSpace(repoRoot)
	if trimmedRoot != "" {
		candidates = append(candidates, filepath.Join(trimmedRoot, artifact))
	}
	cleaned := filepath.Clean(artifact)
	if cleaned != artifact {
		if manifestDir != "" {
			candidates = append(candidates, filepath.Join(manifestDir, cleaned))
		}
		if trimmedRoot != "" {
			candidates = append(candidates, filepath.Join(trimmedRoot, cleaned))
		}
	}
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("artifact %q could not be resolved", artifact)
}

func determineRepoRoot(manifestDir, hint string) (string, error) {
	trimmed := strings.TrimSpace(hint)
	if trimmed != "" {
		info, err := os.Stat(trimmed)
		if err == nil && info.IsDir() {
			if _, err := os.Stat(filepath.Join(trimmed, "go.mod")); err == nil {
				return trimmed, nil
			}
		}
	}

	dir := manifestDir
	for i := 0; i < 8; i++ {
		goMod := filepath.Join(dir, "go.mod")
		if info, err := os.Stat(goMod); err == nil && !info.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", errors.New("repository root could not be determined; set Config.RepoRoot")
}
