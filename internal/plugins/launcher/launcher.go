package launcher

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	artifactPath, err := resolveArtifactPath(manifest.Artifact, manifestDir, cfg.RepoRoot)
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
        if skipSignature {
                if cfg.Stderr != nil {
                        fmt.Fprintln(cfg.Stderr, "warning: skipping signature verification")
                }
        } else {
                if err := integrity.VerifySignature(artifactPath, manifestDir, cfg.RepoRoot, manifest.Signature); err != nil {
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

	build := exec.Command("go", "build", "-o", binaryPath, ".")
	build.Dir = manifestDir
	build.Stdout = cfg.Stdout
	build.Stderr = cfg.Stderr
	if err := build.Run(); err != nil {
		return Result{}, fmt.Errorf("build plugin: %w", err)
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
		Binary: binaryPath,
		Args:   []string{"--server", cfg.ServerAddr, "--token", cfg.AuthToken},
		Env:    envVars,
		Stdout: cfg.Stdout,
		Stderr: cfg.Stderr,
		Limits: limits,
	}

	if err := runner.Run(ctx, runCfg); err != nil {
		return Result{}, err
	}
	return Result{Manifest: manifest}, nil
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
