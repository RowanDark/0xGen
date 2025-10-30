package runner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRunTimeoutKillsProcess(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	source := filepath.Join(dir, "main.go")
	program := "package main\nimport \"time\"\nfunc main(){for {time.Sleep(time.Second)}}"
	if err := os.WriteFile(source, []byte(program), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	binary := executablePath(dir, "sleepy")
	build := exec.Command("go", "build", "-o", binary, source)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build binary: %v\noutput: %s", err, out)
	}

	sandbox := executablePath(dir, "sandbox")
	sandboxBuild := exec.Command("go", "build", "-o", sandbox, "./sandboxcmd")
	sandboxBuild.Dir = "."
	if out, err := sandboxBuild.CombinedOutput(); err != nil {
		t.Fatalf("build sandbox: %v\noutput: %s", err, out)
	}

	err := Run(ctx, Config{Binary: binary, SandboxBinary: sandbox, Limits: Limits{WallTime: 200 * time.Millisecond}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
}

func TestBuildEnvStripsHostVariables(t *testing.T) {
	t.Setenv("0XGEN_SECRET", "classified")
	envCfg := sandboxEnv{Path: "/bin", Home: "/home/plugin", Tmp: "/tmp"}
	env := buildEnv(envCfg, map[string]string{"EXTRA": "1"})
	for _, entry := range env {
		if strings.HasPrefix(entry, "0XGEN_SECRET=") {
			t.Fatalf("host environment leaked into plugin env: %q", entry)
		}
	}
	var pathSeen, homeSeen bool
	for _, entry := range env {
		switch {
		case strings.HasPrefix(entry, "PATH="):
			pathSeen = true
		case strings.HasPrefix(entry, "HOME="):
			homeSeen = true
		}
	}
	if !pathSeen {
		t.Fatal("expected PATH to be present in plugin env")
	}
	if !homeSeen {
		t.Fatal("expected HOME to be present in plugin env")
	}
}

func TestBuildEnvUsesSandboxDirectories(t *testing.T) {
	envCfg := sandboxEnv{Path: "/bin", Home: "/sandbox/home", Tmp: "/sandbox/tmp"}
	env := buildEnv(envCfg, map[string]string{"CUSTOM": "value"})

	envMap := make(map[string]string, len(env))
	for _, entry := range env {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			t.Fatalf("unexpected environment entry: %q", entry)
		}
		envMap[parts[0]] = parts[1]
	}

	if got := envMap["HOME"]; got != envCfg.Home {
		t.Fatalf("HOME = %q, want sandbox directory %q", got, envCfg.Home)
	}
	if got := envMap["TMPDIR"]; got != envCfg.Tmp {
		t.Fatalf("TMPDIR = %q, want sandbox directory %q", got, envCfg.Tmp)
	}
	if runtime.GOOS == "windows" {
		if got := envMap["TEMP"]; got != envCfg.Tmp {
			t.Fatalf("TEMP = %q, want sandbox directory %q", got, envCfg.Tmp)
		}
		if got := envMap["TMP"]; got != envCfg.Tmp {
			t.Fatalf("TMP = %q, want sandbox directory %q", got, envCfg.Tmp)
		}
	}
	if got := envMap["CUSTOM"]; got != "value" {
		t.Fatalf("expected custom environment override, got %q", got)
	}
	for key := range envMap {
		if strings.HasPrefix(key, "0XGEN_") {
			t.Fatalf("unexpected host environment variable leaked: %s", key)
		}
	}
}
