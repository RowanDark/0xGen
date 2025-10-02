package runner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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

	err := Run(ctx, Config{Binary: binary, Limits: Limits{WallTime: 200 * time.Millisecond}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
}

func TestBuildEnvStripsHostVariables(t *testing.T) {
	t.Setenv("GLYPH_SECRET", "classified")
	workDir := t.TempDir()
	env := buildEnv(workDir, map[string]string{"EXTRA": "1"})
	for _, entry := range env {
		if strings.HasPrefix(entry, "GLYPH_SECRET=") {
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
