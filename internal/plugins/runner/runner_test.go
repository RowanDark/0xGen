package runner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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
	binary := filepath.Join(dir, "sleepy")
	build := exec.Command("go", "build", "-o", binary, source)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build binary: %v\noutput: %s", err, out)
	}

	err := Run(ctx, Config{Binary: binary, Limits: Limits{WallTime: 200 * time.Millisecond}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
}
