package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

func captureWSLStdout(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	original := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	os.Stdout = w
	exitCode := fn()
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close pipe reader: %v", err)
	}
	os.Stdout = original
	return string(data), exitCode
}

func TestRunWSLPathToWindows(t *testing.T) {
	output, code := captureWSLStdout(t, func() int {
		return runWSLPath([]string{"--to-windows", "/mnt/c/Users/test"})
	})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if strings.TrimSpace(output) != "C:\\Users\\test" {
		t.Fatalf("unexpected output: %q", output)
	}
}

func TestRunWSLPathToWSL(t *testing.T) {
	output, code := captureWSLStdout(t, func() int {
		return runWSLPath([]string{"--to-wsl", "D:/Projects"})
	})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if strings.TrimSpace(output) != "/mnt/d/Projects" {
		t.Fatalf("unexpected output: %q", output)
	}
}

func TestRunWSLPathFlagValidation(t *testing.T) {
	if code := runWSLPath([]string{}); code != 2 {
		t.Fatalf("expected exit code 2 for missing flags, got %d", code)
	}
	if code := runWSLPath([]string{"--to-windows", "--to-wsl", "input"}); code != 2 {
		t.Fatalf("expected exit code 2 when both directions specified, got %d", code)
	}
	if code := runWSLPath([]string{"--to-windows"}); code != 2 {
		t.Fatalf("expected exit code 2 when path missing, got %d", code)
	}
}
