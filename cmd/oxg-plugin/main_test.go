package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestScaffoldGoProject(t *testing.T) {
	tmp := t.TempDir()
	projectDir := filepath.Join(tmp, "demo-plugin")

	if err := scaffoldGo(projectDir, "example.com/demo-plugin"); err != nil {
		t.Fatalf("scaffoldGo: %v", err)
	}

	goModPath := filepath.Join(projectDir, "go.mod")
	data, err := os.ReadFile(goModPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Contains(data, []byte("module example.com/demo-plugin")) {
		t.Fatalf("go.mod missing module declaration: %s", data)
	}

	if _, err := os.Stat(filepath.Join(projectDir, "go.sum")); err != nil {
		t.Fatalf("go.sum missing: %v", err)
	}
}
