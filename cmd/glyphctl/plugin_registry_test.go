package main

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRunPluginRegistryMissingSubcommand(t *testing.T) {
	if code := runPluginRegistry(nil); code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestRunPluginRegistryPublish(t *testing.T) {
	var (
		invoked         bool
		receivedProgram string
		receivedArgs    []string
	)
	previous := runRegistryCommand
	runRegistryCommand = func(ctx context.Context, program string, args []string) error {
		invoked = true
		receivedProgram = program
		receivedArgs = append([]string(nil), args...)
		return nil
	}
	defer func() { runRegistryCommand = previous }()

	code := runPluginRegistry([]string{"publish", "--python", "python3", "--ref", "HEAD", "--repo-url", "https://example.com", "--", "--verbose"})
	if code != 0 {
		t.Fatalf("expected success exit code, got %d", code)
	}
	if !invoked {
		t.Fatalf("expected generator command to be invoked")
	}
	if receivedProgram != "python3" {
		t.Fatalf("expected python3 executable, got %s", receivedProgram)
	}
	expectedScript := filepath.Join("scripts", "update_plugin_catalog.py")
	if len(receivedArgs) == 0 || receivedArgs[0] != expectedScript {
		t.Fatalf("expected script path %s, got %v", expectedScript, receivedArgs)
	}
	if !reflect.DeepEqual(receivedArgs[1:], []string{"--ref", "HEAD", "--repo-url", "https://example.com", "--verbose"}) {
		t.Fatalf("unexpected arguments: %v", receivedArgs)
	}
}
