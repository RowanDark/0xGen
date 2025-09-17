package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/Glyph/internal/bus"
	"github.com/RowanDark/Glyph/internal/findings"
	pb "github.com/RowanDark/Glyph/proto/gen/go/proto/glyph"
	"google.golang.org/grpc"
)

func TestSampleEmitsFinding(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	findingsBus := findings.NewBus()
	server := bus.NewServer("test-token", findingsBus)
	grpcServer := grpc.NewServer()
	pb.RegisterPluginBusServer(grpcServer, server)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() {
		_ = lis.Close()
	})

	go func() {
		if err := grpcServer.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Logf("grpc server error: %v", err)
		}
	}()
	t.Cleanup(func() {
		grpcServer.GracefulStop()
	})

	go server.StartEventGenerator(ctx)

	findingsCh := findingsBus.Subscribe(ctx)

	cmdCtx, cmdCancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cmdCancel()

	var stdout, stderr bytes.Buffer
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	binDir := t.TempDir()
	binaryPath := filepath.Join(binDir, "passive-header-scan")
	buildCmd := exec.CommandContext(cmdCtx, "go", "build", "-o", binaryPath, ".")
	buildCmd.Dir = wd
	var buildOutput bytes.Buffer
	buildCmd.Stdout = &buildOutput
	buildCmd.Stderr = &buildOutput
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("build plugin: %v\noutput: %s", err, buildOutput.String())
	}

	cmd := exec.CommandContext(cmdCtx, binaryPath, "--server", lis.Addr().String(), "--token", "test-token")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start plugin: %v", err)
	}

	var finding findings.Finding
	select {
	case finding = <-findingsCh:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for finding\nstdout: %s\nstderr: %s", stdout.String(), stderr.String())
	}

	if finding.ID == "" {
		t.Fatal("expected finding id to be populated")
	}
	if finding.Type != "missing-security-header" {
		t.Fatalf("unexpected finding type: %s", finding.Type)
	}
	if finding.Severity != findings.SeverityMedium {
		t.Fatalf("unexpected severity: %s", finding.Severity)
	}
	if finding.DetectedAt.IsZero() {
		t.Fatal("expected detected_at to be set")
	}
	if !strings.HasPrefix(finding.Plugin, "passive-header-scan-") {
		t.Fatalf("unexpected plugin id: %s", finding.Plugin)
	}

	if cmd.Process != nil {
		_ = cmd.Process.Signal(os.Interrupt)
	}

	if err := cmd.Wait(); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "signal: killed") && !strings.Contains(err.Error(), "signal: interrupt") {
		t.Fatalf("plugin exit: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
}
