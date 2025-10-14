package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/bus"
	"github.com/RowanDark/0xgen/internal/findings"
	pb "github.com/RowanDark/0xgen/proto/gen/go/proto/glyph"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type expectedFinding struct {
	Type     string `json:"type"`
	Message  string `json:"message"`
	Target   string `json:"target"`
	Severity string `json:"severity"`
}

func TestExampleHelloEmitsFinding(t *testing.T) {
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

	binaryPath := filepath.Join(t.TempDir(), "example-hello")
	buildCmd := exec.CommandContext(cmdCtx, "go", "build", "-o", binaryPath, ".")
	buildCmd.Dir = wd
	var buildOutput bytes.Buffer
	buildCmd.Stdout = &buildOutput
	buildCmd.Stderr = &buildOutput
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("build plugin: %v\noutput: %s", err, buildOutput.String())
	}

	conn, err := grpc.DialContext(ctx, lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})
	grantCtx, grantCancel := context.WithTimeout(ctx, 5*time.Second)
	defer grantCancel()
	grant, err := pb.NewPluginBusClient(conn).GrantCapabilities(grantCtx, &pb.PluginCapabilityRequest{
		AuthToken:    "test-token",
		PluginName:   "example-hello",
		Capabilities: []string{"CAP_EMIT_FINDINGS"},
	})
	if err != nil {
		t.Fatalf("grant capabilities: %v", err)
	}
	token := strings.TrimSpace(grant.GetCapabilityToken())
	if token == "" {
		t.Fatal("expected capability token")
	}

	cmd := exec.CommandContext(cmdCtx, binaryPath, "--server", lis.Addr().String(), "--token", "test-token")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = append(os.Environ(), "GLYPH_CAPABILITY_TOKEN="+token)

	if err := cmd.Start(); err != nil {
		t.Fatalf("start plugin: %v", err)
	}

	var finding findings.Finding
	select {
	case finding = <-findingsCh:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for finding\nstdout: %s\nstderr: %s", stdout.String(), stderr.String())
	}

	data, err := os.ReadFile(filepath.Join("testdata", "expected_finding.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var expected expectedFinding
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	if finding.ID == "" {
		t.Fatal("expected finding id to be populated")
	}
	if finding.Version != findings.SchemaVersion {
		t.Fatalf("unexpected schema version: %s", finding.Version)
	}
	if finding.Type != expected.Type {
		t.Fatalf("unexpected finding type: %s", finding.Type)
	}
	if finding.Message != expected.Message {
		t.Fatalf("unexpected finding message: %s", finding.Message)
	}
	if finding.Target != expected.Target {
		t.Fatalf("unexpected finding target: %s", finding.Target)
	}
	if string(finding.Severity) != expected.Severity {
		t.Fatalf("unexpected severity: %s", finding.Severity)
	}
	if finding.DetectedAt.IsZero() {
		t.Fatal("expected detected_at timestamp to be set")
	}
	if !strings.HasPrefix(finding.Plugin, "example-hello-") {
		t.Fatalf("unexpected plugin id: %s", finding.Plugin)
	}
	if finding.Metadata["example"] != "true" {
		t.Fatalf("missing metadata entry: %v", finding.Metadata)
	}

	if cmd.Process != nil {
		_ = cmd.Process.Signal(os.Interrupt)
	}

	if err := cmd.Wait(); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "signal: killed") && !strings.Contains(err.Error(), "signal: interrupt") {
		t.Fatalf("plugin exit: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
}
