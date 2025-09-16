package e2e

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func TestGlyphdSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping glyphd smoke test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	root := repoRoot(t)

	binaryPath := buildGlyphd(ctx, t, root)

	listenAddr, dialAddr := resolveAddresses(t)

	cmdCtx, cmdCancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(cmdCtx, binaryPath, "--addr", listenAddr, "--token", "test")
	cmd.Dir = root
	cmd.Env = os.Environ()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start glyphd: %v", err)
	}

	done := make(chan struct{})
	var cmdErr error
	go func() {
		cmdErr = cmd.Wait()
		close(done)
	}()

	t.Cleanup(func() {
		cmdCancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatalf("glyphd did not exit after cancellation")
		}
	})

	if err := waitForListener(cmdCtx, dialAddr, done, func() error { return cmdErr }); err != nil {
		t.Fatalf("glyphd did not become ready: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
}

func buildGlyphd(ctx context.Context, t *testing.T, root string) string {
	t.Helper()

	binaryName := "glyphd"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}

	outputDir := t.TempDir()
	binaryPath := filepath.Join(outputDir, binaryName)

	var output bytes.Buffer
	cmd := exec.CommandContext(ctx, "go", "build", "-o", binaryPath, "./cmd/glyphd")
	cmd.Dir = root
	cmd.Stdout = &output
	cmd.Stderr = &output
	cmd.Env = os.Environ()

	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to build glyphd: %v\n%s", err, output.String())
	}

	return binaryPath
}

func resolveAddresses(t *testing.T) (string, string) {
	t.Helper()

	if addr := os.Getenv("GLYPH_E2E_ADDR"); addr != "" {
		return addr, dialAddress(addr)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to acquire ephemeral port: %v", err)
	}
	listenAddr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("failed to release ephemeral port: %v", err)
	}

	return listenAddr, dialAddress(listenAddr)
}

func dialAddress(listenAddr string) string {
	tcpAddr, err := net.ResolveTCPAddr("tcp", listenAddr)
	if err != nil {
		if len(listenAddr) > 0 && listenAddr[0] == ':' {
			return net.JoinHostPort("127.0.0.1", listenAddr[1:])
		}
		return listenAddr
	}

	hostIP := tcpAddr.IP
	if hostIP == nil || hostIP.IsUnspecified() {
		hostIP = net.IPv4(127, 0, 0, 1)
	}

	return net.JoinHostPort(hostIP.String(), strconv.Itoa(tcpAddr.Port))
}

func waitForListener(ctx context.Context, addr string, done <-chan struct{}, errFn func() error) error {
	dialer := &net.Dialer{Timeout: 200 * time.Millisecond}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for %s: %w", addr, ctx.Err())
		case <-done:
			exitErr := errFn()
			if exitErr == nil {
				return fmt.Errorf("glyphd exited before %s became available", addr)
			}
			return fmt.Errorf("glyphd exited before %s became available: %w", addr, exitErr)
		case <-ticker.C:
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()

	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("failed to determine repository root: %v", err)
	}
	return root
}
