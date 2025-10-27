package main

import (
        "context"
        "io"
        "net"
        "testing"
        "time"

        "github.com/RowanDark/0xgen/internal/findings"
        "github.com/RowanDark/0xgen/internal/logging"
        "google.golang.org/grpc"
        "google.golang.org/grpc/connectivity"
        "google.golang.org/grpc/credentials/insecure"
)

func TestServeBootsAndShutsDown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	coreLogger, err := logging.NewAuditLogger("0xgend_test", logging.WithoutStdout(), logging.WithWriter(io.Discard))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	busLogger, err := logging.NewAuditLogger("plugin_bus_test", logging.WithoutStdout(), logging.WithWriter(io.Discard))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

        errCh := make(chan error, 1)
        publisher := newBusFlowPublisher()
        findingsBus := findings.NewBus()
        go func() {
                errCh <- serve(ctx, lis, "test-token", coreLogger, busLogger, false, "", "auto", publisher, findingsBus)
        }()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to create gRPC client: %v", err)
	}
	conn.Connect()
	for {
		state := conn.GetState()
		if state == connectivity.Ready {
			break
		}
		if !conn.WaitForStateChange(dialCtx, state) {
			t.Fatalf("gRPC connection did not become ready: %v", dialCtx.Err())
		}
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("failed to close client connection: %v", err)
	}

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("serve returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shut down after context cancellation")
	}
}
