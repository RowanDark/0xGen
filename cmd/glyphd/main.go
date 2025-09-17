package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/RowanDark/Glyph/internal/bus"
	"github.com/RowanDark/Glyph/internal/findings"
	"github.com/RowanDark/Glyph/internal/reporter"
	pb "github.com/RowanDark/Glyph/proto/gen/go/proto/glyph"
	"google.golang.org/grpc"
)

type config struct {
	addr  string
	token string
}

func main() {
	addr := flag.String("addr", ":50051", "address for the gRPC server to listen on")
	token := flag.String("token", "", "authentication token required for plugins")
	flag.Parse()

	if *token == "" {
		fmt.Fprintln(os.Stderr, "--token must be provided")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, config{addr: *addr, token: *token}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg config) error {
	lis, err := net.Listen("tcp", cfg.addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", cfg.addr, err)
	}
	defer func() {
		if err := lis.Close(); err != nil {
			log.Printf("failed to close listener: %v", err)
		}
	}()

	return serve(ctx, lis, cfg.token)
}

func serve(ctx context.Context, lis net.Listener, token string) error {
	if token == "" {
		return errors.New("auth token must be provided")
	}

	findingsBus := findings.NewBus()
	findingsPath := resolveFindingsPath()
	log.Printf("writing findings to %s", findingsPath)
	jsonlWriter := reporter.NewJSONL(findingsPath)
	findingsCh := findingsBus.Subscribe(ctx)
	go func() {
		for finding := range findingsCh {
			if err := jsonlWriter.Write(finding); err != nil {
				log.Printf("failed to persist finding: %v", err)
			}
		}
	}()

	srv := grpc.NewServer()
	busServer := bus.NewServer(token, findingsBus)
	pb.RegisterPluginBusServer(srv, busServer)

	// Create a background context used by the event generator. It is cancelled
	// once the gRPC server begins shutting down.
	generatorCtx, cancelGenerator := context.WithCancel(context.Background())
	defer cancelGenerator()
	go busServer.StartEventGenerator(generatorCtx)

	// Stop the gRPC server once the provided context is cancelled.
	go func() {
		<-ctx.Done()
		cancelGenerator()

		done := make(chan struct{})
		go func() {
			srv.GracefulStop()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			srv.Stop()
		}
	}()

	if err := srv.Serve(lis); err != nil {
		if errors.Is(err, grpc.ErrServerStopped) {
			return nil
		}
		return err
	}
	return nil
}

func resolveFindingsPath() string {
	if custom := strings.TrimSpace(os.Getenv("GLYPH_OUT")); custom != "" {
		return filepath.Join(custom, "findings.jsonl")
	}
	return reporter.DefaultFindingsPath
}
