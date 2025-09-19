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
	"github.com/RowanDark/Glyph/internal/proxy"
	"github.com/RowanDark/Glyph/internal/reporter"
	pb "github.com/RowanDark/Glyph/proto/gen/go/proto/glyph"
	"google.golang.org/grpc"
)

type config struct {
	addr        string
	token       string
	proxy       proxy.Config
	enableProxy bool
}

func main() {
	addr := flag.String("addr", ":50051", "address for the gRPC server to listen on")
	token := flag.String("token", "", "authentication token required for plugins")
	proxyAddr := flag.String("proxy-addr", "", "address for the Galdr proxy listener (host:port)")
	proxyPort := flag.String("proxy-port", "8080", "DEPRECATED: preferred flag is --proxy-addr")
	proxyRules := flag.String("proxy-rules", "", "path to proxy modification rules file")
	proxyHistory := flag.String("proxy-history", "", "path to proxy history log")
	proxyCACert := flag.String("proxy-ca-cert", "", "path to proxy CA certificate")
	proxyCAKey := flag.String("proxy-ca-key", "", "path to proxy CA private key")
	enableProxy := flag.Bool("enable-proxy", false, "start Galdr proxy")
	flag.Parse()

	if *token == "" {
		fmt.Fprintln(os.Stderr, "--token must be provided")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := config{
		addr:  *addr,
		token: *token,
		proxy: proxy.Config{
			Addr:        selectProxyAddr(*proxyAddr, *proxyPort),
			RulesPath:   *proxyRules,
			HistoryPath: *proxyHistory,
			CACertPath:  *proxyCACert,
			CAKeyPath:   *proxyCAKey,
		},
		enableProxy: *enableProxy,
	}

	if err := run(ctx, cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func selectProxyAddr(addrFlag, portFlag string) string {
	addr := strings.TrimSpace(addrFlag)
	if addr != "" {
		return addr
	}
	return strings.TrimSpace(portFlag)
}

func run(ctx context.Context, cfg config) error {
	proxyEnabled := cfg.enableProxy || os.Getenv("GLYPH_ENABLE_PROXY") == "1"

	cancelProxy := func() {}
	var (
		proxyErrCh chan error
		proxySrv   *proxy.Proxy
	)

	if proxyEnabled {
		var err error
		proxySrv, err = proxy.New(cfg.proxy)
		if err != nil {
			return fmt.Errorf("initialise proxy: %w", err)
		}

		proxyCtx, proxyCancel := context.WithCancel(ctx)
		cancelProxy = proxyCancel

		proxyErrCh = make(chan error, 1)
		go func() {
			proxyErrCh <- proxySrv.Run(proxyCtx)
		}()

		readyCtx, readyCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer readyCancel()
		if err := proxySrv.WaitUntilReady(readyCtx); err != nil {
			cancelProxy()
			select {
			case errRun := <-proxyErrCh:
				if errRun != nil {
					log.Printf("proxy startup error: %v", errRun)
				}
			default:
			}
			return fmt.Errorf("start proxy: %w", err)
		}
	}

	lis, err := net.Listen("tcp", cfg.addr)
	if err != nil {
		cancelProxy()
		if proxyErrCh != nil {
			if errRun := <-proxyErrCh; errRun != nil {
				log.Printf("proxy terminated: %v", errRun)
			}
		}
		return fmt.Errorf("failed to listen on %s: %w", cfg.addr, err)
	}
	defer func() {
		if err := lis.Close(); err != nil {
			log.Printf("failed to close listener: %v", err)
		}
	}()

	serviceCtx, cancelService := context.WithCancel(ctx)
	defer cancelService()

	grpcErrCh := make(chan error, 1)
	go func() {
		grpcErrCh <- serve(serviceCtx, lis, cfg.token)
	}()

	select {
	case err := <-grpcErrCh:
		cancelProxy()
		if proxyErrCh != nil {
			if pErr := <-proxyErrCh; pErr != nil {
				log.Printf("proxy terminated: %v", pErr)
			}
		}
		return err
	case err := <-proxyErrCh:
		cancelService()
		cancelProxy()
		if err != nil {
			return fmt.Errorf("proxy failed: %w", err)
		}
		return <-grpcErrCh
	case <-ctx.Done():
		cancelService()
		cancelProxy()
		if proxyErrCh != nil {
			if pErr := <-proxyErrCh; pErr != nil {
				log.Printf("proxy terminated: %v", pErr)
			}
		}
		return ctx.Err()
	}
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
