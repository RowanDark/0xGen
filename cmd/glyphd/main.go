package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/RowanDark/Glyph/internal/bus"
	"github.com/RowanDark/Glyph/internal/findings"
	"github.com/RowanDark/Glyph/internal/logging"
	"github.com/RowanDark/Glyph/internal/netgate"
	"github.com/RowanDark/Glyph/internal/netgate/fingerprint"
	obsmetrics "github.com/RowanDark/Glyph/internal/observability/metrics"
	"github.com/RowanDark/Glyph/internal/observability/tracing"
	"github.com/RowanDark/Glyph/internal/plugins/hotreload"
	"github.com/RowanDark/Glyph/internal/proxy"
	"github.com/RowanDark/Glyph/internal/reporter"
	"github.com/RowanDark/Glyph/internal/scope"
	"github.com/RowanDark/Glyph/internal/secrets"
	pb "github.com/RowanDark/Glyph/proto/gen/go/proto/glyph"
	"google.golang.org/grpc"
)

type config struct {
	addr              string
	token             string
	metricsAddr       string
	proxy             proxy.Config
	enableProxy       bool
	fingerprintRotate bool
	pluginsDir        string
	http3Mode         string
	tracing           tracing.Config
	traceHeaders      string
	scopePolicyPath   string
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
	proxyFlowEnabled := flag.Bool("proxy-flow-enabled", true, "enable publishing intercepted flows to plugins")
	proxyFlowSample := flag.Float64("proxy-flow-sample", 1.0, "DEPRECATED: use --flow-sample-rate")
	proxyFlowMaxBody := flag.Int("proxy-flow-max-body", 131072, "DEPRECATED: use --max-body-kb (value in bytes)")
	flowSampleRate := flag.Float64("flow-sample-rate", 1.0, "sampling ratio for intercepted flows (0-1)")
	maxBodyKB := flag.Int("max-body-kb", 128, "maximum raw body kilobytes to include in flow events (-1 disables raw bodies)")
	proxyFlowSeed := flag.Int64("proxy-flow-seed", 0, "seed used to deterministically order flow identifiers (default random)")
	proxyFlowLog := flag.String("proxy-flow-log", "", "path to write sanitized flow transcripts for replay (defaults next to proxy history)")
	scopePolicy := flag.String("scope-policy", "", "path to YAML scope policy used to suppress out-of-scope flows")
	fingerprintRotate := flag.Bool("fingerprint-rotate", false, "enable rotating JA3/JA4 fingerprints per host")
	pluginDir := flag.String("plugins-dir", "plugins", "path to plugin directory")
	metricsAddr := flag.String("metrics-addr", ":9090", "address for the Prometheus metrics endpoint (empty to disable)")
	http3Mode := flag.String("http3", "auto", "HTTP/3 mode: auto, disable, or require")
	traceEndpoint := flag.String("trace-endpoint", "", "OTLP/HTTP endpoint for exported spans (http(s)://host:port/v1/traces)")
	traceInsecure := flag.Bool("trace-insecure-skip-verify", false, "disable TLS verification when exporting spans")
	traceSample := flag.Float64("trace-sample-ratio", 0.25, "probabilistic sampling ratio for root spans (0-1)")
	traceService := flag.String("trace-service-name", "glyphd", "service.name attribute value for traces")
	traceFile := flag.String("trace-file", "", "optional path to write spans as JSONL")
	traceHeaders := flag.String("trace-headers", "", "comma-separated list of additional headers for trace export requests (key=value)")
	flag.Parse()

	visited := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		visited[f.Name] = true
	})

	sampleRate := *flowSampleRate
	if visited["proxy-flow-sample"] && !visited["flow-sample-rate"] {
		sampleRate = *proxyFlowSample
	}

	maxBodyBytes := kilobytesToBytes(*maxBodyKB)
	if visited["proxy-flow-max-body"] && !visited["max-body-kb"] {
		maxBodyBytes = *proxyFlowMaxBody
	}

	if *token == "" {
		fmt.Fprintln(os.Stderr, "--token must be provided")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := config{
		addr:        *addr,
		token:       *token,
		metricsAddr: strings.TrimSpace(*metricsAddr),
		proxy: proxy.Config{
			Addr:        selectProxyAddr(*proxyAddr, *proxyPort),
			RulesPath:   *proxyRules,
			HistoryPath: *proxyHistory,
			CACertPath:  *proxyCACert,
			CAKeyPath:   *proxyCAKey,
			Flow: proxy.FlowCaptureConfig{
				Enabled:      *proxyFlowEnabled,
				SampleRate:   sampleRate,
				MaxBodyBytes: maxBodyBytes,
				Seed:         *proxyFlowSeed,
				LogPath:      strings.TrimSpace(*proxyFlowLog),
			},
		},
		enableProxy:       *enableProxy,
		fingerprintRotate: *fingerprintRotate,
		pluginsDir:        strings.TrimSpace(*pluginDir),
		http3Mode:         strings.TrimSpace(*http3Mode),
		tracing: tracing.Config{
			Endpoint:      strings.TrimSpace(*traceEndpoint),
			SkipTLSVerify: *traceInsecure,
			ServiceName:   strings.TrimSpace(*traceService),
			SampleRatio:   *traceSample,
			FilePath:      strings.TrimSpace(*traceFile),
		},
		traceHeaders: *traceHeaders,
	}

	scopePath := strings.TrimSpace(*scopePolicy)
	if scopePath != "" {
		enforcer, err := scope.LoadEnforcerFromFile(scopePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load scope policy: %v\n", err)
			os.Exit(1)
		}
		cfg.proxy.Scope = enforcer
		cfg.scopePolicyPath = scopePath
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

func kilobytesToBytes(kb int) int {
	if kb < 0 {
		return -1
	}
	return kb * 1024
}

func run(ctx context.Context, cfg config) error {
	coreLogger, err := newAuditLogger("glyphd")
	if err != nil {
		return fmt.Errorf("configure audit logger: %w", err)
	}
	defer coreLogger.Close()

	if cfg.proxy.Scope != nil && strings.TrimSpace(cfg.scopePolicyPath) != "" {
		emitAudit(coreLogger.WithComponent("proxy"), logging.AuditEvent{
			EventType: logging.EventRPCCall,
			Decision:  logging.DecisionInfo,
			Metadata: map[string]any{
				"phase": "scope_policy_loaded",
				"path":  cfg.scopePolicyPath,
			},
		})
	}

	traceCfg := cfg.tracing
	traceCfg.Headers = parseTraceHeaders(cfg.traceHeaders)
	shutdownTracing, err := tracing.Setup(ctx, traceCfg)
	if err != nil {
		return fmt.Errorf("configure tracing: %w", err)
	}
	if shutdownTracing != nil {
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := shutdownTracing(shutdownCtx); err != nil {
				emitAudit(coreLogger, logging.AuditEvent{
					EventType: logging.EventRPCCall,
					Decision:  logging.DecisionInfo,
					Reason:    err.Error(),
					Metadata: map[string]any{
						"phase": "tracing_shutdown",
					},
				})
			}
		}()
	}
	if traceCfg.Endpoint != "" || traceCfg.FilePath != "" {
		emitAudit(coreLogger, logging.AuditEvent{
			EventType: logging.EventRPCCall,
			Decision:  logging.DecisionInfo,
			Metadata: map[string]any{
				"phase":    "tracing_ready",
				"endpoint": traceCfg.Endpoint,
				"file":     traceCfg.FilePath,
			},
		})
	}

	var (
		metricsSrv   *http.Server
		metricsErrCh chan error
	)
	if cfg.metricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", obsmetrics.Handler())
		metricsSrv = &http.Server{Addr: cfg.metricsAddr, Handler: mux}
		metricsErrCh = make(chan error, 1)
		go func() {
			if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				metricsErrCh <- err
			}
		}()
		emitAudit(coreLogger, logging.AuditEvent{
			EventType: logging.EventRPCCall,
			Decision:  logging.DecisionInfo,
			Metadata: map[string]any{
				"phase":   "metrics_ready",
				"address": cfg.metricsAddr,
			},
		})
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := metricsSrv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				emitAudit(coreLogger, logging.AuditEvent{
					EventType: logging.EventRPCCall,
					Decision:  logging.DecisionInfo,
					Reason:    err.Error(),
					Metadata: map[string]any{
						"phase": "metrics_shutdown",
					},
				})
			}
		}()
	}

	busLogger := coreLogger.WithComponent("plugin_bus")
	flowPublisher := newBusFlowPublisher()
	cfg.proxy.FlowPublisher = flowPublisher

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
			emitAudit(coreLogger, logging.AuditEvent{
				EventType: logging.EventProxyLifecycle,
				Decision:  logging.DecisionDeny,
				Reason:    err.Error(),
				Metadata: map[string]any{
					"phase": "initialise",
				},
			})
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
					emitAudit(coreLogger, logging.AuditEvent{
						EventType: logging.EventProxyLifecycle,
						Decision:  logging.DecisionDeny,
						Reason:    errRun.Error(),
						Metadata: map[string]any{
							"phase": "startup",
						},
					})
				}
			default:
			}
			return fmt.Errorf("start proxy: %w", err)
		}
		emitAudit(coreLogger, logging.AuditEvent{
			EventType: logging.EventProxyLifecycle,
			Decision:  logging.DecisionAllow,
			Metadata: map[string]any{
				"phase":   "ready",
				"address": proxySrv.Addr(),
			},
		})
	}

	lis, err := net.Listen("tcp", cfg.addr)
	if err != nil {
		cancelProxy()
		if proxyErrCh != nil {
			if errRun := <-proxyErrCh; errRun != nil {
				emitAudit(coreLogger, logging.AuditEvent{
					EventType: logging.EventProxyLifecycle,
					Decision:  logging.DecisionDeny,
					Reason:    errRun.Error(),
					Metadata: map[string]any{
						"phase": "listen_failed",
					},
				})
			}
		}
		return fmt.Errorf("failed to listen on %s: %w", cfg.addr, err)
	}
	defer func() {
		if err := lis.Close(); err != nil {
			emitAudit(coreLogger, logging.AuditEvent{
				EventType: logging.EventRPCCall,
				Decision:  logging.DecisionInfo,
				Reason:    err.Error(),
				Metadata: map[string]any{
					"phase": "close_listener",
				},
			})
		}
	}()

	serviceCtx, cancelService := context.WithCancel(ctx)
	defer cancelService()

	grpcErrCh := make(chan error, 1)
	go func() {
		grpcErrCh <- serve(serviceCtx, lis, cfg.token, coreLogger, busLogger, cfg.fingerprintRotate, cfg.pluginsDir, cfg.http3Mode, flowPublisher)
	}()

	select {
	case err := <-grpcErrCh:
		cancelProxy()
		if proxyErrCh != nil {
			if pErr := <-proxyErrCh; pErr != nil {
				emitAudit(coreLogger, logging.AuditEvent{
					EventType: logging.EventProxyLifecycle,
					Decision:  logging.DecisionDeny,
					Reason:    pErr.Error(),
					Metadata: map[string]any{
						"phase": "grpc_shutdown",
					},
				})
			}
		}
		return err
	case err := <-metricsErrCh:
		cancelService()
		cancelProxy()
		if err != nil {
			return fmt.Errorf("metrics server failed: %w", err)
		}
		if proxyErrCh != nil {
			if pErr := <-proxyErrCh; pErr != nil {
				emitAudit(coreLogger, logging.AuditEvent{
					EventType: logging.EventProxyLifecycle,
					Decision:  logging.DecisionDeny,
					Reason:    pErr.Error(),
					Metadata: map[string]any{
						"phase": "metrics_shutdown",
					},
				})
			}
		}
		return <-grpcErrCh
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
				emitAudit(coreLogger, logging.AuditEvent{
					EventType: logging.EventProxyLifecycle,
					Decision:  logging.DecisionDeny,
					Reason:    pErr.Error(),
					Metadata: map[string]any{
						"phase": "context_cancel",
					},
				})
			}
		}
		return ctx.Err()
	}
}

func serve(ctx context.Context, lis net.Listener, token string, coreLogger, busLogger *logging.AuditLogger, rotateFingerprints bool, pluginsDir string, http3Mode string, publisher *busFlowPublisher) error {
	if token == "" {
		return errors.New("auth token must be provided")
	}

	findingsBus := findings.NewBus()
	findingsPath := resolveFindingsPath()
	emitAudit(coreLogger, logging.AuditEvent{
		EventType: logging.EventReporter,
		Decision:  logging.DecisionInfo,
		Metadata: map[string]any{
			"findings_path": findingsPath,
		},
	})
	jsonlWriter := reporter.NewJSONL(findingsPath)
	findingsCh := findingsBus.Subscribe(ctx)
	go func() {
		for finding := range findingsCh {
			if err := jsonlWriter.Write(finding); err != nil {
				emitAudit(coreLogger, logging.AuditEvent{
					EventType: logging.EventReporter,
					Decision:  logging.DecisionDeny,
					Reason:    err.Error(),
					Metadata: map[string]any{
						"action": "persist_finding",
					},
				})
			}
		}
	}()

	srv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(tracing.UnaryServerInterceptor()),
		grpc.ChainStreamInterceptor(tracing.StreamServerInterceptor()),
	)
	gateOpts := []netgate.Option{}
	switch mode := strings.ToLower(strings.TrimSpace(http3Mode)); mode {
	case "", "auto":
	case "disable", "off":
		gateOpts = append(gateOpts, netgate.WithTransportConfig(netgate.TransportConfig{EnableHTTP2: true, EnableHTTP3: false}))
	case "require", "force":
		gateOpts = append(gateOpts, netgate.WithTransportConfig(netgate.TransportConfig{EnableHTTP2: true, EnableHTTP3: true, RequireHTTP3: true}))
	default:
		return fmt.Errorf("unsupported http3 mode: %q", http3Mode)
	}
	if rotateFingerprints {
		strategy := fingerprint.DefaultStrategy()
		strategy.EnableRotation(true)
		gateOpts = append(gateOpts, netgate.WithFingerprintStrategy(strategy))
	}
	busServer := bus.NewServer(token, findingsBus, bus.WithAuditLogger(busLogger), bus.WithGateOptions(gateOpts...))
	if publisher != nil {
		publisher.SetBus(busServer)
		defer publisher.SetBus(nil)
	}
	pb.RegisterPluginBusServer(srv, busServer)

	secretsLogger := coreLogger.WithComponent("secrets_broker")
	secretsManager := secrets.NewManager(secrets.FromEnv(os.Environ()), secrets.WithAuditLogger(secretsLogger))
	secretsServer := secrets.NewServer(secretsManager, secrets.WithServerAuditLogger(secretsLogger))
	pb.RegisterSecretsBrokerServer(srv, secretsServer)

	pluginManagerCancel := func() {}
	if strings.TrimSpace(pluginsDir) != "" {
		repoRoot, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("determine working directory: %w", err)
		}
		allowlistPath := filepath.Join(pluginsDir, "ALLOWLIST")
		pluginLogger := coreLogger.WithComponent("plugin_manager")
		reloader, err := hotreload.New(pluginsDir, repoRoot, allowlistPath, busServer, hotreload.WithAuditLogger(pluginLogger))
		if err != nil {
			return fmt.Errorf("configure plugin reloader: %w", err)
		}
		managerCtx, cancel := context.WithCancel(ctx)
		pluginManagerCancel = cancel
		go reloader.Start(managerCtx)
	}
	defer pluginManagerCancel()

	// Create a background context used by the event generator. It is cancelled
	// once the gRPC server begins shutting down.
	generatorCtx, cancelGenerator := context.WithCancel(context.Background())
	defer cancelGenerator()
	if os.Getenv("GLYPH_DISABLE_EVENT_GENERATOR") != "1" {
		go busServer.StartEventGenerator(generatorCtx)
	}

	// Stop the gRPC server once the provided context is cancelled.
	go func() {
		<-ctx.Done()
		cancelGenerator()
		pluginManagerCancel()

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

func newAuditLogger(component string) (*logging.AuditLogger, error) {
	opts := []logging.Option{}
	if disableStdout(os.Getenv("GLYPH_AUDIT_LOG_STDOUT")) {
		opts = append(opts, logging.WithoutStdout())
	}
	if path := strings.TrimSpace(os.Getenv("GLYPH_AUDIT_LOG_PATH")); path != "" {
		opts = append(opts, logging.WithFile(path))
	}
	return logging.NewAuditLogger(component, opts...)
}

func disableStdout(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	return value == "0" || value == "false" || value == "no"
}

func parseTraceHeaders(raw string) map[string]string {
	headers := make(map[string]string)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return headers
	}
	parts := strings.Split(raw, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		key := strings.TrimSpace(kv[0])
		if key == "" {
			continue
		}
		value := ""
		if len(kv) > 1 {
			value = strings.TrimSpace(kv[1])
		}
		headers[key] = value
	}
	return headers
}

func emitAudit(logger *logging.AuditLogger, event logging.AuditEvent) {
	if logger == nil {
		return
	}
	if err := logger.Emit(event); err != nil {
		fmt.Fprintf(os.Stderr, "audit log error: %v\n", err)
	}
}
