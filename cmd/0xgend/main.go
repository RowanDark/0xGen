package main

import (
	"context"
	"encoding/json"
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

	"github.com/RowanDark/0xgen/internal/api"
	"github.com/RowanDark/0xgen/internal/bus"
	"github.com/RowanDark/0xgen/internal/env"
	"github.com/RowanDark/0xgen/internal/findings"
	"github.com/RowanDark/0xgen/internal/logging"
	"github.com/RowanDark/0xgen/internal/netgate"
	"github.com/RowanDark/0xgen/internal/netgate/fingerprint"
	obsmetrics "github.com/RowanDark/0xgen/internal/observability/metrics"
	"github.com/RowanDark/0xgen/internal/observability/tracing"
	"github.com/RowanDark/0xgen/internal/plugins/hotreload"
	"github.com/RowanDark/0xgen/internal/plugins/marketplace"
	"github.com/RowanDark/0xgen/internal/proxy"
	"github.com/RowanDark/0xgen/internal/reporter"
	"github.com/RowanDark/0xgen/internal/scope"
	"github.com/RowanDark/0xgen/internal/secrets"
	"github.com/RowanDark/0xgen/internal/team"
	pb "github.com/RowanDark/0xgen/proto/gen/go/proto/oxg"
	"google.golang.org/grpc"
)

var version = "dev"

type config struct {
	addr              string
	token             string
	metricsAddr       string
	proxy             proxy.Config
	enableProxy       bool
	fingerprintRotate bool
	pluginsDir        string
	registrySource    string
	http3Mode         string
	tracing           tracing.Config
	traceHeaders      string
	scopePolicyPath   string
	apiAddr           string
	apiJWTSecret      string
	apiJWTIssuer      string
	apiTokenTTL       time.Duration
	apiSigningKey     string
	apiScanTimeout    time.Duration
	apiOIDCIssuer     string
	apiOIDCJWKS       string
	apiOIDCAudiences  []string
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
	pluginRegistry := flag.String("plugin-registry", filepath.Join("docs", "en", "data", "plugin-registry.json"), "path or URL for the plugin registry index (empty to disable marketplace API)")
	http3Mode := flag.String("http3", "auto", "HTTP/3 mode: auto, disable, or require")
	traceEndpoint := flag.String("trace-endpoint", "", "OTLP/HTTP endpoint for exported spans (http(s)://host:port/v1/traces)")
	traceInsecure := flag.Bool("trace-insecure-skip-verify", false, "disable TLS verification when exporting spans")
	traceSample := flag.Float64("trace-sample-ratio", 0.25, "probabilistic sampling ratio for root spans (0-1)")
	traceService := flag.String("trace-service-name", "0xgend", "service.name attribute value for traces")
	traceFile := flag.String("trace-file", "", "optional path to write spans as JSONL")
	traceHeaders := flag.String("trace-headers", "", "comma-separated list of additional headers for trace export requests (key=value)")
	apiAddr := flag.String("api-addr", "", "address for the REST API server (host:port)")
	apiSecret := flag.String("api-jwt-secret", "", "HMAC secret used to sign API tokens")
	apiIssuer := flag.String("api-jwt-issuer", "0xgen", "issuer claim for API tokens")
	apiTTL := flag.Duration("api-jwt-ttl", time.Hour, "default lifetime for issued API tokens")
	apiSigningKey := flag.String("api-signing-key", "", "path to a cosign-compatible private key used to sign API results")
	apiScanTimeout := flag.Duration("api-scan-timeout", 2*time.Minute, "maximum duration for API-triggered scans")
	apiOIDCIssuer := flag.String("api-oidc-issuer", "", "OIDC issuer for validating API tokens")
	apiOIDCJWKS := flag.String("api-oidc-jwks", "", "JWKS endpoint for OIDC token validation")
	apiOIDCAud := flag.String("api-oidc-audiences", "", "comma-separated list of allowed OIDC audiences")
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

	rawAud := strings.TrimSpace(*apiOIDCAud)
	var oidcAudiences []string
	if rawAud != "" {
		for _, part := range strings.Split(rawAud, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			oidcAudiences = append(oidcAudiences, part)
		}
	}

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
		registrySource:    strings.TrimSpace(*pluginRegistry),
		http3Mode:         strings.TrimSpace(*http3Mode),
		tracing: tracing.Config{
			Endpoint:      strings.TrimSpace(*traceEndpoint),
			SkipTLSVerify: *traceInsecure,
			ServiceName:   strings.TrimSpace(*traceService),
			SampleRatio:   *traceSample,
			FilePath:      strings.TrimSpace(*traceFile),
		},
		traceHeaders:     *traceHeaders,
		apiAddr:          strings.TrimSpace(*apiAddr),
		apiJWTSecret:     strings.TrimSpace(*apiSecret),
		apiJWTIssuer:     strings.TrimSpace(*apiIssuer),
		apiTokenTTL:      *apiTTL,
		apiSigningKey:    strings.TrimSpace(*apiSigningKey),
		apiScanTimeout:   *apiScanTimeout,
		apiOIDCIssuer:    strings.TrimSpace(*apiOIDCIssuer),
		apiOIDCJWKS:      strings.TrimSpace(*apiOIDCJWKS),
		apiOIDCAudiences: oidcAudiences,
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
	coreLogger, err := newAuditLogger("0xgend")
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

	pluginLogger := coreLogger.WithComponent("plugin_manager")
	var pluginMarketplace *marketplace.Manager
	if strings.TrimSpace(cfg.pluginsDir) != "" {
		registrySource := cfg.registrySource
		if override, ok := env.Lookup("0XGEN_PLUGIN_REGISTRY_URL"); ok {
			trimmed := strings.TrimSpace(override)
			if trimmed != "" {
				registrySource = trimmed
			}
		}
		if strings.TrimSpace(registrySource) != "" {
			marketplaceMgr, err := marketplace.NewManager(cfg.pluginsDir, registrySource, marketplace.WithAuditLogger(pluginLogger))
			if err != nil {
				emitAudit(coreLogger, logging.AuditEvent{
					EventType: logging.EventPluginLoad,
					Decision:  logging.DecisionDeny,
					Reason:    fmt.Sprintf("initialise marketplace: %v", err),
				})
			} else {
				pluginMarketplace = marketplaceMgr
			}
		}
	}

	var (
		metricsSrv   *http.Server
		metricsErrCh chan error
	)
	if cfg.metricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", obsmetrics.Handler())
		pluginAPI := newPluginAPI(pluginMarketplace)
		mux.HandleFunc("/plugins/registry", pluginAPI.handleRegistry)
		mux.HandleFunc("/plugins/install", pluginAPI.handleInstall)
		mux.HandleFunc("/plugins/remove", pluginAPI.handleRemove)
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

	proxyEnabled := cfg.enableProxy
	if val, ok := env.Lookup("0XGEN_ENABLE_PROXY"); ok {
		if strings.TrimSpace(val) == "1" {
			proxyEnabled = true
		}
	}

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

	findingsBus := findings.NewBus()

	grpcErrCh := make(chan error, 1)
	go func() {
		grpcErrCh <- serve(serviceCtx, lis, cfg.token, coreLogger, busLogger, cfg.fingerprintRotate, cfg.pluginsDir, cfg.http3Mode, flowPublisher, findingsBus)
	}()

	var apiErrCh chan error
	if strings.TrimSpace(cfg.apiAddr) != "" {
		if strings.TrimSpace(cfg.pluginsDir) == "" {
			return errors.New("--plugins-dir must be provided when --api-addr is set")
		}
		if strings.TrimSpace(cfg.apiJWTSecret) == "" {
			return errors.New("--api-jwt-secret must be provided when --api-addr is set")
		}
		if strings.TrimSpace(cfg.apiSigningKey) == "" {
			return errors.New("--api-signing-key must be provided when --api-addr is set")
		}
		pluginsAbs := cfg.pluginsDir
		if !filepath.IsAbs(pluginsAbs) {
			abs, err := filepath.Abs(pluginsAbs)
			if err != nil {
				return fmt.Errorf("resolve plugins directory: %w", err)
			}
			pluginsAbs = abs
		}
		allowlistPath := filepath.Join(pluginsAbs, "ALLOWLIST")
		if _, err := os.Stat(allowlistPath); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				allowlistPath = ""
			} else {
				return fmt.Errorf("stat allowlist: %w", err)
			}
		}
		repoRoot := filepath.Dir(pluginsAbs)
		apiLogger := coreLogger.WithComponent("api_server")
		signingKeyPath := cfg.apiSigningKey
		if !filepath.IsAbs(signingKeyPath) {
			abs, err := filepath.Abs(signingKeyPath)
			if err != nil {
				return fmt.Errorf("resolve signing key: %w", err)
			}
			signingKeyPath = abs
		}

		workspaceStore := team.NewStore(apiLogger.WithComponent("workspace_store"))

		apiCfg := api.Config{
			Addr:            cfg.apiAddr,
			StaticToken:     cfg.token,
			JWTSecret:       []byte(cfg.apiJWTSecret),
			JWTIssuer:       strings.TrimSpace(cfg.apiJWTIssuer),
			DefaultTokenTTL: cfg.apiTokenTTL,
			PluginsDir:      pluginsAbs,
			AllowlistPath:   allowlistPath,
			RepoRoot:        repoRoot,
			ServerAddr:      cfg.addr,
			AuthToken:       cfg.token,
			SigningKeyPath:  signingKeyPath,
			FindingsBus:     findingsBus,
			Logger:          apiLogger,
			ScanTimeout:     cfg.apiScanTimeout,
			OIDCIssuer:      cfg.apiOIDCIssuer,
			OIDCJWKSURL:     cfg.apiOIDCJWKS,
			OIDCAudiences:   cfg.apiOIDCAudiences,
			WorkspaceStore:  workspaceStore,
		}
		apiServer, err := api.NewServer(apiCfg)
		if err != nil {
			return fmt.Errorf("configure api server: %w", err)
		}
		apiErrCh = make(chan error, 1)
		go func() {
			apiErrCh <- apiServer.Run(serviceCtx)
		}()
	}

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
	case err := <-apiErrCh:
		cancelService()
		cancelProxy()
		if err != nil {
			return fmt.Errorf("api server failed: %w", err)
		}
		if proxyErrCh != nil {
			if pErr := <-proxyErrCh; pErr != nil {
				emitAudit(coreLogger, logging.AuditEvent{
					EventType: logging.EventProxyLifecycle,
					Decision:  logging.DecisionDeny,
					Reason:    pErr.Error(),
					Metadata: map[string]any{
						"phase": "api_shutdown",
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

func serve(ctx context.Context, lis net.Listener, token string, coreLogger, busLogger *logging.AuditLogger, rotateFingerprints bool, pluginsDir string, http3Mode string, publisher *busFlowPublisher, findingsBus *findings.Bus) error {
	if token == "" {
		return errors.New("auth token must be provided")
	}

	if findingsBus == nil {
		findingsBus = findings.NewBus()
	}
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
		pluginLogger := coreLogger.WithComponent("plugin_manager")
		repoRoot, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("determine working directory: %w", err)
		}
		allowlistPath := filepath.Join(pluginsDir, "ALLOWLIST")
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
	disableEvents := false
	if val, ok := env.Lookup("0XGEN_DISABLE_EVENT_GENERATOR"); ok {
		disableEvents = strings.TrimSpace(val) == "1"
	}
	if !disableEvents {
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
	if val, ok := env.Lookup("0XGEN_OUT"); ok {
		if custom := strings.TrimSpace(val); custom != "" {
			return filepath.Join(custom, "findings.jsonl")
		}
	}
	return reporter.DefaultFindingsPath
}

func newAuditLogger(component string) (*logging.AuditLogger, error) {
	opts := []logging.Option{}
	auditStdout := ""
	if val, ok := env.Lookup("0XGEN_AUDIT_LOG_STDOUT"); ok {
		auditStdout = val
	}
	if disableStdout(auditStdout) {
		opts = append(opts, logging.WithoutStdout())
	}
	if val, ok := env.Lookup("0XGEN_AUDIT_LOG_PATH"); ok {
		if path := strings.TrimSpace(val); path != "" {
			opts = append(opts, logging.WithFile(path))
		}
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

type pluginAPI struct {
	manager *marketplace.Manager
}

func newPluginAPI(manager *marketplace.Manager) *pluginAPI {
	return &pluginAPI{manager: manager}
}

func (p *pluginAPI) handleRegistry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if p.manager == nil {
		http.NotFound(w, r)
		return
	}
	envelope, err := p.manager.Registry(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	response := struct {
		marketplace.DatasetEnvelope
		Status        []marketplace.PluginStatus `json:"status"`
		DaemonVersion string                     `json:"daemon_version"`
	}{
		DatasetEnvelope: envelope,
		Status:          envelope.Status(version),
		DaemonVersion:   version,
	}
	writeJSON(w, http.StatusOK, response)
}

func (p *pluginAPI) handleInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if p.manager == nil {
		http.NotFound(w, r)
		return
	}
	defer r.Body.Close()
	var payload struct {
		ID    string `json:"id"`
		Force bool   `json:"force"`
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	installed, err := p.manager.Install(r.Context(), payload.ID, marketplace.InstallOptions{Force: payload.Force})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, installed)
}

func (p *pluginAPI) handleRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if p.manager == nil {
		http.NotFound(w, r)
		return
	}
	defer r.Body.Close()
	var payload struct {
		ID string `json:"id"`
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if err := p.manager.Remove(payload.ID); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		fmt.Fprintf(os.Stderr, "write response: %v\n", err)
	}
}
