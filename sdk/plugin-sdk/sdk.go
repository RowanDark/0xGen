package pluginsdk

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	pb "github.com/RowanDark/Glyph/proto/gen/go/proto/glyph"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Capability represents a permission that must be granted to the plugin by the host
// before certain operations are allowed.
type Capability string

const (
	// CapabilityEmitFindings allows the plugin to report findings to the host.
	CapabilityEmitFindings Capability = "CAP_EMIT_FINDINGS"
	// CapabilityHTTPPassive allows the plugin to receive passive HTTP events.
	CapabilityHTTPPassive Capability = "CAP_HTTP_PASSIVE"
	// CapabilityWorkspaceRead allows the plugin to read from its allocated workspace.
	CapabilityWorkspaceRead Capability = "CAP_WORKSPACE_READ"
	// CapabilityWorkspaceWrite allows the plugin to write to its allocated workspace.
	CapabilityWorkspaceWrite Capability = "CAP_WORKSPACE_WRITE"
	// CapabilityNetOutbound allows the plugin to make outbound network requests via the broker.
	CapabilityNetOutbound Capability = "CAP_NET_OUTBOUND"
	// CapabilitySecretsRead allows the plugin to retrieve secrets from the broker.
	CapabilitySecretsRead Capability = "CAP_SECRETS_READ"
)

// Subscription identifies the type of host events a plugin is interested in.
type Subscription string

const (
	// SubscriptionFlowResponse subscribes to HTTP response flow events from the host.
	SubscriptionFlowResponse Subscription = "FLOW_RESPONSE"
)

// Severity describes how serious a finding is considered by the plugin.
type Severity pb.Severity

const (
	SeverityInfo     Severity = Severity(pb.Severity_INFO)
	SeverityLow      Severity = Severity(pb.Severity_LOW)
	SeverityMedium   Severity = Severity(pb.Severity_MEDIUM)
	SeverityHigh     Severity = Severity(pb.Severity_HIGH)
	SeverityCritical Severity = Severity(pb.Severity_CRITICAL)
)

// Finding captures the structured data that will be sent back to the host when the
// plugin observes an issue.
type Finding struct {
	ID         string
	Type       string
	Message    string
	Target     string
	Evidence   string
	Severity   Severity
	Metadata   map[string]string
	DetectedAt time.Time
}

// Hooks contains the callbacks provided by a plugin implementation.
type Hooks struct {
	OnStart       OnStartHook
	OnHTTPPassive HTTPPassiveHook
}

// OnStartHook is invoked once after the plugin successfully connects to the host.
type OnStartHook func(ctx *Context) error

// HTTPPassiveHook handles passive HTTP response events streamed from the host.
type HTTPPassiveHook func(ctx *Context, event HTTPPassiveEvent) error

// Config encapsulates the runtime configuration for a plugin instance.
type Config struct {
	// PluginName is the name reported to the host. It should match the manifest.
	PluginName string
	// Host is the host:port combination to dial the Glyph core.
	Host string
	// AuthToken is the shared secret required by the host.
	AuthToken string
	// CapabilityToken binds this invocation to the capabilities granted by the host.
	CapabilityToken string
	// SecretsToken authorises this invocation to retrieve secrets from the broker.
	SecretsToken string
	// SecretsScope binds the secrets token to the specific plugin run scope. If left blank
	// the capability token is used as a fallback.
	SecretsScope string
	// Capabilities is the set of capabilities granted by the manifest.
	Capabilities []Capability
	// Subscriptions lists the host events the plugin wants to receive.
	Subscriptions []Subscription
	// Logger allows callers to customise logging output. A sensible default is used otherwise.
	Logger *slog.Logger
	// Broker injects broker helpers for filesystem, network, and secrets access.
	Broker Broker
}

// HTTPResponse summarises an HTTP response derived from a passive flow event.
type HTTPResponse struct {
	StatusLine string
	Headers    http.Header
	Body       []byte
}

// HTTPPassiveEvent wraps a passive HTTP response observed by the plugin.
type HTTPPassiveEvent struct {
	Raw      []byte
	Response *HTTPResponse
}

// Context provides helpers for hooks to interact with the host safely.
type eventSink interface {
	sendFinding(*pb.Finding) error
}

type Context struct {
	runtime      eventSink
	logger       *slog.Logger
	capabilities map[Capability]struct{}
	pluginName   string
	broker       Broker
}

// Logger returns the logger bound to the plugin context.
func (c *Context) Logger() *slog.Logger {
	return c.logger
}

// EmitFinding reports a finding to the host if the plugin has the required capability.
func (c *Context) EmitFinding(f Finding) error {
	if _, ok := c.capabilities[CapabilityEmitFindings]; !ok {
		return CapabilityError{Capability: CapabilityEmitFindings}
	}
	if strings.TrimSpace(f.Type) == "" {
		return errors.New("finding type must not be empty")
	}
	if strings.TrimSpace(f.Message) == "" {
		return errors.New("finding message must not be empty")
	}

	findingID := strings.TrimSpace(f.ID)
	if findingID == "" {
		findingID = newULID()
	} else {
		findingID = strings.ToUpper(findingID)
	}

	detectedAt := f.DetectedAt
	if detectedAt.IsZero() {
		detectedAt = time.Now().UTC()
	} else {
		detectedAt = detectedAt.UTC()
	}

	pbFinding := &pb.Finding{
		Type:     f.Type,
		Message:  f.Message,
		Severity: toProtoSeverity(f.Severity),
	}
	metadata := make(map[string]string, len(f.Metadata)+4)
	for k, v := range f.Metadata {
		if strings.TrimSpace(k) == "" {
			continue
		}
		metadata[k] = v
	}
	metadata["id"] = findingID
	if target := strings.TrimSpace(f.Target); target != "" {
		metadata["target"] = target
	}
	if evidence := strings.TrimSpace(f.Evidence); evidence != "" {
		metadata["evidence"] = evidence
	}
	metadata["detected_at"] = detectedAt.Format(time.RFC3339)
	if len(metadata) > 0 {
		pbFinding.Metadata = metadata
	}

	if c.runtime == nil {
		return errors.New("runtime not initialised")
	}

	return c.runtime.sendFinding(pbFinding)
}

var sdkCrockford = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

func newULID() string {
	buf := make([]byte, 16)
	ts := uint64(time.Now().UTC().UnixMilli())
	for i := 5; i >= 0; i-- {
		buf[i] = byte(ts & 0xFF)
		ts >>= 8
	}
	if _, err := io.ReadFull(rand.Reader, buf[6:]); err != nil {
		nano := uint64(time.Now().UTC().UnixNano())
		for i := 6; i < len(buf); i++ {
			buf[i] = byte(nano & 0xFF)
			nano >>= 8
		}
	}
	return sdkCrockford.EncodeToString(buf)
}

// CapabilityError indicates a capability is missing for the requested action.
type CapabilityError struct {
	Capability Capability
}

func (e CapabilityError) Error() string {
	return fmt.Sprintf("missing capability %s", e.Capability)
}

func toProtoSeverity(sev Severity) pb.Severity {
	switch sev {
	case SeverityCritical:
		return pb.Severity_CRITICAL
	case SeverityHigh:
		return pb.Severity_HIGH
	case SeverityMedium:
		return pb.Severity_MEDIUM
	case SeverityLow:
		return pb.Severity_LOW
	default:
		return pb.Severity_INFO
	}
}

// runtimeState bundles mutable state shared across hooks and the event loop.
type runtimeState struct {
	stream pb.PluginBus_EventStreamClient
	sendMu sync.Mutex
}

func (r *runtimeState) sendFinding(f *pb.Finding) error {
	r.sendMu.Lock()
	defer r.sendMu.Unlock()
	if r.stream == nil {
		return errors.New("event stream not initialised")
	}
	return r.stream.Send(&pb.PluginEvent{Event: &pb.PluginEvent_Finding{Finding: f}})
}

// Serve launches the plugin runtime and blocks until the context is cancelled or an error occurs.
func Serve(parent context.Context, cfg Config, hooks Hooks) error {
	if cfg.PluginName == "" {
		return errors.New("plugin name is required")
	}
	if cfg.Host == "" {
		return errors.New("host address is required")
	}
	if cfg.AuthToken == "" {
		return errors.New("auth token is required")
	}
	if cfg.CapabilityToken == "" {
		return errors.New("capability token is required")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stdout, nil))
	}

	caps := dedupeCapabilities(cfg.Capabilities)
	subs := dedupeSubscriptions(cfg.Subscriptions)

	if hooks.OnHTTPPassive != nil {
		if _, ok := caps[CapabilityHTTPPassive]; !ok {
			return fmt.Errorf("hook OnHTTPPassive requires capability %s", CapabilityHTTPPassive)
		}
		if _, present := subs[SubscriptionFlowResponse]; !present {
			subs[SubscriptionFlowResponse] = struct{}{}
		}
	}

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	conn, err := grpc.NewClient(cfg.Host, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("dial host: %w", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	broker := cfg.Broker
	if broker == nil {
		secretsScope := strings.TrimSpace(cfg.SecretsScope)
		if secretsScope == "" {
			secretsScope = strings.TrimSpace(cfg.CapabilityToken)
		}
		broker = newRemoteBroker(cfg.PluginName, cfg.SecretsToken, secretsScope, conn)
	}

	client := pb.NewPluginBusClient(conn)
	stream, err := client.EventStream(ctx)
	if err != nil {
		return fmt.Errorf("open event stream: %w", err)
	}
	defer func() {
		_ = stream.CloseSend()
	}()

	hello := &pb.PluginHello{
		AuthToken:       cfg.AuthToken,
		PluginName:      cfg.PluginName,
		Pid:             int32(os.Getpid()),
		Subscriptions:   mapSubscriptions(subs),
		Capabilities:    mapCapabilities(caps),
		CapabilityToken: cfg.CapabilityToken,
	}
	if err := stream.Send(&pb.PluginEvent{Event: &pb.PluginEvent_Hello{Hello: hello}}); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}

	runtime := &runtimeState{stream: stream}
	pluginCtx := &Context{
		runtime:      runtime,
		logger:       logger.With("plugin", cfg.PluginName),
		capabilities: caps,
		pluginName:   cfg.PluginName,
		broker:       broker,
	}

	if hooks.OnStart != nil {
		if err := hooks.OnStart(pluginCtx); err != nil {
			return fmt.Errorf("onStart: %w", err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		hostEvent, err := stream.Recv()
		if err != nil {
			if errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "context canceled") {
				return nil
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("receive host event: %w", err)
		}

		flowEvent := hostEvent.GetFlowEvent()
		if flowEvent == nil {
			continue
		}

		if flowEvent.GetType().String() != string(SubscriptionFlowResponse) {
			continue
		}

		if hooks.OnHTTPPassive == nil {
			continue
		}

		httpResp, err := parseHTTPResponse(flowEvent.GetData())
		if err != nil {
			pluginCtx.Logger().Warn("failed to parse HTTP response", "error", err)
			continue
		}

		event := HTTPPassiveEvent{Raw: flowEvent.GetData(), Response: httpResp}
		if err := hooks.OnHTTPPassive(pluginCtx, event); err != nil {
			return fmt.Errorf("onHTTPPassive: %w", err)
		}
	}
}

// Run is a convenience helper that handles system interrupts and blocks until Serve returns.
func Run(cfg Config, hooks Hooks) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return Serve(ctx, cfg, hooks)
}

func dedupeCapabilities(caps []Capability) map[Capability]struct{} {
	out := make(map[Capability]struct{}, len(caps))
	for _, c := range caps {
		if c != "" {
			out[c] = struct{}{}
		}
	}
	return out
}

func dedupeSubscriptions(subs []Subscription) map[Subscription]struct{} {
	out := make(map[Subscription]struct{}, len(subs))
	for _, s := range subs {
		if s != "" {
			out[s] = struct{}{}
		}
	}
	return out
}

func mapCapabilities(caps map[Capability]struct{}) []string {
	if len(caps) == 0 {
		return nil
	}
	out := make([]string, 0, len(caps))
	for c := range caps {
		out = append(out, string(c))
	}
	return out
}

func mapSubscriptions(subs map[Subscription]struct{}) []string {
	if len(subs) == 0 {
		return nil
	}
	out := make([]string, 0, len(subs))
	for s := range subs {
		out = append(out, string(s))
	}
	return out
}

func parseHTTPResponse(raw []byte) (*HTTPResponse, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty payload")
	}
	sections := bytes.SplitN(raw, []byte("\n\n"), 2)
	headerBlob := string(sections[0])
	lines := strings.Split(headerBlob, "\n")
	if len(lines) == 0 {
		return nil, errors.New("missing status line")
	}
	statusLine := strings.TrimSpace(lines[0])
	headers := http.Header{}
	for _, line := range lines[1:] {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		headers.Add(strings.TrimSpace(key), strings.TrimSpace(value))
	}
	body := []byte{}
	if len(sections) == 2 {
		body = sections[1]
	}
	return &HTTPResponse{StatusLine: statusLine, Headers: headers, Body: body}, nil
}
