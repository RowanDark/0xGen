package pluginsdk

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	pb "github.com/RowanDark/0xgen/proto/gen/go/proto/oxg"
)

// LocalRunConfig configures the local integration test harness.
type LocalRunConfig struct {
	PluginName    string
	Capabilities  []Capability
	Broker        Broker
	Logger        *slog.Logger
	Hooks         Hooks
	PassiveEvents []HTTPPassiveEvent
}

// LocalRunResult captures the results emitted by the plugin during a local run.
type LocalRunResult struct {
	Findings []Finding
}

// RunLocal executes the plugin hooks without connecting to a real 0xgen host.
func RunLocal(ctx context.Context, cfg LocalRunConfig) (*LocalRunResult, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(ioDiscard{}, nil))
	}

	caps := dedupeCapabilities(cfg.Capabilities)
	runtime := &recordingRuntime{}
	pluginCtx := &Context{
		runtime:      runtime,
		logger:       logger,
		capabilities: caps,
		pluginName:   cfg.PluginName,
		broker:       cfg.Broker,
	}

	if cfg.Hooks.OnHTTPPassive != nil {
		if _, ok := caps[CapabilityHTTPPassive]; !ok {
			return nil, errors.New("onHTTPPassive requires CAP_HTTP_PASSIVE")
		}
	}

	if cfg.Hooks.OnStart != nil {
		if err := cfg.Hooks.OnStart(pluginCtx); err != nil {
			return nil, err
		}
	}

	if cfg.Hooks.OnHTTPPassive != nil {
		for _, event := range cfg.PassiveEvents {
			if err := cfg.Hooks.OnHTTPPassive(pluginCtx, event); err != nil {
				return nil, err
			}
		}
	}

	return &LocalRunResult{Findings: runtime.Findings()}, nil
}

type recordingRuntime struct {
	mu       sync.Mutex
	findings []Finding
}

func (r *recordingRuntime) sendFinding(f *pb.Finding) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	md := f.GetMetadata()
	if md == nil {
		md = map[string]string{}
	}
	finding := Finding{
		ID:       md["id"],
		Type:     f.GetType(),
		Message:  f.GetMessage(),
		Target:   md["target"],
		Evidence: md["evidence"],
		Severity: Severity(f.GetSeverity()),
		Metadata: md,
	}
	r.findings = append(r.findings, finding)
	return nil
}

func (r *recordingRuntime) Findings() []Finding {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Finding, len(r.findings))
	copy(out, r.findings)
	return out
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }
