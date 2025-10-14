package pluginsdk_test

import (
	"context"
	"testing"

	pluginsdk "github.com/RowanDark/0xgen/sdk/plugin-sdk"
)

func TestRunLocalEnforcesCapabilities(t *testing.T) {
	broker := pluginsdk.NewFakeBroker()
	broker.SetFile("input.json", []byte(`{"hello":"world"}`))
	broker.DenyNetwork("GET", "https://example.com", "denied in test")

	hooks := pluginsdk.Hooks{
		OnStart: func(ctx *pluginsdk.Context) error {
			if err := pluginsdk.UseFilesystem(ctx, pluginsdk.CapabilityWorkspaceRead, func(fs pluginsdk.FilesystemBroker) error {
				_, err := fs.ReadFile(context.Background(), "input.json")
				return err
			}); err != nil {
				t.Fatalf("UseFilesystem: %v", err)
			}

			if err := pluginsdk.UseNetwork(ctx, func(net pluginsdk.NetworkBroker) error {
				_, err := net.Do(context.Background(), pluginsdk.HTTPRequest{Method: "GET", URL: "https://example.com"})
				return err
			}); err == nil {
				t.Fatalf("expected network capability error")
			}

			if err := pluginsdk.UseSecrets(ctx, func(secrets pluginsdk.SecretsBroker) error {
				_, err := secrets.Get(context.Background(), "token")
				return err
			}); err == nil {
				t.Fatalf("expected secrets capability error")
			}

			return nil
		},
	}

	cfg := pluginsdk.LocalRunConfig{
		PluginName:   "test-plugin",
		Capabilities: []pluginsdk.Capability{pluginsdk.CapabilityEmitFindings, pluginsdk.CapabilityWorkspaceRead},
		Broker:       broker,
		Hooks:        hooks,
	}

	if _, err := pluginsdk.RunLocal(context.Background(), cfg); err != nil {
		t.Fatalf("RunLocal: %v", err)
	}

	audits := broker.AuditLog()
	if len(audits) == 0 {
		t.Fatalf("expected audit entries")
	}
}

func TestRunLocalPassiveEvents(t *testing.T) {
	broker := pluginsdk.NewFakeBroker()
	hooks := pluginsdk.Hooks{
		OnHTTPPassive: func(ctx *pluginsdk.Context, event pluginsdk.HTTPPassiveEvent) error {
			ctx.Logger().Info("received", "status", event.Response.StatusLine)
			return ctx.EmitFinding(pluginsdk.Finding{Type: "info", Message: "ok"})
		},
	}

	cfg := pluginsdk.LocalRunConfig{
		PluginName:   "passive-plugin",
		Capabilities: []pluginsdk.Capability{pluginsdk.CapabilityEmitFindings, pluginsdk.CapabilityHTTPPassive},
		Broker:       broker,
		Hooks:        hooks,
		PassiveEvents: []pluginsdk.HTTPPassiveEvent{
			{Response: &pluginsdk.HTTPResponse{StatusLine: "HTTP/1.1 200 OK"}},
		},
	}

	result, err := pluginsdk.RunLocal(context.Background(), cfg)
	if err != nil {
		t.Fatalf("RunLocal: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
}

func TestFakeBrokerDenials(t *testing.T) {
	broker := pluginsdk.NewFakeBroker()
	broker.SetFile("task.json", []byte("ok"))
	broker.SetSecret("token", "value")
	broker.DenyFilesystem("task.json", "workspace revoked")
	broker.DenySecret("token", "secret revoked")
	broker.DenyNetwork("POST", "https://api.example.com", "network denied")

	if _, err := broker.Filesystem().ReadFile(context.Background(), "task.json"); err == nil {
		t.Fatalf("expected filesystem denial")
	}
	if _, err := broker.Secrets().Get(context.Background(), "token"); err == nil {
		t.Fatalf("expected secret denial")
	}
	if _, err := broker.Network().Do(context.Background(), pluginsdk.HTTPRequest{Method: "POST", URL: "https://api.example.com"}); err == nil {
		t.Fatalf("expected network denial")
	}

	audits := broker.AuditLog()
	if len(audits) != 3 {
		t.Fatalf("expected 3 audit entries, got %d", len(audits))
	}
	for _, entry := range audits {
		if entry.Allowed {
			t.Fatalf("expected denial entry, got allowed for %s", entry.Operation)
		}
		if entry.Message == "" {
			t.Fatalf("expected message for %s", entry.Operation)
		}
	}
}
