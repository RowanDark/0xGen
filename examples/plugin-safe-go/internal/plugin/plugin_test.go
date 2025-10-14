package plugin_test

import (
    "context"
    "testing"

    pluginsdk "github.com/RowanDark/0xgen/sdk/plugin-sdk"

    "github.com/RowanDark/0xgen/examples/plugin-safe-go/internal/plugin"
)

func TestHooksWithCapabilities(t *testing.T) {
    broker := pluginsdk.NewFakeBroker()
    broker.SetFile("task.json", []byte(`{"task":"demo"}`))
    broker.SetSecret("API_TOKEN", "token123")
    broker.SetHTTPResponse("HEAD", "https://example.com/health", pluginsdk.HTTPResult{StatusCode: 204})

    original := plugin.CapabilityMacros
    plugin.CapabilityMacros.NetOutbound = true
    plugin.CapabilityMacros.SecretsRead = true
    t.Cleanup(func() { plugin.CapabilityMacros = original })

    cfg := pluginsdk.LocalRunConfig{
        PluginName: "plugin-safe-go",
        Capabilities: plugin.CapabilityMacros.List(),
        Broker: broker,
        Hooks:  plugin.Hooks(),
        PassiveEvents: []pluginsdk.HTTPPassiveEvent{
            {Response: &pluginsdk.HTTPResponse{StatusLine: "HTTP/1.1 200 OK"}},
        },
    }

    result, err := pluginsdk.RunLocal(context.Background(), cfg)
    if err != nil {
        t.Fatalf("RunLocal: %v", err)
    }
    if len(broker.Requests()) == 0 {
        t.Fatalf("expected broker Do to be invoked")
    }
    if len(result.Findings) != 1 {
        t.Fatalf("expected 1 finding, got %d", len(result.Findings))
    }
}

func TestHooksWithoutCapabilities(t *testing.T) {
    broker := pluginsdk.NewFakeBroker()

    cfg := pluginsdk.LocalRunConfig{
        PluginName:   "plugin-safe-go",
        Capabilities: []pluginsdk.Capability{pluginsdk.CapabilityEmitFindings},
        Broker:       broker,
        Hooks:        plugin.Hooks(),
    }

    if _, err := pluginsdk.RunLocal(context.Background(), cfg); err != nil {
        t.Fatalf("RunLocal: %v", err)
    }
}
