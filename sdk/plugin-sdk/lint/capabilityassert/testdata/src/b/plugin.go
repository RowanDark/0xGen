package b

import (
	"context"

	pluginsdk "github.com/RowanDark/Glyph/sdk/plugin-sdk"
)

func doNetwork(ctx *pluginsdk.Context) error {
	return pluginsdk.UseNetwork(ctx, func(net pluginsdk.NetworkBroker) error {
		_, err := net.Do(context.Background(), pluginsdk.HTTPRequest{Method: "HEAD", URL: "https://example.com"})
		return err
	})
}

func readWorkspace(ctx *pluginsdk.Context) error {
	return pluginsdk.UseFilesystem(ctx, pluginsdk.CapabilityWorkspaceRead, func(fs pluginsdk.FilesystemBroker) error {
		_, err := fs.ReadFile(context.Background(), "task.json")
		return err
	})
}

func guardedNetwork(ctx *pluginsdk.Context) error {
	if CapabilityMacros.NetOutbound {
		return pluginsdk.UseNetwork(ctx, func(net pluginsdk.NetworkBroker) error {
			_, err := net.Do(context.Background(), pluginsdk.HTTPRequest{Method: "GET", URL: "https://example.com/ping"})
			return err
		})
	}
	return nil
}

var debug bool

func networkWithDebug(ctx *pluginsdk.Context) error {
	if CapabilityMacros.NetOutbound || debug {
		return pluginsdk.UseNetwork(ctx, func(net pluginsdk.NetworkBroker) error {
			_, err := net.Do(context.Background(), pluginsdk.HTTPRequest{Method: "GET", URL: "https://example.com/ping"})
			return err
		}) // want "use pluginsdk.UseNetwork with CAP_NET_OUTBOUND"
	}
	return nil
}

func negatedCapability(ctx *pluginsdk.Context) error {
	if !CapabilityMacros.NetOutbound {
		return pluginsdk.UseNetwork(ctx, func(net pluginsdk.NetworkBroker) error {
			_, err := net.Do(context.Background(), pluginsdk.HTTPRequest{Method: "GET", URL: "https://example.com/ping"})
			return err
		}) // want "use pluginsdk.UseNetwork with CAP_NET_OUTBOUND"
	}
	return nil
}
