package plugin

import (
    "context"
    "errors"

    pluginsdk "github.com/RowanDark/0xgen/sdk/plugin-sdk"
)

func Hooks() pluginsdk.Hooks {
    return pluginsdk.Hooks{
        OnStart:       onStart,
        OnHTTPPassive: onHTTPPassive,
    }
}

func onStart(ctx *pluginsdk.Context) error {
    if CapabilityMacros.WorkspaceRead {
        if err := pluginsdk.UseFilesystem(ctx, pluginsdk.CapabilityWorkspaceRead, func(fs pluginsdk.FilesystemBroker) error {
            data, err := fs.ReadFile(context.Background(), "task.json")
            if errors.Is(err, pluginsdk.ErrNotFound) {
                ctx.Logger().Info("no task file provided")
                return nil
            }
            if err != nil {
                return err
            }
            ctx.Logger().Info("loaded task file", "bytes", len(data))
            return nil
        }); err != nil {
            var capErr pluginsdk.CapabilityError
            if !errors.As(err, &capErr) && !errors.Is(err, pluginsdk.ErrBrokerUnavailable) {
                return err
            }
            ctx.Logger().Warn("filesystem capability unavailable", "error", err)
        }
    } else {
        ctx.Logger().Info("workspace read capability disabled; skipping task.json load")
    }

    if CapabilityMacros.SecretsRead {
        if err := pluginsdk.UseSecrets(ctx, func(secrets pluginsdk.SecretsBroker) error {
            secret, err := secrets.Get(context.Background(), "API_TOKEN")
            if errors.Is(err, pluginsdk.ErrNotFound) {
                ctx.Logger().Info("API_TOKEN not provisioned")
                return nil
            }
            if err != nil {
                return err
            }
            ctx.Logger().Info("secret retrieved", "name", "API_TOKEN", "length", len(secret))
            return nil
        }); err != nil {
            var capErr pluginsdk.CapabilityError
            if !errors.As(err, &capErr) && !errors.Is(err, pluginsdk.ErrBrokerUnavailable) {
                return err
            }
            ctx.Logger().Warn("secrets capability unavailable", "error", err)
        }
    } else {
        ctx.Logger().Info("secrets capability disabled; skipping API_TOKEN lookup")
    }

    return nil
}

func onHTTPPassive(ctx *pluginsdk.Context, event pluginsdk.HTTPPassiveEvent) error {
    if event.Response != nil {
        ctx.Logger().Info("passive response", "status", event.Response.StatusLine)
    }

    if CapabilityMacros.NetOutbound {
        if err := pluginsdk.UseNetwork(ctx, func(net pluginsdk.NetworkBroker) error {
            _, err := net.Do(context.Background(), pluginsdk.HTTPRequest{Method: "HEAD", URL: "https://example.com/health"})
            return err
        }); err != nil {
            var capErr pluginsdk.CapabilityError
            if !errors.As(err, &capErr) && !errors.Is(err, pluginsdk.ErrBrokerUnavailable) {
                return err
            }
            ctx.Logger().Warn("network capability unavailable", "error", err)
        }
    } else {
        ctx.Logger().Info("network capability disabled; skipping outbound HEAD request")
    }

    return ctx.EmitFinding(pluginsdk.Finding{Type: "observation", Message: "passive HTTP event observed"})
}
