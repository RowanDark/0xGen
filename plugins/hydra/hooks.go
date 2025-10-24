package main

import (
	"time"

	pluginsdk "github.com/RowanDark/0xgen/sdk/plugin-sdk"
)

func newHydraHooks(now func() time.Time) pluginsdk.Hooks {
	engine := newHydraEngine(now)
	return pluginsdk.Hooks{
		OnStart: func(ctx *pluginsdk.Context) error {
			ctx.Logger().Info("hydra AI analysis initialised", "analyzers", len(engine.analyzers))
			return nil
		},
		OnHTTPPassive: func(ctx *pluginsdk.Context, event pluginsdk.HTTPPassiveEvent) error {
			return engine.process(ctx, event)
		},
	}
}
