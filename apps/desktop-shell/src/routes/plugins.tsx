import { createFileRoute } from '@tanstack/react-router';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { toast } from 'sonner';

import {
  fetchPluginRegistryData,
  installMarketplacePlugin,
  removeMarketplacePlugin,
  type InstalledPluginSummary,
  type PluginRegistry,
  type PluginStatus,
  type RegistryPlugin
} from '../lib/ipc';
import { Button } from '../components/ui/button';
import { cn } from '../lib/utils';

export const Route = createFileRoute('/plugins')({
  component: MarketplaceScreen
});

const capabilityLabels: Record<string, string> = {
  CAP_EMIT_FINDINGS: 'Findings',
  CAP_HTTP_ACTIVE: 'HTTP (active)',
  CAP_HTTP_PASSIVE: 'HTTP (passive)',
  CAP_WS: 'WebSockets',
  CAP_SPIDER: 'Crawler',
  CAP_REPORT: 'Reporting',
  CAP_STORAGE: 'Storage',
  CAP_AI_ANALYSIS: 'AI Analysis',
  CAP_FLOW_INSPECT: 'Flow inspect',
  CAP_FLOW_INSPECT_RAW: 'Raw flow inspect'
};

function getCapabilityLabel(value: string) {
  return capabilityLabels[value] ?? value.replace(/CAP_/g, '').replace(/_/g, ' ').toLowerCase();
}

function MarketplaceScreen() {
  const [registry, setRegistry] = useState<PluginRegistry | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [installing, setInstalling] = useState<string | null>(null);
  const [removing, setRemoving] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchPluginRegistryData();
      setRegistry(data);
      setError(null);
    } catch (rawError) {
      const message = rawError instanceof Error ? rawError.message : String(rawError);
      setError(message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const installedMap = useMemo(() => {
    const map = new Map<string, InstalledPluginSummary>();
    for (const plugin of registry?.installed ?? []) {
      map.set(plugin.id, plugin);
    }
    return map;
  }, [registry]);

  const statusMap = useMemo(() => {
    const map = new Map<string, PluginStatus>();
    for (const entry of registry?.status ?? []) {
      map.set(entry.id, entry);
    }
    return map;
  }, [registry]);

  const handleInstall = useCallback(
    async (plugin: RegistryPlugin, force: boolean) => {
      setInstalling(plugin.id);
      try {
        const result = await installMarketplacePlugin(plugin.id, { force });
        toast.success(
          force ? `Updated ${result.name} to v${result.version}` : `Installed ${result.name} v${result.version}`
        );
        await refresh();
      } catch (rawError) {
        const message = rawError instanceof Error ? rawError.message : String(rawError);
        toast.error(`Failed to install ${plugin.name}`, { description: message });
      } finally {
        setInstalling(null);
      }
    },
    [refresh]
  );

  const handleRemove = useCallback(
    async (plugin: RegistryPlugin) => {
      setRemoving(plugin.id);
      try {
        await removeMarketplacePlugin(plugin.id);
        toast.success(`Removed ${plugin.name}`);
        await refresh();
      } catch (rawError) {
        const message = rawError instanceof Error ? rawError.message : String(rawError);
        toast.error(`Failed to remove ${plugin.name}`, { description: message });
      } finally {
        setRemoving(null);
      }
    },
    [refresh]
  );

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-semibold text-foreground">Plugin Marketplace</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Discover, install, and update plugins without leaving the desktop shell.
        </p>
      </div>

      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <div>
          {registry ? (
            <span>
              Schema {registry.schemaVersion} • Generated {new Date(registry.generatedAt).toLocaleString()}
            </span>
          ) : (
            <span>Marketplace status unavailable</span>
          )}
        </div>
        <Button variant="secondary" size="sm" onClick={() => void refresh()} disabled={loading || installing !== null}>
          Refresh
        </Button>
      </div>

      {loading ? (
        <div className="rounded-md border border-border bg-muted/40 p-6 text-sm text-muted-foreground">
          Loading plugin catalog…
        </div>
      ) : error ? (
        <div className="rounded-md border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive">
          <p className="font-medium">Unable to load plugin registry</p>
          <p className="mt-1 text-xs opacity-80">{error}</p>
        </div>
      ) : registry ? (
        <div className="grid gap-4 lg:grid-cols-2">
          {registry.plugins.map((plugin) => {
            const installed = installedMap.get(plugin.id);
            const status = statusMap.get(plugin.id);
            const compatibility = status?.compatibility ?? 'unknown';
            const canInstall = (status?.compatible ?? true) && compatibility !== 'unsupported';
            const updateAvailable = status?.updateAvailable ?? false;
            const isInstalling = installing === plugin.id;
            const isRemoving = removing === plugin.id;
            const primaryLabel = installed ? (updateAvailable ? 'Update' : 'Reinstall') : 'Install';
            const disablePrimary = isInstalling || (!installed && !canInstall);
            const documentationUrl = plugin.links.documentation ?? plugin.links.readme;

            return (
              <div key={plugin.id} className="flex h-full flex-col justify-between rounded-lg border border-border bg-card p-4">
                <div className="space-y-4">
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <h2 className="text-lg font-semibold text-foreground">{plugin.name}</h2>
                      <p className="text-xs uppercase tracking-wide text-muted-foreground">v{plugin.version}</p>
                    </div>
                    {documentationUrl ? (
                      <a
                        href={documentationUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="text-xs font-medium text-primary hover:underline"
                      >
                        Documentation
                      </a>
                    ) : null}
                  </div>
                  <p className="text-sm text-muted-foreground">{plugin.summary}</p>
                  {plugin.categories.length > 0 ? (
                    <div className="flex flex-wrap gap-2">
                      {plugin.categories.map((category) => (
                        <span
                          key={`${plugin.id}-category-${category}`}
                          className="inline-flex items-center rounded-full bg-muted/60 px-2 py-0.5 text-[0.65rem] font-medium uppercase tracking-wide text-muted-foreground"
                        >
                          {category}
                        </span>
                      ))}
                    </div>
                  ) : null}
                  <div className="flex flex-wrap gap-2">
                    {plugin.capabilities.map((capability) => (
                      <span
                        key={`${plugin.id}-cap-${capability}`}
                        className="inline-flex items-center rounded-full bg-primary/10 px-2 py-0.5 text-[0.7rem] font-semibold text-primary"
                      >
                        {getCapabilityLabel(capability)}
                      </span>
                    ))}
                  </div>
                  <div className="text-xs text-muted-foreground">
                    <p className="font-medium text-foreground">
                      {installed ? `Installed version ${installed.version}` : 'Not currently installed'}
                    </p>
                    <p>
                      Compatibility:{' '}
                      <span
                        className={cn(
                          'font-semibold',
                          compatibility === 'unsupported' && 'text-destructive',
                          compatibility === 'limited' && 'text-amber-500'
                        )}
                      >
                        {compatibility}
                      </span>
                    </p>
                    {updateAvailable ? (
                      <p className="text-emerald-600 dark:text-emerald-400">Update available</p>
                    ) : null}
                  </div>
                </div>

                <div className="mt-6 flex items-center gap-2">
                  <Button onClick={() => void handleInstall(plugin, Boolean(installed))} disabled={disablePrimary}>
                    {isInstalling ? 'Working…' : primaryLabel}
                  </Button>
                  <Button
                    variant="secondary"
                    disabled={!installed || isRemoving}
                    onClick={() => void handleRemove(plugin)}
                  >
                    {isRemoving ? 'Removing…' : 'Remove'}
                  </Button>
                </div>
                {!canInstall && !installed ? (
                  <p className="mt-3 text-xs text-destructive">
                    Installation disabled: marked as {compatibility} for this build.
                  </p>
                ) : null}
              </div>
            );
          })}
        </div>
      ) : (
        <div className="rounded-md border border-border bg-muted/40 p-6 text-sm text-muted-foreground">
          No plugins available in the registry.
        </div>
      )}
    </div>
  );
}
