import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { X } from 'lucide-react';
import { cn } from '../../lib/utils';

interface OASTSettingsProps {
  onClose: () => void;
  onSave: (config: OASTConfig) => void;
}

interface OASTConfig {
  enabled: boolean;
  mode: 'local' | 'selfhosted' | 'cloud';
  port: number;
  host: string;
  timeout: number;
}

export function OASTSettings({ onClose, onSave }: OASTSettingsProps) {
  const [config, setConfig] = useState<OASTConfig>({
    enabled: true,
    mode: 'local',
    port: 0,
    host: 'localhost',
    timeout: 5,
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSave(config);
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.95, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.95, opacity: 0 }}
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-md rounded-lg border border-border bg-card p-6 shadow-lg"
        role="dialog"
        aria-modal="true"
        aria-labelledby="oast-settings-title"
      >
        <div className="mb-4 flex items-center justify-between">
          <h2 id="oast-settings-title" className="text-lg font-semibold">
            OAST Settings
          </h2>
          <button
            onClick={onClose}
            className="inline-flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Enable/Disable */}
          <div className="flex items-center justify-between">
            <label htmlFor="oast-enabled" className="text-sm font-medium">
              Enable OAST
            </label>
            <button
              type="button"
              id="oast-enabled"
              role="switch"
              aria-checked={config.enabled}
              onClick={() => setConfig((prev) => ({ ...prev, enabled: !prev.enabled }))}
              className={cn(
                'relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2',
                config.enabled ? 'bg-primary' : 'bg-input'
              )}
            >
              <span
                className={cn(
                  'pointer-events-none block h-5 w-5 rounded-full bg-background shadow-lg ring-0 transition-transform',
                  config.enabled ? 'translate-x-5' : 'translate-x-0'
                )}
              />
            </button>
          </div>

          {/* Mode */}
          <div>
            <label htmlFor="oast-mode" className="mb-2 block text-sm font-medium">
              Mode
            </label>
            <select
              id="oast-mode"
              value={config.mode}
              onChange={(e) =>
                setConfig((prev) => ({
                  ...prev,
                  mode: e.target.value as OASTConfig['mode'],
                }))
              }
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              disabled={!config.enabled}
            >
              <option value="local">Local Server</option>
              <option value="selfhosted">Self-Hosted</option>
              <option value="cloud">Cloud (Coming Soon)</option>
            </select>
          </div>

          {/* Host */}
          <div>
            <label htmlFor="oast-host" className="mb-2 block text-sm font-medium">
              Host
            </label>
            <input
              type="text"
              id="oast-host"
              value={config.host}
              onChange={(e) => setConfig((prev) => ({ ...prev, host: e.target.value }))}
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              placeholder="localhost"
              disabled={!config.enabled}
            />
          </div>

          {/* Port */}
          <div>
            <label htmlFor="oast-port" className="mb-2 block text-sm font-medium">
              Port
            </label>
            <input
              type="number"
              id="oast-port"
              value={config.port}
              onChange={(e) =>
                setConfig((prev) => ({ ...prev, port: parseInt(e.target.value, 10) || 0 }))
              }
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              placeholder="0 (auto)"
              min={0}
              max={65535}
              disabled={!config.enabled}
            />
            <p className="mt-1 text-xs text-muted-foreground">Use 0 for automatic port selection</p>
          </div>

          {/* Timeout */}
          <div>
            <label htmlFor="oast-timeout" className="mb-2 block text-sm font-medium">
              Timeout (seconds)
            </label>
            <input
              type="number"
              id="oast-timeout"
              value={config.timeout}
              onChange={(e) =>
                setConfig((prev) => ({ ...prev, timeout: parseInt(e.target.value, 10) || 5 }))
              }
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              min={1}
              max={60}
              disabled={!config.enabled}
            />
          </div>

          {/* Actions */}
          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="inline-flex items-center justify-center rounded-md border border-input bg-background px-4 py-2 text-sm font-medium transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="inline-flex items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              Save
            </button>
          </div>
        </form>
      </motion.div>
    </motion.div>
  );
}
