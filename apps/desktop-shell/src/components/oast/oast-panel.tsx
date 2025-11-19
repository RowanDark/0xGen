import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { RefreshCw, Settings, X, Radio, RadioOff } from 'lucide-react';
import { useOAST, type Interaction } from '../../lib/use-oast';
import { InteractionList } from './interaction-list';
import { InteractionDetail } from './interaction-detail';
import { OASTSettings } from './oast-settings';
import { cn } from '../../lib/utils';

interface OASTPanelProps {
  className?: string;
}

export function OASTPanel({ className }: OASTPanelProps) {
  const { isEnabled, status, interactions, stats, refresh, loading } = useOAST();

  const [selectedInteraction, setSelectedInteraction] = useState<Interaction | null>(null);
  const [showSettings, setShowSettings] = useState(false);

  if (!isEnabled) {
    return (
      <div className={cn('flex flex-col items-center justify-center p-8', className)}>
        <div className="text-center">
          <RadioOff className="mx-auto h-12 w-12 text-muted-foreground/50" />
          <h3 className="mt-4 text-lg font-semibold">OAST is Disabled</h3>
          <p className="mt-2 text-sm text-muted-foreground">
            Enable OAST to detect blind vulnerabilities
          </p>
          <button
            onClick={() => setShowSettings(true)}
            className="mt-4 inline-flex items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            Enable OAST
          </button>
        </div>

        <AnimatePresence>
          {showSettings && (
            <OASTSettings
              onClose={() => setShowSettings(false)}
              onSave={() => {
                setShowSettings(false);
              }}
            />
          )}
        </AnimatePresence>
      </div>
    );
  }

  return (
    <div className={cn('flex h-full flex-col', className)}>
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span
              className={cn(
                'h-2 w-2 rounded-full',
                status?.running ? 'bg-success animate-pulse' : 'bg-muted-foreground'
              )}
            />
            <span className="text-sm font-medium">
              {status?.running ? `Running on :${status.port}` : 'Stopped'}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-3 text-xs text-muted-foreground">
            <span>
              <span className="font-medium text-foreground">{stats.total}</span> total
            </span>
            <span>
              <span className="font-medium text-foreground">{stats.uniqueIDs}</span> unique
            </span>
          </div>

          <div className="flex items-center gap-1">
            <button
              onClick={() => void refresh()}
              disabled={loading}
              className="inline-flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
              title="Refresh"
            >
              <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
            </button>
            <button
              onClick={() => setShowSettings(true)}
              className="inline-flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              title="Settings"
            >
              <Settings className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="flex flex-1 overflow-hidden">
        {/* Interaction List */}
        <div className="w-1/2 overflow-auto border-r border-border">
          <InteractionList
            interactions={interactions}
            selectedId={selectedInteraction?.id}
            onSelect={setSelectedInteraction}
          />
        </div>

        {/* Interaction Detail */}
        <div className="w-1/2 overflow-auto">
          {selectedInteraction ? (
            <InteractionDetail
              interaction={selectedInteraction}
              onClose={() => setSelectedInteraction(null)}
            />
          ) : (
            <div className="flex h-full items-center justify-center p-8 text-center">
              <div>
                <Radio className="mx-auto h-8 w-8 text-muted-foreground/50" />
                <p className="mt-2 text-sm text-muted-foreground">
                  Select an interaction to view details
                </p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Settings Modal */}
      <AnimatePresence>
        {showSettings && (
          <OASTSettings
            onClose={() => setShowSettings(false)}
            onSave={() => {
              setShowSettings(false);
            }}
          />
        )}
      </AnimatePresence>
    </div>
  );
}
