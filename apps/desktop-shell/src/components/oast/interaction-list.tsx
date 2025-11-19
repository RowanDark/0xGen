import React from 'react';
import { formatDistanceToNow } from 'date-fns';
import { Inbox } from 'lucide-react';
import type { Interaction } from '../../lib/use-oast';
import { cn } from '../../lib/utils';

interface InteractionListProps {
  interactions: Interaction[];
  selectedId?: string;
  onSelect: (interaction: Interaction) => void;
}

export function InteractionList({ interactions, selectedId, onSelect }: InteractionListProps) {
  if (interactions.length === 0) {
    return (
      <div className="flex h-full flex-col items-center justify-center p-8 text-center">
        <Inbox className="h-8 w-8 text-muted-foreground/50" />
        <p className="mt-2 text-sm font-medium text-muted-foreground">No interactions yet</p>
        <p className="mt-1 text-xs text-muted-foreground/75">
          Callbacks will appear here in real-time
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col">
      {/* Header */}
      <div className="sticky top-0 z-10 flex items-center gap-2 border-b border-border bg-background/95 px-3 py-2 text-xs font-medium text-muted-foreground backdrop-blur">
        <span className="w-24">Time</span>
        <span className="flex-1">Callback ID</span>
        <span className="w-16 text-center">Type</span>
        <span className="w-16 text-center">Method</span>
        <span className="w-24">Client IP</span>
      </div>

      {/* List */}
      <div className="divide-y divide-border">
        {interactions.map((interaction, index) => (
          <button
            key={`${interaction.id}-${interaction.timestamp}-${index}`}
            onClick={() => onSelect(interaction)}
            className={cn(
              'flex w-full items-center gap-2 px-3 py-2 text-left text-sm transition-colors hover:bg-accent/50',
              selectedId === interaction.id && 'bg-accent'
            )}
          >
            <span
              className="w-24 truncate text-xs text-muted-foreground"
              title={interaction.timestamp}
            >
              {formatDistanceToNow(new Date(interaction.timestamp), { addSuffix: true })}
            </span>

            <span className="flex-1 truncate font-mono text-xs">
              {shortenID(interaction.id)}
            </span>

            <span className="w-16 text-center">
              <span
                className={cn(
                  'inline-flex rounded-full px-2 py-0.5 text-xs font-medium',
                  getTypeBadgeClass(interaction.type)
                )}
              >
                {interaction.type.toUpperCase()}
              </span>
            </span>

            <span className="w-16 text-center font-mono text-xs text-muted-foreground">
              {interaction.method || '-'}
            </span>

            <span className="w-24 truncate text-xs text-muted-foreground">
              {interaction.clientIP}
            </span>
          </button>
        ))}
      </div>
    </div>
  );
}

function shortenID(id: string): string {
  if (id.length <= 20) return id;
  return `${id.substring(0, 8)}...${id.substring(id.length - 8)}`;
}

function getTypeBadgeClass(type: string): string {
  switch (type.toLowerCase()) {
    case 'http':
      return 'bg-primary/10 text-primary border border-primary/20';
    case 'dns':
      return 'bg-success/10 text-success border border-success/20';
    case 'smtp':
      return 'bg-warning/10 text-warning border border-warning/20';
    default:
      return 'bg-muted text-muted-foreground border border-border';
  }
}
