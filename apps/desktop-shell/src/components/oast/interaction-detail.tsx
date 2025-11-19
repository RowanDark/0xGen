import React from 'react';
import { Copy, Download, X, ExternalLink } from 'lucide-react';
import type { Interaction } from '../../lib/use-oast';
import { cn } from '../../lib/utils';

interface InteractionDetailProps {
  interaction: Interaction;
  onClose?: () => void;
}

export function InteractionDetail({ interaction, onClose }: InteractionDetailProps) {
  const handleCopyJSON = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(interaction, null, 2));
    } catch (err) {
      console.error('Failed to copy to clipboard:', err);
    }
  };

  const handleExport = () => {
    const blob = new Blob([JSON.stringify(interaction, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `interaction-${interaction.id}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex h-full flex-col">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <h3 className="text-sm font-semibold">Interaction Details</h3>
        <div className="flex items-center gap-1">
          <button
            onClick={handleCopyJSON}
            className="inline-flex h-7 items-center gap-1.5 rounded-md px-2 text-xs text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground"
            title="Copy JSON"
          >
            <Copy className="h-3.5 w-3.5" />
            Copy
          </button>
          <button
            onClick={handleExport}
            className="inline-flex h-7 items-center gap-1.5 rounded-md px-2 text-xs text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground"
            title="Export"
          >
            <Download className="h-3.5 w-3.5" />
            Export
          </button>
          {onClose && (
            <button
              onClick={onClose}
              className="ml-1 inline-flex h-7 w-7 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground"
              title="Close"
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto p-4">
        <div className="space-y-6">
          {/* Overview Section */}
          <section>
            <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Overview
            </h4>
            <dl className="space-y-2">
              <DetailRow label="Callback ID">
                <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
                  {interaction.id}
                </code>
              </DetailRow>

              <DetailRow label="Type">
                <span
                  className={cn(
                    'inline-flex rounded-full px-2 py-0.5 text-xs font-medium',
                    getTypeBadgeClass(interaction.type)
                  )}
                >
                  {interaction.type}
                </span>
              </DetailRow>

              <DetailRow label="Timestamp">
                {new Date(interaction.timestamp).toLocaleString()}
              </DetailRow>

              <DetailRow label="Client IP">{interaction.clientIP}</DetailRow>

              {interaction.userAgent && (
                <DetailRow label="User Agent">
                  <span className="text-xs">{interaction.userAgent}</span>
                </DetailRow>
              )}
            </dl>
          </section>

          {/* HTTP Request Section */}
          {interaction.type === 'http' && (
            <section>
              <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                HTTP Request
              </h4>
              <dl className="space-y-2">
                <DetailRow label="Method">
                  <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
                    {interaction.method}
                  </code>
                </DetailRow>

                <DetailRow label="Path">
                  <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
                    {interaction.path}
                  </code>
                </DetailRow>

                {interaction.query && (
                  <DetailRow label="Query">
                    <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
                      {interaction.query}
                    </code>
                  </DetailRow>
                )}
              </dl>
            </section>
          )}

          {/* Headers Section */}
          {interaction.headers && Object.keys(interaction.headers).length > 0 && (
            <section>
              <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Headers
              </h4>
              <pre className="overflow-x-auto rounded-md bg-muted p-3 font-mono text-xs">
                {formatHeaders(interaction.headers)}
              </pre>
            </section>
          )}

          {/* Body Section */}
          {interaction.body && (
            <section>
              <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Body
              </h4>
              <pre className="max-h-48 overflow-auto rounded-md bg-muted p-3 font-mono text-xs">
                {interaction.body}
              </pre>
            </section>
          )}

          {/* Linked Test Section */}
          {interaction.testID && (
            <section>
              <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Linked Test
              </h4>
              <a
                href={`#/tests/${interaction.testID}`}
                className="inline-flex items-center gap-1.5 text-sm text-primary hover:underline"
              >
                View test {interaction.testID}
                <ExternalLink className="h-3.5 w-3.5" />
              </a>
            </section>
          )}
        </div>
      </div>
    </div>
  );
}

interface DetailRowProps {
  label: string;
  children: React.ReactNode;
}

function DetailRow({ label, children }: DetailRowProps) {
  return (
    <div className="flex items-start gap-2">
      <dt className="w-24 shrink-0 text-xs text-muted-foreground">{label}:</dt>
      <dd className="text-sm">{children}</dd>
    </div>
  );
}

function formatHeaders(headers: Record<string, string[]>): string {
  return Object.entries(headers)
    .map(([key, values]) => `${key}: ${values.join(', ')}`)
    .join('\n');
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
