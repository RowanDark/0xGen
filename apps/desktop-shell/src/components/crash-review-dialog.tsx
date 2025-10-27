import { useEffect, useMemo, useRef, type ReactNode } from 'react';
import { motion } from 'framer-motion';
import { AlertTriangle, Copy, Download, Trash2 } from 'lucide-react';

import { Button } from './ui/button';
import type { CrashBundleSummary } from '../types/crash';
import { useTheme } from '../providers/theme-provider';

export type CrashPreviewEntry =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'ready'; content: string; truncated?: boolean }
  | { status: 'error'; error: string };

interface CrashReviewDialogProps {
  bundle: CrashBundleSummary;
  previews: Record<string, CrashPreviewEntry>;
  saving: boolean;
  onRequestPreview: (path: string) => void;
  onSave: () => void;
  onDiscard: () => void;
  onCopy: (value: string, label: string) => void;
}

export function CrashReviewDialog({
  bundle,
  previews,
  saving,
  onRequestPreview,
  onSave,
  onDiscard,
  onCopy,
}: CrashReviewDialogProps) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const { prefersReducedMotion } = useTheme();

  useEffect(() => {
    dialogRef.current?.focus();
  }, []);

  const capturedAt = useMemo(() => new Date(bundle.createdAt), [bundle.createdAt]);
  const formattedCapturedAt = useMemo(() => formatTimestamp(capturedAt), [capturedAt]);

  const duration = prefersReducedMotion ? 0 : 0.2;

  return (
    <motion.div
      className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration, ease: prefersReducedMotion ? 'linear' : [0.16, 1, 0.3, 1] }}
    >
      <motion.div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="crash-review-title"
        tabIndex={-1}
        className="mx-4 w-full max-w-3xl rounded-lg border border-border bg-background p-6 shadow-xl focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        initial={{ scale: prefersReducedMotion ? 1 : 0.96, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: prefersReducedMotion ? 1 : 0.96, opacity: 0 }}
        transition={{ duration, ease: prefersReducedMotion ? 'linear' : [0.16, 1, 0.3, 1] }}
      >
        <div className="space-y-2">
          <p className="text-sm font-semibold uppercase tracking-wide text-destructive">Crash detected</p>
          <h2 id="crash-review-title" className="text-2xl font-semibold">
            Review crash bundle
          </h2>
          <p className="text-sm text-muted-foreground">{bundle.reason.message}</p>
        </div>

        <div className="mt-4 space-y-3">
          <MetadataRow
            label="Crash ID"
            value={<code className="rounded bg-muted px-1.5 py-0.5 text-xs">{bundle.id}</code>}
            actionLabel="Crash ID"
            onCopy={() => onCopy(bundle.id, 'Crash ID')}
          />
          <MetadataRow
            label="Captured at"
            value={<span className="text-sm text-muted-foreground">{formattedCapturedAt}</span>}
          />
          <MetadataRow
            label="Crash directory"
            value={
              <code className="block truncate rounded bg-muted px-1.5 py-0.5 text-xs" title={bundle.directory}>
                {bundle.directory}
              </code>
            }
            actionLabel="Bundle path"
            onCopy={() => onCopy(bundle.directory, 'Bundle path')}
          />
          {bundle.reason.location ? (
            <MetadataRow
              label="Source location"
              value={<span className="text-sm text-muted-foreground">{bundle.reason.location}</span>}
            />
          ) : null}
        </div>

        {bundle.reason.stack ? (
          <details className="mt-4 rounded-lg border border-border bg-muted/30 p-4">
            <summary className="cursor-pointer text-sm font-medium">View stack trace</summary>
            <pre className="mt-3 max-h-60 overflow-y-auto whitespace-pre-wrap break-words text-xs font-mono text-muted-foreground">
              {bundle.reason.stack}
            </pre>
          </details>
        ) : null}

        <div className="mt-4 flex items-start gap-3 rounded-lg border border-amber-300 bg-amber-50 p-4 text-sm text-amber-900 dark:border-amber-600 dark:bg-amber-950/40 dark:text-amber-50">
          <AlertTriangle className="mt-0.5 h-5 w-5 flex-shrink-0" aria-hidden="true" />
          <p>
            Review each file before saving. Sensitive fields have been redacted; expanding a file shows the exact text that will be
            included in the bundle.
          </p>
        </div>

        <section className="mt-5">
          <h3 className="text-lg font-semibold">Bundle contents</h3>
          <p className="text-sm text-muted-foreground">
            Expand a file to preview it. Previews are limited to 256 KB to keep the review accessible.
          </p>
          <div className="mt-3 max-h-72 space-y-3 overflow-y-auto rounded-lg border border-border bg-muted/30 p-3">
            {bundle.files.length === 0 ? (
              <p className="text-sm text-muted-foreground">No files were captured for this crash.</p>
            ) : (
              bundle.files.map((file) => {
                const preview = previews[file.path] ?? { status: 'idle' };
                return (
                  <details
                    key={file.path}
                    className="group rounded border border-border bg-background"
                    onToggle={(event) => {
                      if ((event.currentTarget as HTMLDetailsElement).open && preview.status === 'idle') {
                        onRequestPreview(file.path);
                      }
                    }}
                  >
                    <summary className="flex cursor-pointer items-start justify-between gap-4 px-4 py-3 text-sm font-medium">
                      <span className="flex flex-col gap-1 text-left">
                        <span className="font-semibold text-foreground">{file.path}</span>
                        <span className="text-xs font-normal text-muted-foreground">{file.description}</span>
                      </span>
                      <span className="text-xs text-muted-foreground">{formatBytes(file.bytes)}</span>
                    </summary>
                    <div className="border-t border-border bg-muted/40 p-4 text-sm">
                      <PreviewContent entry={preview} />
                    </div>
                  </details>
                );
              })
            )}
          </div>
        </section>

        <div className="mt-6 flex flex-wrap justify-end gap-2">
          <Button variant="destructive" onClick={onDiscard} className="flex items-center gap-2">
            <Trash2 className="h-4 w-4" aria-hidden="true" />
            Discard bundle
          </Button>
          <Button onClick={onSave} disabled={saving} className="flex items-center gap-2">
            <Download className="h-4 w-4" aria-hidden="true" />
            {saving ? 'Saving…' : 'Save bundle'}
          </Button>
        </div>
      </motion.div>
    </motion.div>
  );
}

interface MetadataRowProps {
  label: string;
  value: ReactNode;
  actionLabel?: string;
  onCopy?: () => void;
}

function MetadataRow({ label, value, actionLabel, onCopy }: MetadataRowProps) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
      <div className="flex flex-col">
        <span className="font-medium text-foreground">{label}</span>
        <span>{value}</span>
      </div>
      {onCopy && actionLabel ? (
        <Button variant="outline" size="sm" className="flex items-center gap-2" onClick={onCopy}>
          <Copy className="h-4 w-4" aria-hidden="true" />
          Copy {actionLabel}
        </Button>
      ) : null}
    </div>
  );
}

function PreviewContent({ entry }: { entry: CrashPreviewEntry }) {
  if (entry.status === 'idle') {
    return <p className="text-sm text-muted-foreground">Expand the file to load its preview.</p>;
  }

  if (entry.status === 'loading') {
    return <p className="animate-pulse text-sm text-muted-foreground">Loading preview…</p>;
  }

  if (entry.status === 'error') {
    return <p className="text-sm text-destructive">Failed to load preview: {entry.error}</p>;
  }

  return (
    <div className="space-y-3">
      <pre className="max-h-60 overflow-y-auto whitespace-pre-wrap break-words text-xs font-mono text-foreground">
        {entry.content}
      </pre>
      {entry.truncated ? (
        <p className="text-xs text-muted-foreground">
          Preview truncated to 256 KB. The saved bundle will still include the full file.
        </p>
      ) : null}
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes === 0) {
    return '0 B';
  }
  const units = ['B', 'KB', 'MB', 'GB'];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, exponent);
  return `${value.toFixed(exponent === 0 ? 0 : 1)} ${units[exponent]}`;
}

function formatTimestamp(date: Date): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'long',
  }).format(date);
}
