import { createFileRoute } from '@tanstack/react-router';
import { AnimatePresence, motion } from 'framer-motion';
import { useCallback, useEffect, useMemo, useState, useTransition } from 'react';
import { Download, RefreshCw, Trash2, Camera, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { toast } from 'sonner';

import { Button } from '../components/ui/button';
import { cn } from '../lib/utils';
import {
  captureCaseSnapshot,
  deleteCaseSnapshot,
  listCaseSnapshots,
  loadCaseSnapshot,
  type CaseRecord,
  type CaseSnapshot,
  type CaseSnapshotSummary
} from '../lib/ipc';
import {
  buildCaseDiffJson,
  buildCaseDiffSarif,
  computeCaseDiff,
  type CaseChange,
  type CaseDiffSummary,
  type EvidenceDiff,
  type KeyChange
} from '../lib/case-diff';

function formatDate(value: string) {
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function formatConfidenceValue(value: number | undefined) {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return '0%';
  }
  if (value > 1) {
    const bounded = Math.max(0, Math.min(100, value));
    return `${bounded.toFixed(0)}%`;
  }
  const percentage = Math.max(0, Math.min(1, value)) * 100;
  return `${percentage.toFixed(0)}%`;
}

function downloadFile(filename: string, mime: string, data: string) {
  const blob = new Blob([data], { type: mime });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function SnapshotList({
  snapshots,
  selectedBaseline,
  selectedTarget,
  onBaselineChange,
  onTargetChange,
  onDelete
}: {
  snapshots: CaseSnapshotSummary[];
  selectedBaseline: string;
  selectedTarget: string;
  onBaselineChange: (id: string) => void;
  onTargetChange: (id: string) => void;
  onDelete: (id: string) => void;
}) {
  return (
    <div className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <label className="flex flex-col gap-2 text-sm">
          <span className="font-medium text-muted-foreground">Baseline snapshot</span>
          <select
            value={selectedBaseline}
            onChange={(event) => onBaselineChange(event.target.value)}
            className="rounded-md border border-border bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
          >
            <option value="">Select baseline…</option>
            {snapshots.map((snapshot) => (
              <option key={`baseline-${snapshot.id}`} value={snapshot.id}>
                {formatDate(snapshot.capturedAt)} • {snapshot.caseCount} cases
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-2 text-sm">
          <span className="font-medium text-muted-foreground">Target snapshot</span>
          <select
            value={selectedTarget}
            onChange={(event) => onTargetChange(event.target.value)}
            className="rounded-md border border-border bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
          >
            <option value="">Select target…</option>
            {snapshots.map((snapshot) => (
              <option key={`target-${snapshot.id}`} value={snapshot.id}>
                {formatDate(snapshot.capturedAt)} • {snapshot.caseCount} cases
              </option>
            ))}
          </select>
        </label>
      </div>
      <div className="rounded-lg border border-border">
        <div className="border-b border-border px-4 py-3 text-sm font-semibold uppercase text-muted-foreground">
          Stored snapshots
        </div>
        <ul className="divide-y divide-border">
          {snapshots.map((snapshot) => (
            <li key={snapshot.id} className="flex items-start justify-between gap-4 px-4 py-3 text-sm">
              <div className="space-y-1">
                <p className="font-semibold text-foreground">{snapshot.label}</p>
                <p className="text-muted-foreground">
                  Captured {formatDate(snapshot.capturedAt)} • {snapshot.caseCount}{' '}
                  {snapshot.caseCount === 1 ? 'case' : 'cases'}
                </p>
                <p className="text-xs text-muted-foreground">Hash {snapshot.hash}</p>
              </div>
              <Button
                variant="ghost"
                size="icon"
                className="text-muted-foreground hover:text-destructive"
                onClick={() => onDelete(snapshot.id)}
                title="Delete snapshot"
              >
                <Trash2 className="h-4 w-4" />
              </Button>
            </li>
          ))}
          {snapshots.length === 0 && (
            <li className="px-4 py-6 text-sm text-muted-foreground">No snapshots captured yet.</li>
          )}
        </ul>
      </div>
    </div>
  );
}

function SummaryStat({ label, value, tone }: { label: string; value: number; tone: 'neutral' | 'positive' | 'negative' }) {
  const toneClasses =
    tone === 'positive'
      ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-500'
      : tone === 'negative'
        ? 'border-red-500/40 bg-red-500/10 text-red-500'
        : 'border-border bg-muted/50 text-muted-foreground';
  return (
    <div className={cn('rounded-lg border px-4 py-3 text-center', toneClasses)}>
      <p className="text-xs font-semibold uppercase tracking-wide">{label}</p>
      <p className="mt-1 text-2xl font-semibold">{value}</p>
    </div>
  );
}

function KeyChangeList({ title, items }: { title: string; items: KeyChange[] }) {
  if (items.length === 0) {
    return null;
  }
  return (
    <div className="space-y-2">
      <p className="text-xs font-semibold uppercase text-muted-foreground">{title}</p>
      <div className="overflow-hidden rounded-md border border-border">
        <table className="w-full table-auto text-xs">
          <thead className="bg-muted/60 text-left font-semibold text-muted-foreground">
            <tr>
              <th className="px-3 py-2">Key</th>
              <th className="px-3 py-2">Previous</th>
              <th className="px-3 py-2">Current</th>
              <th className="px-3 py-2">Change</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {items.map((item) => (
              <tr key={`${title}-${item.key}`}>
                <td className="px-3 py-2 font-medium">{item.key}</td>
                <td className="px-3 py-2 text-muted-foreground">{item.before ?? '∅'}</td>
                <td className="px-3 py-2 text-foreground">{item.after ?? '∅'}</td>
                <td className="px-3 py-2 capitalize text-muted-foreground">{item.change}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function EvidenceDiffCard({ diff }: { diff: EvidenceDiff }) {
  const changeTone =
    diff.change === 'added'
      ? 'text-emerald-500'
      : diff.change === 'removed'
        ? 'text-red-500'
        : diff.change === 'changed'
          ? 'text-amber-500'
          : 'text-muted-foreground';
  return (
    <div className="space-y-3 rounded-lg border border-border bg-card p-4">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-semibold text-foreground">
            {diff.plugin} <span className="text-muted-foreground">({diff.type})</span>
          </p>
          <p className={cn('text-xs font-semibold uppercase', changeTone)}>{diff.change}</p>
        </div>
      </div>
      {diff.bodyText && (
        <div>
          <p className="text-xs font-semibold uppercase text-muted-foreground">Body</p>
          <div className="grid gap-3 lg:grid-cols-2">
            <pre className="max-h-56 overflow-auto rounded bg-muted/60 p-3 text-xs text-muted-foreground">
              {diff.bodyText.before || '∅'}
            </pre>
            <pre className="max-h-56 overflow-auto rounded bg-muted/60 p-3 text-xs text-foreground">
              {diff.bodyText.after || '∅'}
            </pre>
          </div>
        </div>
      )}
      <KeyChangeList title="Body metadata" items={diff.bodyMetadata} />
      <KeyChangeList title="Headers" items={diff.headers} />
      <KeyChangeList title="Metadata" items={diff.metadata} />
    </div>
  );
}

function CaseSummaryPanel({ title, caseRecord }: { title: string; caseRecord: CaseRecord }) {
  return (
    <div className="space-y-3 rounded-lg border border-border bg-card p-4">
      <div>
        <p className="text-xs font-semibold uppercase text-muted-foreground">{title}</p>
        <h3 className="text-lg font-semibold text-foreground">{caseRecord.summary}</h3>
      </div>
      <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
        <span className="inline-flex items-center gap-1 rounded-full bg-muted px-2 py-1">
          <AlertTriangle className="h-3.5 w-3.5" />
          Severity {caseRecord.risk?.severity ?? 'informational'}
        </span>
        <span className="inline-flex items-center gap-1 rounded-full bg-muted px-2 py-1">
          <CheckCircle2 className="h-3.5 w-3.5" />
          Confidence {formatConfidenceValue(caseRecord.confidence)}
        </span>
      </div>
      <div className="space-y-1 text-sm text-muted-foreground">
        <p>
          <span className="font-semibold text-foreground">Asset:</span> {caseRecord.asset.kind} · {caseRecord.asset.identifier}
        </p>
        {caseRecord.labels && Object.keys(caseRecord.labels).length > 0 && (
          <p>
            <span className="font-semibold text-foreground">Labels:</span>{' '}
            {Object.entries(caseRecord.labels)
              .map(([key, value]) => (value ? `${key}:${value}` : key))
              .join(', ')}
          </p>
        )}
      </div>
    </div>
  );
}

function CaseChangeDetail({ change }: { change: CaseChange }) {
  return (
    <AnimatePresence mode="wait">
      <motion.div
        key={change.id}
        initial={{ opacity: 0, x: -16 }}
        animate={{ opacity: 1, x: 0 }}
        exit={{ opacity: 0, x: 16 }}
        transition={{ duration: 0.2 }}
        className="space-y-6"
      >
        <div className="grid gap-4 lg:grid-cols-2">
          <CaseSummaryPanel title="Baseline" caseRecord={change.before} />
          <CaseSummaryPanel title="Target" caseRecord={change.after} />
        </div>
        <div className="space-y-4">
          {change.evidenceDiff.length === 0 ? (
            <p className="text-sm text-muted-foreground">Evidence unchanged between snapshots.</p>
          ) : (
            change.evidenceDiff.map((diff) => <EvidenceDiffCard key={diff.key} diff={diff} />)
          )}
        </div>
      </motion.div>
    </AnimatePresence>
  );
}

function CompareRunsRoute() {
  const [snapshots, setSnapshots] = useState<CaseSnapshotSummary[]>([]);
  const [baseline, setBaseline] = useState<CaseSnapshot | null>(null);
  const [target, setTarget] = useState<CaseSnapshot | null>(null);
  const [selectedBaselineId, setSelectedBaselineId] = useState('');
  const [selectedTargetId, setSelectedTargetId] = useState('');
  const [activeChangeId, setActiveChangeId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingSnapshots, setLoadingSnapshots] = useState(false);
  const [isCapturing, startCapture] = useTransition();

  const refreshSnapshots = useCallback(() => {
    setLoading(true);
    listCaseSnapshots()
      .then((list) => {
        setSnapshots(list);
        setLoading(false);
      })
      .catch((error) => {
        console.error('Failed to list case snapshots', error);
        toast.error('Unable to load stored snapshots');
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    refreshSnapshots();
  }, [refreshSnapshots]);

  useEffect(() => {
    if (!selectedBaselineId) {
      setBaseline(null);
      return;
    }
    setLoadingSnapshots(true);
    loadCaseSnapshot(selectedBaselineId)
      .then(setBaseline)
      .catch((error) => {
        console.error('Failed to load baseline snapshot', error);
        toast.error('Unable to load baseline snapshot');
        setBaseline(null);
      })
      .finally(() => setLoadingSnapshots(false));
  }, [selectedBaselineId]);

  useEffect(() => {
    if (!selectedTargetId) {
      setTarget(null);
      return;
    }
    setLoadingSnapshots(true);
    loadCaseSnapshot(selectedTargetId)
      .then(setTarget)
      .catch((error) => {
        console.error('Failed to load target snapshot', error);
        toast.error('Unable to load target snapshot');
        setTarget(null);
      })
      .finally(() => setLoadingSnapshots(false));
  }, [selectedTargetId]);

  const diff = useMemo<CaseDiffSummary | null>(() => {
    if (!baseline || !target) {
      return null;
    }
    try {
      return computeCaseDiff(baseline, target);
    } catch (error) {
      console.error('Failed to compute case diff', error);
      toast.error('Unable to compute diff');
      return null;
    }
  }, [baseline, target]);

  useEffect(() => {
    if (!diff) {
      setActiveChangeId(null);
      return;
    }
    if (diff.changed.length > 0) {
      setActiveChangeId(diff.changed[0].id);
    } else {
      setActiveChangeId(null);
    }
  }, [diff?.baseline.id, diff?.target.id, diff?.changed.length]);

  const activeChange = useMemo(() => diff?.changed.find((item) => item.id === activeChangeId) ?? null, [diff, activeChangeId]);

  const handleCapture = useCallback(() => {
    startCapture(() => {
      captureCaseSnapshot()
        .then((snapshot) => {
          toast.success(`Captured snapshot with ${snapshot.caseCount} cases`);
          refreshSnapshots();
        })
        .catch((error) => {
          console.error('Failed to capture snapshot', error);
          toast.error('Unable to capture snapshot (load an artifact first)');
        });
    });
  }, [refreshSnapshots]);

  const handleDelete = useCallback(
    (id: string) => {
      deleteCaseSnapshot(id)
        .then(() => {
          toast.success('Snapshot deleted');
          if (selectedBaselineId === id) {
            setSelectedBaselineId('');
          }
          if (selectedTargetId === id) {
            setSelectedTargetId('');
          }
          refreshSnapshots();
        })
        .catch((error) => {
          console.error('Failed to delete snapshot', error);
          toast.error('Unable to delete snapshot');
        });
    },
    [refreshSnapshots, selectedBaselineId, selectedTargetId]
  );

  const handleExport = useCallback(
    (format: 'json' | 'sarif') => {
      if (!diff) {
        return;
      }
      try {
        if (format === 'json') {
          const payload = buildCaseDiffJson(diff);
          downloadFile('case-diff.json', 'application/json', JSON.stringify(payload, null, 2));
          toast.success('Exported diff as JSON');
        } else {
          const payload = buildCaseDiffSarif(diff);
          downloadFile('case-diff.sarif', 'application/json', JSON.stringify(payload, null, 2));
          toast.success('Exported diff as SARIF');
        }
      } catch (error) {
        console.error('Failed to export diff', error);
        toast.error('Unable to export diff');
      }
    },
    [diff]
  );

  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-6 p-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-semibold tracking-tight">Compare Runs</h1>
          <p className="text-muted-foreground">
            Capture case snapshots and highlight what changed between investigation runs.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" className="gap-2" onClick={refreshSnapshots} disabled={loading}>
            <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
            Refresh
          </Button>
          <Button className="gap-2" onClick={handleCapture} disabled={isCapturing}>
            <Camera className={cn('h-4 w-4', isCapturing && 'animate-spin')} />
            Capture snapshot
          </Button>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-[320px_1fr]">
        <SnapshotList
          snapshots={snapshots}
          selectedBaseline={selectedBaselineId}
          selectedTarget={selectedTargetId}
          onBaselineChange={setSelectedBaselineId}
          onTargetChange={setSelectedTargetId}
          onDelete={handleDelete}
        />

        <div className="flex flex-col gap-4 rounded-lg border border-border bg-card p-5">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xl font-semibold text-foreground">Diff overview</h2>
              <p className="text-sm text-muted-foreground">
                Select two snapshots to compute differences across cases.
              </p>
            </div>
            <div className="flex gap-2">
              <Button
                variant="secondary"
                className="gap-2"
                disabled={!diff || loadingSnapshots}
                onClick={() => handleExport('json')}
              >
                <Download className="h-4 w-4" /> JSON
              </Button>
              <Button
                variant="secondary"
                className="gap-2"
                disabled={!diff || loadingSnapshots}
                onClick={() => handleExport('sarif')}
              >
                <Download className="h-4 w-4" /> SARIF
              </Button>
            </div>
          </div>

          {!diff && (
            <div className="rounded-md border border-dashed border-border bg-background p-6 text-center text-sm text-muted-foreground">
              Select a baseline and target snapshot to view the diff.
            </div>
          )}

          {diff && (
            <div className="space-y-6">
              <div className="grid gap-3 sm:grid-cols-3">
                <SummaryStat label="New cases" value={diff.added.length} tone="positive" />
                <SummaryStat label="Resolved" value={diff.removed.length} tone="negative" />
                <SummaryStat label="Updated" value={diff.changed.length} tone="neutral" />
              </div>

              <div className="space-y-4">
                <div>
                  <h3 className="text-sm font-semibold uppercase text-muted-foreground">New cases</h3>
                  {diff.added.length === 0 ? (
                    <p className="text-sm text-muted-foreground">No new cases introduced.</p>
                  ) : (
                    <ul className="space-y-2 text-sm">
                      {diff.added.map((item) => (
                        <li key={`added-${item.id}`} className="rounded-md border border-emerald-500/40 bg-emerald-500/10 p-3">
                          <p className="font-semibold text-emerald-600">{item.summary}</p>
                          <p className="text-xs text-emerald-600/80">Severity {item.risk?.severity ?? 'informational'}</p>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
                <div>
                  <h3 className="text-sm font-semibold uppercase text-muted-foreground">Resolved cases</h3>
                  {diff.removed.length === 0 ? (
                    <p className="text-sm text-muted-foreground">No cases resolved.</p>
                  ) : (
                    <ul className="space-y-2 text-sm">
                      {diff.removed.map((item) => (
                        <li key={`removed-${item.id}`} className="rounded-md border border-red-500/40 bg-red-500/10 p-3">
                          <p className="font-semibold text-red-600">{item.summary}</p>
                          <p className="text-xs text-red-600/80">Severity {item.risk?.severity ?? 'informational'}</p>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>

              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold uppercase text-muted-foreground">Updated cases</h3>
                  <span className="text-xs text-muted-foreground">
                    {diff.changed.length === 0 ? 'None' : `${diff.changed.length} case(s) updated`}
                  </span>
                </div>
                {diff.changed.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No existing cases changed.</p>
                ) : (
                  <div className="grid gap-4 lg:grid-cols-[220px_1fr]">
                    <div className="space-y-2">
                      {diff.changed.map((change) => (
                        <button
                          key={change.id}
                          type="button"
                          onClick={() => setActiveChangeId(change.id)}
                          className={cn(
                            'w-full rounded-md border px-3 py-2 text-left text-sm transition hover:border-primary hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary',
                            activeChangeId === change.id ? 'border-primary bg-primary/10 text-primary' : 'border-border'
                          )}
                        >
                          <p className="font-semibold">{change.after.summary}</p>
                          <p className="text-xs text-muted-foreground">{change.changedFields.join(', ') || 'Minor updates'}</p>
                        </button>
                      ))}
                    </div>
                    <div className="min-h-[320px] rounded-lg border border-border bg-background p-4">
                      {activeChange ? (
                        <CaseChangeDetail change={activeChange} />
                      ) : (
                        <p className="text-sm text-muted-foreground">Select a case to inspect detailed changes.</p>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export const Route = createFileRoute('/compare')({
  component: CompareRunsRoute
});

export default CompareRunsRoute;
