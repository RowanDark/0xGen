import { createFileRoute } from '@tanstack/react-router';
import { useVirtualizer } from '@tanstack/react-virtual';
import { useCallback, useEffect, useMemo, useRef, useState, useTransition } from 'react';
import { CheckCircle2, Download, FileCode, Filter, RefreshCw, StickyNote, ThumbsDown, ThumbsUp } from 'lucide-react';
import mermaid from 'mermaid';
import { z } from 'zod';

import { Button } from '../components/ui/button';
import { RedactionNotice } from '../components/redaction-notice';
import { cn, isRedactedValue } from '../lib/utils';
import { toast } from 'sonner';
import { fetchArtifactCases, type CaseRecord } from '../lib/ipc';
import { useArtifact } from '../providers/artifact-provider';
import { useCommandCenter } from '../providers/command-center';
import { useDebouncedValue } from '../lib/use-debounced-value';

export type CaseSeverity = 'critical' | 'high' | 'medium' | 'low' | 'informational';

type CaseEvidence = {
  id: string;
  title: string;
  description: string;
  link?: string;
  type: 'network' | 'log' | 'screenshot' | 'artifact' | 'note';
};

type CaseViewModel = {
  id: string;
  title: string;
  severity: CaseSeverity;
  asset: string;
  tags: string[];
  confidence: number;
  summary: string;
  dedupedFindings: string[];
  recommendedActions: string[];
  evidence: CaseEvidence[];
  reproSteps: string[];
  poc: string;
  graph: string;
  hasRedactions: boolean;
  original: CaseRecord;
};

const severityOrder: Record<CaseSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4
};

const severityCopy: Record<CaseSeverity, { label: string; tone: string }> = {
  critical: { label: 'Critical', tone: 'bg-red-500/10 text-red-500 border-red-500/30' },
  high: { label: 'High', tone: 'bg-amber-500/10 text-amber-500 border-amber-500/30' },
  medium: { label: 'Medium', tone: 'bg-yellow-500/10 text-yellow-600 border-yellow-500/30' },
  low: { label: 'Low', tone: 'bg-sky-500/10 text-sky-500 border-sky-500/30' },
  informational: { label: 'Informational', tone: 'bg-muted text-muted-foreground border-border' }
};

const sarifSchema = z.object({
  version: z.literal('2.1.0'),
  $schema: z.string(),
  runs: z.array(
    z.object({
      tool: z.object({
        driver: z.object({
          name: z.string(),
          informationUri: z.string().optional()
        })
      }),
      artifacts: z
        .array(
          z.object({
            location: z.object({
              uri: z.string()
            }),
            description: z.object({ text: z.string() }).optional()
          })
        )
        .optional(),
      results: z.array(
        z.object({
          ruleId: z.string(),
          level: z.enum(['error', 'warning', 'note']),
          message: z.object({ text: z.string() }),
          locations: z.array(
            z.object({
              physicalLocation: z.object({
                artifactLocation: z.object({ uri: z.string() }),
                region: z.object({ startLine: z.number().int().min(1) }).optional()
              })
            })
          )
        })
      )
    })
  )
});

const jsonlSchema = z.object({
  id: z.string(),
  severity: z.string(),
  asset: z.string(),
  confidence: z.number(),
  summary: z.string()
});

const tabOptions = ['summary', 'evidence', 'repro', 'graph'] as const;
type TabKey = (typeof tabOptions)[number];

function formatConfidence(confidence: number) {
  return `${confidence.toFixed(0)}%`;
}

function severityToSarifLevel(severity: CaseSeverity) {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    default:
      return 'note';
  }
}

function mapSeverity(value: string | undefined): CaseSeverity {
  const normalized = value?.trim().toLowerCase();
  switch (normalized) {
    case 'crit':
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'med':
    case 'medium':
      return 'medium';
    case 'low':
      return 'low';
    default:
      return 'informational';
  }
}

function normaliseConfidence(value: number | undefined): number {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return 0;
  }
  if (value <= 1) {
    return Math.max(0, Math.min(1, value)) * 100;
  }
  if (value > 100) {
    return 100;
  }
  return Math.max(0, Math.min(100, value));
}

function mapEvidence(record: CaseRecord): CaseEvidence[] {
  return record.evidence?.map((item, index) => {
    const typeHint = item.type?.toLowerCase() ?? '';
    let type: CaseEvidence['type'] = 'artifact';
    if (typeHint.includes('screenshot') || typeHint.includes('image')) {
      type = 'screenshot';
    } else if (typeHint.includes('log')) {
      type = 'log';
    } else if (typeHint.includes('http') || typeHint.includes('request') || typeHint.includes('response')) {
      type = 'network';
    }
    return {
      id: `${record.id}-evidence-${index + 1}`,
      title: `${item.plugin} (${item.type})`,
      description: item.message,
      link: undefined,
      type
    };
  }) ?? [];
}

function buildCaseView(record: CaseRecord): CaseViewModel {
  const assetParts = [record.asset.kind, record.asset.identifier].filter((part) => part && part.trim());
  const assetLabel = assetParts.join(': ') || record.asset.details || 'Unknown asset';
  const labels = Object.entries(record.labels ?? {}).map(([key, value]) =>
    value ? `${key}:${value}` : key
  );
  const tags = Array.from(new Set([...labels, record.vector?.kind ?? ''].filter(Boolean))).sort();
  const dedupedFindings = (record.sources ?? []).map((source) =>
    `${source.plugin} ${source.type} (${source.severity})`
  );

  const recommendedActions: string[] = [];
  const confidence = normaliseConfidence(record.confidence);
  const poc = record.proof.summary ?? record.proof.steps?.join('\n') ?? '';
  const graph = record.graph.mermaid || record.graph.dot || '';
  const hasRedactions = isRedactedValue(record);

  return {
    id: record.id,
    title: record.summary,
    severity: mapSeverity(record.risk?.severity),
    asset: assetLabel,
    tags,
    confidence,
    summary: record.summary,
    dedupedFindings,
    recommendedActions,
    evidence: mapEvidence(record),
    reproSteps: record.proof.steps ?? [],
    poc,
    graph,
    hasRedactions,
    original: record
  };
}

function useMermaid(graphDefinition: string) {
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!ref.current) {
      return;
    }

    let isCancelled = false;

    const renderGraph = async () => {
      try {
        mermaid.initialize({ startOnLoad: false, securityLevel: 'strict' });
        const { svg } = await mermaid.render(`graph-${Math.random().toString(16).slice(2)}`, graphDefinition);
        if (!isCancelled && ref.current) {
          ref.current.innerHTML = svg;
        }
      } catch (error) {
        console.error('Failed to render mermaid graph', error);
        if (!isCancelled && ref.current) {
          ref.current.innerHTML = '<pre class="text-destructive">Unable to render graph</pre>';
        }
      }
    };

    void renderGraph();

    return () => {
      isCancelled = true;
    };
  }, [graphDefinition]);

  return ref;
}

function CaseExplorer({ cases }: { cases: CaseViewModel[] }) {
  const [, startTransition] = useTransition();
  const [severityFilter, setSeverityFilter] = useState<CaseSeverity[]>([]);
  const [tagFilter, setTagFilter] = useState<string[]>([]);
  const [tagInput, setTagInput] = useState('');
  const [activeCaseId, setActiveCaseId] = useState(cases[0]?.id ?? '');
  const [activeTab, setActiveTab] = useState<TabKey>('summary');
  const [notes, setNotes] = useState<Record<string, string[]>>({});
  const [noteDraft, setNoteDraft] = useState('');
  const [disposition, setDisposition] = useState<Record<string, 'tp' | 'fp' | undefined>>({});
  const caseListRef = useRef<HTMLDivElement | null>(null);
  const filterInputRef = useRef<HTMLInputElement | null>(null);
  const caseDetailRef = useRef<HTMLDivElement | null>(null);
  const { registerCommand } = useCommandCenter();
  const debouncedTagInput = useDebouncedValue(tagInput, 200);

  useEffect(() => {
    if (cases.length > 0) {
      setActiveCaseId((previous) => (cases.some((item) => item.id === previous) ? previous : cases[0].id));
    } else {
      setActiveCaseId('');
    }
    setNotes({});
    setDisposition({});
    setNoteDraft('');
    setActiveTab('summary');
  }, [cases]);

  const allTags = useMemo(() => Array.from(new Set(cases.flatMap((item) => item.tags))).sort(), [cases]);

  useEffect(() => {
    const values = debouncedTagInput
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean);

    startTransition(() => {
      setTagFilter((previous) => {
        if (previous.length === values.length && previous.every((item, index) => item === values[index])) {
          return previous;
        }
        return values;
      });
    });
  }, [debouncedTagInput, startTransition]);

  const filteredCases = useMemo(() => {
    return cases
      .filter((item) => {
        const severityMatch = severityFilter.length === 0 || severityFilter.includes(item.severity);
        const tagMatch = tagFilter.length === 0 || item.tags.some((tag) => tagFilter.includes(tag));
        return severityMatch && tagMatch;
      })
      .sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  }, [cases, severityFilter, tagFilter]);

  const clearFilters = useCallback(() => {
    startTransition(() => {
      setSeverityFilter([]);
      setTagFilter([]);
    });
    setTagInput('');
  }, [startTransition]);

  const toggleSeverity = useCallback(
    (value: CaseSeverity) => {
      startTransition(() => {
        setSeverityFilter((previous) => {
          const exists = previous.includes(value);
          if (exists) {
            return previous.filter((item) => item !== value);
          }
          return [...previous, value];
        });
      });
    },
    [startTransition]
  );

  const toggleTag = useCallback(
    (value: string) => {
      startTransition(() => {
        setTagFilter((previous) => {
          const exists = previous.includes(value);
          const next = exists ? previous.filter((item) => item !== value) : [...previous, value];
          setTagInput(next.join(', '));
          return next;
        });
      });
    },
    [startTransition]
  );

  useEffect(() => {
    if (!filteredCases.find((item) => item.id === activeCaseId)) {
      setActiveCaseId(filteredCases[0]?.id ?? '');
    }
  }, [filteredCases, activeCaseId]);

  const activeCase = useMemo(
    () => filteredCases.find((item) => item.id === activeCaseId) ?? filteredCases[0],
    [filteredCases, activeCaseId]
  );

  const caseVirtualizer = useVirtualizer({
    count: filteredCases.length,
    getScrollElement: () => caseListRef.current,
    estimateSize: () => 220,
    overscan: 8
  });
  const virtualCaseItems = caseVirtualizer.getVirtualItems();

  const mermaidRef = useMermaid(activeCase?.graph ?? '');

  const escapeHtml = (value: string) =>
    String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');

  const handleExport = async (format: 'sarif' | 'jsonl' | 'html') => {
    if (!activeCase) {
      return;
    }
    if (activeCase.hasRedactions) {
      toast.info('Case content redacted by policy. CAP_SECRETS_READ reveals original data.');
      return;
    }

    try {
      let data = '';
      let mime = 'application/json';
      let filename = `${activeCase.id.toLowerCase()}`;

      if (format === 'sarif') {
        const sarif = {
          version: '2.1.0',
          $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
          runs: [
            {
              tool: {
                driver: {
                  name: '0xgen AI Investigator',
                  informationUri: 'https://0xgen.sh'
                }
              },
              artifacts: activeCase.evidence.map((item) => ({
                location: { uri: item.link ?? item.title.replace(/\s+/g, '-').toLowerCase() },
                description: { text: item.description }
              })),
              results: [
                {
                  ruleId: activeCase.id,
                  level: severityToSarifLevel(activeCase.severity),
                  message: { text: activeCase.summary },
                  locations: [
                    {
                      physicalLocation: {
                        artifactLocation: { uri: activeCase.asset },
                        region: { startLine: 1 }
                      }
                    }
                  ]
                }
              ]
            }
          ]
        } as const;

        sarifSchema.parse(sarif);
        data = JSON.stringify(sarif, null, 2);
        filename += '.sarif';
      } else if (format === 'jsonl') {
        const jsonl = {
          id: activeCase.id,
          severity: activeCase.severity,
          asset: activeCase.asset,
          confidence: activeCase.confidence,
          summary: activeCase.summary
        };
        jsonlSchema.parse(jsonl);
        data = `${JSON.stringify(jsonl)}\n`;
        filename += '.jsonl';
      } else {
        const html = `<!doctype html><html lang="en"><head><meta charset="utf-8" />\n<title>${escapeHtml(
          activeCase.title
        )}</title></head><body>\n<h1>${escapeHtml(activeCase.title)}</h1>\n<p><strong>Severity:</strong> ${escapeHtml(
          severityCopy[activeCase.severity].label
        )}</p>\n<p><strong>Asset:</strong> ${escapeHtml(activeCase.asset)}</p>\n<p>${escapeHtml(activeCase.summary)}</p>\n<h2>Deduped findings</h2><ul>${activeCase.dedupedFindings
          .map((finding) => `<li>${escapeHtml(finding)}</li>`)
          .join('')}</ul>\n</body></html>`;
        data = html;
        mime = 'text/html';
        filename += '.html';
      }

      const blob = new Blob([data], { type: mime });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      toast.success(`Exported case ${activeCase.id} as ${format.toUpperCase()}`);
    } catch (error) {
      console.error('Failed to export case', error);
      toast.error('Unable to export case');
    }
  };

  useEffect(() => {
    const cleanups = [
      registerCommand({
        id: 'cases.focusFilters',
        title: 'Focus case filters',
        description: 'Move focus to the case filter search',
        group: 'Cases',
        shortcut: 'alt+1',
        run: () => {
          if (filterInputRef.current) {
            filterInputRef.current.focus();
            filterInputRef.current.select?.();
          }
        },
        allowInInput: true
      }),
      registerCommand({
        id: 'cases.focusList',
        title: 'Focus case list',
        description: 'Highlight the currently selected case in the list',
        group: 'Cases',
        shortcut: 'alt+2',
        run: () => {
          const container = caseListRef.current;
          if (!container) {
            return;
          }
          const selector = activeCaseId ? `[data-case-id="${activeCaseId}"]` : '[data-case-id]';
          const target = container.querySelector<HTMLButtonElement>(selector);
          if (target) {
            target.focus();
          } else {
            container.focus();
          }
        },
        allowInInput: true
      }),
      registerCommand({
        id: 'cases.focusDetails',
        title: 'Focus case details',
        description: 'Jump to the active case detail panel',
        group: 'Cases',
        shortcut: 'alt+3',
        run: () => {
          caseDetailRef.current?.focus();
        },
        allowInInput: true
      })
    ];

    return () => {
      for (const cleanup of cleanups) {
        cleanup();
      }
    };
  }, [registerCommand, activeCaseId]);

  if (cases.length === 0) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-4 text-center text-muted-foreground">
        <FileCode className="h-10 w-10" />
        <div>
          <h2 className="text-lg font-semibold text-foreground">No cases available</h2>
          <p>Open a replay artifact to review recorded investigations.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-full min-h-0">
      <aside className="w-72 border-r border-border bg-card px-4 py-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold uppercase text-muted-foreground">Filters</h2>
          <Button variant="ghost" size="sm" onClick={clearFilters} className="h-auto px-2 py-1 text-xs">
            Clear
          </Button>
        </div>
        <div className="mt-4 space-y-4">
          <div>
            <label className="text-xs font-semibold uppercase text-muted-foreground" htmlFor="case-search">
              Search
            </label>
            <div className="relative mt-2">
              <Filter className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
              <input
                id="case-search"
                type="search"
                placeholder="Filter by tag"
                ref={filterInputRef}
                className="w-full rounded-md border border-border bg-background py-2 pl-9 pr-3 text-sm text-foreground placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                value={tagInput}
                onChange={(event) => setTagInput(event.target.value)}
              />
            </div>
          </div>
          <FilterGroup
            title="Severity"
            options={Object.entries(severityCopy).map(([key, value]) => ({
              value: key as CaseSeverity,
              label: value.label
            }))}
            selected={severityFilter}
            onToggle={toggleSeverity}
          />
          <FilterGroup
            title="Tags"
            options={allTags.map((tag) => ({ value: tag, label: tag }))}
            selected={tagFilter}
            onToggle={toggleTag}
            emptyLabel="No tags"
          />
        </div>
      </aside>
      <section className="flex min-h-0 flex-1 flex-col">
        <div className="flex min-h-0 flex-1">
          <div
            ref={caseListRef}
            className="w-96 overflow-y-auto border-r border-border"
            tabIndex={-1}
            role="region"
            aria-label="Case list"
          >
            <ul className="relative" role="listbox" aria-label="Cases">
              <li style={{ height: caseVirtualizer.getTotalSize() }} />
              {virtualCaseItems.map((virtualRow) => {
                const item = filteredCases[virtualRow.index];
                if (!item) {
                  return null;
                }
                const isActive = item.id === activeCase?.id;
                return (
                  <li
                    key={item.id}
                    className="absolute inset-x-0"
                    ref={caseVirtualizer.measureElement}
                    style={{ transform: `translateY(${virtualRow.start}px)` }}
                  >
                    <button
                      type="button"
                      onClick={() => setActiveCaseId(item.id)}
                      data-case-id={item.id}
                      role="option"
                      aria-selected={isActive}
                      tabIndex={isActive ? 0 : -1}
                      className={cn(
                        'flex w-full flex-col gap-3 border-b border-border bg-card p-4 text-left transition hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2',
                        isActive && 'border-primary bg-primary/10'
                      )}
                    >
                      <div className="flex items-center justify-between">
                        <h3 className="text-sm font-semibold text-foreground">{item.title}</h3>
                        <span
                          className={cn(
                            'rounded-full border px-2 py-0.5 text-xs font-semibold uppercase',
                            severityCopy[item.severity].tone
                          )}
                        >
                          {severityCopy[item.severity].label}
                        </span>
                      </div>
                      <p className="mt-2 line-clamp-3 text-xs text-muted-foreground">{item.summary}</p>
                      <div className="mt-3 flex flex-wrap gap-2">
                        <span className="rounded bg-secondary px-2 py-1 text-xs text-secondary-foreground">
                          {item.asset}
                        </span>
                        <span className="rounded bg-muted px-2 py-1 text-xs text-muted-foreground">
                          Confidence {formatConfidence(item.confidence)}
                        </span>
                        {item.tags.map((tag) => (
                          <span key={tag} className="rounded bg-muted px-2 py-1 text-xs text-muted-foreground">
                            {tag}
                          </span>
                        ))}
                      </div>
                    </button>
                  </li>
                );
              })}
            </ul>
          </div>
          <div className="flex flex-1 flex-col overflow-y-auto">
            {activeCase ? (
              <article
                ref={caseDetailRef}
                className="flex-1 space-y-6 overflow-y-auto p-6"
                tabIndex={-1}
                role="region"
                aria-label="Case details"
              >
                <header className="space-y-4">
                  <div className="flex items-center justify-between gap-4">
                    <div>
                      <div className="flex items-center gap-2 text-xs text-muted-foreground">
                        <span className="font-semibold uppercase">Case ID</span>
                        <span>{activeCase.id}</span>
                      </div>
                      <h1 className="mt-2 text-2xl font-semibold text-foreground">{activeCase.title}</h1>
                    </div>
                    <div className="flex items-center gap-2">
                      <Button
                        size="sm"
                        variant="secondary"
                        className="gap-2"
                        onClick={() => handleExport('sarif')}
                        disabled={activeCase.hasRedactions}
                        title={
                          activeCase.hasRedactions
                            ? 'Case content redacted by policy (requires CAP_SECRETS_READ)'
                            : undefined
                        }
                      >
                        <Download className="h-4 w-4" />
                        Export SARIF
                      </Button>
                      <Button
                        size="sm"
                        variant="secondary"
                        className="gap-2"
                        onClick={() => handleExport('jsonl')}
                        disabled={activeCase.hasRedactions}
                        title={
                          activeCase.hasRedactions
                            ? 'Case content redacted by policy (requires CAP_SECRETS_READ)'
                            : undefined
                        }
                      >
                        <FileCode className="h-4 w-4" />
                        Export JSONL
                      </Button>
                      <Button
                        size="sm"
                        variant="secondary"
                        className="gap-2"
                        onClick={() => handleExport('html')}
                        disabled={activeCase.hasRedactions}
                        title={
                          activeCase.hasRedactions
                            ? 'Case content redacted by policy (requires CAP_SECRETS_READ)'
                            : undefined
                        }
                      >
                        <Download className="h-4 w-4" />
                        Export HTML
                      </Button>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-3 text-sm text-muted-foreground">
                    <span className="inline-flex items-center gap-2">
                      <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                      Confidence {formatConfidence(activeCase.confidence)}
                    </span>
                    <span className="inline-flex items-center gap-2">
                      <StickyNote className="h-4 w-4" />
                      {activeCase.asset}
                    </span>
                    <span className="inline-flex items-center gap-2">
                      <Filter className="h-4 w-4" />
                      {severityCopy[activeCase.severity].label}
                    </span>
                  </div>
                </header>

                {activeCase.hasRedactions && (
                  <RedactionNotice
                    capability="CAP_SECRETS_READ"
                    className="mt-4"
                    message="Case content redacted by policy"
                  />
                )}

                <div className="border-b border-border">
                  <nav className="flex gap-4 text-sm font-medium">
                    {tabOptions.map((tab) => (
                      <button
                        key={tab}
                        type="button"
                        onClick={() => setActiveTab(tab)}
                        className={cn(
                          'border-b-2 pb-2 transition',
                          activeTab === tab ? 'border-primary text-primary' : 'border-transparent text-muted-foreground'
                        )}
                      >
                        {tab === 'summary'
                          ? 'Summary'
                          : tab === 'evidence'
                            ? 'Evidence'
                            : tab === 'repro'
                              ? 'Reproduction'
                              : 'Graph'}
                      </button>
                    ))}
                  </nav>
                </div>

                {activeTab === 'summary' && (
                  <section className="space-y-4">
                    <h2 className="text-lg font-semibold text-foreground">Executive summary</h2>
                    <p className="text-sm text-muted-foreground">{activeCase.summary}</p>
                    <div>
                      <h3 className="text-sm font-semibold uppercase text-muted-foreground">Deduped findings</h3>
                      <ul className="mt-2 space-y-2">
                        {activeCase.dedupedFindings.map((finding) => (
                          <li key={finding} className="rounded border border-border bg-card/50 p-3 text-sm text-muted-foreground">
                            {finding}
                          </li>
                        ))}
                        {activeCase.dedupedFindings.length === 0 && (
                          <li className="rounded border border-dashed border-border bg-card/50 p-3 text-sm text-muted-foreground">
                            No supporting findings recorded.
                          </li>
                        )}
                      </ul>
                    </div>
                  </section>
                )}

                {activeTab === 'evidence' && (
                  <section className="space-y-4">
                    <h2 className="text-lg font-semibold text-foreground">Supporting evidence</h2>
                    <ul className="space-y-3">
                      {activeCase.evidence.map((item) => (
                        <li key={item.id} className="rounded-md border border-border bg-card p-4">
                          <div className="flex items-center justify-between">
                            <div>
                              <h3 className="text-sm font-semibold text-foreground">{item.title}</h3>
                              <p className="text-xs text-muted-foreground">{item.description}</p>
                            </div>
                            <span className="rounded bg-muted px-2 py-1 text-xs uppercase text-muted-foreground">
                              {item.type}
                            </span>
                          </div>
                        </li>
                      ))}
                      {activeCase.evidence.length === 0 && (
                        <li className="rounded border border-dashed border-border bg-card/50 p-4 text-sm text-muted-foreground">
                          No evidence captured for this case.
                        </li>
                      )}
                    </ul>
                  </section>
                )}

                {activeTab === 'repro' && (
                  <section className="space-y-4">
                    <h2 className="text-lg font-semibold text-foreground">Reproduction steps</h2>
                    <ol className="list-decimal space-y-2 pl-4 text-sm text-muted-foreground">
                      {activeCase.reproSteps.map((step, index) => (
                        <li key={`${activeCase.id}-repro-${index}`}>{step}</li>
                      ))}
                      {activeCase.reproSteps.length === 0 && (
                        <li>No reproduction steps provided.</li>
                      )}
                    </ol>
                    {activeCase.poc && (
                      <div className="rounded-md bg-muted p-4 text-xs text-muted-foreground">
                        <pre className="whitespace-pre-wrap break-words">{activeCase.poc}</pre>
                      </div>
                    )}
                  </section>
                )}

                {activeTab === 'graph' && (
                  <section className="space-y-4">
                    <h2 className="text-lg font-semibold text-foreground">Exploit graph</h2>
                    <div ref={mermaidRef} className="overflow-auto rounded-md border border-border bg-card p-4" />
                  </section>
                )}

                <section className="space-y-4">
                  <header className="flex items-center justify-between">
                    <h2 className="text-lg font-semibold text-foreground">Analyst notes</h2>
                    <div className="flex items-center gap-2">
                      <Button
                        variant={disposition[activeCase.id] === 'tp' ? 'default' : 'outline'}
                        size="sm"
                        className="gap-2"
                        onClick={() =>
                          setDisposition((prev) => ({
                            ...prev,
                            [activeCase.id]: prev[activeCase.id] === 'tp' ? undefined : 'tp'
                          }))
                        }
                      >
                        <ThumbsUp className="h-4 w-4" />
                        True positive
                      </Button>
                      <Button
                        variant={disposition[activeCase.id] === 'fp' ? 'destructive' : 'outline'}
                        size="sm"
                        className="gap-2"
                        onClick={() =>
                          setDisposition((prev) => ({
                            ...prev,
                            [activeCase.id]: prev[activeCase.id] === 'fp' ? undefined : 'fp'
                          }))
                        }
                      >
                        <ThumbsDown className="h-4 w-4" />
                        False positive
                      </Button>
                    </div>
                  </header>
                  <div className="space-y-3">
                    {(notes[activeCase.id] ?? []).map((note, index) => (
                      <div key={`${activeCase.id}-note-${index}`} className="rounded-md border border-border bg-card p-3 text-sm">
                        {note}
                      </div>
                    ))}
                    <div className="flex gap-2">
                      <textarea
                        className="min-h-[80px] flex-1 rounded-md border border-border bg-background p-3 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                        placeholder="Add a note for other analysts"
                        value={noteDraft}
                        onChange={(event) => setNoteDraft(event.target.value)}
                      />
                      <Button
                        size="sm"
                        className="self-start"
                        onClick={() => {
                          const trimmed = noteDraft.trim();
                          if (!trimmed) {
                            return;
                          }
                          setNotes((prev) => ({
                            ...prev,
                            [activeCase.id]: [...(prev[activeCase.id] ?? []), trimmed]
                          }));
                          setNoteDraft('');
                        }}
                      >
                        Add note
                      </Button>
                    </div>
                  </div>
                </section>
              </article>
            ) : (
              <div className="flex flex-1 items-center justify-center text-muted-foreground">
                Select a case to review details.
              </div>
            )}
          </div>
        </div>
      </section>
    </div>
  );
}

type FilterGroupProps<T extends string | number> = {
  title: string;
  options: { value: T; label: string }[];
  selected: T[];
  onToggle: (value: T) => void;
  emptyLabel?: string;
};

function FilterGroup<T extends string | number>({ title, options, selected, onToggle, emptyLabel }: FilterGroupProps<T>) {
  return (
    <div>
      <h3 className="text-xs font-semibold uppercase text-muted-foreground">{title}</h3>
      <div className="mt-2 space-y-2">
        {options.length === 0 && (
          <p className="text-xs text-muted-foreground">{emptyLabel ?? 'No options available'}</p>
        )}
        {options.map((option) => {
          const isActive = selected.includes(option.value);
          return (
            <button
              key={option.value}
              type="button"
              onClick={() => onToggle(option.value)}
              className={cn(
                'flex w-full items-center justify-between rounded border px-3 py-2 text-left text-xs transition',
                isActive ? 'border-primary bg-primary/10 text-primary' : 'border-border hover:bg-muted'
              )}
            >
              <span>{option.label}</span>
              {isActive && <CheckCircle2 className="h-4 w-4" />}
            </button>
          );
        })}
      </div>
    </div>
  );
}

function CasesRoute() {
  const { status } = useArtifact();
  const [cases, setCases] = useState<CaseViewModel[]>([]);
  const [loading, setLoading] = useState(false);
  const artifactKey = `${status?.manifest?.casesFile ?? ''}:${status?.caseCount ?? 0}`;
  const offlineMode = Boolean(status?.loaded);

  useEffect(() => {
    if (!offlineMode) {
      setCases([]);
      return;
    }

    let cancelled = false;
    setLoading(true);

    fetchArtifactCases()
      .then((records) => {
        if (cancelled) {
          return;
        }
        const mapped = records.map(buildCaseView);
        setCases(mapped);
      })
      .catch((error) => {
        console.error('Failed to load cases', error);
        if (!cancelled) {
          toast.error('Unable to load cases from artifact');
          setCases([]);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [artifactKey, offlineMode]);

  if (!offlineMode) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-4 text-center text-muted-foreground">
        <FileCode className="h-10 w-10" />
        <div>
          <h2 className="text-lg font-semibold text-foreground">Replay artifact required</h2>
          <p>Open a replay archive to inspect recorded cases without a running daemon.</p>
        </div>
      </div>
    );
  }

  if (loading && cases.length === 0) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-2 text-muted-foreground">
        <RefreshCw className="h-5 w-5 animate-spin" />
        Loading cases…
      </div>
    );
  }

  return <CaseExplorer cases={cases} />;
}

export const Route = createFileRoute('/cases')({
  component: CasesRoute
});

export default CasesRoute;
