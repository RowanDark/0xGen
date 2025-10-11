import { createFileRoute } from '@tanstack/react-router';
import { useEffect, useMemo, useState } from 'react';
import Editor, { useMonaco } from '@monaco-editor/react';
import 'monaco-editor/esm/vs/basic-languages/yaml/yaml.contribution';
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  ClipboardCopy,
  FileText,
  ListChecks,
  Loader2,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Sparkles,
  Wand2
} from 'lucide-react';
import { toast } from 'sonner';

import { Button } from '../components/ui/button';
import {
  applyScopePolicy,
  dryRunScopePolicy,
  fetchScopePolicy,
  parseScopeText,
  validateScopePolicy,
  type ScopeApplyResponse,
  type ScopeDryRunDecision,
  type ScopeParseSuggestion,
  type ScopePolicyDocument,
  type ScopeValidationMessage,
  type ScopeValidationResult
} from '../lib/ipc';
import { scopeBenchmarks } from '../lib/scope-test-bench';
import { cn } from '../lib/utils';

const scopePolicySchema = {
  $id: 'inmemory://model/scope-policy.schema.json',
  type: 'object',
  additionalProperties: false,
  properties: {
    version: {
      type: 'number',
      enum: [1],
      description: 'Scope policy format version (defaults to 1).'
    },
    allow: {
      type: 'array',
      description: 'Targets that are explicitly in scope for crawling.',
      items: { $ref: '#/definitions/rule' }
    },
    deny: {
      type: 'array',
      description: 'Targets that are out of scope.',
      items: { $ref: '#/definitions/rule' }
    },
    private_networks: {
      type: 'string',
      enum: ['allow', 'block', 'unspecified'],
      description: 'How private network ranges should be treated.'
    },
    pii: {
      type: 'string',
      enum: ['allow', 'forbid', 'unspecified'],
      description: 'Whether personally identifiable information can be collected.'
    }
  },
  required: [],
  definitions: {
    rule: {
      type: 'object',
      required: ['type', 'value'],
      additionalProperties: false,
      properties: {
        type: {
          type: 'string',
          enum: ['domain', 'wildcard', 'url', 'url_prefix', 'path', 'cidr', 'ip', 'pattern']
        },
        value: { type: 'string' },
        notes: { type: 'string' }
      }
    }
  }
};

const riskyRuleTypes = new Set(['wildcard', 'pattern']);

type BenchmarkOutcome =
  | {
      status: 'pass' | 'fail';
      expected: string;
      actual: string;
      summary?: string;
      rationale?: string[];
    }
  | {
      status: 'error';
      error: string;
    };

function describeLocation(message: ScopeValidationMessage) {
  if (message.line == null && message.column == null) {
    return undefined;
  }
  if (message.line != null && message.column != null) {
    return `line ${message.line}, column ${message.column}`;
  }
  if (message.line != null) {
    return `line ${message.line}`;
  }
  return `column ${message.column}`;
}

function isRuleRisky(rule: { type: string }) {
  return riskyRuleTypes.has(rule.type);
}

function DecisionBadge({ allowed }: { allowed: boolean }) {
  const Icon = allowed ? ShieldCheck : ShieldX;
  const label = allowed ? 'Allowed' : 'Denied';
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium',
        allowed ? 'bg-success/10 text-success' : 'bg-destructive/10 text-destructive-foreground'
      )}
    >
      <Icon className="h-3.5 w-3.5" aria-hidden />
      {label}
    </span>
  );
}

function RulePreview({ rule }: { rule: { type: string; value: string; notes?: string | null } }) {
  const risky = isRuleRisky(rule);
  return (
    <div
      className={cn(
        'rounded-md border bg-background p-3 text-sm',
        risky ? 'border-warning/70 bg-warning/5' : 'border-border'
      )}
    >
      <div className="font-medium">{rule.type}</div>
      <div className="text-muted-foreground break-words">{rule.value}</div>
      {rule.notes ? <div className="mt-2 text-xs text-muted-foreground">{rule.notes}</div> : null}
      {risky ? (
        <div className="mt-2 flex items-center gap-1 text-xs text-warning">
          <AlertTriangle className="h-3.5 w-3.5" aria-hidden />
          Review this wildcard or pattern carefully before enforcing.
        </div>
      ) : null}
    </div>
  );
}

function useEditorTheme() {
  const [editorTheme, setEditorTheme] = useState<'vs' | 'vs-dark'>(() => {
    const theme = document.documentElement.dataset.theme;
    return !theme || theme === 'light' ? 'vs' : 'vs-dark';
  });

  useEffect(() => {
    const update = () => {
      const theme = document.documentElement.dataset.theme;
      setEditorTheme(!theme || theme === 'light' ? 'vs' : 'vs-dark');
    };

    const observer = new MutationObserver(update);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    return () => observer.disconnect();
  }, []);

  return editorTheme;
}

function ScopeScreen() {
  const monaco = useMonaco();
  const editorTheme = useEditorTheme();
  const [isLoading, setIsLoading] = useState(true);
  const [policy, setPolicy] = useState('');
  const [activePolicy, setActivePolicy] = useState<ScopePolicyDocument | null>(null);
  const [validation, setValidation] = useState<ScopeValidationResult | null>(null);
  const [isValidating, setIsValidating] = useState(false);
  const [isApplying, setIsApplying] = useState(false);
  const [parseInput, setParseInput] = useState('');
  const [isParsing, setIsParsing] = useState(false);
  const [suggestions, setSuggestions] = useState<ScopeParseSuggestion[]>([]);
  const [selectedBenchmarkId, setSelectedBenchmarkId] = useState(scopeBenchmarks[0]?.id ?? '');
  const [isBenchmarking, setIsBenchmarking] = useState(false);
  const [benchmarkResult, setBenchmarkResult] = useState<BenchmarkOutcome | null>(null);
  const [dryRunInput, setDryRunInput] = useState('');
  const [isDryRunning, setIsDryRunning] = useState(false);
  const [dryRunResults, setDryRunResults] = useState<ScopeDryRunDecision[]>([]);
  const [applyMeta, setApplyMeta] = useState<ScopeApplyResponse | null>(null);

  useEffect(() => {
    if (!monaco) {
      return;
    }
    const languages = monaco.languages as typeof monaco.languages & {
      yaml?: { yamlDefaults: { setDiagnosticsOptions: (options: unknown) => void } };
    };
    languages.yaml?.yamlDefaults.setDiagnosticsOptions({
      validate: true,
      enableSchemaRequest: false,
      schemas: [
        {
          uri: scopePolicySchema.$id,
          fileMatch: ['*'],
          schema: scopePolicySchema
        }
      ]
    });
  }, [monaco]);

  useEffect(() => {
    let cancelled = false;
    const loadPolicy = async () => {
      try {
        const document = await fetchScopePolicy();
        if (cancelled) {
          return;
        }
        setPolicy(document.policy);
        setActivePolicy(document);
        setApplyMeta(null);
      } catch (error) {
        console.error('Failed to load scope policy', error);
        toast.error('Unable to load the current scope policy.');
      } finally {
        if (!cancelled) {
          setIsLoading(false);
        }
      }
    };

    void loadPolicy();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    setValidation(null);
  }, [policy]);

  const hasUnsavedChanges = useMemo(() => {
    return (activePolicy?.policy ?? '') !== policy;
  }, [activePolicy, policy]);

  const selectedBenchmark = useMemo(() => {
    return scopeBenchmarks.find((benchmark) => benchmark.id === selectedBenchmarkId) ?? null;
  }, [selectedBenchmarkId]);

  useEffect(() => {
    setBenchmarkResult(null);
  }, [selectedBenchmarkId]);

  const handleValidate = async () => {
    setIsValidating(true);
    try {
      const result = await validateScopePolicy(policy);
      setValidation(result);
      if (result.errors.length === 0) {
        toast.success('Scope policy looks good.');
      } else {
        toast.error('Scope policy contains issues.');
      }
    } catch (error) {
      console.error('Failed to validate policy', error);
      toast.error('Unable to validate the scope policy.');
    } finally {
      setIsValidating(false);
    }
  };

  const handleApply = async () => {
    setIsApplying(true);
    try {
      const response = await applyScopePolicy(policy);
      setPolicy(response.policy);
      setActivePolicy({ policy: response.policy, source: activePolicy?.source, updatedAt: response.appliedAt });
      setApplyMeta(response);
      setValidation(null);
      toast.success('Scope policy applied to the crawler.');
    } catch (error) {
      console.error('Failed to apply scope policy', error);
      toast.error('Unable to apply the scope policy.');
    } finally {
      setIsApplying(false);
    }
  };

  const handleParse = async () => {
    const trimmed = parseInput.trim();
    if (trimmed === '') {
      toast.info('Paste some bounty program text to extract rules.');
      return;
    }
    setIsParsing(true);
    try {
      const response = await parseScopeText(trimmed);
      setSuggestions(response.suggestions);
      if (response.suggestions.length === 0) {
        toast.info('No scope rules were identified in the provided text.');
      } else {
        toast.success('Generated scope suggestions from bounty text.');
      }
    } catch (error) {
      console.error('Failed to parse bounty text', error);
      toast.error('Unable to generate scope suggestions.');
    } finally {
      setIsParsing(false);
    }
  };

  const handleCopySuggestion = async (suggestion: ScopeParseSuggestion) => {
    try {
      await navigator.clipboard.writeText(suggestion.policy);
      toast.success('Suggestion copied to clipboard');
    } catch (error) {
      console.error('Failed to copy suggestion', error);
      toast.error('Unable to copy suggestion');
    }
  };

  const handleApplySuggestion = (suggestion: ScopeParseSuggestion) => {
    const containsWildcard = Boolean(
      suggestion.rules?.allow?.some((rule) => isRuleRisky(rule)) ||
        suggestion.rules?.deny?.some((rule) => isRuleRisky(rule))
    );

    if (containsWildcard) {
      const confirmed = window.confirm(
        'This suggestion includes wildcard or pattern rules. Confirm before replacing the current policy?'
      );
      if (!confirmed) {
        toast.info('Wildcard suggestion was not applied.');
        return;
      }
    }

    setPolicy(suggestion.policy);
    toast.success('Replaced the editor contents with the generated policy.');
  };

  const normalizePolicy = (value: string) =>
    value
      .replace(/\r?\n/g, '\n')
      .split('\n')
      .map((line) => line.trimEnd())
      .join('\n')
      .trim();

  const handleRunBenchmark = async () => {
    if (!selectedBenchmark) {
      toast.info('Select a policy snippet to benchmark.');
      return;
    }

    setIsBenchmarking(true);
    setBenchmarkResult(null);

    try {
      const response = await parseScopeText(selectedBenchmark.text);

      if (response.suggestions.length === 0) {
        setBenchmarkResult({ status: 'error', error: 'No suggestions were returned for this snippet.' });
        toast.error('Benchmark did not return any scope suggestions.');
        return;
      }

      const [primarySuggestion] = response.suggestions;
      const expected = normalizePolicy(selectedBenchmark.expectedPolicy);
      const actual = normalizePolicy(primarySuggestion.policy);
      const status: 'pass' | 'fail' = expected === actual ? 'pass' : 'fail';

      setBenchmarkResult({
        status,
        expected,
        actual,
        summary: primarySuggestion.summary,
        rationale:
          primarySuggestion.rationale && primarySuggestion.rationale.length > 0
            ? primarySuggestion.rationale
            : primarySuggestion.notes
              ? [primarySuggestion.notes]
              : undefined
      });

      if (status === 'pass') {
        toast.success('Generated policy matches the golden benchmark.');
      } else {
        toast.error('Generated policy differs from the golden benchmark.');
      }
    } catch (error) {
      console.error('Failed to run scope benchmark', error);
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      setBenchmarkResult({ status: 'error', error: errorMessage });
      toast.error('Unable to run the benchmark against the policy service.');
    } finally {
      setIsBenchmarking(false);
    }
  };

  const handleDryRun = async () => {
    const urls = dryRunInput
      .split(/\r?\n/)
      .map((entry) => entry.trim())
      .filter((entry) => entry !== '');

    if (urls.length === 0) {
      toast.info('Add at least one URL to preview the policy decisions.');
      return;
    }

    setIsDryRunning(true);
    try {
      const response = await dryRunScopePolicy({ policy, urls });
      setDryRunResults(response.results);
      if (response.results.length === 0) {
        toast.info('No decisions were returned. Double-check the provided URLs.');
      }
    } catch (error) {
      console.error('Failed to dry-run scope policy', error);
      toast.error('Unable to preview scope decisions.');
    } finally {
      setIsDryRunning(false);
    }
  };

  const lastAppliedAt = useMemo(() => {
    const timestamp = applyMeta?.appliedAt ?? activePolicy?.updatedAt;
    if (!timestamp) {
      return undefined;
    }
    return new Date(timestamp).toLocaleString();
  }, [activePolicy?.updatedAt, applyMeta?.appliedAt]);

  return (
    <div className="mx-auto flex h-full max-w-7xl flex-col gap-6 p-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Scope policy</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Edit the YAML scope policy, validate changes, and apply them directly to the crawler.
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-[2fr,1fr]">
        <div className="flex flex-col gap-4">
          <div className="rounded-xl border border-border bg-card shadow-sm">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-4 py-3">
              <div>
                <h2 className="text-lg font-semibold">Policy editor</h2>
                <p className="text-xs text-muted-foreground">
                  {lastAppliedAt ? `Last applied ${lastAppliedAt}` : 'Load the current policy and make edits before applying.'}
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={isLoading || isValidating}
                  onClick={handleValidate}
                >
                  {isValidating ? <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden /> : <CheckCircle2 className="mr-2 h-4 w-4" aria-hidden />} 
                  Validate
                </Button>
                <Button
                  type="button"
                  size="sm"
                  disabled={isLoading || isApplying || policy.trim() === '' || !hasUnsavedChanges}
                  onClick={handleApply}
                >
                  {isApplying ? <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden /> : <RefreshCw className="mr-2 h-4 w-4" aria-hidden />} 
                  Apply
                </Button>
              </div>
            </div>
            <div className="h-[420px] overflow-hidden border-t border-border">
              {isLoading ? (
                <div className="flex h-full items-center justify-center text-muted-foreground">
                  <Loader2 className="mr-2 h-5 w-5 animate-spin" aria-hidden />
                  Loading scope policy…
                </div>
              ) : (
                <Editor
                  language="yaml"
                  theme={editorTheme}
                  value={policy}
                  onChange={(value) => setPolicy(value ?? '')}
                  options={{
                    minimap: { enabled: false },
                    fontSize: 14,
                    lineNumbers: 'on',
                    scrollBeyondLastLine: false,
                    renderWhitespace: 'selection'
                  }}
                />
              )}
            </div>
          </div>

          {validation ? (
            <div className="rounded-xl border border-border bg-card p-4 shadow-sm">
              <div className="flex items-center gap-2 text-sm font-medium">
                {validation.errors.length === 0 ? (
                  <CheckCircle2 className="h-4 w-4 text-success" aria-hidden />
                ) : (
                  <AlertCircle className="h-4 w-4 text-destructive" aria-hidden />
                )}
                {validation.errors.length === 0
                  ? 'No blocking issues detected in the policy.'
                  : `${validation.errors.length} problem${validation.errors.length === 1 ? '' : 's'} detected.`}
              </div>
              {validation.errors.length > 0 ? (
                <ul className="mt-3 space-y-2 text-sm text-destructive">
                  {validation.errors.map((message, index) => (
                    <li key={`${message.message}-${index}`} className="flex items-start gap-2">
                      <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0" aria-hidden />
                      <div>
                        <div>{message.message}</div>
                        {describeLocation(message) ? (
                          <div className="text-xs text-muted-foreground">{describeLocation(message)}</div>
                        ) : null}
                      </div>
                    </li>
                  ))}
                </ul>
              ) : null}
              {validation.warnings && validation.warnings.length > 0 ? (
                <div className="mt-4 rounded-lg border border-border/60 bg-muted/10 p-3 text-sm">
                  <div className="flex items-center gap-2 font-medium">
                    <AlertTriangle className="h-4 w-4 text-warning" aria-hidden />
                    {validation.warnings.length} warning{validation.warnings.length === 1 ? '' : 's'}
                  </div>
                  <ul className="mt-2 space-y-2 text-muted-foreground">
                    {validation.warnings.map((warning, index) => (
                      <li key={`${warning.message}-${index}`}>
                        <div>{warning.message}</div>
                        {describeLocation(warning) ? (
                          <div className="text-xs text-muted-foreground">{describeLocation(warning)}</div>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>
          ) : null}
        </div>

        <div className="flex flex-col gap-4">
          <div className="rounded-xl border border-border bg-card shadow-sm">
            <div className="flex items-center justify-between border-b border-border px-4 py-3">
              <div>
                <h2 className="text-lg font-semibold">LLM helper</h2>
                <p className="text-xs text-muted-foreground">
                  Paste bounty text to generate draft allow/deny rules.
                </p>
              </div>
              <Sparkles className="h-4 w-4 text-primary" aria-hidden />
            </div>
            <div className="space-y-3 p-4">
              <textarea
                value={parseInput}
                onChange={(event) => setParseInput(event.target.value)}
                className="h-36 w-full rounded-lg border border-border bg-background p-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                placeholder="Paste the program scope or bounty brief…"
              />
              <div className="flex justify-end gap-2">
                <Button type="button" variant="ghost" size="sm" onClick={() => setParseInput('')}>
                  Clear
                </Button>
                <Button type="button" size="sm" onClick={handleParse} disabled={isParsing}>
                  {isParsing ? <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden /> : <Wand2 className="mr-2 h-4 w-4" aria-hidden />} 
                  Generate rules
                </Button>
              </div>
              {suggestions.length > 0 ? (
                <div className="space-y-4">
                  {suggestions.map((suggestion, index) => {
                    const allowRules = suggestion.rules?.allow ?? [];
                    const denyRules = suggestion.rules?.deny ?? [];
                    const hasWildcards =
                      allowRules.some((rule) => isRuleRisky(rule)) || denyRules.some((rule) => isRuleRisky(rule));
                    const rationaleItems =
                      suggestion.rationale && suggestion.rationale.length > 0
                        ? suggestion.rationale
                        : suggestion.notes
                          ? [suggestion.notes]
                          : [];

                    return (
                      <div
                        key={index}
                        className={cn(
                          'rounded-lg border bg-background p-3',
                          hasWildcards ? 'border-warning/70' : 'border-border'
                        )}
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="text-sm font-medium">Suggestion {index + 1}</div>
                          <div className="flex gap-2">
                            <Button
                              type="button"
                              size="sm"
                              variant="outline"
                              onClick={() => void handleCopySuggestion(suggestion)}
                            >
                              <ClipboardCopy className="mr-2 h-4 w-4" aria-hidden />
                              Copy YAML
                            </Button>
                            <Button type="button" size="sm" onClick={() => handleApplySuggestion(suggestion)}>
                              Apply to editor
                            </Button>
                          </div>
                        </div>
                        {suggestion.summary ? (
                          <p className="mt-2 text-xs text-muted-foreground">{suggestion.summary}</p>
                        ) : null}
                        {hasWildcards ? (
                          <div className="mt-3 flex items-start gap-2 rounded-md border border-warning/70 bg-warning/10 p-2 text-xs text-warning">
                            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" aria-hidden />
                            <span>Wildcard or pattern matches detected. You will be asked to confirm before applying.</span>
                          </div>
                        ) : null}
                        {rationaleItems.length > 0 ? (
                          <div className="mt-3 rounded-md border border-border/70 bg-muted/10 p-3 text-xs">
                            <div className="flex items-center gap-2 font-medium text-foreground">
                              <FileText className="h-3.5 w-3.5" aria-hidden />
                              Rationale
                            </div>
                            <ul className="mt-2 space-y-1 list-disc pl-4 text-muted-foreground">
                              {rationaleItems.map((item, rationaleIndex) => (
                                <li key={rationaleIndex}>{item}</li>
                              ))}
                            </ul>
                          </div>
                        ) : null}
                        <div className="mt-3">
                          <div className="text-xs font-medium uppercase text-muted-foreground">Proposed policy</div>
                          <pre className="mt-1 max-h-64 overflow-auto rounded-md border border-border bg-background p-2 text-xs">
                            {suggestion.policy}
                          </pre>
                        </div>
                        {allowRules.length + denyRules.length > 0 ? (
                          <div className="mt-3 grid gap-2 md:grid-cols-2">
                            {allowRules.map((rule, ruleIndex) => (
                              <RulePreview key={`allow-${rule.type}-${ruleIndex}`} rule={rule} />
                            ))}
                            {denyRules.map((rule, ruleIndex) => (
                              <RulePreview key={`deny-${rule.type}-${ruleIndex}`} rule={rule} />
                            ))}
                          </div>
                        ) : null}
                      </div>
                    );
                  })}
                </div>
              ) : null}
            </div>
          </div>

          <div className="rounded-xl border border-border bg-card shadow-sm">
            <div className="flex items-center justify-between border-b border-border px-4 py-3">
              <div>
                <h2 className="text-lg font-semibold">Test bench</h2>
                <p className="text-xs text-muted-foreground">
                  Run saved program snippets against golden policies to spot regressions.
                </p>
              </div>
              <ListChecks className="h-4 w-4 text-primary" aria-hidden />
            </div>
            <div className="space-y-3 p-4 text-sm">
              <div className="space-y-1">
                <label className="text-xs font-medium uppercase tracking-wide text-muted-foreground" htmlFor="scope-benchmark">
                  Snippet
                </label>
                <select
                  id="scope-benchmark"
                  value={selectedBenchmarkId}
                  onChange={(event) => setSelectedBenchmarkId(event.target.value)}
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                >
                  {scopeBenchmarks.map((benchmark) => (
                    <option key={benchmark.id} value={benchmark.id}>
                      {benchmark.label}
                    </option>
                  ))}
                </select>
              </div>
              {selectedBenchmark?.description ? (
                <p className="text-xs text-muted-foreground">{selectedBenchmark.description}</p>
              ) : null}
              {selectedBenchmark?.notes ? (
                <p className="text-xs text-muted-foreground">{selectedBenchmark.notes}</p>
              ) : null}
              {selectedBenchmark ? (
                <div className="rounded-md border border-dashed border-border bg-background/80 p-3 text-xs text-muted-foreground whitespace-pre-wrap">
                  {selectedBenchmark.text}
                </div>
              ) : null}
              <div className="flex justify-end">
                <Button type="button" size="sm" onClick={handleRunBenchmark} disabled={isBenchmarking || !selectedBenchmark}>
                  {isBenchmarking ? (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />
                  ) : (
                    <ListChecks className="mr-2 h-4 w-4" aria-hidden />
                  )}
                  Run benchmark
                </Button>
              </div>
              {benchmarkResult ? (
                <div className="space-y-3 rounded-md border border-border/70 bg-muted/10 p-3 text-xs">
                  {benchmarkResult.status === 'error' ? (
                    <div className="flex items-start gap-2 text-destructive">
                      <AlertCircle className="mt-0.5 h-4 w-4" aria-hidden />
                      <span>{benchmarkResult.error}</span>
                    </div>
                  ) : (
                    <>
                      <div className="flex items-center gap-2 text-sm font-medium">
                        {benchmarkResult.status === 'pass' ? (
                          <CheckCircle2 className="h-4 w-4 text-success" aria-hidden />
                        ) : (
                          <AlertCircle className="h-4 w-4 text-destructive" aria-hidden />
                        )}
                        {benchmarkResult.status === 'pass'
                          ? 'Generated policy matches the golden result.'
                          : 'Generated policy deviates from the golden result.'}
                      </div>
                      {benchmarkResult.summary ? (
                        <p className="text-muted-foreground">{benchmarkResult.summary}</p>
                      ) : null}
                      {benchmarkResult.rationale && benchmarkResult.rationale.length > 0 ? (
                        <div className="space-y-1">
                          <div className="flex items-center gap-2 font-medium text-foreground">
                            <FileText className="h-3.5 w-3.5" aria-hidden />
                            Rationale from model
                          </div>
                          <ul className="list-disc space-y-1 pl-5 text-muted-foreground">
                            {benchmarkResult.rationale.map((item, rationaleIndex) => (
                              <li key={`benchmark-rationale-${rationaleIndex}`}>{item}</li>
                            ))}
                          </ul>
                        </div>
                      ) : null}
                      <div className="grid gap-3 md:grid-cols-2">
                        <div>
                          <div className="text-xs font-medium uppercase text-muted-foreground">Expected</div>
                          <pre className="mt-1 max-h-60 overflow-auto rounded-md border border-border bg-background p-2 text-[11px]">
                            {benchmarkResult.expected}
                          </pre>
                        </div>
                        <div>
                          <div className="text-xs font-medium uppercase text-muted-foreground">Generated</div>
                          <pre className="mt-1 max-h-60 overflow-auto rounded-md border border-border bg-background p-2 text-[11px]">
                            {benchmarkResult.actual}
                          </pre>
                        </div>
                      </div>
                    </>
                  )}
                </div>
              ) : null}
            </div>
          </div>

          <div className="rounded-xl border border-border bg-card shadow-sm">
            <div className="flex items-center justify-between border-b border-border px-4 py-3">
              <div>
                <h2 className="text-lg font-semibold">Dry run</h2>
                <p className="text-xs text-muted-foreground">Preview how the current policy treats sample URLs.</p>
              </div>
              <ShieldAlert className="h-4 w-4 text-warning" aria-hidden />
            </div>
            <div className="space-y-3 p-4">
              <textarea
                value={dryRunInput}
                onChange={(event) => setDryRunInput(event.target.value)}
                className="h-36 w-full rounded-lg border border-border bg-background p-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                placeholder={`https://example.com/login\nhttps://admin.example.com/\nhttps://10.0.0.5/api`}
              />
              <div className="flex justify-end">
                <Button type="button" size="sm" onClick={handleDryRun} disabled={isDryRunning}>
                  {isDryRunning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden /> : <ShieldAlert className="mr-2 h-4 w-4" aria-hidden />} 
                  Preview decisions
                </Button>
              </div>
              {dryRunResults.length > 0 ? (
                <div className="overflow-hidden rounded-lg border border-border">
                  <table className="min-w-full divide-y divide-border text-sm">
                    <thead className="bg-muted/40 text-xs uppercase tracking-wide text-muted-foreground">
                      <tr>
                        <th className="px-3 py-2 text-left font-medium">URL</th>
                        <th className="px-3 py-2 text-left font-medium">Decision</th>
                        <th className="px-3 py-2 text-left font-medium">Reason</th>
                        <th className="px-3 py-2 text-left font-medium">Matched rule</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border bg-background">
                      {dryRunResults.map((result, index) => (
                        <tr key={`${result.url}-${index}`}>
                          <td className="px-3 py-2 align-top text-xs md:text-sm">{result.url}</td>
                          <td className="px-3 py-2 align-top">
                            <DecisionBadge allowed={result.allowed} />
                          </td>
                          <td className="px-3 py-2 align-top text-xs text-muted-foreground">
                            {result.reason ?? '—'}
                          </td>
                          <td className="px-3 py-2 align-top text-xs text-muted-foreground">
                            {result.matchedRule ? `${result.matchedRule.type}: ${result.matchedRule.value}` : '—'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : null}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export const Route = createFileRoute('/scope')({
  component: ScopeScreen
});

export default ScopeScreen;
