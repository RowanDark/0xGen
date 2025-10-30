import { createFileRoute, Link, useNavigate } from '@tanstack/react-router';
import {
  ArrowLeft,
  Bot,
  CalendarClock,
  Check,
  ChevronLeft,
  ChevronRight,
  DownloadCloud,
  Flame,
  Lightbulb,
  Loader2,
  Plug,
  RefreshCw,
  Send,
  ShieldAlert,
  Sparkles,
  Zap
} from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { toast } from 'sonner';

import { Button } from '../components/ui/button';
import { startRun, type StartRunPayload } from '../lib/ipc';
import { useLocalStorage } from '../lib/use-local-storage';
import { useCommandCenter } from '../providers/command-center';
import {
  buildContextFingerprint,
  runMimirAgent,
  type MimirAgentContext,
  type MimirRecommendation
} from '../lib/mimir-agent';

type RunComposerStep = {
  id: 'targets' | 'plugins' | 'limits' | 'auth' | 'review';
  title: string;
  description: string;
};

type PluginDefinition = {
  id: string;
  name: string;
  description: string;
  category: string;
  risk: 'low' | 'medium' | 'high';
};

type AuthStrategy = 'none' | 'apiKey' | 'basic' | 'oauth';

type RunComposerPreset = {
  id: string;
  name: string;
  createdAt: string;
  data: RunComposerState;
};

type RunComposerState = {
  name: string;
  targets: string[];
  targetNotes: string;
  scopePolicy: string;
  plugins: string[];
  limits: {
    concurrency: number;
    maxRps: number;
    maxFindings: number;
    safeMode: boolean;
  };
  auth: {
    strategy: AuthStrategy;
    apiKey: string;
    username: string;
    password: string;
    oauthClientId: string;
    oauthClientSecret: string;
  };
  schedule: {
    mode: 'now' | 'later';
    startAt: string;
    timezone: string;
  };
};

const steps: RunComposerStep[] = [
  {
    id: 'targets',
    title: 'Targets',
    description: 'Pick where to send instrumentation and define policy scope.'
  },
  {
    id: 'plugins',
    title: 'Plugins',
    description: 'Select automation to execute for the run.'
  },
  {
    id: 'limits',
    title: 'Limits',
    description: 'Rate limits and safety controls for this run.'
  },
  {
    id: 'auth',
    title: 'Auth',
    description: 'Provide credentials or tokens for restricted endpoints.'
  },
  {
    id: 'review',
    title: 'Review',
    description: 'Double-check configuration, save presets, and launch.'
  }
];

const pluginCatalog: PluginDefinition[] = [
  {
    id: 'http-crawler',
    name: 'HTTP Crawler',
    description: 'Discovers linked pages and APIs from a seed list.',
    category: 'Discovery',
    risk: 'low'
  },
  {
    id: 'form-fuzzer',
    name: 'Form Fuzzer',
    description: 'Submits generated payloads to detected forms to uncover errors.',
    category: 'Fuzzing',
    risk: 'high'
  },
  {
    id: 'js-runtime',
    name: 'Browser Runtime',
    description: 'Executes scoped scripts inside a sandboxed browser context.',
    category: 'Execution',
    risk: 'medium'
  },
  {
    id: 'secrets-scanner',
    name: 'Secrets Scanner',
    description: 'Searches responses for exposed credentials or secrets.',
    category: 'Inspection',
    risk: 'medium'
  },
  {
    id: 'traffic-recorder',
    name: 'Traffic Recorder',
    description: 'Captures live HTTP traffic for later replay.',
    category: 'Telemetry',
    risk: 'low'
  }
];

const scopeOptions = [
  {
    id: 'strict',
    title: 'Strict scope',
    subtitle: 'Production-only, critical endpoints',
    description: 'Allow requests to *.0xgen.app and block sensitive admin consoles.'
  },
  {
    id: 'staging',
    title: 'Staging mirrors',
    subtitle: 'Non-production, parity with prod',
    description: 'Targets *.staging.0xgen.app with relaxed rate limits.'
  },
  {
    id: 'broad',
    title: 'Broad discovery',
    subtitle: 'Expansive crawl of known hosts',
    description: 'Includes marketing and documentation properties for a full inventory.'
  }
];

const defaultState: RunComposerState = {
  name: 'New 0xgen run',
  targets: ['https://0xgen.app'],
  targetNotes: '',
  scopePolicy: 'strict',
  plugins: ['http-crawler', 'secrets-scanner'],
  limits: {
    concurrency: 4,
    maxRps: 10,
    maxFindings: 100,
    safeMode: true
  },
  auth: {
    strategy: 'none',
    apiKey: '',
    username: '',
    password: '',
    oauthClientId: '',
    oauthClientSecret: ''
  },
  schedule: {
    mode: 'now',
    startAt: new Date(Date.now() + 30 * 60 * 1000).toISOString().slice(0, 16),
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
  }
};

const presetStorageKey = '0xgen.desktop.runComposerPresets';

function buildStartRunPayload(
  state: RunComposerState,
  scheduleStartAt?: string
): StartRunPayload {
  const trimmedName = state.name.trim();
  const sanitizedTargets = state.targets.map((target) => target.trim()).filter((target) => target.length > 0);

  return {
    name: trimmedName.length > 0 ? trimmedName : defaultState.name,
    template: state.scopePolicy || undefined,
    targets: sanitizedTargets,
    targetNotes: state.targetNotes.trim() || undefined,
    scopePolicy: state.scopePolicy,
    plugins: [...state.plugins],
    limits: {
      concurrency: state.limits.concurrency,
      maxRps: state.limits.maxRps,
      maxFindings: state.limits.maxFindings,
      safeMode: state.limits.safeMode
    },
    auth: {
      strategy: state.auth.strategy,
      apiKey: state.auth.apiKey.trim() || undefined,
      username: state.auth.username.trim() || undefined,
      password: state.auth.password.trim() || undefined,
      oauthClientId: state.auth.oauthClientId.trim() || undefined,
      oauthClientSecret: state.auth.oauthClientSecret.trim() || undefined
    },
    schedule: {
      mode: state.schedule.mode,
      startAt: state.schedule.mode === 'later' ? scheduleStartAt : undefined,
      timezone:
        state.schedule.mode === 'later' ? state.schedule.timezone.trim() || undefined : undefined
    }
  } satisfies StartRunPayload;
}

function computeEstimatedImpact(state: RunComposerState) {
  const targetCount = state.targets.filter((value) => value.trim().length > 0).length;
  const pluginCount = state.plugins.length;
  const concurrency = state.limits.concurrency;

  const estimatedRequests = Math.max(targetCount * pluginCount * Math.max(concurrency, 1), pluginCount);
  const estimatedDurationMinutes = Math.max(Math.ceil(estimatedRequests / Math.max(state.limits.maxRps, 1)), 1);

  return {
    targets: targetCount,
    plugins: pluginCount,
    estimatedRequests,
    estimatedDurationMinutes
  };
}

function computeWarnings(state: RunComposerState) {
  const warnings: string[] = [];

  const riskyPlugins = pluginCatalog.filter((plugin) => plugin.risk === 'high' && state.plugins.includes(plugin.id));
  if (!state.limits.safeMode && riskyPlugins.length > 0) {
    warnings.push(
      `Safe mode is disabled while using ${riskyPlugins
        .map((plugin) => plugin.name)
        .join(', ')}. Consider enabling safe mode to prevent destructive calls.`
    );
  }

  if (state.limits.concurrency >= 12) {
    warnings.push('High concurrency may overwhelm smaller targets. Reduce concurrency or enable safe mode.');
  }

  if (state.limits.maxRps >= 50) {
    warnings.push('The selected rate limit exceeds the default safe threshold of 50 RPS.');
  }

  return warnings;
}

function StepIndicator({ currentStep }: { currentStep: RunComposerStep }) {
  return (
    <ol className="flex flex-wrap gap-4 text-sm font-medium text-muted-foreground">
      {steps.map((step, index) => {
        const isActive = step.id === currentStep.id;
        const isCompleted = steps.findIndex((entry) => entry.id === currentStep.id) > index;
        return (
          <li key={step.id} className="flex items-center gap-2">
            <span
              className={`flex h-6 w-6 items-center justify-center rounded-full border text-xs ${
                isActive
                  ? 'border-primary bg-primary text-primary-foreground'
                  : isCompleted
                    ? 'border-green-500 bg-green-500 text-white'
                    : 'border-border bg-background'
              }`}
            >
              {isCompleted ? <Check className="h-3 w-3" /> : index + 1}
            </span>
            <span className={isActive ? 'text-foreground' : undefined}>{step.title}</span>
          </li>
        );
      })}
    </ol>
  );
}

function TargetsStep({
  value,
  onChange
}: {
  value: RunComposerState;
  onChange: (next: RunComposerState) => void;
}) {
  return (
    <div className="space-y-8">
      <div>
        <label className="text-sm font-medium text-foreground">Run name</label>
        <input
          value={value.name}
          onChange={(event) => onChange({ ...value, name: event.target.value })}
          className="mt-2 w-full rounded-md border border-border bg-background px-3 py-2 text-sm shadow-sm focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
          placeholder="Give this run a memorable name"
        />
      </div>
      <div>
        <div className="flex items-center justify-between">
          <label className="text-sm font-medium text-foreground">Targets</label>
          <span className="text-xs text-muted-foreground">One URL or CIDR per line</span>
        </div>
        <textarea
          value={value.targets.join('\n')}
          onChange={(event) => onChange({ ...value, targets: event.target.value.split('\n') })}
          className="mt-2 h-40 w-full rounded-md border border-border bg-background px-3 py-2 text-sm shadow-sm focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
        />
        <p className="mt-2 text-xs text-muted-foreground">
          Paste known targets or import from scope inventory. Discovery plugins can expand from here.
        </p>
      </div>
      <div>
        <label className="text-sm font-medium text-foreground">Scope policy</label>
        <div className="mt-3 grid gap-3 md:grid-cols-3">
          {scopeOptions.map((option) => {
            const isSelected = value.scopePolicy === option.id;
            return (
              <button
                key={option.id}
                type="button"
                onClick={() => onChange({ ...value, scopePolicy: option.id })}
                className={`rounded-lg border p-4 text-left transition hover:border-primary ${
                  isSelected ? 'border-primary bg-primary/5 shadow-sm' : 'border-border bg-card'
                }`}
              >
                <p className="text-sm font-semibold text-foreground">{option.title}</p>
                <p className="mt-1 text-xs uppercase tracking-wide text-muted-foreground">{option.subtitle}</p>
                <p className="mt-2 text-xs text-muted-foreground">{option.description}</p>
              </button>
            );
          })}
        </div>
      </div>
      <div>
        <label className="text-sm font-medium text-foreground">Notes for the operations team</label>
        <textarea
          value={value.targetNotes}
          onChange={(event) => onChange({ ...value, targetNotes: event.target.value })}
          className="mt-2 h-24 w-full rounded-md border border-border bg-background px-3 py-2 text-sm shadow-sm focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
          placeholder="Document out-of-scope hosts, change freezes, or expected noisy endpoints"
        />
      </div>
    </div>
  );
}

function PluginsStep({
  value,
  onChange
}: {
  value: RunComposerState;
  onChange: (next: RunComposerState) => void;
}) {
  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
      <div className="space-y-6">
        <div className="grid gap-3 sm:grid-cols-2">
          {pluginCatalog.map((plugin) => {
            const isEnabled = value.plugins.includes(plugin.id);
            return (
              <button
                key={plugin.id}
                type="button"
                onClick={() => {
                  onChange({
                    ...value,
                    plugins: isEnabled
                      ? value.plugins.filter((id) => id !== plugin.id)
                      : [...value.plugins, plugin.id]
                  });
                }}
                className={`flex h-full flex-col rounded-lg border p-4 text-left transition hover:border-primary ${
                  isEnabled ? 'border-primary bg-primary/5 shadow-sm' : 'border-border bg-card'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-semibold text-foreground">{plugin.name}</p>
                    <p className="text-xs uppercase tracking-wide text-muted-foreground">{plugin.category}</p>
                  </div>
                  {plugin.risk === 'high' ? <Flame className="h-4 w-4 text-destructive" /> : <Plug className="h-4 w-4 text-muted-foreground" />}
                </div>
                <p className="mt-3 text-sm text-muted-foreground">{plugin.description}</p>
                <div className="mt-auto pt-4 text-xs text-muted-foreground">
                  Risk level: <span className="font-medium capitalize">{plugin.risk}</span>
                </div>
              </button>
            );
          })}
        </div>
        {value.plugins.length === 0 ? (
          <p className="text-sm text-muted-foreground">Select at least one plugin to continue.</p>
        ) : null}
      </div>
      <MimirAssistant value={value} onChange={onChange} />
    </div>
  );
}

type MimirAssistantMessage =
  | {
      id: string;
      role: 'user';
      content: string;
    }
  | {
      id: string;
      role: 'assistant';
      content: string;
      recommendations?: MimirRecommendation[];
      followUps?: string[];
      kind: 'context' | 'chat';
    };

function createAgentContext(state: RunComposerState): MimirAgentContext {
  return {
    scopePolicy: state.scopePolicy,
    targets: [...state.targets],
    targetNotes: state.targetNotes,
    plugins: [...state.plugins],
    limits: {
      concurrency: state.limits.concurrency,
      maxRps: state.limits.maxRps,
      maxFindings: state.limits.maxFindings,
      safeMode: state.limits.safeMode
    }
  } satisfies MimirAgentContext;
}

function createMessageId() {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return Math.random().toString(36).slice(2);
}

function MimirAssistant({
  value,
  onChange
}: {
  value: RunComposerState;
  onChange: (next: RunComposerState) => void;
}) {
  const [messages, setMessages] = useState<MimirAssistantMessage[]>([]);
  const [input, setInput] = useState('');
  const [isThinking, setIsThinking] = useState(false);
  const [contextSignature, setContextSignature] = useState('');
  const hasBootstrappedRef = useRef(false);
  const inputIdRef = useRef(`mimir-input-${createMessageId()}`);

  const context = useMemo(() => createAgentContext(value), [value]);
  const fingerprint = useMemo(() => buildContextFingerprint(context), [context]);

  const pluginNameLookup = useMemo(() => {
    const map = new Map<string, string>();
    for (const plugin of pluginCatalog) {
      map.set(plugin.id, plugin.name);
    }
    return map;
  }, []);

  const primeAgent = useCallback(async () => {
    setIsThinking(true);
    try {
      const response = await runMimirAgent({ intent: 'context', context, messages: [] });
      setMessages([
        {
          id: createMessageId(),
          role: 'assistant',
          content: response.message,
          recommendations: response.recommendations,
          followUps: response.followUps,
          kind: 'context'
        }
      ]);
      setContextSignature(fingerprint);
    } catch (error) {
      console.error('Failed to prime Mimir assistant', error);
      toast.error('Unable to load Mimir recommendations.');
    } finally {
      setIsThinking(false);
    }
  }, [context, fingerprint]);

  useEffect(() => {
    if (hasBootstrappedRef.current) {
      return;
    }
    hasBootstrappedRef.current = true;
    void primeAgent();
  }, [primeAgent]);

  useEffect(() => {
    if (!hasBootstrappedRef.current) {
      return;
    }
    if (messages.length !== 1) {
      return;
    }
    const [message] = messages;
    if (message.role !== 'assistant' || message.kind !== 'context') {
      return;
    }
    if (contextSignature === fingerprint) {
      return;
    }
    if (isThinking) {
      return;
    }
    void primeAgent();
  }, [contextSignature, fingerprint, isThinking, messages, primeAgent]);

  const contextStale = contextSignature !== '' && fingerprint !== contextSignature;

  const handleSend = useCallback(async () => {
    const trimmed = input.trim();
    if (trimmed === '' || isThinking) {
      return;
    }
    const userMessage: MimirAssistantMessage = {
      id: createMessageId(),
      role: 'user',
      content: trimmed
    };
    const conversation = [...messages, userMessage];
    setMessages(conversation);
    setInput('');
    setIsThinking(true);
    try {
      const response = await runMimirAgent({
        intent: 'chat',
        context,
        messages: conversation.map((message) => ({ role: message.role, content: message.content }))
      });
      setMessages((previous) => [
        ...previous,
        {
          id: createMessageId(),
          role: 'assistant',
          content: response.message,
          recommendations: response.recommendations,
          followUps: response.followUps,
          kind: 'chat'
        }
      ]);
      setContextSignature(fingerprint);
    } catch (error) {
      console.error('Mimir assistant failed to respond', error);
      toast.error('Mimir was unable to generate a response.');
    } finally {
      setIsThinking(false);
    }
  }, [context, fingerprint, input, isThinking, messages]);

  const handleApplyRecommendation = useCallback(
    (recommendation: MimirRecommendation) => {
      const nextPlugins = new Set(value.plugins);
      let changed = false;
      for (const pluginId of recommendation.plugins) {
        if (!nextPlugins.has(pluginId)) {
          nextPlugins.add(pluginId);
          changed = true;
        }
      }
      if (!changed) {
        toast.info('All recommended plugins are already enabled.');
        return;
      }
      onChange({
        ...value,
        plugins: Array.from(nextPlugins)
      });
      toast.success(`Enabled ${recommendation.title}`);
    },
    [onChange, value]
  );

  return (
    <div className="flex h-full min-h-[24rem] flex-col rounded-lg border border-border bg-card shadow-sm">
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <div>
          <div className="flex items-center gap-2 text-sm font-semibold text-foreground">
            <Bot className="h-4 w-4 text-primary" aria-hidden />
            <span>Mimir assistant</span>
          </div>
          <p className="text-xs text-muted-foreground">Context-aware plugin strategist powered by embedded LLM heuristics.</p>
        </div>
        <Button
          type="button"
          variant="ghost"
          size="icon"
          onClick={() => void primeAgent()}
          disabled={isThinking}
          aria-label="Refresh Mimir suggestions"
        >
          {isThinking ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : <RefreshCw className="h-4 w-4" aria-hidden />}
        </Button>
      </div>
      <div className="flex flex-1 flex-col gap-3 p-4">
        <div className="flex-1 space-y-3 overflow-y-auto pr-1">
          {messages.map((message) => {
            if (message.role === 'assistant') {
              const assistant = message;
              return (
                <div key={message.id} className="space-y-2">
                  <div className="w-full rounded-lg border border-border bg-muted/40 p-3 text-sm text-foreground">
                    <p className="whitespace-pre-wrap leading-relaxed">{assistant.content}</p>
                  </div>
                  {assistant.recommendations && assistant.recommendations.length > 0 ? (
                    <div className="space-y-3">
                      {assistant.recommendations.map((recommendation) => (
                        <div key={recommendation.id} className="rounded-md border border-border bg-background p-3 text-sm">
                          <div className="flex flex-wrap items-start justify-between gap-2">
                            <div>
                              <p className="text-sm font-semibold text-foreground">{recommendation.title}</p>
                              <p className="text-xs text-muted-foreground">{recommendation.description}</p>
                            </div>
                            <Button
                              type="button"
                              variant="outline"
                              size="sm"
                              onClick={() => handleApplyRecommendation(recommendation)}
                              disabled={isThinking}
                            >
                              Enable
                            </Button>
                          </div>
                          <div className="mt-2 flex flex-wrap gap-1">
                            {recommendation.plugins.map((pluginId) => {
                              const label = pluginNameLookup.get(pluginId) ?? pluginId;
                              const enabled = value.plugins.includes(pluginId);
                              return (
                                <span
                                  key={`${recommendation.id}-${pluginId}`}
                                  className={`rounded-full border px-2 py-0.5 text-xs ${
                                    enabled
                                      ? 'border-primary/60 bg-primary/10 text-primary'
                                      : 'border-border bg-muted/40 text-muted-foreground'
                                  }`}
                                >
                                  {label}
                                </span>
                              );
                            })}
                          </div>
                          <p className="mt-2 text-xs text-muted-foreground">{recommendation.rationale}</p>
                          {recommendation.nextScan ? (
                            <div className="mt-2 flex items-start gap-2 rounded-md border border-dashed border-primary/50 bg-primary/5 p-2 text-xs text-primary">
                              <Lightbulb className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" aria-hidden />
                              <span>{recommendation.nextScan}</span>
                            </div>
                          ) : null}
                        </div>
                      ))}
                    </div>
                  ) : null}
                  {assistant.followUps && assistant.followUps.length > 0 ? (
                    <div className="space-y-1 text-xs text-muted-foreground">
                      {assistant.followUps.map((item, index) => (
                        <div key={`${assistant.id}-followup-${index}`} className="flex items-start gap-2">
                          <Sparkles className="mt-0.5 h-3 w-3 text-primary" aria-hidden />
                          <span>{item}</span>
                        </div>
                      ))}
                    </div>
                  ) : null}
                </div>
              );
            }

            return (
              <div key={message.id} className="flex justify-end">
                <div className="max-w-[85%] rounded-lg border border-primary/50 bg-primary/10 px-3 py-2 text-sm text-primary">
                  <p className="whitespace-pre-wrap leading-relaxed">{message.content}</p>
                </div>
              </div>
            );
          })}
          {isThinking ? (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
              <span>Thinking through your scope…</span>
            </div>
          ) : null}
        </div>
        {contextStale ? (
          <div className="flex items-center gap-2 rounded-md border border-warning/40 bg-warning/10 p-2 text-xs text-warning">
            <Sparkles className="h-3.5 w-3.5" aria-hidden />
            <span>Configuration changed since the last suggestion. Refresh Mimir to sync context.</span>
          </div>
        ) : null}
        <div className="space-y-2">
          <label className="text-xs font-medium uppercase tracking-wide text-muted-foreground" htmlFor={inputIdRef.current}>
            Ask Mimir
          </label>
          <div className="flex flex-col gap-2">
            <textarea
              id={inputIdRef.current}
              value={input}
              onChange={(event) => setInput(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter' && !event.shiftKey) {
                  event.preventDefault();
                  void handleSend();
                }
              }}
              rows={3}
              className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
              placeholder="Ask for plugin combos, next scans, or risk trade-offs…"
            />
            <div className="flex items-center justify-end">
              <Button type="button" size="sm" onClick={() => void handleSend()} disabled={isThinking || input.trim() === ''}>
                <Send className="mr-2 h-4 w-4" aria-hidden />
                Send
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function LimitsStep({
  value,
  onChange
}: {
  value: RunComposerState;
  onChange: (next: RunComposerState) => void;
}) {
  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-3">
        <div className="rounded-lg border border-border bg-card p-4">
          <label className="text-sm font-medium text-foreground">Concurrent workers</label>
          <input
            type="number"
            min={1}
            max={30}
            value={value.limits.concurrency}
            onChange={(event) =>
              onChange({
                ...value,
                limits: { ...value.limits, concurrency: Number.parseInt(event.target.value || '1', 10) }
              })
            }
            className="mt-2 w-full rounded-md border border-border bg-background px-3 py-2 text-sm shadow-sm focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
          />
          <p className="mt-2 text-xs text-muted-foreground">
            Total parallel plugin executions. Safe defaults keep infrastructure load predictable.
          </p>
        </div>
        <div className="rounded-lg border border-border bg-card p-4">
          <label className="text-sm font-medium text-foreground">Max requests per second</label>
          <input
            type="number"
            min={1}
            max={500}
            value={value.limits.maxRps}
            onChange={(event) =>
              onChange({
                ...value,
                limits: { ...value.limits, maxRps: Number.parseInt(event.target.value || '1', 10) }
              })
            }
            className="mt-2 w-full rounded-md border border-border bg-background px-3 py-2 text-sm shadow-sm focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
          />
          <p className="mt-2 text-xs text-muted-foreground">
            Apply global throttling to respect third-party limits and reduce false positives.
          </p>
        </div>
        <div className="rounded-lg border border-border bg-card p-4">
          <label className="text-sm font-medium text-foreground">Finding threshold</label>
          <input
            type="number"
            min={1}
            max={5_000}
            value={value.limits.maxFindings}
            onChange={(event) =>
              onChange({
                ...value,
                limits: { ...value.limits, maxFindings: Number.parseInt(event.target.value || '1', 10) }
              })
            }
            className="mt-2 w-full rounded-md border border-border bg-background px-3 py-2 text-sm shadow-sm focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
          />
          <p className="mt-2 text-xs text-muted-foreground">
            Automatically pause once this number of findings has been generated.
          </p>
        </div>
      </div>
      <label className="inline-flex items-center gap-2 text-sm font-medium text-foreground">
        <input
          type="checkbox"
          checked={value.limits.safeMode}
          onChange={(event) =>
            onChange({
              ...value,
              limits: { ...value.limits, safeMode: event.target.checked }
            })
          }
          className="h-4 w-4 rounded border border-border"
        />
        Enable safe mode (block destructive verbs and force dry-run paths)
      </label>
      <p className="text-xs text-muted-foreground">
        Safe mode reduces risk by sanitizing payloads and enforcing non-destructive HTTP verbs.
      </p>
    </div>
  );
}

function AuthStep({
  value,
  onChange
}: {
  value: RunComposerState;
  onChange: (next: RunComposerState) => void;
}) {
  return (
    <div className="space-y-6">
      <div className="grid gap-3 md:grid-cols-4">
        {[
          { id: 'none', title: 'No auth', description: 'Use for public endpoints.' },
          { id: 'apiKey', title: 'API key', description: 'Send token via header or query param.' },
          { id: 'basic', title: 'Basic auth', description: 'Username and password credentials.' },
          { id: 'oauth', title: 'OAuth2 client', description: 'Exchange client credentials before requests.' }
        ].map((option) => {
          const isSelected = value.auth.strategy === option.id;
          return (
            <button
              key={option.id}
              type="button"
              onClick={() =>
                onChange({
                  ...value,
                  auth: { ...value.auth, strategy: option.id as AuthStrategy }
                })
              }
              className={`rounded-lg border p-4 text-left transition hover:border-primary ${
                isSelected ? 'border-primary bg-primary/5 shadow-sm' : 'border-border bg-card'
              }`}
            >
              <p className="text-sm font-semibold text-foreground">{option.title}</p>
              <p className="mt-2 text-xs text-muted-foreground">{option.description}</p>
            </button>
          );
        })}
      </div>

      {value.auth.strategy === 'apiKey' ? (
        <div className="rounded-lg border border-border bg-card p-4">
          <label className="text-sm font-medium text-foreground">API key</label>
          <input
            value={value.auth.apiKey}
            onChange={(event) =>
              onChange({
                ...value,
                auth: { ...value.auth, apiKey: event.target.value }
              })
            }
            className="mt-2 w-full rounded-md border border-border bg-background px-3 py-2 text-sm shadow-sm focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
            placeholder="sk_live_..."
          />
          <p className="mt-2 text-xs text-muted-foreground">
            Stored securely in the 0xgen vault and injected only for this run.
          </p>
        </div>
      ) : null}

      {value.auth.strategy === 'basic' ? (
        <div className="grid gap-3 md:grid-cols-2">
          <div className="rounded-lg border border-border bg-card p-4">
            <label className="text-sm font-medium text-foreground">Username</label>
            <input
              value={value.auth.username}
              onChange={(event) =>
                onChange({
                  ...value,
                  auth: { ...value.auth, username: event.target.value }
                })
              }
              className="mt-2 w-full rounded-md border border-border bg-background px-3 py-2 text-sm shadow-sm focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
            />
          </div>
          <div className="rounded-lg border border-border bg-card p-4">
            <label className="text-sm font-medium text-foreground">Password</label>
            <input
              type="password"
              value={value.auth.password}
              onChange={(event) =>
                onChange({
                  ...value,
                  auth: { ...value.auth, password: event.target.value }
                })
              }
              className="mt-2 w-full rounded-md border border-border bg-background px-3 py-2 text-sm shadow-sm focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
            />
          </div>
        </div>
      ) : null}

      {value.auth.strategy === 'oauth' ? (
        <div className="grid gap-3 md:grid-cols-2">
          <div className="rounded-lg border border-border bg-card p-4">
            <label className="text-sm font-medium text-foreground">Client ID</label>
            <input
              value={value.auth.oauthClientId}
              onChange={(event) =>
                onChange({
                  ...value,
                  auth: { ...value.auth, oauthClientId: event.target.value }
                })
              }
              className="mt-2 w-full rounded-md border border-border bg-background px-3 py-2 text-sm shadow-sm focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
            />
          </div>
          <div className="rounded-lg border border-border bg-card p-4">
            <label className="text-sm font-medium text-foreground">Client secret</label>
            <input
              value={value.auth.oauthClientSecret}
              onChange={(event) =>
                onChange({
                  ...value,
                  auth: { ...value.auth, oauthClientSecret: event.target.value }
                })
              }
              className="mt-2 w-full rounded-md border border-border bg-background px-3 py-2 text-sm shadow-sm focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
            />
          </div>
        </div>
      ) : null}
    </div>
  );
}

function ReviewStep({
  value,
  estimatedImpact,
  warnings,
  presets,
  onSavePreset,
  onSelectPreset,
  onChange
}: {
  value: RunComposerState;
  estimatedImpact: ReturnType<typeof computeEstimatedImpact>;
  warnings: string[];
  presets: RunComposerPreset[];
  onSavePreset: (name: string) => void;
  onSelectPreset: (id: string) => void;
  onChange: (next: RunComposerState) => void;
}) {
  const [presetName, setPresetName] = useState('');

  return (
    <div className="space-y-8">
      <div className="rounded-lg border border-border bg-card p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-sm font-medium text-foreground">Estimated impact</p>
            <p className="text-xs text-muted-foreground">
              Based on selected targets, plugins, and limits. Adjust scope or rate limits to tune.
            </p>
          </div>
          <Zap className="h-5 w-5 text-primary" />
        </div>
        <dl className="mt-4 grid gap-4 sm:grid-cols-4">
          <div>
            <dt className="text-xs uppercase tracking-wide text-muted-foreground">Targets</dt>
            <dd className="text-lg font-semibold text-foreground">{estimatedImpact.targets}</dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-muted-foreground">Plugins</dt>
            <dd className="text-lg font-semibold text-foreground">{estimatedImpact.plugins}</dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-muted-foreground">Est. requests</dt>
            <dd className="text-lg font-semibold text-foreground">{estimatedImpact.estimatedRequests}</dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-muted-foreground">Est. duration</dt>
            <dd className="text-lg font-semibold text-foreground">{estimatedImpact.estimatedDurationMinutes} min</dd>
          </div>
        </dl>
      </div>

      {warnings.length > 0 ? (
        <div className="rounded-lg border border-amber-500 bg-amber-500/10 p-4 text-sm text-amber-900">
          <div className="flex items-center gap-2 font-semibold">
            <ShieldAlert className="h-4 w-4" />
            Safe mode advisory
          </div>
          <ul className="mt-2 list-disc space-y-1 pl-5">
            {warnings.map((warning, index) => (
              <li key={index}>{warning}</li>
            ))}
          </ul>
        </div>
      ) : null}

      <div className="rounded-lg border border-border bg-card p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-sm font-medium text-foreground">Presets</p>
            <p className="text-xs text-muted-foreground">Save reusable templates for future runs.</p>
          </div>
          <DownloadCloud className="h-5 w-5 text-muted-foreground" />
        </div>
        <div className="mt-4 flex flex-col gap-3 md:flex-row">
          <input
            value={presetName}
            onChange={(event) => setPresetName(event.target.value)}
            placeholder="Preset name"
            className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm shadow-sm focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
          />
          <Button
            type="button"
            onClick={() => {
              if (presetName.trim().length === 0) {
                toast.error('Give the preset a name before saving');
                return;
              }
              onSavePreset(presetName.trim());
              setPresetName('');
            }}
          >
            Save preset
          </Button>
        </div>
        {presets.length > 0 ? (
          <div className="mt-4">
            <label className="text-xs uppercase tracking-wide text-muted-foreground">Load preset</label>
            <div className="mt-2 flex flex-col gap-2">
              {presets.map((preset) => (
                <button
                  key={preset.id}
                  type="button"
                  onClick={() => onSelectPreset(preset.id)}
                  className="flex flex-col rounded-md border border-border bg-background p-3 text-left transition hover:border-primary"
                >
                  <span className="text-sm font-medium text-foreground">{preset.name}</span>
                  <span className="text-xs text-muted-foreground">
                    Saved {new Date(preset.createdAt).toLocaleString()}
                  </span>
                </button>
              ))}
            </div>
          </div>
        ) : (
          <p className="mt-4 text-xs text-muted-foreground">
            No presets saved yet. Create one to rehydrate this form instantly next time.
          </p>
        )}
      </div>

      <div className="rounded-lg border border-border bg-card p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-sm font-medium text-foreground">Scheduling</p>
            <p className="text-xs text-muted-foreground">Launch immediately or pick a time in the future.</p>
          </div>
          <CalendarClock className="h-5 w-5 text-muted-foreground" />
        </div>
        <div className="mt-4 flex flex-col gap-3 md:flex-row">
          <label className="flex items-center gap-2 text-sm">
            <input
              type="radio"
              checked={value.schedule.mode === 'now'}
              onChange={() =>
                onChange({
                  ...value,
                  schedule: { ...value.schedule, mode: 'now' }
                })
              }
            />
            Start immediately
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="radio"
              checked={value.schedule.mode === 'later'}
              onChange={() =>
                onChange({
                  ...value,
                  schedule: { ...value.schedule, mode: 'later' }
                })
              }
            />
            Schedule for later
          </label>
        </div>
        {value.schedule.mode === 'later' ? (
          <div className="mt-4 grid gap-3 md:grid-cols-2">
            <div>
              <label className="text-xs uppercase tracking-wide text-muted-foreground">Start at</label>
              <input
                type="datetime-local"
                value={value.schedule.startAt}
                onChange={(event) =>
                  onChange({
                    ...value,
                    schedule: { ...value.schedule, startAt: event.target.value }
                  })
                }
                className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2 text-sm shadow-sm focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
              />
            </div>
            <div>
              <label className="text-xs uppercase tracking-wide text-muted-foreground">Timezone</label>
              <input
                value={value.schedule.timezone}
                onChange={(event) =>
                  onChange({
                    ...value,
                    schedule: { ...value.schedule, timezone: event.target.value }
                  })
                }
                className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2 text-sm shadow-sm focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
              />
            </div>
          </div>
        ) : null}
      </div>

      <div className="rounded-lg border border-border bg-card p-4">
        <p className="text-sm font-medium text-foreground">Summary</p>
        <dl className="mt-3 grid gap-4 sm:grid-cols-2">
          <div>
            <dt className="text-xs uppercase tracking-wide text-muted-foreground">Run name</dt>
            <dd className="text-sm text-foreground">{value.name}</dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-muted-foreground">Scope policy</dt>
            <dd className="text-sm text-foreground">{scopeOptions.find((option) => option.id === value.scopePolicy)?.title}</dd>
          </div>
          <div className="sm:col-span-2">
            <dt className="text-xs uppercase tracking-wide text-muted-foreground">Targets</dt>
            <dd className="text-sm text-foreground">
              {value.targets.filter((target) => target.trim().length > 0).length > 0
                ? value.targets.filter((target) => target.trim().length > 0).join(', ')
                : '—'}
            </dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-muted-foreground">Plugins</dt>
            <dd className="text-sm text-foreground">
              {value.plugins
                .map((id) => pluginCatalog.find((plugin) => plugin.id === id)?.name ?? id)
                .join(', ') || '—'}
            </dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-muted-foreground">Limits</dt>
            <dd className="text-sm text-foreground">
              {value.limits.concurrency} workers, {value.limits.maxRps} rps, stop at {value.limits.maxFindings} findings
            </dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-muted-foreground">Auth</dt>
            <dd className="text-sm text-foreground">{value.auth.strategy === 'none' ? 'No auth' : value.auth.strategy}</dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-muted-foreground">Safe mode</dt>
            <dd className="text-sm text-foreground">{value.limits.safeMode ? 'Enabled' : 'Disabled'}</dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-muted-foreground">Schedule</dt>
            <dd className="text-sm text-foreground">
              {value.schedule.mode === 'now'
                ? 'Start immediately'
                : `Scheduled for ${new Date(value.schedule.startAt).toLocaleString()} (${value.schedule.timezone})`}
            </dd>
          </div>
        </dl>
      </div>
    </div>
  );
}

function RunComposerRoute() {
  const navigate = useNavigate();
  const [activeIndex, setActiveIndex] = useState(0);
  const [state, setState] = useState<RunComposerState>(defaultState);
  const [presets, setPresets] = useLocalStorage<RunComposerPreset[]>(presetStorageKey, []);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const { registerCommand } = useCommandCenter();

  const currentStep = steps[activeIndex];

  const estimatedImpact = useMemo(() => computeEstimatedImpact(state), [state]);
  const warnings = useMemo(() => computeWarnings(state), [state]);

  const handleStateChange = (next: RunComposerState) => {
    setState(next);
  };

  const goToStep = (direction: 'next' | 'previous') => {
    setActiveIndex((previous) => {
      if (direction === 'next') {
        return Math.min(previous + 1, steps.length - 1);
      }
      return Math.max(previous - 1, 0);
    });
  };

  const renderStep = () => {
    switch (currentStep.id) {
      case 'targets':
        return <TargetsStep value={state} onChange={handleStateChange} />;
      case 'plugins':
        return <PluginsStep value={state} onChange={handleStateChange} />;
      case 'limits':
        return <LimitsStep value={state} onChange={handleStateChange} />;
      case 'auth':
        return <AuthStep value={state} onChange={handleStateChange} />;
      case 'review':
        return (
          <ReviewStep
            value={state}
            estimatedImpact={estimatedImpact}
            warnings={warnings}
            presets={presets}
            onSavePreset={(name) => {
              const preset: RunComposerPreset = {
                id: `preset-${Date.now()}`,
                name,
                createdAt: new Date().toISOString(),
                data: JSON.parse(JSON.stringify(state)) as RunComposerState
              };
              setPresets((existing) => [preset, ...existing].slice(0, 12));
              toast.success(`Preset "${name}" saved`);
            }}
            onSelectPreset={(id) => {
              const preset = presets.find((item) => item.id === id);
              if (!preset) {
                toast.error('Preset not found');
                return;
              }
              setState(JSON.parse(JSON.stringify(preset.data)) as RunComposerState);
              toast.success(`Preset "${preset.name}" loaded`);
            }}
            onChange={handleStateChange}
          />
        );
      default:
        return null;
    }
  };

  const canContinue = useMemo(() => {
    if (currentStep.id === 'targets') {
      return state.name.trim().length > 0 && state.targets.some((target) => target.trim().length > 0);
    }
    if (currentStep.id === 'plugins') {
      return state.plugins.length > 0;
    }
    if (currentStep.id === 'auth') {
      if (state.auth.strategy === 'apiKey') {
        return state.auth.apiKey.trim().length > 0;
      }
      if (state.auth.strategy === 'basic') {
        return state.auth.username.trim().length > 0 && state.auth.password.trim().length > 0;
      }
      if (state.auth.strategy === 'oauth') {
        return state.auth.oauthClientId.trim().length > 0 && state.auth.oauthClientSecret.trim().length > 0;
      }
    }
    if (currentStep.id === 'limits') {
      return state.limits.concurrency > 0 && state.limits.maxRps > 0 && state.limits.maxFindings > 0;
    }
    return true;
  }, [currentStep.id, state]);

  const handleLaunch = useCallback(async () => {
    const scheduleDate =
      state.schedule.mode === 'later' && state.schedule.startAt
        ? new Date(state.schedule.startAt)
        : undefined;

    if (state.schedule.mode === 'later') {
      if (!scheduleDate || Number.isNaN(scheduleDate.getTime())) {
        toast.error('Please provide a valid start time for scheduled runs.');
        return;
      }
    }

    const payload = buildStartRunPayload(state, scheduleDate?.toISOString());

    try {
      setIsSubmitting(true);
      const response = await startRun(payload);

      if (payload.schedule.mode === 'later') {
        toast.success(
          `Run ${response.id} scheduled for ${scheduleDate!.toLocaleString()} (${payload.schedule.timezone ?? 'UTC'})`
        );
        navigate({ to: '/runs' });
        return;
      }

      toast.success(`Run ${response.id} kicked off`);
      navigate({ to: '/runs/$runId', params: { runId: response.id } });
    } catch (error) {
      console.error('Failed to launch run', error);
      toast.error('Failed to launch run');
    } finally {
      setIsSubmitting(false);
    }
  }, [navigate, state]);

  useEffect(() => {
    return registerCommand({
      id: 'runs.launch',
      title: state.schedule.mode === 'later' ? 'Schedule run' : 'Launch run now',
      description: 'Start the configured run without leaving the keyboard',
      group: 'Runs',
      shortcut: 'mod+enter',
      run: () => {
        if (currentStep.id === 'review' && !isSubmitting) {
          void handleLaunch();
        }
      },
      disabled: currentStep.id !== 'review' || isSubmitting,
      allowInInput: true
    });
  }, [registerCommand, state.schedule.mode, currentStep.id, isSubmitting, handleLaunch]);

  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-8 p-6">
      <div className="flex items-center justify-between">
        <div className="space-y-2">
          <div className="flex items-center gap-3 text-sm text-muted-foreground">
            <Link to="/runs" className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
              <ArrowLeft className="h-3 w-3" /> Back to runs
            </Link>
            <span className="text-muted-foreground">/</span>
            <span>Run composer</span>
          </div>
          <h1 className="text-3xl font-semibold tracking-tight">Compose a run</h1>
          <p className="text-muted-foreground">
            Configure targets, automation, and guardrails before launching. Presets make repeatable playbooks easy.
          </p>
        </div>
        <Button
          variant="outline"
          onClick={() => {
            setState(defaultState);
            setActiveIndex(0);
          }}
          disabled={isSubmitting}
        >
          Reset
        </Button>
      </div>

      <StepIndicator currentStep={currentStep} />

      <section className="rounded-xl border border-border bg-card p-6 shadow-sm">
        <header className="mb-6 space-y-1">
          <p className="text-sm font-semibold text-foreground">{currentStep.title}</p>
          <p className="text-sm text-muted-foreground">{currentStep.description}</p>
        </header>
        <div>{renderStep()}</div>
      </section>

      <footer className="flex items-center justify-between">
        <Button
          type="button"
          variant="ghost"
          onClick={() => {
            if (activeIndex === 0) {
              navigate({ to: '/runs' });
            } else {
              goToStep('previous');
            }
          }}
          disabled={activeIndex === 0 && isSubmitting}
          className="gap-2"
        >
          <ChevronLeft className="h-4 w-4" />
          {activeIndex === 0 ? 'Cancel' : 'Back'}
        </Button>
        <div className="flex items-center gap-3">
          {currentStep.id !== 'review' ? (
            <Button type="button" className="gap-2" onClick={() => goToStep('next')} disabled={!canContinue}>
              Next
              <ChevronRight className="h-4 w-4" />
            </Button>
          ) : (
            <Button type="button" className="gap-2" onClick={handleLaunch} disabled={isSubmitting}>
              {state.schedule.mode === 'later' ? 'Schedule run' : isSubmitting ? 'Launching…' : 'Launch run'}
              <PlayIcon />
            </Button>
          )}
        </div>
      </footer>
    </div>
  );
}

function PlayIcon() {
  return (
    <span className="flex h-5 w-5 items-center justify-center rounded-full bg-primary text-primary-foreground">
      <svg viewBox="0 0 16 16" className="h-3 w-3 fill-current">
        <path d="M5 3.5v9l7-4.5-7-4.5z" />
      </svg>
    </span>
  );
}

export const Route = createFileRoute('/runs/composer')({
  component: RunComposerRoute
});

export default RunComposerRoute;
