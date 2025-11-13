import { createFileRoute } from '@tanstack/react-router';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Play,
  Pause,
  X,
  Download,
  AlertTriangle,
  Zap,
  Target,
  Clock,
  Activity,
  ChevronRight,
  ChevronDown,
  Settings,
  FileText,
  Search
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

import { Button } from '../components/ui/button';
import { cn } from '../lib/utils';
import { toast } from 'sonner';

// Types
type AttackType = 'sniper' | 'battering-ram' | 'pitchfork' | 'cluster-bomb';

type PayloadType = 'wordlist' | 'range' | 'custom' | 'ai-generated';

type Position = {
  index: number;
  name: string;
  start: number;
  end: number;
  color: string;
};

type FuzzResult = {
  id: number;
  payload: string;
  statusCode: number;
  contentLength: number;
  duration: number;
  anomalyScore: number;
  isInteresting: boolean;
  timestamp: string;
};

type BlitzSession = {
  running: boolean;
  progress: {
    completed: number;
    total: number;
    rps: number;
    eta: number;
  };
  anomalies: number;
  results: FuzzResult[];
};

// Colors for position markers
const POSITION_COLORS = [
  'bg-blue-500/20 border-blue-500 text-blue-700 dark:text-blue-300',
  'bg-purple-500/20 border-purple-500 text-purple-700 dark:text-purple-300',
  'bg-green-500/20 border-green-500 text-green-700 dark:text-green-300',
  'bg-orange-500/20 border-orange-500 text-orange-700 dark:text-orange-300',
  'bg-pink-500/20 border-pink-500 text-pink-700 dark:text-pink-300'
];

// Request Template Editor Component
function RequestTemplateEditor({
  value,
  onChange,
  positions,
  onPositionsChange
}: {
  value: string;
  onChange: (value: string) => void;
  positions: Position[];
  onPositionsChange: (positions: Position[]) => void;
}) {
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const [selection, setSelection] = useState<{ start: number; end: number } | null>(null);

  const handleAddMarker = useCallback(() => {
    const textarea = textareaRef.current;
    if (!textarea) return;

    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;

    if (start === end) {
      toast.error('Please select text to mark as a fuzz position');
      return;
    }

    const selectedText = value.substring(start, end);
    const name = selectedText.trim() || `pos${positions.length + 1}`;

    const newPosition: Position = {
      index: positions.length,
      name,
      start,
      end,
      color: POSITION_COLORS[positions.length % POSITION_COLORS.length]
    };

    // Insert markers
    const newValue = value.substring(0, start) + `{{${selectedText}}}` + value.substring(end);

    onChange(newValue);
    onPositionsChange([...positions, newPosition]);

    toast.success(`Added fuzz position: ${name}`);
  }, [value, positions, onChange, onPositionsChange]);

  const handleRemovePosition = useCallback((index: number) => {
    const newPositions = positions.filter(p => p.index !== index);
    onPositionsChange(newPositions);
  }, [positions, onPositionsChange]);

  return (
    <div className="flex h-full flex-col gap-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <FileText className="h-4 w-4 text-muted-foreground" />
          <h3 className="text-sm font-medium">Request Template</h3>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={handleAddMarker}
          disabled={!selection}
        >
          <Target className="mr-1.5 h-3.5 w-3.5" />
          Add Marker
        </Button>
      </div>

      <div className="flex-1 overflow-hidden rounded-lg border border-border bg-muted/30">
        <textarea
          ref={textareaRef}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onSelect={(e) => {
            const target = e.target as HTMLTextAreaElement;
            if (target.selectionStart !== target.selectionEnd) {
              setSelection({ start: target.selectionStart, end: target.selectionEnd });
            } else {
              setSelection(null);
            }
          }}
          className="h-full w-full resize-none bg-transparent p-4 font-mono text-sm focus:outline-none"
          placeholder="GET /api/user/123 HTTP/1.1&#10;Host: example.com&#10;&#10;Paste your HTTP request here..."
          spellCheck={false}
        />
      </div>

      {positions.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {positions.map((pos) => (
            <button
              key={pos.index}
              onClick={() => handleRemovePosition(pos.index)}
              className={cn(
                'inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs font-medium transition-colors hover:opacity-80',
                pos.color
              )}
            >
              <Target className="h-3 w-3" />
              {pos.name}
              <X className="h-3 w-3" />
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// Payload Configuration Panel
function PayloadConfigPanel({
  type,
  onTypeChange,
  config,
  onConfigChange
}: {
  type: PayloadType;
  onTypeChange: (type: PayloadType) => void;
  config: any;
  onConfigChange: (config: any) => void;
}) {
  const [previewPayloads, setPreviewPayloads] = useState<string[]>([]);

  useEffect(() => {
    // Generate preview based on type
    const previews: string[] = [];
    switch (type) {
      case 'wordlist':
        previews.push('admin', 'user', 'test', 'root', 'guest');
        break;
      case 'range':
        previews.push('1', '2', '3', '...', '100');
        break;
      case 'custom':
        previews.push("'", '"', '1=1', 'admin', '<script>');
        break;
      case 'ai-generated':
        previews.push("' OR 1=1--", '<script>alert(1)</script>', '; whoami', '../../../etc/passwd');
        break;
    }
    setPreviewPayloads(previews);
  }, [type]);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-2">
        <Zap className="h-4 w-4 text-muted-foreground" />
        <h3 className="text-sm font-medium">Payload Configuration</h3>
      </div>

      <div className="space-y-3">
        <div>
          <label className="mb-1.5 block text-xs font-medium text-muted-foreground">
            Payload Type
          </label>
          <select
            value={type}
            onChange={(e) => onTypeChange(e.target.value as PayloadType)}
            className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
          >
            <option value="wordlist">Wordlist</option>
            <option value="range">Range (Numeric)</option>
            <option value="custom">Custom List</option>
            <option value="ai-generated">AI-Generated</option>
          </select>
        </div>

        {type === 'wordlist' && (
          <div>
            <label className="mb-1.5 block text-xs font-medium text-muted-foreground">
              Wordlist File
            </label>
            <Button variant="outline" size="sm" className="w-full justify-start">
              <FileText className="mr-2 h-3.5 w-3.5" />
              Choose file...
            </Button>
          </div>
        )}

        {type === 'range' && (
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="mb-1.5 block text-xs font-medium text-muted-foreground">
                Start
              </label>
              <input
                type="number"
                value={config.start || 1}
                onChange={(e) => onConfigChange({ ...config, start: parseInt(e.target.value) })}
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
              />
            </div>
            <div>
              <label className="mb-1.5 block text-xs font-medium text-muted-foreground">
                End
              </label>
              <input
                type="number"
                value={config.end || 100}
                onChange={(e) => onConfigChange({ ...config, end: parseInt(e.target.value) })}
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
              />
            </div>
          </div>
        )}

        {type === 'custom' && (
          <div>
            <label className="mb-1.5 block text-xs font-medium text-muted-foreground">
              Custom Payloads (one per line)
            </label>
            <textarea
              value={config.custom || ''}
              onChange={(e) => onConfigChange({ ...config, custom: e.target.value })}
              className="h-24 w-full resize-none rounded-md border border-border bg-background p-2 font-mono text-xs focus:outline-none focus:ring-2 focus:ring-primary"
              placeholder="payload1&#10;payload2&#10;payload3"
            />
          </div>
        )}

        {type === 'ai-generated' && (
          <div className="rounded-lg bg-primary/10 p-3 text-xs text-primary">
            <div className="flex items-start gap-2">
              <Zap className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" />
              <div>
                <p className="font-medium">AI-Powered Payloads</p>
                <p className="mt-1 text-xs opacity-80">
                  Payloads will be generated based on endpoint context and target parameter analysis.
                </p>
              </div>
            </div>
          </div>
        )}
      </div>

      <div>
        <div className="mb-2 flex items-center justify-between">
          <label className="text-xs font-medium text-muted-foreground">Preview</label>
          <span className="text-xs text-muted-foreground">{previewPayloads.length} payloads</span>
        </div>
        <div className="max-h-32 overflow-y-auto rounded-md border border-border bg-muted/30 p-2">
          <div className="space-y-1">
            {previewPayloads.map((payload, index) => (
              <div key={index} className="font-mono text-xs text-foreground/80">
                {payload}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// Attack Settings Panel
function AttackSettingsPanel({
  attackType,
  onAttackTypeChange,
  concurrency,
  onConcurrencyChange,
  rateLimit,
  onRateLimitChange
}: {
  attackType: AttackType;
  onAttackTypeChange: (type: AttackType) => void;
  concurrency: number;
  onConcurrencyChange: (value: number) => void;
  rateLimit: number;
  onRateLimitChange: (value: number) => void;
}) {
  const [expanded, setExpanded] = useState(true);

  return (
    <div className="flex flex-col gap-3">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center justify-between text-sm font-medium hover:text-foreground"
      >
        <div className="flex items-center gap-2">
          <Settings className="h-4 w-4 text-muted-foreground" />
          <span>Attack Settings</span>
        </div>
        {expanded ? (
          <ChevronDown className="h-4 w-4 text-muted-foreground" />
        ) : (
          <ChevronRight className="h-4 w-4 text-muted-foreground" />
        )}
      </button>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="space-y-3 overflow-hidden"
          >
            <div>
              <label className="mb-1.5 block text-xs font-medium text-muted-foreground">
                Attack Type
              </label>
              <select
                value={attackType}
                onChange={(e) => onAttackTypeChange(e.target.value as AttackType)}
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
              >
                <option value="sniper">Sniper</option>
                <option value="battering-ram">Battering Ram</option>
                <option value="pitchfork">Pitchfork</option>
                <option value="cluster-bomb">Cluster Bomb</option>
              </select>
              <p className="mt-1 text-xs text-muted-foreground">
                {attackType === 'sniper' && 'Target one position at a time'}
                {attackType === 'battering-ram' && 'Use same payload in all positions'}
                {attackType === 'pitchfork' && 'Pair payloads from multiple lists'}
                {attackType === 'cluster-bomb' && 'Test all combinations'}
              </p>
            </div>

            <div>
              <label className="mb-1.5 flex items-center justify-between text-xs font-medium text-muted-foreground">
                <span>Concurrency</span>
                <span className="font-mono">{concurrency}</span>
              </label>
              <input
                type="range"
                min="1"
                max="100"
                value={concurrency}
                onChange={(e) => onConcurrencyChange(parseInt(e.target.value))}
                className="w-full"
              />
              <p className="mt-1 text-xs text-muted-foreground">Number of parallel requests</p>
            </div>

            <div>
              <label className="mb-1.5 flex items-center justify-between text-xs font-medium text-muted-foreground">
                <span>Rate Limit</span>
                <span className="font-mono">{rateLimit} req/s</span>
              </label>
              <input
                type="range"
                min="0"
                max="500"
                step="10"
                value={rateLimit}
                onChange={(e) => onRateLimitChange(parseInt(e.target.value))}
                className="w-full"
              />
              <p className="mt-1 text-xs text-muted-foreground">
                {rateLimit === 0 ? 'No rate limit' : `Max ${rateLimit} requests per second`}
              </p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// Progress Indicator Component
function ProgressIndicator({ session }: { session: BlitzSession }) {
  const percentage = session.progress.total > 0
    ? (session.progress.completed / session.progress.total) * 100
    : 0;

  const formatTime = (seconds: number) => {
    if (seconds < 60) return `${Math.round(seconds)}s`;
    const minutes = Math.floor(seconds / 60);
    const secs = Math.round(seconds % 60);
    return `${minutes}m ${secs}s`;
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between text-sm">
        <span className="font-medium">
          {session.progress.completed} / {session.progress.total} requests
        </span>
        <span className="font-mono text-muted-foreground">{percentage.toFixed(1)}%</span>
      </div>

      <div className="h-2 overflow-hidden rounded-full bg-muted">
        <motion.div
          className="h-full bg-gradient-to-r from-primary to-primary/80"
          initial={{ width: 0 }}
          animate={{ width: `${percentage}%` }}
          transition={{ duration: 0.3 }}
        />
      </div>

      <div className="grid grid-cols-3 gap-3 text-xs">
        <div className="flex items-center gap-2">
          <Activity className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-muted-foreground">RPS:</span>
          <span className="font-mono font-medium">{session.progress.rps.toFixed(1)}</span>
        </div>
        <div className="flex items-center gap-2">
          <Clock className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-muted-foreground">ETA:</span>
          <span className="font-mono font-medium">{formatTime(session.progress.eta)}</span>
        </div>
        <div className="flex items-center gap-2">
          <AlertTriangle className="h-3.5 w-3.5 text-orange-500" />
          <span className="text-muted-foreground">Anomalies:</span>
          <span className="font-mono font-medium text-orange-500">{session.anomalies}</span>
        </div>
      </div>
    </div>
  );
}

// Results Table Component
function ResultsTable({
  results,
  onResultClick
}: {
  results: FuzzResult[];
  onResultClick: (result: FuzzResult) => void;
}) {
  const [sortColumn, setSortColumn] = useState<keyof FuzzResult>('id');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('asc');

  const sortedResults = useMemo(() => {
    return [...results].sort((a, b) => {
      const aVal = a[sortColumn];
      const bVal = b[sortColumn];
      const direction = sortDirection === 'asc' ? 1 : -1;

      if (typeof aVal === 'string' && typeof bVal === 'string') {
        return aVal.localeCompare(bVal) * direction;
      }

      return ((aVal as number) - (bVal as number)) * direction;
    });
  }, [results, sortColumn, sortDirection]);

  const handleSort = (column: keyof FuzzResult) => {
    if (sortColumn === column) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortColumn(column);
      setSortDirection('asc');
    }
  };

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Search className="h-4 w-4 text-muted-foreground" />
          <h3 className="text-sm font-medium">Results</h3>
          <span className="rounded-full bg-muted px-2 py-0.5 text-xs font-medium">
            {results.length}
          </span>
        </div>
        <Button variant="outline" size="sm">
          <Download className="mr-1.5 h-3.5 w-3.5" />
          Export
        </Button>
      </div>

      <div className="overflow-hidden rounded-lg border border-border">
        <div className="max-h-96 overflow-y-auto">
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-muted/80 backdrop-blur">
              <tr className="border-b border-border">
                <th className="cursor-pointer px-3 py-2 text-left font-medium" onClick={() => handleSort('id')}>
                  #
                </th>
                <th className="cursor-pointer px-3 py-2 text-left font-medium" onClick={() => handleSort('payload')}>
                  Payload
                </th>
                <th className="cursor-pointer px-3 py-2 text-left font-medium" onClick={() => handleSort('statusCode')}>
                  Status
                </th>
                <th className="cursor-pointer px-3 py-2 text-left font-medium" onClick={() => handleSort('contentLength')}>
                  Length
                </th>
                <th className="cursor-pointer px-3 py-2 text-left font-medium" onClick={() => handleSort('duration')}>
                  Time
                </th>
                <th className="cursor-pointer px-3 py-2 text-left font-medium" onClick={() => handleSort('anomalyScore')}>
                  Anomaly
                </th>
              </tr>
            </thead>
            <tbody>
              {sortedResults.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-muted-foreground">
                    No results yet. Start fuzzing to see data here.
                  </td>
                </tr>
              ) : (
                sortedResults.map((result) => (
                  <tr
                    key={result.id}
                    onClick={() => onResultClick(result)}
                    className={cn(
                      'cursor-pointer border-b border-border/50 transition-colors hover:bg-muted/50',
                      result.isInteresting && 'bg-orange-500/10'
                    )}
                  >
                    <td className="px-3 py-2 font-mono text-xs text-muted-foreground">{result.id}</td>
                    <td className="max-w-xs truncate px-3 py-2 font-mono text-xs">{result.payload}</td>
                    <td className="px-3 py-2">
                      <span
                        className={cn(
                          'inline-block rounded px-2 py-0.5 text-xs font-medium',
                          result.statusCode >= 200 && result.statusCode < 300 && 'bg-green-500/20 text-green-700 dark:text-green-300',
                          result.statusCode >= 300 && result.statusCode < 400 && 'bg-blue-500/20 text-blue-700 dark:text-blue-300',
                          result.statusCode >= 400 && result.statusCode < 500 && 'bg-yellow-500/20 text-yellow-700 dark:text-yellow-300',
                          result.statusCode >= 500 && 'bg-red-500/20 text-red-700 dark:text-red-300'
                        )}
                      >
                        {result.statusCode}
                      </span>
                    </td>
                    <td className="px-3 py-2 font-mono text-xs">{result.contentLength} B</td>
                    <td className="px-3 py-2 font-mono text-xs">{result.duration}ms</td>
                    <td className="px-3 py-2">
                      {result.anomalyScore > 0 && (
                        <div className="flex items-center gap-1.5">
                          <div
                            className={cn(
                              'h-2 w-2 rounded-full',
                              result.anomalyScore > 0.7 && 'bg-red-500',
                              result.anomalyScore > 0.4 && result.anomalyScore <= 0.7 && 'bg-orange-500',
                              result.anomalyScore <= 0.4 && 'bg-yellow-500'
                            )}
                          />
                          <span className="font-mono text-xs">{(result.anomalyScore * 100).toFixed(0)}%</span>
                        </div>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// Main Blitz Component
function BlitzRoute() {
  // State
  const [requestTemplate, setRequestTemplate] = useState('');
  const [positions, setPositions] = useState<Position[]>([]);
  const [payloadType, setPayloadType] = useState<PayloadType>('ai-generated');
  const [payloadConfig, setPayloadConfig] = useState<any>({ start: 1, end: 100 });
  const [attackType, setAttackType] = useState<AttackType>('sniper');
  const [concurrency, setConcurrency] = useState(10);
  const [rateLimit, setRateLimit] = useState(50);

  const [session, setSession] = useState<BlitzSession>({
    running: false,
    progress: { completed: 0, total: 0, rps: 0, eta: 0 },
    anomalies: 0,
    results: []
  });

  const [selectedResult, setSelectedResult] = useState<FuzzResult | null>(null);

  // Simulate fuzzing (would connect to Tauri backend in production)
  const handleStart = useCallback(() => {
    if (positions.length === 0) {
      toast.error('Please add at least one fuzz position');
      return;
    }

    setSession((prev) => ({ ...prev, running: true, progress: { ...prev.progress, total: 100 } }));
    toast.success('Fuzzing started');

    // Simulate progress
    const interval = setInterval(() => {
      setSession((prev) => {
        if (prev.progress.completed >= prev.progress.total) {
          clearInterval(interval);
          toast.success('Fuzzing completed!');
          return { ...prev, running: false };
        }

        const newCompleted = prev.progress.completed + 1;
        const newResult: FuzzResult = {
          id: newCompleted,
          payload: `payload_${newCompleted}`,
          statusCode: Math.random() > 0.9 ? 500 : 200,
          contentLength: Math.floor(Math.random() * 5000) + 1000,
          duration: Math.floor(Math.random() * 500) + 50,
          anomalyScore: Math.random(),
          isInteresting: Math.random() > 0.9,
          timestamp: new Date().toISOString()
        };

        return {
          ...prev,
          progress: {
            ...prev.progress,
            completed: newCompleted,
            rps: Math.random() * 20 + 30,
            eta: (prev.progress.total - newCompleted) / 40
          },
          anomalies: prev.anomalies + (newResult.isInteresting ? 1 : 0),
          results: [...prev.results, newResult]
        };
      });
    }, 100);
  }, [positions]);

  const handleStop = useCallback(() => {
    setSession((prev) => ({ ...prev, running: false }));
    toast.info('Fuzzing stopped');
  }, []);

  const handleReset = useCallback(() => {
    setSession({
      running: false,
      progress: { completed: 0, total: 0, rps: 0, eta: 0 },
      anomalies: 0,
      results: []
    });
    toast.info('Session reset');
  }, []);

  return (
    <div className="flex h-full flex-col gap-4 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Blitz Fuzzer</h1>
          <p className="text-sm text-muted-foreground">
            AI-powered web fuzzing with real-time anomaly detection
          </p>
        </div>
        <div className="flex gap-2">
          {!session.running ? (
            <Button onClick={handleStart} size="sm" className="gap-2">
              <Play className="h-4 w-4" />
              Start Attack
            </Button>
          ) : (
            <Button onClick={handleStop} variant="destructive" size="sm" className="gap-2">
              <Pause className="h-4 w-4" />
              Stop
            </Button>
          )}
          <Button onClick={handleReset} variant="outline" size="sm" className="gap-2">
            <X className="h-4 w-4" />
            Reset
          </Button>
        </div>
      </div>

      {/* Progress Indicator */}
      {session.running && (
        <div className="rounded-lg border border-border bg-card p-4">
          <ProgressIndicator session={session} />
        </div>
      )}

      {/* Main Layout */}
      <div className="grid flex-1 gap-4 overflow-hidden lg:grid-cols-[1fr_320px]">
        {/* Left: Request Template + Results */}
        <div className="flex flex-col gap-4 overflow-hidden">
          <div className="flex-1 overflow-hidden rounded-lg border border-border bg-card p-4">
            <RequestTemplateEditor
              value={requestTemplate}
              onChange={setRequestTemplate}
              positions={positions}
              onPositionsChange={setPositions}
            />
          </div>

          <div className="h-[400px] rounded-lg border border-border bg-card p-4">
            <ResultsTable
              results={session.results}
              onResultClick={setSelectedResult}
            />
          </div>
        </div>

        {/* Right: Payload Config + Attack Settings */}
        <div className="flex flex-col gap-4 overflow-y-auto">
          <div className="rounded-lg border border-border bg-card p-4">
            <PayloadConfigPanel
              type={payloadType}
              onTypeChange={setPayloadType}
              config={payloadConfig}
              onConfigChange={setPayloadConfig}
            />
          </div>

          <div className="rounded-lg border border-border bg-card p-4">
            <AttackSettingsPanel
              attackType={attackType}
              onAttackTypeChange={setAttackType}
              concurrency={concurrency}
              onConcurrencyChange={setConcurrency}
              rateLimit={rateLimit}
              onRateLimitChange={setRateLimit}
            />
          </div>
        </div>
      </div>
    </div>
  );
}

export const Route = createFileRoute('/blitz')({
  component: BlitzRoute
});

export default BlitzRoute;
