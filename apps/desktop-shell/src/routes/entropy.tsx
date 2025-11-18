import { createFileRoute } from '@tanstack/react-router';
import { useCallback, useEffect, useState } from 'react';
import { toast } from 'sonner';
import { Play, Pause, Square, Download, RefreshCw, AlertTriangle, CheckCircle2, AlertCircle, GitCompare } from 'lucide-react';

import {
  listEntropySessions,
  startEntropySession,
  pauseEntropySession,
  resumeEntropySession,
  stopEntropySession,
  getEntropyAnalysis,
  getIncrementalStats,
  getTokenSamples,
  exportEntropySession,
  exportEntropyReport,
  compareSessions,
  type CaptureSession,
  type EntropyAnalysis,
  type IncrementalStats,
  type TokenSample,
  type SessionComparison,
  type StartEntropySessionPayload,
  type RiskLevel
} from '../lib/ipc';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { cn } from '../lib/utils';
import { VisualizationDashboard } from '../components/entropy-visualizations';

export const Route = createFileRoute('/entropy')({
  component: EntropyScreen
});

// Quick start presets for common token types
const TOKEN_PRESETS = [
  {
    name: 'Session Cookie (PHPSESSID)',
    extractor: { pattern: '', location: 'cookie', name: 'PHPSESSID' },
    targetCount: 1000,
    timeoutSeconds: 3600
  },
  {
    name: 'Session Cookie (JSESSIONID)',
    extractor: { pattern: '', location: 'cookie', name: 'JSESSIONID' },
    targetCount: 1000,
    timeoutSeconds: 3600
  },
  {
    name: 'Session Cookie (sessionid)',
    extractor: { pattern: '', location: 'cookie', name: 'sessionid' },
    targetCount: 1000,
    timeoutSeconds: 3600
  },
  {
    name: 'Authorization Header (Bearer)',
    extractor: { pattern: 'Bearer\\s+([A-Za-z0-9._-]+)', location: 'header', name: 'Authorization' },
    targetCount: 1000,
    timeoutSeconds: 3600
  },
  {
    name: 'CSRF Token (X-CSRF-Token)',
    extractor: { pattern: '', location: 'header', name: 'X-CSRF-Token' },
    targetCount: 500,
    timeoutSeconds: 1800
  },
  {
    name: 'Custom JSON Field',
    extractor: { pattern: '', location: 'body', name: 'token' },
    targetCount: 1000,
    timeoutSeconds: 3600
  }
];

function getRiskBadgeVariant(risk: RiskLevel): 'default' | 'secondary' | 'destructive' | 'outline' {
  switch (risk) {
    case 'critical':
      return 'destructive';
    case 'high':
      return 'destructive';
    case 'medium':
      return 'secondary';
    case 'low':
      return 'outline';
    default:
      return 'default';
  }
}

function getRiskIcon(risk: RiskLevel) {
  switch (risk) {
    case 'critical':
      return <AlertTriangle className="h-4 w-4 text-destructive" />;
    case 'high':
      return <AlertCircle className="h-4 w-4 text-destructive" />;
    case 'medium':
      return <AlertCircle className="h-4 w-4 text-amber-500" />;
    case 'low':
      return <CheckCircle2 className="h-4 w-4 text-emerald-500" />;
  }
}

function getStatusBadgeVariant(status: string): 'default' | 'secondary' | 'outline' {
  switch (status) {
    case 'active':
      return 'default';
    case 'paused':
      return 'secondary';
    case 'stopped':
      return 'outline';
    default:
      return 'outline';
  }
}

function EntropyScreen() {
  const [sessions, setSessions] = useState<CaptureSession[]>([]);
  const [selectedSession, setSelectedSession] = useState<number | null>(null);
  const [analysis, setAnalysis] = useState<EntropyAnalysis | null>(null);
  const [stats, setStats] = useState<IncrementalStats | null>(null);
  const [tokens, setTokens] = useState<TokenSample[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [showVisualizations, setShowVisualizations] = useState(false);

  // Comparison view state
  const [showComparison, setShowComparison] = useState(false);
  const [selectedForComparison, setSelectedForComparison] = useState<number[]>([]);
  const [comparisons, setComparisons] = useState<SessionComparison[]>([]);
  const [comparing, setComparing] = useState(false);

  // Capture setup state
  const [showSetup, setShowSetup] = useState(false);
  const [setupName, setSetupName] = useState('');
  const [setupPreset, setSetupPreset] = useState<number | null>(null);
  const [setupTargetCount, setSetupTargetCount] = useState(1000);
  const [setupTimeout, setSetupTimeout] = useState(3600);
  const [creating, setCreating] = useState(false);

  const loadSessions = useCallback(async () => {
    try {
      const data = await listEntropySessions();
      setSessions(data);

      // If we have a selected session, refresh its analysis and stats
      if (selectedSession) {
        const [analysisData, statsData] = await Promise.all([
          getEntropyAnalysis(selectedSession),
          getIncrementalStats(selectedSession)
        ]);
        setAnalysis(analysisData);
        setStats(statsData);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      toast.error('Failed to load sessions', { description: message });
    }
  }, [selectedSession]);

  const refresh = useCallback(async () => {
    setRefreshing(true);
    await loadSessions();
    setRefreshing(false);
  }, [loadSessions]);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      await loadSessions();
      setLoading(false);
    };
    void load();

    // Auto-refresh every 5 seconds for active sessions
    const interval = setInterval(() => {
      void loadSessions();
    }, 5000);

    return () => clearInterval(interval);
  }, [loadSessions]);

  const handleStartSession = useCallback(async () => {
    if (!setupName.trim()) {
      toast.error('Session name is required');
      return;
    }

    if (setupPreset === null) {
      toast.error('Please select a token preset');
      return;
    }

    const preset = TOKEN_PRESETS[setupPreset];
    const payload: StartEntropySessionPayload = {
      name: setupName,
      extractor: preset.extractor,
      targetCount: setupTargetCount,
      timeoutSeconds: setupTimeout
    };

    setCreating(true);
    try {
      const session = await startEntropySession(payload);
      toast.success(`Started session: ${session.name}`);
      setShowSetup(false);
      setSetupName('');
      setSetupPreset(null);
      await loadSessions();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      toast.error('Failed to start session', { description: message });
    } finally {
      setCreating(false);
    }
  }, [setupName, setupPreset, setupTargetCount, setupTimeout, loadSessions]);

  const handlePause = useCallback(
    async (id: number) => {
      try {
        await pauseEntropySession(id);
        toast.success('Session paused');
        await loadSessions();
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        toast.error('Failed to pause session', { description: message });
      }
    },
    [loadSessions]
  );

  const handleResume = useCallback(
    async (id: number) => {
      try {
        await resumeEntropySession(id);
        toast.success('Session resumed');
        await loadSessions();
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        toast.error('Failed to resume session', { description: message });
      }
    },
    [loadSessions]
  );

  const handleStop = useCallback(
    async (id: number) => {
      try {
        await stopEntropySession(id);
        toast.success('Session stopped');
        await loadSessions();
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        toast.error('Failed to stop session', { description: message });
      }
    },
    [loadSessions]
  );

  const handleExport = useCallback(async (id: number, format: 'csv' | 'json' | 'html' | 'markdown' | 'pdf') => {
    try {
      let data: string;
      let mimeType: string;
      let extension: string;

      if (format === 'csv' || format === 'json') {
        data = await exportEntropySession(id, format);
        mimeType = format === 'csv' ? 'text/csv' : 'application/json';
        extension = format;
      } else {
        data = await exportEntropyReport(id, format);
        switch (format) {
          case 'html':
            mimeType = 'text/html';
            extension = 'html';
            break;
          case 'markdown':
            mimeType = 'text/markdown';
            extension = 'md';
            break;
          case 'pdf':
            mimeType = 'application/pdf';
            extension = 'pdf';
            break;
          default:
            throw new Error(`Unsupported format: ${format}`);
        }
      }

      // Create download
      const blob = new Blob([data], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `entropy-session-${id}.${extension}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast.success(`Exported session to ${format.toUpperCase()}`);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      toast.error('Failed to export session', { description: message });
    }
  }, []);

  const handleSelectSession = useCallback(
    async (id: number) => {
      setSelectedSession(id);
      try {
        const [analysisData, statsData, tokenData] = await Promise.all([
          getEntropyAnalysis(id),
          getIncrementalStats(id),
          getTokenSamples(id, 1000)
        ]);
        setAnalysis(analysisData);
        setStats(statsData);
        setTokens(tokenData);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        toast.error('Failed to load session details', { description: message });
      }
    },
    []
  );

  const toggleCompareSelection = useCallback((id: number) => {
    setSelectedForComparison((prev) =>
      prev.includes(id) ? prev.filter((sid) => sid !== id) : [...prev, id]
    );
  }, []);

  const handleCompare = useCallback(async () => {
    if (selectedForComparison.length < 2) {
      toast.error('Select at least 2 sessions to compare');
      return;
    }

    setComparing(true);
    try {
      const results = await compareSessions(selectedForComparison);
      setComparisons(results);
      setShowComparison(true);
      toast.success(`Comparing ${selectedForComparison.length} sessions`);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      toast.error('Failed to compare sessions', { description: message });
    } finally {
      setComparing(false);
    }
  }, [selectedForComparison]);

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-foreground">Entropy Analyzer</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Analyze token randomness to detect weak PRNGs and predictable session IDs
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => void refresh()} disabled={refreshing}>
            <RefreshCw className={cn('mr-2 h-4 w-4', refreshing && 'animate-spin')} />
            Refresh
          </Button>
          {selectedForComparison.length > 0 && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => void handleCompare()}
              disabled={comparing || selectedForComparison.length < 2}
            >
              <GitCompare className="mr-2 h-4 w-4" />
              Compare ({selectedForComparison.length})
            </Button>
          )}
          <Button onClick={() => setShowSetup(!showSetup)}>
            {showSetup ? 'Hide Setup' : 'New Session'}
          </Button>
        </div>
      </div>

      {/* Capture Setup Panel */}
      {showSetup && (
        <Card>
          <CardHeader>
            <CardTitle>Start Capture Session</CardTitle>
            <CardDescription>Configure token extraction and auto-stop conditions</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <label className="text-sm font-medium">Session Name</label>
              <input
                type="text"
                className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
                placeholder="e.g., Production Session Tokens"
                value={setupName}
                onChange={(e) => setSetupName(e.target.value)}
              />
            </div>

            <div>
              <label className="text-sm font-medium">Token Preset</label>
              <div className="mt-2 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {TOKEN_PRESETS.map((preset, index) => (
                  <button
                    key={index}
                    onClick={() => setSetupPreset(index)}
                    className={cn(
                      'rounded-md border p-3 text-left text-sm transition-colors',
                      setupPreset === index
                        ? 'border-primary bg-primary/10 text-foreground'
                        : 'border-border bg-card text-muted-foreground hover:bg-muted/50'
                    )}
                  >
                    <div className="font-medium">{preset.name}</div>
                    <div className="mt-1 text-xs opacity-80">
                      {preset.extractor.location}: {preset.extractor.name}
                    </div>
                  </button>
                ))}
              </div>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <label className="text-sm font-medium">Target Token Count</label>
                <input
                  type="number"
                  className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
                  value={setupTargetCount}
                  onChange={(e) => setSetupTargetCount(parseInt(e.target.value) || 1000)}
                  min={100}
                  max={10000}
                />
                <p className="mt-1 text-xs text-muted-foreground">Stop after collecting N tokens</p>
              </div>
              <div>
                <label className="text-sm font-medium">Timeout (seconds)</label>
                <input
                  type="number"
                  className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
                  value={setupTimeout}
                  onChange={(e) => setSetupTimeout(parseInt(e.target.value) || 3600)}
                  min={60}
                  max={86400}
                />
                <p className="mt-1 text-xs text-muted-foreground">
                  Auto-stop after {Math.floor(setupTimeout / 60)} minutes
                </p>
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <Button variant="outline" onClick={() => setShowSetup(false)}>
                Cancel
              </Button>
              <Button onClick={() => void handleStartSession()} disabled={creating}>
                {creating ? 'Starting...' : 'Start Capture'}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Sessions List */}
      <div className="grid gap-4 lg:grid-cols-2">
        {loading ? (
          <div className="rounded-md border border-border bg-muted/40 p-6 text-sm text-muted-foreground">
            Loading sessions…
          </div>
        ) : sessions.length === 0 ? (
          <div className="rounded-md border border-border bg-muted/40 p-6 text-sm text-muted-foreground">
            No capture sessions yet. Click "New Session" to start.
          </div>
        ) : (
          sessions.map((session) => (
            <Card
              key={session.id}
              className={cn(
                'cursor-pointer transition-all',
                selectedSession === session.id && 'border-primary'
              )}
              onClick={() => void handleSelectSession(session.id)}
            >
              <CardHeader>
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-start gap-3">
                    <input
                      type="checkbox"
                      checked={selectedForComparison.includes(session.id)}
                      onChange={(e) => {
                        e.stopPropagation();
                        toggleCompareSelection(session.id);
                      }}
                      className="mt-1 h-4 w-4 rounded border-border"
                    />
                    <div className="space-y-1">
                      <CardTitle className="text-lg">{session.name}</CardTitle>
                      <CardDescription>
                        {session.extractor.location}: {session.extractor.name}
                      </CardDescription>
                    </div>
                  </div>
                  <Badge variant={getStatusBadgeVariant(session.status)}>
                    {session.status}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <div className="text-muted-foreground">Tokens Captured</div>
                    <div className="text-lg font-semibold">
                      {session.tokenCount}
                      {session.targetCount ? ` / ${session.targetCount}` : ''}
                    </div>
                  </div>
                  <div>
                    <div className="text-muted-foreground">Started</div>
                    <div className="text-sm">{new Date(session.startedAt).toLocaleString()}</div>
                  </div>
                </div>

                {stats && selectedSession === session.id && (
                  <div className="rounded-md border border-border bg-muted/30 p-3 space-y-2">
                    <div className="text-xs font-medium text-muted-foreground">Live Statistics</div>
                    <div className="grid grid-cols-3 gap-2 text-sm">
                      <div>
                        <div className="text-xs text-muted-foreground">Entropy</div>
                        <div className="font-semibold">{stats.currentEntropy.toFixed(2)} bits</div>
                      </div>
                      <div>
                        <div className="text-xs text-muted-foreground">Collisions</div>
                        <div className="font-semibold">{stats.collisionCount}</div>
                      </div>
                      <div>
                        <div className="text-xs text-muted-foreground">Confidence</div>
                        <div className="font-semibold">{stats.reliabilityScore.toFixed(0)}%</div>
                      </div>
                    </div>
                  </div>
                )}

                <div className="flex gap-2">
                  {session.status === 'active' && (
                    <>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={(e) => {
                          e.stopPropagation();
                          void handlePause(session.id);
                        }}
                      >
                        <Pause className="mr-1 h-3 w-3" />
                        Pause
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={(e) => {
                          e.stopPropagation();
                          void handleStop(session.id);
                        }}
                      >
                        <Square className="mr-1 h-3 w-3" />
                        Stop
                      </Button>
                    </>
                  )}
                  {session.status === 'paused' && (
                    <>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={(e) => {
                          e.stopPropagation();
                          void handleResume(session.id);
                        }}
                      >
                        <Play className="mr-1 h-3 w-3" />
                        Resume
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={(e) => {
                          e.stopPropagation();
                          void handleStop(session.id);
                        }}
                      >
                        <Square className="mr-1 h-3 w-3" />
                        Stop
                      </Button>
                    </>
                  )}
                  <div className="relative group">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={(e) => {
                        e.stopPropagation();
                      }}
                    >
                      <Download className="mr-1 h-3 w-3" />
                      Export
                    </Button>
                    <div className="absolute bottom-full left-0 mb-1 hidden group-hover:block z-10 rounded-md border border-border bg-card shadow-lg">
                      <div className="flex flex-col gap-1 p-2 min-w-[120px]">
                        {(['csv', 'json', 'html', 'markdown', 'pdf'] as const).map((format) => (
                          <button
                            key={format}
                            onClick={(e) => {
                              e.stopPropagation();
                              void handleExport(session.id, format);
                            }}
                            className="rounded px-3 py-1.5 text-left text-sm transition-colors hover:bg-muted"
                          >
                            {format.toUpperCase()}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </div>

      {/* Analysis Results */}
      {analysis && selectedSession && (
        <Card>
          <CardHeader>
            <div className="flex items-start justify-between">
              <div>
                <CardTitle>Analysis Results</CardTitle>
                <CardDescription>
                  Session #{selectedSession} • {analysis.tokenCount} tokens analyzed
                </CardDescription>
              </div>
              <div className="flex items-center gap-2">
                {getRiskIcon(analysis.risk)}
                <Badge variant={getRiskBadgeVariant(analysis.risk)}>
                  {analysis.risk.toUpperCase()} RISK
                </Badge>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Overview */}
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <div className="rounded-lg border border-border bg-muted/30 p-4">
                <div className="text-xs text-muted-foreground">Randomness Score</div>
                <div className="mt-1 text-2xl font-bold">{analysis.randomnessScore.toFixed(1)}/100</div>
              </div>
              <div className="rounded-lg border border-border bg-muted/30 p-4">
                <div className="text-xs text-muted-foreground">Shannon Entropy</div>
                <div className="mt-1 text-2xl font-bold">{analysis.shannonEntropy.toFixed(2)} bits</div>
              </div>
              <div className="rounded-lg border border-border bg-muted/30 p-4">
                <div className="text-xs text-muted-foreground">Collision Rate</div>
                <div className="mt-1 text-2xl font-bold">{(analysis.collisionRate * 100).toFixed(2)}%</div>
              </div>
              <div className="rounded-lg border border-border bg-muted/30 p-4">
                <div className="text-xs text-muted-foreground">Sample Quality</div>
                <div className="mt-1 text-2xl font-bold capitalize">{analysis.sampleQuality}</div>
              </div>
            </div>

            {/* Statistical Tests */}
            <div>
              <h3 className="mb-3 text-sm font-semibold">Statistical Tests</h3>
              <div className="space-y-2">
                {[
                  { name: 'Chi-Squared Test', result: analysis.chiSquared },
                  { name: 'Runs Test', result: analysis.runs },
                  { name: 'Serial Correlation', result: analysis.serialCorrelation },
                  { name: 'Spectral Test', result: analysis.spectral }
                ].map((test) => (
                  <div
                    key={test.name}
                    className="flex items-center justify-between rounded-md border border-border bg-muted/20 px-4 py-2"
                  >
                    <span className="text-sm">{test.name}</span>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-muted-foreground">
                        p={test.result.pValue.toFixed(4)}
                      </span>
                      <Badge variant={test.result.passed ? 'outline' : 'destructive'}>
                        {test.result.passed ? 'PASS' : 'FAIL'}
                      </Badge>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Detected PRNG */}
            {analysis.detectedPRNG && (
              <div className="rounded-lg border border-destructive bg-destructive/10 p-4">
                <h3 className="mb-2 text-sm font-semibold text-destructive">
                  Weak PRNG Detected: {analysis.detectedPRNG.name}
                </h3>
                <p className="text-sm text-muted-foreground">{analysis.detectedPRNG.weakness}</p>
                <p className="mt-2 text-sm font-medium">Exploit: {analysis.detectedPRNG.exploitHint}</p>
                <div className="mt-2 text-xs text-muted-foreground">
                  Confidence: {(analysis.detectedPRNG.confidence * 100).toFixed(0)}%
                </div>
              </div>
            )}

            {/* Detected Patterns */}
            {analysis.detectedPatterns.length > 0 && (
              <div>
                <h3 className="mb-3 text-sm font-semibold">Detected Patterns</h3>
                <div className="space-y-2">
                  {analysis.detectedPatterns.map((pattern, index) => (
                    <div
                      key={index}
                      className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3"
                    >
                      <div className="flex items-start justify-between">
                        <div className="space-y-1">
                          <div className="text-sm font-medium capitalize">
                            {pattern.type.replace(/_/g, ' ')}
                          </div>
                          <div className="text-xs text-muted-foreground">{pattern.description}</div>
                          <div className="text-xs text-muted-foreground">Evidence: {pattern.evidence}</div>
                        </div>
                        <Badge variant="secondary">
                          {(pattern.confidence * 100).toFixed(0)}% confidence
                        </Badge>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Recommendations */}
            <div>
              <h3 className="mb-3 text-sm font-semibold">Recommendations</h3>
              <div className="space-y-1 rounded-md border border-border bg-muted/20 p-4">
                {analysis.recommendations.map((rec, index) => (
                  <div key={index} className="text-sm text-muted-foreground">
                    {rec}
                  </div>
                ))}
              </div>
            </div>

            {/* Toggle Visualizations */}
            <div className="flex justify-center">
              <Button
                variant="outline"
                onClick={() => setShowVisualizations(!showVisualizations)}
                className="gap-2"
              >
                {showVisualizations ? 'Hide' : 'Show'} Advanced Visualizations
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Visualizations Dashboard */}
      {analysis && tokens.length > 0 && showVisualizations && (
        <Card>
          <CardHeader>
            <CardTitle>Advanced Visualizations</CardTitle>
            <CardDescription>
              Interactive charts and graphs for detailed entropy analysis
            </CardDescription>
          </CardHeader>
          <CardContent>
            <VisualizationDashboard
              analysis={analysis}
              tokens={tokens.map((t) => t.tokenValue)}
            />
          </CardContent>
        </Card>
      )}

      {/* Comparison View */}
      {showComparison && comparisons.length > 0 && (
        <Card>
          <CardHeader>
            <div className="flex items-start justify-between">
              <div>
                <CardTitle>Session Comparison</CardTitle>
                <CardDescription>
                  Side-by-side comparison of {comparisons.length} entropy sessions
                </CardDescription>
              </div>
              <Button variant="outline" size="sm" onClick={() => setShowComparison(false)}>
                Close
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-6">
              {/* Comparison Table */}
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border">
                      <th className="p-2 text-left font-semibold">Metric</th>
                      {comparisons.map((comp) => (
                        <th key={comp.sessionId} className="p-2 text-left font-semibold">
                          {comp.sessionName}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    <tr className="border-b border-border">
                      <td className="p-2 text-muted-foreground">Randomness Score</td>
                      {comparisons.map((comp) => (
                        <td key={comp.sessionId} className="p-2 font-medium">
                          {comp.analysis?.randomnessScore.toFixed(1) ?? 'N/A'}/100
                          {comp.deltaFromBaseline && (
                            <span
                              className={cn(
                                'ml-2 text-xs',
                                comp.deltaFromBaseline.randomnessScoreDelta > 0
                                  ? 'text-emerald-500'
                                  : 'text-red-500'
                              )}
                            >
                              {comp.deltaFromBaseline.randomnessScoreDelta > 0 ? '+' : ''}
                              {comp.deltaFromBaseline.randomnessScoreDelta.toFixed(1)}
                            </span>
                          )}
                        </td>
                      ))}
                    </tr>
                    <tr className="border-b border-border">
                      <td className="p-2 text-muted-foreground">Shannon Entropy</td>
                      {comparisons.map((comp) => (
                        <td key={comp.sessionId} className="p-2 font-medium">
                          {comp.analysis?.shannonEntropy.toFixed(2) ?? 'N/A'} bits
                          {comp.deltaFromBaseline && (
                            <span
                              className={cn(
                                'ml-2 text-xs',
                                comp.deltaFromBaseline.entropyDelta > 0 ? 'text-emerald-500' : 'text-red-500'
                              )}
                            >
                              {comp.deltaFromBaseline.entropyDelta > 0 ? '+' : ''}
                              {comp.deltaFromBaseline.entropyDelta.toFixed(2)}
                            </span>
                          )}
                        </td>
                      ))}
                    </tr>
                    <tr className="border-b border-border">
                      <td className="p-2 text-muted-foreground">Collision Rate</td>
                      {comparisons.map((comp) => (
                        <td key={comp.sessionId} className="p-2 font-medium">
                          {comp.analysis ? (comp.analysis.collisionRate * 100).toFixed(2) : 'N/A'}%
                          {comp.deltaFromBaseline && (
                            <span
                              className={cn(
                                'ml-2 text-xs',
                                comp.deltaFromBaseline.collisionRateDelta < 0
                                  ? 'text-emerald-500'
                                  : 'text-red-500'
                              )}
                            >
                              {comp.deltaFromBaseline.collisionRateDelta > 0 ? '+' : ''}
                              {(comp.deltaFromBaseline.collisionRateDelta * 100).toFixed(2)}%
                            </span>
                          )}
                        </td>
                      ))}
                    </tr>
                    <tr className="border-b border-border">
                      <td className="p-2 text-muted-foreground">Risk Level</td>
                      {comparisons.map((comp) => (
                        <td key={comp.sessionId} className="p-2">
                          {comp.analysis ? (
                            <Badge variant={getRiskBadgeVariant(comp.analysis.risk)}>
                              {comp.analysis.risk.toUpperCase()}
                            </Badge>
                          ) : (
                            'N/A'
                          )}
                        </td>
                      ))}
                    </tr>
                    <tr className="border-b border-border">
                      <td className="p-2 text-muted-foreground">Token Count</td>
                      {comparisons.map((comp) => (
                        <td key={comp.sessionId} className="p-2 font-medium">
                          {comp.analysis?.tokenCount.toLocaleString() ?? 'N/A'}
                        </td>
                      ))}
                    </tr>
                    <tr className="border-b border-border">
                      <td className="p-2 text-muted-foreground">Sample Quality</td>
                      {comparisons.map((comp) => (
                        <td key={comp.sessionId} className="p-2 font-medium capitalize">
                          {comp.analysis?.sampleQuality ?? 'N/A'}
                        </td>
                      ))}
                    </tr>
                  </tbody>
                </table>
              </div>

              {/* Statistical Tests Comparison */}
              <div>
                <h3 className="mb-3 text-sm font-semibold">Statistical Tests</h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border">
                        <th className="p-2 text-left font-semibold">Test</th>
                        {comparisons.map((comp) => (
                          <th key={comp.sessionId} className="p-2 text-left font-semibold">
                            {comp.sessionName}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {['chiSquared', 'runs', 'serialCorrelation', 'spectral'].map((testKey) => (
                        <tr key={testKey} className="border-b border-border">
                          <td className="p-2 text-muted-foreground capitalize">
                            {testKey.replace(/([A-Z])/g, ' $1').trim()}
                          </td>
                          {comparisons.map((comp) => {
                            const test = comp.analysis?.[testKey as keyof typeof comp.analysis];
                            const passed =
                              test && typeof test === 'object' && 'passed' in test ? test.passed : false;
                            return (
                              <td key={comp.sessionId} className="p-2">
                                <Badge variant={passed ? 'outline' : 'destructive'}>
                                  {passed ? 'PASS' : 'FAIL'}
                                </Badge>
                              </td>
                            );
                          })}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
