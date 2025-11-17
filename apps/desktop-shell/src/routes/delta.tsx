/**
 * Delta Comparison GUI
 *
 * Comprehensive diff visualization with side-by-side comparison, semantic highlighting,
 * noise filtering, and batch comparison analysis.
 *
 * Features:
 * - Comparison Setup Panel with baseline selection
 * - Side-by-side Diff Visualization with Monaco Editor
 * - Semantic Diff Highlighting (JSON/XML tree views)
 * - Noise Filtering Controls
 * - Batch Comparison Matrix View
 * - Export & Reporting (PDF, HTML, Markdown)
 * - Keyboard Shortcuts & UX enhancements
 */

import { createFileRoute } from '@tanstack/react-router';
import { useState, useEffect, useCallback, useMemo } from 'react';
import { toast } from 'sonner';
import {
  Play,
  LayoutGrid,
  Split,
  Filter,
  Download,
  ChevronRight,
  ChevronLeft,
  AlertCircle,
  CheckCircle2,
  XCircle,
  FileJson,
  FileCode,
  Search,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Copy,
  BarChart3,
  Eye,
  EyeOff,
  Workflow
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { cn } from '../lib/utils';
import {
  type DiffResult,
  type BatchDiffResult,
  type FilteredDiffResult,
  type ResponseIdentifier,
  type BaselineStrategy,
  type DiffType,
  type Change,
  performDiff,
  compareBatch,
  filterDiff,
  exportDiff
} from '../lib/delta-service';

export const Route = createFileRoute('/delta')({
  component: DeltaScreen
});

// View modes
type ViewMode = 'simple' | 'batch';
type DiffViewMode = 'side-by-side' | 'inline' | 'tree';

function DeltaScreen() {
  // Core state
  const [viewMode, setViewMode] = useState<ViewMode>('simple');
  const [diffViewMode, setDiffViewMode] = useState<DiffViewMode>('side-by-side');
  const [loading, setLoading] = useState(false);

  // Simple diff state
  const [leftContent, setLeftContent] = useState('');
  const [rightContent, setRightContent] = useState('');
  const [diffResult, setDiffResult] = useState<DiffResult | null>(null);
  const [filteredDiff, setFilteredDiff] = useState<FilteredDiffResult | null>(null);
  const [showFiltered, setShowFiltered] = useState(false);

  // Batch diff state
  const [responses, setResponses] = useState<ResponseIdentifier[]>([]);
  const [batchResult, setBatchResult] = useState<BatchDiffResult | null>(null);
  const [baselineStrategy, setBaselineStrategy] = useState<BaselineStrategy>('first');
  const [outlierThreshold, setOutlierThreshold] = useState(80);

  // UI state
  const [currentChangeIndex, setCurrentChangeIndex] = useState(0);
  const [searchTerm, setSearchTerm] = useState('');
  const [fontSize, setFontSize] = useState(14);
  const [selectedResponseIndices, setSelectedResponseIndices] = useState<number[]>([]);

  // Load sample data on mount
  useEffect(() => {
    loadSampleData();
  }, []);

  const loadSampleData = () => {
    // Sample responses for demonstration
    const sampleContent1 = `{
  "id": "req-001",
  "timestamp": "2024-01-15T10:30:00Z",
  "status": "success",
  "data": {
    "user": "alice",
    "action": "login",
    "ip": "192.168.1.100"
  }
}`;

    const sampleContent2 = `{
  "id": "req-002",
  "timestamp": "2024-01-15T10:31:00Z",
  "status": "success",
  "data": {
    "user": "alice",
    "action": "view_dashboard",
    "ip": "192.168.1.100"
  }
}`;

    setLeftContent(sampleContent1);
    setRightContent(sampleContent2);

    // Initialize batch responses
    const sampleResponses: ResponseIdentifier[] = [
      { id: 'resp-1', name: 'Response 1', content: sampleContent1, statusCode: 200, responseTimeMs: 150 },
      { id: 'resp-2', name: 'Response 2', content: sampleContent2, statusCode: 200, responseTimeMs: 145 },
      { id: 'resp-3', name: 'Response 3 (Outlier)', content: '{"error": "Not found"}', statusCode: 404, responseTimeMs: 50 },
      { id: 'resp-4', name: 'Response 4', content: sampleContent1, statusCode: 200, responseTimeMs: 155 },
      { id: 'resp-5', name: 'Response 5', content: sampleContent2, statusCode: 200, responseTimeMs: 148 }
    ];

    setResponses(sampleResponses);
  };

  // Perform simple diff
  const handlePerformDiff = useCallback(async () => {
    if (!leftContent || !rightContent) {
      toast.error('Please provide both left and right content');
      return;
    }

    setLoading(true);
    try {
      const result = await performDiff(leftContent, rightContent, 'json', 'line');
      setDiffResult(result);

      // Auto-filter
      const filtered = await filterDiff(result);
      setFilteredDiff(filtered);

      toast.success(`Diff complete: ${result.similarityScore.toFixed(1)}% similar`);
    } catch (error) {
      console.error('Diff failed:', error);
      toast.error('Failed to perform diff');
    } finally {
      setLoading(false);
    }
  }, [leftContent, rightContent]);

  // Perform batch comparison
  const handleBatchCompare = useCallback(async () => {
    if (responses.length < 2) {
      toast.error('At least 2 responses required for batch comparison');
      return;
    }

    setLoading(true);
    try {
      const result = await compareBatch({
        responses,
        diffType: 'json',
        baselineStrategy,
        outlierThreshold,
        enableClustering: true,
        enablePatterns: true,
        enableAnomalies: true
      });

      setBatchResult(result);
      toast.success(`Batch comparison complete: ${result.statistics.totalComparisons} comparisons`);
    } catch (error) {
      console.error('Batch comparison failed:', error);
      toast.error('Failed to perform batch comparison');
    } finally {
      setLoading(false);
    }
  }, [responses, baselineStrategy, outlierThreshold]);

  // Export functionality
  const handleExport = useCallback(async (format: 'csv' | 'json' | 'html') => {
    const dataToExport = viewMode === 'simple' ? diffResult : batchResult;
    if (!dataToExport) {
      toast.error('No data to export');
      return;
    }

    try {
      const exported = await exportDiff(dataToExport, format);
      const blob = new Blob([exported], { type: `text/${format}` });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `delta-export.${format}`;
      a.click();
      URL.revokeObjectURL(url);

      toast.success(`Exported as ${format.toUpperCase()}`);
    } catch (error) {
      console.error('Export failed:', error);
      toast.error('Failed to export');
    }
  }, [viewMode, diffResult, batchResult]);

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Ctrl/Cmd+D: Quick compare
      if ((e.ctrlKey || e.metaKey) && e.key === 'd') {
        e.preventDefault();
        if (viewMode === 'simple') {
          handlePerformDiff();
        } else {
          handleBatchCompare();
        }
      }

      // N: Next change
      if (e.key === 'n' && !e.ctrlKey && !e.metaKey && diffResult) {
        e.preventDefault();
        setCurrentChangeIndex((prev) =>
          Math.min(prev + 1, diffResult.changes.length - 1)
        );
      }

      // P: Previous change
      if (e.key === 'p' && !e.ctrlKey && !e.metaKey && diffResult) {
        e.preventDefault();
        setCurrentChangeIndex((prev) => Math.max(prev - 1, 0));
      }

      // F: Toggle filter
      if (e.key === 'f' && !e.ctrlKey && !e.metaKey) {
        e.preventDefault();
        setShowFiltered((prev) => !prev);
      }

      // Ctrl/Cmd+C: Copy current change
      if ((e.ctrlKey || e.metaKey) && e.key === 'c' && diffResult) {
        const change = diffResult.changes[currentChangeIndex];
        if (change) {
          navigator.clipboard.writeText(JSON.stringify(change, null, 2));
          toast.success('Change copied to clipboard');
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [viewMode, diffResult, currentChangeIndex, handlePerformDiff, handleBatchCompare]);

  // Get display changes (filtered or all)
  const displayChanges = useMemo(() => {
    if (!diffResult) return [];
    if (showFiltered && filteredDiff) {
      return filteredDiff.signalChanges;
    }
    return diffResult.changes;
  }, [diffResult, filteredDiff, showFiltered]);

  return (
    <div className="mx-auto flex h-[calc(100vh-4rem)] w-full max-w-screen-2xl flex-col gap-4 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Delta Comparison</h1>
          <p className="text-sm text-muted-foreground">
            Advanced diff analysis with semantic highlighting and noise filtering
          </p>
        </div>

        <div className="flex items-center gap-2">
          {/* View mode selector */}
          <div className="rounded-lg border border-border bg-muted/50 p-1">
            <Button
              variant={viewMode === 'simple' ? 'default' : 'ghost'}
              size="sm"
              onClick={() => setViewMode('simple')}
              className="gap-2"
            >
              <Split className="h-4 w-4" />
              Simple
            </Button>
            <Button
              variant={viewMode === 'batch' ? 'default' : 'ghost'}
              size="sm"
              onClick={() => setViewMode('batch')}
              className="gap-2"
            >
              <LayoutGrid className="h-4 w-4" />
              Batch
            </Button>
          </div>

          {/* Export menu */}
          <div className="flex items-center gap-1">
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleExport('json')}
              disabled={!diffResult && !batchResult}
              title="Export as JSON"
            >
              <Download className="h-4 w-4" />
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleExport('csv')}
              disabled={!diffResult && !batchResult}
              title="Export as CSV"
            >
              <FileCode className="h-4 w-4" />
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleExport('html')}
              disabled={!diffResult && !batchResult}
              title="Export as HTML"
            >
              <FileJson className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </div>

      {/* Main content */}
      {viewMode === 'simple' ? (
        <SimpleDiffView
          leftContent={leftContent}
          rightContent={rightContent}
          setLeftContent={setLeftContent}
          setRightContent={setRightContent}
          diffResult={diffResult}
          filteredDiff={filteredDiff}
          showFiltered={showFiltered}
          setShowFiltered={setShowFiltered}
          diffViewMode={diffViewMode}
          setDiffViewMode={setDiffViewMode}
          currentChangeIndex={currentChangeIndex}
          setCurrentChangeIndex={setCurrentChangeIndex}
          displayChanges={displayChanges}
          fontSize={fontSize}
          setFontSize={setFontSize}
          loading={loading}
          onPerformDiff={handlePerformDiff}
        />
      ) : (
        <BatchDiffView
          responses={responses}
          setResponses={setResponses}
          batchResult={batchResult}
          baselineStrategy={baselineStrategy}
          setBaselineStrategy={setBaselineStrategy}
          outlierThreshold={outlierThreshold}
          setOutlierThreshold={setOutlierThreshold}
          selectedResponseIndices={selectedResponseIndices}
          setSelectedResponseIndices={setSelectedResponseIndices}
          loading={loading}
          onBatchCompare={handleBatchCompare}
        />
      )}

      {/* Keyboard shortcuts help */}
      <div className="rounded-lg border border-border bg-muted/30 px-4 py-2 text-xs text-muted-foreground">
        <span className="font-semibold">Shortcuts:</span>{' '}
        <kbd className="rounded bg-muted px-1.5 py-0.5">Ctrl+D</kbd> Compare |{' '}
        <kbd className="rounded bg-muted px-1.5 py-0.5">N</kbd> Next |{' '}
        <kbd className="rounded bg-muted px-1.5 py-0.5">P</kbd> Previous |{' '}
        <kbd className="rounded bg-muted px-1.5 py-0.5">F</kbd> Toggle Filter |{' '}
        <kbd className="rounded bg-muted px-1.5 py-0.5">Ctrl+C</kbd> Copy
      </div>
    </div>
  );
}

// Simple diff view component
interface SimpleDiffViewProps {
  leftContent: string;
  rightContent: string;
  setLeftContent: (content: string) => void;
  setRightContent: (content: string) => void;
  diffResult: DiffResult | null;
  filteredDiff: FilteredDiffResult | null;
  showFiltered: boolean;
  setShowFiltered: (show: boolean) => void;
  diffViewMode: DiffViewMode;
  setDiffViewMode: (mode: DiffViewMode) => void;
  currentChangeIndex: number;
  setCurrentChangeIndex: (index: number) => void;
  displayChanges: Change[];
  fontSize: number;
  setFontSize: (size: number) => void;
  loading: boolean;
  onPerformDiff: () => void;
}

function SimpleDiffView({
  leftContent,
  rightContent,
  setLeftContent,
  setRightContent,
  diffResult,
  filteredDiff,
  showFiltered,
  setShowFiltered,
  diffViewMode,
  setDiffViewMode,
  currentChangeIndex,
  setCurrentChangeIndex,
  displayChanges,
  fontSize,
  setFontSize,
  loading,
  onPerformDiff
}: SimpleDiffViewProps) {
  return (
    <div className="flex flex-1 flex-col gap-4 overflow-hidden">
      {/* Controls */}
      <div className="flex items-center justify-between rounded-lg border border-border bg-card p-4">
        <div className="flex items-center gap-4">
          {/* Diff view mode */}
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium">View:</span>
            <div className="flex gap-1">
              <Button
                variant={diffViewMode === 'side-by-side' ? 'default' : 'outline'}
                size="sm"
                onClick={() => setDiffViewMode('side-by-side')}
              >
                <Split className="h-4 w-4" />
              </Button>
              <Button
                variant={diffViewMode === 'inline' ? 'default' : 'outline'}
                size="sm"
                onClick={() => setDiffViewMode('inline')}
              >
                <FileCode className="h-4 w-4" />
              </Button>
              <Button
                variant={diffViewMode === 'tree' ? 'default' : 'outline'}
                size="sm"
                onClick={() => setDiffViewMode('tree')}
              >
                <Workflow className="h-4 w-4" />
              </Button>
            </div>
          </div>

          {/* Font size controls */}
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setFontSize(Math.max(10, fontSize - 2))}
            >
              <ZoomOut className="h-4 w-4" />
            </Button>
            <span className="text-sm">{fontSize}px</span>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setFontSize(Math.min(24, fontSize + 2))}
            >
              <ZoomIn className="h-4 w-4" />
            </Button>
          </div>

          {/* Filter toggle */}
          {filteredDiff && (
            <Button
              variant={showFiltered ? 'default' : 'outline'}
              size="sm"
              onClick={() => setShowFiltered(!showFiltered)}
              className="gap-2"
            >
              {showFiltered ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              {showFiltered ? 'Show All' : 'Show Signal Only'}
              {filteredDiff && (
                <span className="rounded bg-primary/20 px-1.5 py-0.5 text-xs">
                  {showFiltered
                    ? `${filteredDiff.signalChanges.length} signal`
                    : `${filteredDiff.noiseChanges.length} filtered`}
                </span>
              )}
            </Button>
          )}
        </div>

        <Button onClick={onPerformDiff} disabled={loading} className="gap-2">
          <Play className="h-4 w-4" />
          {loading ? 'Comparing...' : 'Compare'}
        </Button>
      </div>

      {/* Diff result summary */}
      {diffResult && (
        <div className="grid grid-cols-4 gap-4">
          <SummaryCard
            label="Similarity"
            value={`${diffResult.similarityScore.toFixed(1)}%`}
            tone={diffResult.similarityScore >= 80 ? 'positive' : 'negative'}
          />
          <SummaryCard
            label="Changes"
            value={diffResult.changes.length.toString()}
            tone="neutral"
          />
          <SummaryCard
            label="Compute Time"
            value={`${diffResult.computeTimeMs.toFixed(0)}ms`}
            tone="neutral"
          />
          {filteredDiff && (
            <SummaryCard
              label="Noise Filtered"
              value={`${filteredDiff.filterStats.noisePercentage.toFixed(0)}%`}
              tone="neutral"
            />
          )}
        </div>
      )}

      {/* Main diff display */}
      <div className="flex flex-1 gap-4 overflow-hidden">
        {/* Content editors */}
        <div className="flex flex-1 gap-4">
          {/* Left pane */}
          <div className="flex flex-1 flex-col gap-2">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Original (A)</span>
              <span className="text-xs text-muted-foreground">
                {leftContent.length} chars
              </span>
            </div>
            <textarea
              value={leftContent}
              onChange={(e) => setLeftContent(e.target.value)}
              className="flex-1 rounded-lg border border-border bg-muted/50 p-4 font-mono text-sm"
              style={{ fontSize: `${fontSize}px` }}
              placeholder="Enter left content..."
            />
          </div>

          {/* Right pane */}
          <div className="flex flex-1 flex-col gap-2">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Modified (B)</span>
              <span className="text-xs text-muted-foreground">
                {rightContent.length} chars
              </span>
            </div>
            <textarea
              value={rightContent}
              onChange={(e) => setRightContent(e.target.value)}
              className="flex-1 rounded-lg border border-border bg-muted/50 p-4 font-mono text-sm"
              style={{ fontSize: `${fontSize}px` }}
              placeholder="Enter right content..."
            />
          </div>
        </div>

        {/* Change navigator */}
        {diffResult && displayChanges.length > 0 && (
          <div className="flex w-80 flex-col gap-4">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">
                Changes ({displayChanges.length})
              </span>
              <div className="flex items-center gap-1">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setCurrentChangeIndex(Math.max(0, currentChangeIndex - 1))}
                  disabled={currentChangeIndex === 0}
                >
                  <ChevronLeft className="h-4 w-4" />
                </Button>
                <span className="text-xs text-muted-foreground">
                  {currentChangeIndex + 1} / {displayChanges.length}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() =>
                    setCurrentChangeIndex(Math.min(displayChanges.length - 1, currentChangeIndex + 1))
                  }
                  disabled={currentChangeIndex >= displayChanges.length - 1}
                >
                  <ChevronRight className="h-4 w-4" />
                </Button>
              </div>
            </div>

            <div className="flex-1 space-y-2 overflow-y-auto rounded-lg border border-border bg-card p-3">
              {displayChanges.map((change, idx) => (
                <ChangeItem
                  key={idx}
                  change={change}
                  isActive={idx === currentChangeIndex}
                  onClick={() => setCurrentChangeIndex(idx)}
                />
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// Batch diff view component (to be continued...)
interface BatchDiffViewProps {
  responses: ResponseIdentifier[];
  setResponses: (responses: ResponseIdentifier[]) => void;
  batchResult: BatchDiffResult | null;
  baselineStrategy: BaselineStrategy;
  setBaselineStrategy: (strategy: BaselineStrategy) => void;
  outlierThreshold: number;
  setOutlierThreshold: (threshold: number) => void;
  selectedResponseIndices: number[];
  setSelectedResponseIndices: (indices: number[]) => void;
  loading: boolean;
  onBatchCompare: () => void;
}

function BatchDiffView({
  responses,
  batchResult,
  baselineStrategy,
  setBaselineStrategy,
  outlierThreshold,
  setOutlierThreshold,
  loading,
  onBatchCompare
}: BatchDiffViewProps) {
  return (
    <div className="flex flex-1 flex-col gap-4 overflow-hidden">
      {/* Batch controls */}
      <div className="flex items-center justify-between rounded-lg border border-border bg-card p-4">
        <div className="flex items-center gap-4">
          {/* Baseline strategy */}
          <div className="flex flex-col gap-1">
            <span className="text-xs text-muted-foreground">Baseline Strategy</span>
            <select
              value={baselineStrategy}
              onChange={(e) => setBaselineStrategy(e.target.value as BaselineStrategy)}
              className="rounded border border-border bg-muted px-3 py-1.5 text-sm"
            >
              <option value="first">First Response</option>
              <option value="median">Median Similarity</option>
              <option value="user_selected">User Selected</option>
              <option value="all_pairs">All Pairs (N×N)</option>
            </select>
          </div>

          {/* Outlier threshold */}
          <div className="flex flex-col gap-1">
            <span className="text-xs text-muted-foreground">Outlier Threshold</span>
            <div className="flex items-center gap-2">
              <input
                type="range"
                min="50"
                max="95"
                value={outlierThreshold}
                onChange={(e) => setOutlierThreshold(Number(e.target.value))}
                className="w-32"
              />
              <span className="text-sm font-medium">{outlierThreshold}%</span>
            </div>
          </div>

          <div className="text-sm text-muted-foreground">
            {responses.length} responses loaded
          </div>
        </div>

        <Button onClick={onBatchCompare} disabled={loading || responses.length < 2} className="gap-2">
          <BarChart3 className="h-4 w-4" />
          {loading ? 'Comparing...' : 'Batch Compare'}
        </Button>
      </div>

      {/* Batch result */}
      {batchResult && (
        <div className="flex flex-1 gap-4 overflow-hidden">
          {/* Similarity matrix */}
          <div className="flex flex-1 flex-col gap-2">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Similarity Matrix</span>
              <div className="flex items-center gap-4 text-xs text-muted-foreground">
                <div className="flex items-center gap-2">
                  <div className="h-4 w-4 rounded bg-emerald-500/20"></div>
                  <span>&gt;95% (High)</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="h-4 w-4 rounded bg-amber-500/20"></div>
                  <span>80-95% (Medium)</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="h-4 w-4 rounded bg-red-500/20"></div>
                  <span>&lt;80% (Low)</span>
                </div>
              </div>
            </div>

            <div className="flex-1 overflow-auto rounded-lg border border-border bg-card p-4">
              <SimilarityMatrix
                matrix={batchResult.similarityMatrix}
                responses={batchResult.responses}
                outliers={batchResult.outliers}
              />
            </div>
          </div>

          {/* Statistics and insights */}
          <div className="flex w-80 flex-col gap-4">
            <div className="space-y-2">
              <span className="text-sm font-medium">Statistics</span>
              <div className="space-y-2 rounded-lg border border-border bg-card p-3">
                <StatRow
                  label="Mean Similarity"
                  value={`${batchResult.statistics.meanSimilarity.toFixed(1)}%`}
                />
                <StatRow
                  label="Median Similarity"
                  value={`${batchResult.statistics.medianSimilarity.toFixed(1)}%`}
                />
                <StatRow
                  label="Std Deviation"
                  value={batchResult.statistics.stdDevSimilarity.toFixed(2)}
                />
                <StatRow
                  label="Comparisons"
                  value={batchResult.statistics.totalComparisons.toString()}
                />
              </div>
            </div>

            {/* Outliers */}
            {batchResult.outliers.length > 0 && (
              <div className="space-y-2">
                <span className="text-sm font-medium">Outliers ({batchResult.outliers.length})</span>
                <div className="space-y-1 rounded-lg border border-border bg-card p-3">
                  {batchResult.outliers.map((idx) => (
                    <div
                      key={idx}
                      className="rounded bg-red-500/10 px-2 py-1 text-sm text-red-500"
                    >
                      {batchResult.responses[idx].name || `Response ${idx + 1}`}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* AI Insights */}
            {batchResult.patterns?.aiInsights && (
              <div className="space-y-2">
                <span className="text-sm font-medium">AI Insights</span>
                <div className="space-y-2 rounded-lg border border-border bg-card p-3">
                  {batchResult.patterns.aiInsights.map((insight, idx) => (
                    <div key={idx} className="text-xs text-muted-foreground">
                      • {insight}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Clusters */}
            {batchResult.clusters && batchResult.clusters.length > 0 && (
              <div className="space-y-2">
                <span className="text-sm font-medium">Clusters ({batchResult.clusters.length})</span>
                <div className="space-y-2 rounded-lg border border-border bg-card p-3">
                  {batchResult.clusters.map((cluster) => (
                    <div key={cluster.clusterId} className="space-y-1 rounded bg-muted/50 p-2">
                      <div className="text-xs font-medium">Cluster {cluster.clusterId + 1}</div>
                      <div className="text-xs text-muted-foreground">
                        {cluster.size} responses • {cluster.avgSimilarity.toFixed(1)}% similar
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// Helper components

function SummaryCard({
  label,
  value,
  tone
}: {
  label: string;
  value: string;
  tone: 'positive' | 'negative' | 'neutral';
}) {
  const toneClasses =
    tone === 'positive'
      ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-500'
      : tone === 'negative'
        ? 'border-red-500/40 bg-red-500/10 text-red-500'
        : 'border-border bg-muted/50 text-foreground';

  return (
    <div className={cn('rounded-lg border px-4 py-3', toneClasses)}>
      <div className="text-xs font-medium opacity-75">{label}</div>
      <div className="text-2xl font-bold">{value}</div>
    </div>
  );
}

function ChangeItem({
  change,
  isActive,
  onClick
}: {
  change: Change;
  isActive: boolean;
  onClick: () => void;
}) {
  const icon =
    change.type === 'added' ? (
      <CheckCircle2 className="h-4 w-4 text-emerald-500" />
    ) : change.type === 'removed' ? (
      <XCircle className="h-4 w-4 text-red-500" />
    ) : (
      <AlertCircle className="h-4 w-4 text-amber-500" />
    );

  return (
    <div
      onClick={onClick}
      className={cn(
        'cursor-pointer rounded-lg border p-2 transition-all hover:bg-muted/50',
        isActive ? 'border-primary bg-primary/10' : 'border-transparent'
      )}
    >
      <div className="flex items-start gap-2">
        {icon}
        <div className="flex-1 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium capitalize">{change.type}</span>
            {change.lineNumber && (
              <span className="text-xs text-muted-foreground">Line {change.lineNumber}</span>
            )}
          </div>
          {change.path && <div className="text-xs text-muted-foreground">{change.path}</div>}
          <div className="max-h-16 overflow-hidden text-xs">
            {change.oldValue && (
              <div className="text-red-500">- {change.oldValue.substring(0, 50)}</div>
            )}
            {change.newValue && (
              <div className="text-emerald-500">+ {change.newValue.substring(0, 50)}</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function SimilarityMatrix({
  matrix,
  responses,
  outliers
}: {
  matrix: number[][];
  responses: ResponseIdentifier[];
  outliers: number[];
}) {
  const getSimilarityColor = (similarity: number) => {
    if (similarity >= 95) return 'bg-emerald-500/20 text-emerald-500';
    if (similarity >= 80) return 'bg-amber-500/20 text-amber-500';
    return 'bg-red-500/20 text-red-500';
  };

  return (
    <table className="w-full text-xs">
      <thead>
        <tr>
          <th className="border border-border p-2"></th>
          {responses.map((resp, idx) => (
            <th key={idx} className="border border-border p-2">
              {resp.name || `R${idx + 1}`}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {matrix.map((row, i) => (
          <tr key={i}>
            <th
              className={cn(
                'border border-border p-2 text-left',
                outliers.includes(i) && 'bg-red-500/10 font-bold'
              )}
            >
              {responses[i].name || `R${i + 1}`}
            </th>
            {row.map((similarity, j) => (
              <td
                key={j}
                className={cn(
                  'border border-border p-2 text-center font-mono',
                  i === j ? 'bg-muted/50' : getSimilarityColor(similarity)
                )}
              >
                {similarity.toFixed(0)}%
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function StatRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between text-xs">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-medium">{value}</span>
    </div>
  );
}

export default DeltaScreen;
