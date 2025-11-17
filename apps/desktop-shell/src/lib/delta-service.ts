/**
 * Delta Comparison Service
 *
 * This service provides an interface to the delta comparison backend.
 * Currently uses mock data for demonstration. Replace with actual Tauri IPC calls
 * when backend integration is complete.
 *
 * TODO: Wire up to backend via one of:
 * - Tauri command handlers (requires Rust->Go bridge)
 * - REST API endpoint (requires Go HTTP server)
 * - Direct FFI calls (requires cgo/bindgen setup)
 */

export type DiffType = 'text' | 'json' | 'xml';
export type DiffGranularity = 'line' | 'word' | 'character';
export type ChangeType = 'added' | 'removed' | 'modified';
export type BaselineStrategy = 'first' | 'median' | 'user_selected' | 'all_pairs';

export interface Change {
  type: ChangeType;
  path?: string;
  oldValue?: string;
  newValue?: string;
  lineNumber?: number;
  context?: string;
}

export interface DiffResult {
  type: DiffType;
  changes: Change[];
  similarityScore: number;
  leftSize: number;
  rightSize: number;
  computeTimeMs: number;
  granularity?: string;
}

export interface ResponseIdentifier {
  id: string;
  name?: string;
  content: string;
  statusCode?: number;
  contentType?: string;
  responseTimeMs?: number;
  metadata?: Record<string, string>;
}

export interface ResponseCluster {
  clusterId: number;
  responseIndices: number[];
  representative: number;
  avgSimilarity: number;
  size: number;
}

export interface DistributionStats {
  mean: number;
  median: number;
  stdDev: number;
  min: number;
  max: number;
}

export interface BatchStatistics {
  totalResponses: number;
  totalComparisons: number;
  meanSimilarity: number;
  medianSimilarity: number;
  stdDevSimilarity: number;
  minSimilarity: number;
  maxSimilarity: number;
  responseTimeStats?: DistributionStats;
  statusCodeDist?: Record<number, number>;
  contentLengthStats?: DistributionStats;
}

export interface PatternAnalysis {
  commonHeaders?: Record<string, number>;
  commonJsonKeys?: Record<string, number>;
  commonErrorMsgs?: Record<string, number>;
  uniqueElements?: Record<number, string[]>;
  constantFields?: string[];
  variableFields?: string[];
  aiInsights?: string[];
}

export interface AnomalyDetection {
  unusualStatusCodes?: number[];
  unusualLengths?: number[];
  uniqueErrors?: number[];
  slowResponses?: number[];
  summary?: string;
}

export interface ComparisonPair {
  leftIndex: number;
  rightIndex: number;
  diffResult: DiffResult;
}

export interface BatchDiffResult {
  responses: ResponseIdentifier[];
  baseline?: ResponseIdentifier;
  baselineIndex?: number;
  comparisons?: DiffResult[];
  comparisonMatrix?: ComparisonPair[];
  outliers: number[];
  similarityMatrix: number[][];
  clusters?: ResponseCluster[];
  statistics: BatchStatistics;
  patterns?: PatternAnalysis;
  anomalies?: AnomalyDetection;
  computeTimeMs: number;
}

export interface FilteredDiffResult {
  original: DiffResult;
  signalChanges: Change[];
  noiseChanges: Change[];
  classifications: NoiseClassification[];
  filterStats: FilterStats;
  computeTimeMs: number;
}

export interface NoiseClassification {
  isNoise: boolean;
  confidence: number;
  reason: string;
  category: string;
  patternName?: string;
  userOverride?: boolean;
}

export interface FilterStats {
  totalChanges: number;
  noiseCount: number;
  signalCount: number;
  noisePercentage: number;
  avgNoiseConfidence: number;
  avgSignalConfidence: number;
  userOverrideCount: number;
}

export interface CompareBatchRequest {
  responses: ResponseIdentifier[];
  diffType: DiffType;
  granularity?: DiffGranularity;
  baselineStrategy: BaselineStrategy;
  baselineIndex?: number;
  outlierThreshold?: number;
  enableClustering: boolean;
  enablePatterns: boolean;
  enableAnomalies: boolean;
}

// Mock data generation helpers
function generateMockChange(type: ChangeType, lineNumber: number): Change {
  const changes = {
    added: { newValue: `+ New line added at ${lineNumber}`, context: 'Added content' },
    removed: { oldValue: `- Line removed at ${lineNumber}`, context: 'Removed content' },
    modified: {
      oldValue: `Old value at line ${lineNumber}`,
      newValue: `Modified value at line ${lineNumber}`,
      context: 'Modified content'
    }
  };

  return {
    type,
    lineNumber,
    ...changes[type]
  };
}

function generateMockDiffResult(similarityScore: number): DiffResult {
  const changeCount = Math.floor((100 - similarityScore) / 5);
  const changes: Change[] = [];

  for (let i = 0; i < changeCount; i++) {
    const types: ChangeType[] = ['added', 'removed', 'modified'];
    const type = types[i % 3];
    changes.push(generateMockChange(type, i + 1));
  }

  return {
    type: 'text',
    changes,
    similarityScore,
    leftSize: 1000,
    rightSize: 1000 + (changeCount * 50),
    computeTimeMs: Math.random() * 100,
    granularity: 'line'
  };
}

/**
 * Perform a simple diff between two responses
 *
 * @param left - Left response content
 * @param right - Right response content
 * @param diffType - Type of diff to perform
 * @param granularity - Level of detail for text diffs
 * @returns Diff result with changes and similarity score
 */
export async function performDiff(
  left: string,
  right: string,
  diffType: DiffType = 'text',
  granularity: DiffGranularity = 'line'
): Promise<DiffResult> {
  // TODO: Replace with actual IPC call to backend
  // Example: return await invoke('delta_diff', { left, right, diffType, granularity });

  // Mock implementation
  await new Promise(resolve => setTimeout(resolve, 100));

  // Simple similarity calculation based on string length difference
  const maxLen = Math.max(left.length, right.length);
  const lenDiff = Math.abs(left.length - right.length);
  const similarity = ((maxLen - lenDiff) / maxLen) * 100;

  return generateMockDiffResult(similarity);
}

/**
 * Perform a batch comparison of multiple responses
 *
 * @param request - Batch comparison request with responses and configuration
 * @returns Batch diff result with similarity matrix, outliers, and statistics
 */
export async function compareBatch(
  request: CompareBatchRequest
): Promise<BatchDiffResult> {
  // TODO: Replace with actual IPC call to backend
  // Example: return await invoke('delta_compare_batch', request);

  // Mock implementation
  await new Promise(resolve => setTimeout(resolve, 300));

  const n = request.responses.length;
  const similarityMatrix: number[][] = [];
  const outliers: number[] = [];

  // Generate mock similarity matrix
  for (let i = 0; i < n; i++) {
    similarityMatrix[i] = [];
    let avgSim = 0;

    for (let j = 0; j < n; j++) {
      if (i === j) {
        similarityMatrix[i][j] = 100;
      } else {
        // Generate random similarity between 70-100%
        const sim = 70 + Math.random() * 30;
        similarityMatrix[i][j] = sim;
        avgSim += sim;
      }
    }

    // Mark as outlier if average similarity is below threshold
    avgSim = avgSim / (n - 1);
    if (avgSim < (request.outlierThreshold || 80)) {
      outliers.push(i);
    }
  }

  // Calculate statistics
  const allSimilarities: number[] = [];
  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      allSimilarities.push(similarityMatrix[i][j]);
    }
  }

  const mean = allSimilarities.reduce((a, b) => a + b, 0) / allSimilarities.length;
  const sorted = [...allSimilarities].sort((a, b) => a - b);
  const median = sorted[Math.floor(sorted.length / 2)];
  const variance = allSimilarities.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / allSimilarities.length;
  const stdDev = Math.sqrt(variance);

  // Mock clusters
  const clusters: ResponseCluster[] = request.enableClustering ? [
    {
      clusterId: 0,
      responseIndices: [0, 1, 2],
      representative: 0,
      avgSimilarity: 95,
      size: 3
    },
    {
      clusterId: 1,
      responseIndices: [3, 4],
      representative: 3,
      avgSimilarity: 92,
      size: 2
    }
  ] : [];

  // Mock patterns
  const patterns: PatternAnalysis | undefined = request.enablePatterns ? {
    commonJsonKeys: { id: n, name: n, status: n, timestamp: n },
    constantFields: ['status', 'version'],
    variableFields: ['timestamp', 'requestId'],
    aiInsights: [
      `${n} responses compared with ${mean.toFixed(1)}% average similarity`,
      `${outliers.length} outlier(s) detected with similarity below ${request.outlierThreshold || 80}%`,
      'All responses share common structure with varying dynamic fields'
    ]
  } : undefined;

  // Mock anomalies
  const anomalies: AnomalyDetection | undefined = request.enableAnomalies ? {
    unusualStatusCodes: outliers.length > 0 ? [outliers[0]] : [],
    unusualLengths: [],
    slowResponses: [],
    summary: outliers.length > 0
      ? `Found ${outliers.length} response(s) with unusual characteristics`
      : 'No significant anomalies detected'
  } : undefined;

  return {
    responses: request.responses,
    outliers,
    similarityMatrix,
    clusters,
    statistics: {
      totalResponses: n,
      totalComparisons: allSimilarities.length,
      meanSimilarity: mean,
      medianSimilarity: median,
      stdDevSimilarity: stdDev,
      minSimilarity: Math.min(...allSimilarities),
      maxSimilarity: Math.max(...allSimilarities)
    },
    patterns,
    anomalies,
    computeTimeMs: 150 + Math.random() * 100
  };
}

/**
 * Filter a diff result to separate signal from noise
 *
 * @param diffResult - Original diff result to filter
 * @returns Filtered result with signal and noise separated
 */
export async function filterDiff(
  diffResult: DiffResult
): Promise<FilteredDiffResult> {
  // TODO: Replace with actual IPC call to backend
  // Example: return await invoke('delta_filter_diff', { diffResult });

  // Mock implementation
  await new Promise(resolve => setTimeout(resolve, 50));

  const signalChanges: Change[] = [];
  const noiseChanges: Change[] = [];
  const classifications: NoiseClassification[] = [];

  diffResult.changes.forEach((change) => {
    // Simple heuristic: treat timestamp/uuid-like changes as noise
    const isLikelyNoise =
      change.path?.includes('timestamp') ||
      change.path?.includes('requestId') ||
      change.oldValue?.match(/\d{4}-\d{2}-\d{2}/) ||
      change.newValue?.match(/[0-9a-f]{8}-[0-9a-f]{4}/);

    const classification: NoiseClassification = {
      isNoise: !!isLikelyNoise,
      confidence: isLikelyNoise ? 0.85 : 0.15,
      reason: isLikelyNoise ? 'Matches temporal/identifier pattern' : 'Significant content change',
      category: isLikelyNoise ? 'Timestamp/ID' : 'Content'
    };

    classifications.push(classification);

    if (isLikelyNoise) {
      noiseChanges.push(change);
    } else {
      signalChanges.push(change);
    }
  });

  return {
    original: diffResult,
    signalChanges,
    noiseChanges,
    classifications,
    filterStats: {
      totalChanges: diffResult.changes.length,
      noiseCount: noiseChanges.length,
      signalCount: signalChanges.length,
      noisePercentage: (noiseChanges.length / diffResult.changes.length) * 100,
      avgNoiseConfidence: 0.85,
      avgSignalConfidence: 0.15,
      userOverrideCount: 0
    },
    computeTimeMs: 20 + Math.random() * 30
  };
}

/**
 * Export diff result to specified format
 *
 * @param result - Diff result to export
 * @param format - Export format (csv, json, html)
 * @returns Exported content as string
 */
export async function exportDiff(
  result: DiffResult | BatchDiffResult,
  format: 'csv' | 'json' | 'html'
): Promise<string> {
  // TODO: Replace with actual IPC call to backend
  // Example: return await invoke('delta_export', { result, format });

  // Mock implementation
  await new Promise(resolve => setTimeout(resolve, 100));

  switch (format) {
    case 'json':
      return JSON.stringify(result, null, 2);
    case 'csv':
      return 'Change Type,Line,Old Value,New Value\n' +
        ('changes' in result ? result.changes : [])
          .map(c => `${c.type},${c.lineNumber},${c.oldValue || ''},${c.newValue || ''}`)
          .join('\n');
    case 'html':
      return `<!DOCTYPE html>
<html>
<head><title>Diff Report</title></head>
<body>
  <h1>Diff Report</h1>
  <pre>${JSON.stringify(result, null, 2)}</pre>
</body>
</html>`;
    default:
      throw new Error(`Unsupported format: ${format}`);
  }
}
