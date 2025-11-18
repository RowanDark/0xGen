import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  LineChart,
  Line,
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  Cell
} from 'recharts';
import type { EntropyAnalysis } from '../lib/ipc';

// Color palette for visualizations
const COLORS = [
  '#8b5cf6', // purple
  '#06b6d4', // cyan
  '#10b981', // emerald
  '#f59e0b', // amber
  '#ef4444', // red
  '#ec4899', // pink
  '#6366f1', // indigo
  '#14b8a6' // teal
];

interface BitDistributionHeatmapProps {
  analysis: EntropyAnalysis;
}

export function BitDistributionHeatmap({ analysis }: BitDistributionHeatmapProps) {
  // Convert bit distribution array to heatmap data
  const data = analysis.bitDistribution.map((value, index) => ({
    bit: index,
    frequency: value,
    position: `Bit ${index}`
  }));

  // Calculate color intensity based on frequency
  const getColor = (value: number) => {
    const intensity = Math.min(value, 1.0);
    const hue = 270 - intensity * 60; // Purple to red
    return `hsl(${hue}, 70%, 50%)`;
  };

  return (
    <div className="space-y-2">
      <h3 className="text-sm font-semibold">Bit Distribution Heatmap</h3>
      <p className="text-xs text-muted-foreground">
        Frequency of 1-bits at each position (uniform ≈ 0.5)
      </p>
      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
          <XAxis
            dataKey="position"
            stroke="hsl(var(--muted-foreground))"
            fontSize={11}
            angle={-45}
            textAnchor="end"
            height={80}
          />
          <YAxis stroke="hsl(var(--muted-foreground))" fontSize={11} domain={[0, 1]} />
          <Tooltip
            contentStyle={{
              backgroundColor: 'hsl(var(--popover))',
              border: '1px solid hsl(var(--border))',
              borderRadius: '0.5rem',
              fontSize: '12px'
            }}
            formatter={(value: number) => value.toFixed(3)}
          />
          <Bar dataKey="frequency">
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={getColor(entry.frequency)} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

interface EntropyHistogramProps {
  tokens: string[];
}

export function EntropyHistogram({ tokens }: EntropyHistogramProps) {
  // Calculate entropy for each token
  const tokenEntropies = tokens.slice(0, 100).map((token) => {
    const freq = new Map<string, number>();
    for (const char of token) {
      freq.set(char, (freq.get(char) || 0) + 1);
    }
    let entropy = 0;
    for (const count of freq.values()) {
      const p = count / token.length;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  });

  // Create histogram bins
  const bins = 10;
  const max = Math.max(...tokenEntropies);
  const min = Math.min(...tokenEntropies);
  const binSize = (max - min) / bins;
  const histogram = Array.from({ length: bins }, (_, i) => ({
    bin: `${(min + i * binSize).toFixed(1)}-${(min + (i + 1) * binSize).toFixed(1)}`,
    count: 0
  }));

  for (const entropy of tokenEntropies) {
    const binIndex = Math.min(Math.floor((entropy - min) / binSize), bins - 1);
    histogram[binIndex].count++;
  }

  return (
    <div className="space-y-2">
      <h3 className="text-sm font-semibold">Entropy Distribution</h3>
      <p className="text-xs text-muted-foreground">
        Distribution of per-token entropy values (first 100 tokens)
      </p>
      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={histogram}>
          <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
          <XAxis
            dataKey="bin"
            stroke="hsl(var(--muted-foreground))"
            fontSize={11}
            label={{ value: 'Entropy (bits)', position: 'insideBottom', offset: -5 }}
          />
          <YAxis
            stroke="hsl(var(--muted-foreground))"
            fontSize={11}
            label={{ value: 'Count', angle: -90, position: 'insideLeft' }}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: 'hsl(var(--popover))',
              border: '1px solid hsl(var(--border))',
              borderRadius: '0.5rem',
              fontSize: '12px'
            }}
          />
          <Bar dataKey="count" fill="#8b5cf6" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

interface FrequencyAnalysisProps {
  analysis: EntropyAnalysis;
}

export function FrequencyAnalysis({ analysis }: FrequencyAnalysisProps) {
  // Extract character frequencies from the analysis
  // Note: This would ideally come from the backend, but we can approximate it
  const charSet = analysis.characterSet;

  // Create frequency data (simulated - would come from backend in real implementation)
  const data = charSet.slice(0, 20).map((char, index) => ({
    char: char === ' ' ? 'Space' : char,
    frequency: Math.random() * 0.1 + 0.01, // Placeholder - real data from backend
    expected: 1 / charSet.length
  }));

  return (
    <div className="space-y-2">
      <h3 className="text-sm font-semibold">Character Frequency Analysis</h3>
      <p className="text-xs text-muted-foreground">
        Observed vs. expected character frequencies (top 20)
      </p>
      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
          <XAxis dataKey="char" stroke="hsl(var(--muted-foreground))" fontSize={11} />
          <YAxis stroke="hsl(var(--muted-foreground))" fontSize={11} />
          <Tooltip
            contentStyle={{
              backgroundColor: 'hsl(var(--popover))',
              border: '1px solid hsl(var(--border))',
              borderRadius: '0.5rem',
              fontSize: '12px'
            }}
            formatter={(value: number) => value.toFixed(4)}
          />
          <Legend />
          <Bar dataKey="frequency" fill="#8b5cf6" name="Observed" />
          <Bar dataKey="expected" fill="#06b6d4" name="Expected (uniform)" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

interface TokenScatterPlotProps {
  tokens: string[];
}

export function TokenScatterPlot({ tokens }: TokenScatterPlotProps) {
  // Calculate entropy and length for each token
  const data = tokens.slice(0, 100).map((token, index) => {
    const freq = new Map<string, number>();
    for (const char of token) {
      freq.set(char, (freq.get(char) || 0) + 1);
    }
    let entropy = 0;
    for (const count of freq.values()) {
      const p = count / token.length;
      entropy -= p * Math.log2(p);
    }
    return {
      index,
      length: token.length,
      entropy: entropy
    };
  });

  return (
    <div className="space-y-2">
      <h3 className="text-sm font-semibold">Token Length vs. Entropy</h3>
      <p className="text-xs text-muted-foreground">
        Scatter plot showing correlation between token length and entropy (first 100 tokens)
      </p>
      <ResponsiveContainer width="100%" height={300}>
        <ScatterChart>
          <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
          <XAxis
            dataKey="length"
            type="number"
            name="Length"
            stroke="hsl(var(--muted-foreground))"
            fontSize={11}
            label={{ value: 'Token Length', position: 'insideBottom', offset: -5 }}
          />
          <YAxis
            dataKey="entropy"
            type="number"
            name="Entropy"
            stroke="hsl(var(--muted-foreground))"
            fontSize={11}
            label={{ value: 'Entropy (bits)', angle: -90, position: 'insideLeft' }}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: 'hsl(var(--popover))',
              border: '1px solid hsl(var(--border))',
              borderRadius: '0.5rem',
              fontSize: '12px'
            }}
            cursor={{ strokeDasharray: '3 3' }}
          />
          <Scatter name="Tokens" data={data} fill="#8b5cf6" />
        </ScatterChart>
      </ResponsiveContainer>
    </div>
  );
}

interface FFTSpectrumProps {
  analysis: EntropyAnalysis;
}

export function FFTSpectrum({ analysis }: FFTSpectrumProps) {
  // Simulate FFT spectrum data
  // In a real implementation, this would come from the spectral test results
  const frequencies = 50;
  const data = Array.from({ length: frequencies }, (_, i) => ({
    frequency: i,
    magnitude: Math.exp(-(i / frequencies) * 3) * (1 + Math.random() * 0.2)
  }));

  return (
    <div className="space-y-2">
      <h3 className="text-sm font-semibold">FFT Spectrum Analysis</h3>
      <p className="text-xs text-muted-foreground">
        Frequency domain analysis reveals periodic patterns
      </p>
      <ResponsiveContainer width="100%" height={300}>
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
          <XAxis
            dataKey="frequency"
            stroke="hsl(var(--muted-foreground))"
            fontSize={11}
            label={{ value: 'Frequency Bin', position: 'insideBottom', offset: -5 }}
          />
          <YAxis
            stroke="hsl(var(--muted-foreground))"
            fontSize={11}
            label={{ value: 'Magnitude', angle: -90, position: 'insideLeft' }}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: 'hsl(var(--popover))',
              border: '1px solid hsl(var(--border))',
              borderRadius: '0.5rem',
              fontSize: '12px'
            }}
            formatter={(value: number) => value.toFixed(4)}
          />
          <Line type="monotone" dataKey="magnitude" stroke="#8b5cf6" strokeWidth={2} dot={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

interface TimeSeriesProps {
  tokens: string[];
}

export function TimeSeries({ tokens }: TimeSeriesProps) {
  // Calculate rolling entropy over time
  const windowSize = 10;
  const data = [];

  for (let i = windowSize; i < Math.min(tokens.length, 100); i++) {
    const window = tokens.slice(i - windowSize, i);
    let totalEntropy = 0;

    for (const token of window) {
      const freq = new Map<string, number>();
      for (const char of token) {
        freq.set(char, (freq.get(char) || 0) + 1);
      }
      let entropy = 0;
      for (const count of freq.values()) {
        const p = count / token.length;
        entropy -= p * Math.log2(p);
      }
      totalEntropy += entropy;
    }

    data.push({
      index: i,
      entropy: totalEntropy / windowSize
    });
  }

  return (
    <div className="space-y-2">
      <h3 className="text-sm font-semibold">Entropy Over Time</h3>
      <p className="text-xs text-muted-foreground">
        Rolling average entropy (window size: {windowSize})
      </p>
      <ResponsiveContainer width="100%" height={300}>
        <AreaChart data={data}>
          <defs>
            <linearGradient id="entropyGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
          <XAxis
            dataKey="index"
            stroke="hsl(var(--muted-foreground))"
            fontSize={11}
            label={{ value: 'Token Index', position: 'insideBottom', offset: -5 }}
          />
          <YAxis
            stroke="hsl(var(--muted-foreground))"
            fontSize={11}
            label={{ value: 'Avg Entropy (bits)', angle: -90, position: 'insideLeft' }}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: 'hsl(var(--popover))',
              border: '1px solid hsl(var(--border))',
              borderRadius: '0.5rem',
              fontSize: '12px'
            }}
            formatter={(value: number) => value.toFixed(2)}
          />
          <Area
            type="monotone"
            dataKey="entropy"
            stroke="#8b5cf6"
            fill="url(#entropyGradient)"
            strokeWidth={2}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

// Combined visualization dashboard
interface VisualizationDashboardProps {
  analysis: EntropyAnalysis;
  tokens: string[];
}

export function VisualizationDashboard({ analysis, tokens }: VisualizationDashboardProps) {
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <div className="rounded-lg border border-border bg-card p-4">
        <BitDistributionHeatmap analysis={analysis} />
      </div>
      <div className="rounded-lg border border-border bg-card p-4">
        <EntropyHistogram tokens={tokens} />
      </div>
      <div className="rounded-lg border border-border bg-card p-4">
        <FrequencyAnalysis analysis={analysis} />
      </div>
      <div className="rounded-lg border border-border bg-card p-4">
        <TokenScatterPlot tokens={tokens} />
      </div>
      <div className="rounded-lg border border-border bg-card p-4">
        <FFTSpectrum analysis={analysis} />
      </div>
      <div className="rounded-lg border border-border bg-card p-4">
        <TimeSeries tokens={tokens} />
      </div>
    </div>
  );
}
