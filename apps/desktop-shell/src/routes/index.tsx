import { createFileRoute, Link, useNavigate } from '@tanstack/react-router';
import {
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type ReactNode
} from 'react';
import {
  Activity,
  AlertTriangle,
  FileText,
  History,
  ListOrdered,
  Play,
  Target,
  Timer
} from 'lucide-react';
import { Area, AreaChart, ResponsiveContainer } from 'recharts';

import { Button } from '../components/ui/button';
import { fetchMetrics, listRuns, type DashboardMetrics, type Run } from '../lib/ipc';
import { cn } from '../lib/utils';
import { toast } from 'sonner';

type SparklinePoint = {
  time: number;
  value: number;
};

type MetricSnapshot = DashboardMetrics & { timestamp: number };

type RunHistoryPoint = {
  timestamp: number;
  count: number;
};

type StatCardProps = {
  title: string;
  value: ReactNode;
  subtitle?: ReactNode;
  icon: ReactNode;
  data: SparklinePoint[];
  color: string;
  onClick: () => void;
  className?: string;
};

const HISTORY_LIMIT = 24;

const palette = {
  latestRun: '#6366f1',
  failures: '#ef4444',
  queue: '#22c55e',
  latency: '#f97316',
  cases: '#0ea5e9'
};

function Sparkline({ data, color }: { data: SparklinePoint[]; color: string }) {
  const gradientId = useId();
  const points = data.filter((point) => Number.isFinite(point.value));

  if (points.length < 2) {
    return (
      <div className="flex h-full items-center justify-center text-xs text-muted-foreground">
        Awaiting data
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={points} margin={{ top: 4, right: 0, bottom: 0, left: 0 }}>
        <defs>
          <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor={color} stopOpacity={0.35} />
            <stop offset="95%" stopColor={color} stopOpacity={0} />
          </linearGradient>
        </defs>
        <Area type="monotone" dataKey="value" stroke={color} strokeWidth={2} fill={`url(#${gradientId})`} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

function StatCard({
  title,
  value,
  subtitle,
  icon,
  data,
  color,
  onClick,
  className
}: StatCardProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'group flex flex-col justify-between rounded-xl border border-border bg-card p-4 text-left shadow-sm transition hover:border-primary/60 hover:shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2',
        className
      )}
    >
      <div className="flex items-start justify-between">
        <div>
          <span className="text-sm font-medium text-muted-foreground">{title}</span>
          <div className="mt-1 text-2xl font-semibold tracking-tight text-foreground">{value}</div>
          {subtitle}
        </div>
        <div className="rounded-full bg-primary/10 p-2 text-primary">{icon}</div>
      </div>
      <div className="mt-4 h-16">
        <Sparkline data={data} color={color} />
      </div>
    </button>
  );
}

function DashboardRoute() {
  const navigate = useNavigate();
  const [runs, setRuns] = useState<Run[]>([]);
  const [runHistory, setRunHistory] = useState<RunHistoryPoint[]>([]);
  const [metricsHistory, setMetricsHistory] = useState<MetricSnapshot[]>([]);
  const runsErrorShownRef = useRef(false);
  const metricsErrorShownRef = useRef(false);

  const integerFormatter = useMemo(() => new Intl.NumberFormat(), []);
  const decimalFormatter = useMemo(() => new Intl.NumberFormat(undefined, { maximumFractionDigits: 2 }), []);

  const applyRuns = (data: Run[]) => {
    const sorted = [...data].sort(
      (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );
    setRuns(sorted.slice(0, 5));
    setRunHistory((previous) => {
      const next = [...previous, { timestamp: Date.now(), count: data.length }];
      return next.slice(-HISTORY_LIMIT);
    });
  };

  useEffect(() => {
    let cancelled = false;

    const loadRuns = async () => {
      try {
        const data = await listRuns();
        if (cancelled) {
          return;
        }
        applyRuns(data);
        runsErrorShownRef.current = false;
      } catch (error) {
        console.error('Failed to load runs', error);
        if (!runsErrorShownRef.current) {
          toast.error('Unable to load recent runs');
          runsErrorShownRef.current = true;
        }
      }
    };

    void loadRuns();
    const interval = window.setInterval(loadRuns, 30_000);

    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    let cancelled = false;

    const loadMetrics = async () => {
      try {
        const snapshot = await fetchMetrics();
        if (cancelled) {
          return;
        }
        setMetricsHistory((previous) => {
          const next = [...previous, { timestamp: Date.now(), ...snapshot }];
          return next.slice(-HISTORY_LIMIT);
        });
        metricsErrorShownRef.current = false;
      } catch (error) {
        console.error('Failed to load metrics', error);
        if (!metricsErrorShownRef.current) {
          toast.error('Unable to load metrics');
          metricsErrorShownRef.current = true;
        }
      }
    };

    void loadMetrics();
    const interval = window.setInterval(loadMetrics, 15_000);

    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, []);

  const latestRun = runs[0];
  const latestMetrics = metricsHistory.length > 0 ? metricsHistory[metricsHistory.length - 1] : undefined;

  const runSparkline = runHistory.map((entry) => ({ time: entry.timestamp, value: entry.count }));
  const failuresSparkline = metricsHistory.map((entry) => ({ time: entry.timestamp, value: entry.failures }));
  const queueSparkline = metricsHistory.map((entry) => ({ time: entry.timestamp, value: entry.queueDepth }));
  const latencySparkline = metricsHistory.map((entry) => ({ time: entry.timestamp, value: entry.avgLatencyMs }));
  const casesSparkline = metricsHistory.map((entry) => ({ time: entry.timestamp, value: entry.casesFound }));

  const latestRunSubtitle = latestRun ? (
    <div className="mt-3 space-y-1 text-sm text-muted-foreground">
      <span className="inline-flex items-center rounded-full bg-secondary px-2 py-0.5 text-xs font-medium uppercase text-secondary-foreground">
        {latestRun.status}
      </span>
      <p>Started {new Date(latestRun.createdAt).toLocaleString()}</p>
    </div>
  ) : (
    <p className="mt-3 text-sm text-muted-foreground">Launch a run to see live telemetry.</p>
  );

  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-8 p-6">
      <section className="space-y-6">
        <div className="space-y-2">
          <h1 className="text-3xl font-semibold tracking-tight">Operations overview</h1>
          <p className="text-muted-foreground">
            Monitor live runs, watch queue health, and keep an eye on investigation throughput at a glance.
          </p>
        </div>
        <div className="grid gap-2 sm:grid-cols-3">
          <Button
            className="gap-2"
            onClick={() => {
              navigate({ to: '/runs/composer' });
            }}
          >
            <Play className="h-4 w-4" />
            New run
          </Button>
          <Button
            variant="outline"
            className="gap-2"
            onClick={() => {
              navigate({ to: '/runs' });
            }}
          >
            <History className="h-4 w-4" />
            Open replay
          </Button>
          <Button
            variant="outline"
            className="gap-2"
            onClick={() => {
              navigate({ to: '/runs' });
            }}
          >
            <FileText className="h-4 w-4" />
            Open report
          </Button>
        </div>
      </section>

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <StatCard
          title="Latest run"
          value={latestRun ? latestRun.name : 'No runs yet'}
          subtitle={latestRunSubtitle}
          icon={<Activity className="h-5 w-5" />}
          data={runSparkline}
          color={palette.latestRun}
          onClick={() => {
            navigate({ to: '/runs' });
          }}
          className="md:col-span-2 xl:col-span-2"
        />
        <StatCard
          title="Failures"
          value={integerFormatter.format(Math.max(0, Math.floor(latestMetrics?.failures ?? 0)))}
          subtitle={<p className="mt-3 text-sm text-muted-foreground">Total RPC errors recorded</p>}
          icon={<AlertTriangle className="h-5 w-5" />}
          data={failuresSparkline}
          color={palette.failures}
          onClick={() => {
            navigate({ to: '/runs' });
          }}
        />
        <StatCard
          title="Queue"
          value={integerFormatter.format(Math.round(latestMetrics?.queueDepth ?? 0))}
          subtitle={<p className="mt-3 text-sm text-muted-foreground">Messages waiting across plugins</p>}
          icon={<ListOrdered className="h-5 w-5" />}
          data={queueSparkline}
          color={palette.queue}
          onClick={() => {
            navigate({ to: '/runs' });
          }}
        />
        <StatCard
          title="Avg latency"
          value={`${decimalFormatter.format(Math.max(0, latestMetrics?.avgLatencyMs ?? 0))} ms`}
          subtitle={<p className="mt-3 text-sm text-muted-foreground">Plugin processing time</p>}
          icon={<Timer className="h-5 w-5" />}
          data={latencySparkline}
          color={palette.latency}
          onClick={() => {
            navigate({ to: '/runs' });
          }}
        />
        <StatCard
          title="Cases found"
          value={integerFormatter.format(Math.max(0, Math.floor(latestMetrics?.casesFound ?? 0)))}
          subtitle={<p className="mt-3 text-sm text-muted-foreground">Aggregated from telemetry exports</p>}
          icon={<Target className="h-5 w-5" />}
          data={casesSparkline}
          color={palette.cases}
          onClick={() => {
            navigate({ to: '/runs' });
          }}
        />
      </section>

      <section className="rounded-xl border border-border bg-card">
        <header className="flex items-center justify-between border-b border-border px-4 py-3">
          <div>
            <h2 className="text-lg font-medium">Recent runs</h2>
            <p className="text-sm text-muted-foreground">Stay on top of the latest executions.</p>
          </div>
          <Button variant="outline" size="sm" asChild>
            <Link to="/runs">View all</Link>
          </Button>
        </header>
        <ul className="divide-y divide-border">
          {runs.length === 0 ? (
            <li className="flex flex-col items-center justify-center gap-2 px-6 py-12 text-center text-muted-foreground">
              <AlertTriangle className="h-6 w-6" />
              <span>No runs available. Launch one to get started.</span>
            </li>
          ) : (
            runs.map((run) => (
              <li key={run.id} className="flex items-center justify-between px-6 py-4">
                <div>
                  <p className="font-medium text-foreground">{run.name}</p>
                  <p className="text-sm text-muted-foreground">Started {new Date(run.createdAt).toLocaleString()}</p>
                </div>
                <span className="rounded-full bg-secondary px-3 py-1 text-xs font-semibold uppercase text-secondary-foreground">
                  {run.status}
                </span>
              </li>
            ))
          )}
        </ul>
      </section>
    </div>
  );
}

export const Route = createFileRoute('/')({
  component: DashboardRoute
});

export default DashboardRoute;
