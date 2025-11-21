import { createFileRoute, Link, useNavigate } from '@tanstack/react-router';
import { motion, useReducedMotion } from 'framer-motion';
import {
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type ReactNode
} from 'react';
import { Activity, AlertTriangle, Layers, ListOrdered, Sparkles, Target, Timer, type LucideIcon } from 'lucide-react';
import { Area, AreaChart, ResponsiveContainer } from 'recharts';

import { Button } from '../components/ui/button';
import { StatusChip } from '../components/ui/status-chip';
import { listRuns, type Run } from '../lib/ipc';
import { cn } from '../lib/utils';
import { toast } from 'sonner';
import { useArtifact } from '../providers/artifact-provider';
import { useMetrics } from '../providers/metrics-provider';
import { useTheme } from '../providers/theme-provider';
import { baseTransition, hoverTransition } from '../lib/motion';
import { useMode } from '../providers/mode-provider';

type SparklinePoint = {
  time: number;
  value: number;
};

type RunHistoryPoint = {
  timestamp: number;
  count: number;
};

type DotShape = 'circle' | 'square' | 'diamond';

type StatCardProps = {
  title: string;
  value: ReactNode;
  subtitle?: ReactNode;
  icon: LucideIcon;
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

type SparklineDotProps = {
  cx?: number;
  cy?: number;
  color: string;
  shape: DotShape;
};

function SparklineDot({ cx, cy, color, shape }: SparklineDotProps) {
  if (typeof cx !== 'number' || typeof cy !== 'number') {
    return null;
  }

  const strokeWidth = 1.75;

  switch (shape) {
    case 'square':
      return (
        <rect
          x={cx - 4}
          y={cy - 4}
          width={8}
          height={8}
          fill="white"
          stroke={color}
          strokeWidth={strokeWidth}
          rx={1.5}
        />
      );
    case 'diamond':
      return (
        <polygon
          points={`${cx},${cy - 5} ${cx + 5},${cy} ${cx},${cy + 5} ${cx - 5},${cy}`}
          fill="white"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinejoin="round"
        />
      );
    default:
      return <circle cx={cx} cy={cy} r={4} fill="white" stroke={color} strokeWidth={strokeWidth} />;
  }
}

function Sparkline({ data, color }: { data: SparklinePoint[]; color: string }) {
  const gradientId = useId();
  const patternId = useId();
  const points = data.filter((point) => Number.isFinite(point.value));
  const { isVisionSimulationActive } = useTheme();

  if (points.length < 2) {
    return (
      <div className="flex h-full items-center justify-center rounded-xl bg-muted/10 text-xs text-muted-foreground">
        Awaiting data
      </div>
    );
  }

  const variants: DotShape[] = ['circle', 'diamond', 'square'];
  const dashPatterns = ['4 3', '2 2', '6 3'];
  const hash = Math.abs(Array.from(color).reduce((acc, char) => acc + char.charCodeAt(0), 0));
  const variantIndex = hash % variants.length;
  const selectedShape = variants[variantIndex];
  const strokeDasharray = dashPatterns[variantIndex];

  return (
    <div className="h-full w-full overflow-hidden rounded-xl bg-muted/5">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={points} margin={{ top: 4, right: 0, bottom: 0, left: 0 }}>
          <defs>
            <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={color} stopOpacity={0.35} />
              <stop offset="95%" stopColor={color} stopOpacity={0} />
            </linearGradient>
            <pattern id={patternId} width={12} height={12} patternUnits="userSpaceOnUse">
              <rect width="12" height="12" fill={color} opacity={0.12} />
              <path d="M0 12 L12 0" stroke={color} strokeWidth={1.25} opacity={0.55} />
              {variantIndex === 0 && (
                <path d="M0 0 L12 12" stroke={color} strokeWidth={1.25} opacity={0.35} />
              )}
              {variantIndex === 1 && (
                <g stroke={color} strokeWidth={1.15} opacity={0.45}>
                  <path d="M-2 0 H14" />
                  <path d="M-2 0 H14" transform="translate(0 6)" />
                </g>
              )}
              {variantIndex === 2 && (
                <g fill={color} opacity={0.45}>
                  <circle cx={3} cy={3} r={1.2} />
                  <circle cx={9} cy={9} r={1.2} />
                </g>
              )}
            </pattern>
          </defs>
          <Area
            type="monotone"
            dataKey="value"
            stroke={color}
            strokeWidth={isVisionSimulationActive ? 2.5 : 2}
            strokeDasharray={isVisionSimulationActive ? strokeDasharray : undefined}
            fill={`url(#${isVisionSimulationActive ? patternId : gradientId})`}
            fillOpacity={1}
            dot={
              isVisionSimulationActive
                ? (props) => (
                    <SparklineDot
                      {...(props as SparklineDotProps)}
                      color={color}
                      shape={selectedShape}
                    />
                  )
                : false
            }
            activeDot={
              isVisionSimulationActive
                ? (props) => (
                    <SparklineDot
                      {...(props as SparklineDotProps)}
                      color={color}
                      shape={selectedShape}
                    />
                  )
                : undefined
            }
            isAnimationActive={!isVisionSimulationActive}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
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
  const Icon = icon;
  const shouldReduceMotion = useReducedMotion();

  return (
    <motion.button
      type="button"
      onClick={onClick}
      initial={shouldReduceMotion ? false : { opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={shouldReduceMotion ? { duration: 0 } : baseTransition}
      whileHover={
        shouldReduceMotion
          ? undefined
          : {
              y: -4,
              transition: hoverTransition
            }
      }
      whileTap={shouldReduceMotion ? undefined : { scale: 0.98, transition: hoverTransition }}
      className={cn(
        'group flex h-full flex-col justify-between rounded-2xl border border-border/70 bg-card/95 p-6 text-left shadow-soft backdrop-blur-sm',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2',
        className
      )}
    >
      <div className="flex items-start justify-between gap-6">
        <div className="space-y-2">
          <span className="text-sm font-medium text-muted-foreground">{title}</span>
          <div className="text-2xl font-semibold tracking-tight text-foreground">{value}</div>
          {subtitle}
        </div>
        <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-primary/10 text-primary shadow-subtle">
          <Icon className="h-5 w-5" strokeWidth={1.75} aria-hidden />
        </div>
      </div>
      <div className="mt-6 h-20">
        <Sparkline data={data} color={color} />
      </div>
    </motion.button>
  );
}

function DashboardRoute() {
  const navigate = useNavigate();
  const shouldReduceMotion = useReducedMotion();
  const [runs, setRuns] = useState<Run[]>([]);
  const [runHistory, setRunHistory] = useState<RunHistoryPoint[]>([]);
  const runsErrorShownRef = useRef(false);
  const metricsErrorShownRef = useRef(false);
  const { status } = useArtifact();
  const offlineMode = Boolean(status?.loaded);
  const {
    history: metricsHistory,
    latest: latestMetrics,
    error: metricsError
  } = useMetrics();
  const { config: modeConfig } = useMode();
  const ModeIcon = modeConfig.icon;

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
    if (offlineMode) {
      setRuns([]);
      setRunHistory([]);
      return;
    }

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
  }, [offlineMode]);

  useEffect(() => {
    if (metricsError) {
      console.error('Failed to load metrics', metricsError);
      if (!metricsErrorShownRef.current) {
        toast.error('Unable to load metrics');
        metricsErrorShownRef.current = true;
      }
    } else {
      metricsErrorShownRef.current = false;
    }
  }, [metricsError]);

  const latestRun = runs[0];

  const runSparkline = runHistory.map((entry) => ({ time: entry.timestamp, value: entry.count }));
  const failuresSparkline = metricsHistory.map((entry) => ({ time: entry.timestamp, value: entry.failures }));
  const queueSparkline = metricsHistory.map((entry) => ({ time: entry.timestamp, value: entry.queueDepth }));
  const latencySparkline = metricsHistory.map((entry) => ({ time: entry.timestamp, value: entry.avgLatencyMs }));
  const casesSparkline = metricsHistory.map((entry) => ({ time: entry.timestamp, value: entry.casesFound }));

  const latestRunSubtitle = latestRun ? (
    <div className="mt-4 space-y-2 text-sm text-muted-foreground">
      <StatusChip status={latestRun.status} />
      <p>Started {new Date(latestRun.createdAt).toLocaleString()}</p>
    </div>
  ) : (
    <p className="mt-4 text-sm text-muted-foreground">Launch a run to see live telemetry.</p>
  );

  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-10 p-8">
      {/* Control Center Featured Banner */}
      <motion.section
        initial={shouldReduceMotion ? false : { opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={shouldReduceMotion ? { duration: 0 } : baseTransition}
        className="overflow-hidden rounded-2xl border border-border/70 bg-gradient-to-br from-purple-500/10 via-pink-500/10 to-rose-500/10 shadow-soft backdrop-blur-sm"
      >
        <div className="flex flex-col gap-6 p-8 md:flex-row md:items-center md:justify-between">
          <div className="flex items-start gap-4">
            <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-purple-500 via-pink-500 to-rose-500 shadow-lg">
              <Layers className="h-7 w-7 text-white" strokeWidth={2} />
            </div>
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <h2 className="text-2xl font-semibold tracking-tight">Control Center</h2>
                <span className="inline-flex items-center rounded-full bg-purple-500/20 px-2 py-0.5 text-xs font-semibold text-purple-600 ring-1 ring-inset ring-purple-500/30 dark:text-purple-400">
                  <Sparkles className="mr-1 h-3 w-3" />
                  New
                </span>
              </div>
              <p className="text-sm text-muted-foreground">
                Access all security testing plugins and features from one unified interface. Monitor plugin status, launch workflows, and manage your entire testing pipeline.
              </p>
            </div>
          </div>
          <Button
            size="lg"
            onClick={() => navigate({ to: '/control-center' })}
            className="bg-gradient-to-r from-purple-500 via-pink-500 to-rose-500 text-white shadow-lg hover:opacity-90"
          >
            Open Control Center
          </Button>
        </div>
      </motion.section>

      <section className="space-y-8">
        <div className="space-y-3">
          <h1 className="text-3xl font-semibold tracking-tight">Operations overview</h1>
          <p className="text-muted-foreground">
            Monitor live runs, watch queue health, and keep an eye on investigation throughput at a glance.
          </p>
        </div>
        <div className="grid gap-2 sm:grid-cols-3">
          {modeConfig.actions.map((action, index) => {
            const Icon = action.icon;
            const variant = action.variant ?? (index === 0 ? 'default' : 'outline');
            return (
              <Button
                key={action.id}
                variant={variant}
                className={cn('gap-2', action.className)}
                onClick={() => {
                  navigate({ to: action.to });
                }}
              >
                <Icon className="h-4 w-4" aria-hidden />
                {action.label}
              </Button>
            );
          })}
        </div>
      </section>

      <section className="overflow-hidden rounded-2xl border border-border/70 bg-card/95 shadow-soft backdrop-blur-sm">
        <div
          className={cn(
            'border-b border-border/70 px-8 py-6 text-white',
            'bg-gradient-to-r',
            modeConfig.accentGradient
          )}
        >
          <div className="flex items-start gap-4">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-white/20 text-white/90 backdrop-blur">
              <ModeIcon className="h-5 w-5" aria-hidden />
            </div>
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide text-white/70">Highlighted modules</p>
              <h2 className="text-lg font-semibold tracking-tight">{modeConfig.label}</h2>
              <p className="mt-1 text-sm text-white/80">{modeConfig.description}</p>
            </div>
          </div>
        </div>
        <div className="grid gap-4 px-8 py-6 md:grid-cols-3">
          {modeConfig.modules.map((module) => {
            const Icon = module.icon;
            return (
              <button
                key={module.id}
                type="button"
                onClick={() => {
                  navigate({ to: module.to });
                }}
                className="group flex h-full flex-col gap-4 rounded-xl border border-border/70 bg-background/60 p-5 text-left transition hover:-translate-y-1 hover:border-primary/60 hover:shadow-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 focus-visible:ring-offset-background"
              >
                <span
                  className={cn(
                    'inline-flex w-fit items-center rounded-full px-2 py-0.5 text-[0.65rem] font-semibold uppercase tracking-wide',
                    module.badgeClass
                  )}
                >
                  {module.focus}
                </span>
                <div className="flex items-start gap-4">
                  <div className={cn('flex h-12 w-12 items-center justify-center rounded-xl', module.iconClass)}>
                    <Icon className="h-5 w-5" aria-hidden />
                  </div>
                  <div>
                    <h3 className="text-base font-semibold text-foreground">{module.name}</h3>
                    <p className="mt-1 text-sm text-muted-foreground">{module.description}</p>
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      </section>

      <section className="grid gap-6 md:grid-cols-2 xl:grid-cols-5">
        <StatCard
          title="Latest run"
          value={latestRun ? latestRun.name : 'No runs yet'}
          subtitle={latestRunSubtitle}
          icon={Activity}
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
          subtitle={<p className="mt-4 text-sm text-muted-foreground">Total RPC errors recorded</p>}
          icon={AlertTriangle}
          data={failuresSparkline}
          color={palette.failures}
          onClick={() => {
            navigate({ to: '/runs' });
          }}
        />
        <StatCard
          title="Queue"
          value={integerFormatter.format(Math.round(latestMetrics?.queueDepth ?? 0))}
          subtitle={<p className="mt-4 text-sm text-muted-foreground">Messages waiting across plugins</p>}
          icon={ListOrdered}
          data={queueSparkline}
          color={palette.queue}
          onClick={() => {
            navigate({ to: '/runs' });
          }}
        />
        <StatCard
          title="Avg latency"
          value={`${decimalFormatter.format(Math.max(0, latestMetrics?.avgLatencyMs ?? 0))} ms`}
          subtitle={<p className="mt-4 text-sm text-muted-foreground">Plugin processing time</p>}
          icon={Timer}
          data={latencySparkline}
          color={palette.latency}
          onClick={() => {
            navigate({ to: '/runs' });
          }}
        />
        <StatCard
          title="Cases found"
          value={integerFormatter.format(Math.max(0, Math.floor(latestMetrics?.casesFound ?? 0)))}
          subtitle={<p className="mt-4 text-sm text-muted-foreground">Aggregated from telemetry exports</p>}
          icon={Target}
          data={casesSparkline}
          color={palette.cases}
          onClick={() => {
            navigate({ to: '/runs' });
          }}
        />
      </section>

      <section className="rounded-2xl border border-border/70 bg-card/95 shadow-soft backdrop-blur-sm">
        <header className="flex items-center justify-between gap-4 border-b border-border/70 px-8 py-6">
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
            <li className="flex flex-col items-center justify-center gap-3 px-8 py-12 text-center text-muted-foreground">
              <AlertTriangle className="h-6 w-6" aria-hidden />
              <span>No runs available. Launch one to get started.</span>
            </li>
          ) : (
            runs.map((run) => (
              <motion.li
                key={run.id}
                initial={shouldReduceMotion ? false : { opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={shouldReduceMotion ? { duration: 0 } : baseTransition}
                className="flex items-center justify-between px-8 py-6"
              >
                <div className="space-y-2">
                  <p className="font-medium text-foreground">{run.name}</p>
                  <p className="text-sm text-muted-foreground">Started {new Date(run.createdAt).toLocaleString()}</p>
                </div>
                <StatusChip status={run.status} />
              </motion.li>
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
