import { createPortal } from 'react-dom';
import { useMemo, type ReactNode } from 'react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from 'recharts';
import { X, ExternalLink } from 'lucide-react';

import { Button } from './ui/button';
import { cn } from '../lib/utils';
import { useMetrics } from '../providers/metrics-provider';

function formatTime(value: number) {
  return new Date(value).toLocaleTimeString();
}

function formatRate(value: number) {
  return `${value.toFixed(2)} req/s`;
}

function ChartFallback({ message }: { message: string }) {
  return (
    <div className="flex h-52 items-center justify-center rounded-lg border border-dashed border-border text-sm text-muted-foreground">
      {message}
    </div>
  );
}

function ChartCard({
  title,
  description,
  className,
  children
}: {
  title: string;
  description?: string;
  className?: string;
  children: ReactNode;
}) {
  return (
    <section className={cn('flex flex-col gap-3 rounded-xl border border-border bg-muted/10 p-4', className)}>
      <header className="space-y-1">
        <h3 className="text-base font-semibold text-foreground">{title}</h3>
        {description ? <p className="text-sm text-muted-foreground">{description}</p> : null}
      </header>
      {children}
    </section>
  );
}

export function MetricsPanel({ open, onOpenChange }: { open: boolean; onOpenChange: (next: boolean) => void }) {
  const { history, latest } = useMetrics();

  const rpsSeries = useMemo(() => {
    if (history.length < 2) {
      return [];
    }
    const points = [] as { time: number; rate: number }[];
    for (let index = 1; index < history.length; index += 1) {
      const current = history[index];
      const previous = history[index - 1];
      const deltaCount = current.eventsTotal - previous.eventsTotal;
      const deltaTime = (current.timestamp - previous.timestamp) / 1000;
      if (deltaCount < 0 || deltaTime <= 0) {
        continue;
      }
      const rate = deltaCount / deltaTime;
      points.push({ time: current.timestamp, rate: Math.max(0, rate) });
    }
    return points;
  }, [history]);

  const queueSeries = useMemo(
    () => history.map((entry) => ({ time: entry.timestamp, depth: entry.queueDepth })),
    [history]
  );

  const dropSeries = useMemo(() => {
    if (history.length < 2) {
      return [];
    }
    const points = [] as { time: number; drops: number }[];
    for (let index = 1; index < history.length; index += 1) {
      const current = history[index];
      const previous = history[index - 1];
      const delta = current.queueDrops - previous.queueDrops;
      const deltaTime = (current.timestamp - previous.timestamp) / 1000;
      if (delta < 0 || deltaTime <= 0) {
        continue;
      }
      points.push({ time: current.timestamp, drops: Math.max(0, delta / deltaTime) });
    }
    return points;
  }, [history]);

  const latencyBuckets = useMemo(
    () =>
      (latest?.latencyBuckets ?? []).map((bucket) => ({
        upperBoundMs: bucket.upperBoundMs,
        label: `${Math.round(bucket.upperBoundMs)} ms`,
        count: bucket.count
      })),
    [latest?.latencyBuckets]
  );

  const pluginErrors = useMemo(
    () =>
      (latest?.pluginErrors ?? []).map((item) => ({
        plugin: item.plugin,
        errors: item.errors
      })),
    [latest?.pluginErrors]
  );

  const lastUpdated = latest ? new Date(latest.timestamp).toLocaleTimeString() : null;

  if (!open) {
    return null;
  }

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 p-4 backdrop-blur">
      <div className="relative flex w-full max-w-6xl flex-col gap-4 overflow-hidden rounded-3xl border border-border bg-card p-6 shadow-2xl">
        <header className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-2xl font-semibold text-foreground">Operations metrics</h2>
            <p className="text-sm text-muted-foreground">
              Live Prometheus readings from the Glyph daemon.
              {lastUpdated ? ` Last updated at ${lastUpdated}.` : null}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <a
              href="/metrics"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-2 rounded-full border border-border bg-background px-3 py-1 text-sm font-medium text-primary transition hover:border-primary hover:bg-primary/10"
            >
              <ExternalLink className="h-4 w-4" aria-hidden />
              Raw metrics
            </a>
            <Button variant="ghost" size="icon" onClick={() => onOpenChange(false)} aria-label="Close metrics panel">
              <X className="h-5 w-5" />
            </Button>
          </div>
        </header>
        <div className="grid gap-4 md:grid-cols-2">
          <ChartCard title="Requests per second" description="Computed from plugin event throughput">
            {rpsSeries.length === 0 ? (
              <ChartFallback message="Awaiting enough samples to chart request rate" />
            ) : (
              <div className="h-52">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={rpsSeries} margin={{ top: 16, right: 24, left: 0, bottom: 0 }}>
                    <defs>
                      <linearGradient id="rpsGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#6366f1" stopOpacity={0.35} />
                        <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" strokeOpacity={0.1} />
                    <XAxis
                      dataKey="time"
                      type="number"
                      tickFormatter={formatTime}
                      domain={[rpsSeries[0]?.time ?? 'dataMin', rpsSeries[rpsSeries.length - 1]?.time ?? 'dataMax']}
                    />
                    <YAxis tickFormatter={(value) => value.toFixed(1)} width={60} />
                    <Tooltip
                      labelFormatter={formatTime}
                      formatter={(value: number) => [formatRate(value), 'RPS']}
                    />
                    <Area type="monotone" dataKey="rate" stroke="#6366f1" strokeWidth={2} fill="url(#rpsGradient)" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            )}
          </ChartCard>
          <ChartCard title="Queue depth" description="Pending messages across all plugins">
            {queueSeries.length === 0 ? (
              <ChartFallback message="No queue depth samples yet" />
            ) : (
              <div className="h-52">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={queueSeries} margin={{ top: 16, right: 24, left: 0, bottom: 0 }}>
                    <defs>
                      <linearGradient id="queueGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#22c55e" stopOpacity={0.35} />
                        <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" strokeOpacity={0.1} />
                    <XAxis dataKey="time" type="number" tickFormatter={formatTime} />
                    <YAxis width={60} allowDecimals={false} />
                    <Tooltip
                      labelFormatter={formatTime}
                      formatter={(value: number) => [`${value.toFixed(0)} messages`, 'Queue depth']}
                    />
                    <Area type="monotone" dataKey="depth" stroke="#22c55e" strokeWidth={2} fill="url(#queueGradient)" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            )}
          </ChartCard>
          <ChartCard title="Queue drops" description="Rate of discarded events per second">
            {dropSeries.length === 0 ? (
              <ChartFallback message="No drop activity observed" />
            ) : (
              <div className="h-52">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={dropSeries} margin={{ top: 16, right: 24, left: 0, bottom: 0 }}>
                    <defs>
                      <linearGradient id="dropGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#f97316" stopOpacity={0.35} />
                        <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" strokeOpacity={0.1} />
                    <XAxis dataKey="time" type="number" tickFormatter={formatTime} />
                    <YAxis width={60} tickFormatter={(value) => value.toFixed(2)} />
                    <Tooltip
                      labelFormatter={formatTime}
                      formatter={(value: number) => [`${value.toFixed(2)} /s`, 'Drops']}
                    />
                    <Area type="monotone" dataKey="drops" stroke="#f97316" strokeWidth={2} fill="url(#dropGradient)" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            )}
          </ChartCard>
          <ChartCard title="Plugin errors" description="Total error counters by plugin">
            {pluginErrors.length === 0 ? (
              <ChartFallback message="No plugin errors reported" />
            ) : (
              <div className="h-52">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={pluginErrors} margin={{ top: 16, right: 24, left: 0, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" strokeOpacity={0.1} />
                    <XAxis dataKey="plugin" tick={{ fontSize: 12 }} interval={0} angle={-20} height={60} textAnchor="end" />
                    <YAxis allowDecimals={false} width={60} />
                    <Tooltip formatter={(value: number) => [`${value.toFixed(0)}`, 'Errors']} />
                    <Bar dataKey="errors" fill="#ef4444" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </ChartCard>
        </div>
        <ChartCard title="Latency histogram" description="Distribution of plugin processing duration">
          {latencyBuckets.length === 0 ? (
            <ChartFallback message="Latency histogram unavailable" />
          ) : (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={latencyBuckets} margin={{ top: 16, right: 24, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" strokeOpacity={0.1} />
                  <XAxis dataKey="label" />
                  <YAxis allowDecimals={false} width={60} />
                  <Tooltip
                    formatter={(value: number, _name, payload) => [
                      `${value.toFixed(0)} events`,
                      `≤ ${payload?.payload?.label ?? ''}`
                    ]}
                  />
                  <Bar dataKey="count" fill="#0ea5e9" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </ChartCard>
      </div>
    </div>,
    document.body
  );
}
