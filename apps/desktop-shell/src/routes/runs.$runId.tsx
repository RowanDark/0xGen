import { createFileRoute, Link, useParams } from '@tanstack/react-router';
import { Loader2, Octagon, Radio, RefreshCcw, Timer, Zap } from 'lucide-react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { toast } from 'sonner';

import { Button } from '../components/ui/button';
import { listRuns, stopRun, streamEvents, type Run, type RunEvent, type StreamHandle } from '../lib/ipc';
import { useCommandCenter } from '../providers/command-center';

function useRun(runId: string) {
  const [run, setRun] = useState<Run | undefined>(undefined);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    setIsLoading(true);

    listRuns()
      .then((runs) => {
        if (!mounted) {
          return;
        }
        setRun(runs.find((candidate) => candidate.id === runId));
      })
      .catch((error) => {
        console.error('Failed to load run', error);
        toast.error('Unable to fetch run details');
      })
      .finally(() => {
        if (mounted) {
          setIsLoading(false);
        }
      });

    return () => {
      mounted = false;
    };
  }, [runId]);

  return { run, isLoading };
}

function useRunEvents(runId: string) {
  const [events, setEvents] = useState<RunEvent[]>([]);

  useEffect(() => {
    let cancelled = false;
    let handle: StreamHandle | undefined;

    streamEvents(runId, (event) => {
      if (cancelled) {
        return;
      }

      setEvents((previous) => [event, ...previous].slice(0, 200));
    })
      .then((value) => {
        if (cancelled) {
          void value.close();
          return;
        }
        handle = value;
      })
      .catch((error) => {
        console.error('Failed to stream events', error);
        toast.error('Unable to stream run events');
      });

    return () => {
      cancelled = true;
      if (handle) {
        handle
          .close()
          .catch((error) => {
            console.warn('Failed to close stream', error);
          })
          .finally(() => {
            handle = undefined;
          });
      }
    };
  }, [runId]);

  return events;
}

function RunDetailRoute() {
  const { runId } = useParams({ from: '/runs/$runId' });
  const { run, isLoading } = useRun(runId);
  const events = useRunEvents(runId);
  const { registerCommand } = useCommandCenter();

  const latestStatus = useMemo(() => events.find((event) => event.type === 'status:update')?.payload, [events]);
  const canStop = useMemo(() => {
    if (!run) {
      return false;
    }
    const terminalStates = ['completed', 'failed', 'stopped', 'cancelled', 'finished'];
    return !terminalStates.includes(run.status.toLowerCase());
  }, [run]);

  const handleStop = useCallback(() => {
    toast.promise(stopRun(runId), {
      loading: 'Sending stop request…',
      success: 'Stop signal sent to run',
      error: 'Unable to stop run'
    });
  }, [runId]);

  useEffect(() => {
    return registerCommand({
      id: `run.${runId}.stop`,
      title: 'Stop current run',
      description: 'Send a stop signal to the active run',
      group: 'Runs',
      shortcut: 'mod+shift+s',
      run: () => {
        if (canStop) {
          handleStop();
        }
      },
      disabled: !canStop,
      allowInInput: true
    });
  }, [registerCommand, runId, canStop, handleStop]);

  return (
    <div className="mx-auto flex w-full max-w-4xl flex-col gap-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3 text-sm text-muted-foreground">
            <Link to="/runs" className="text-xs text-muted-foreground hover:text-foreground">
              Back to runs
            </Link>
            <span>/</span>
            <span className="font-medium text-foreground">Run {runId.slice(0, 8)}</span>
          </div>
          <h1 className="text-3xl font-semibold tracking-tight">Live run progress</h1>
          <p className="text-muted-foreground">
            Watch events stream in real time. Refresh metadata or return to history at any time.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              toast.promise(
                listRuns().then((runs) => {
                  const latest = runs.find((candidate) => candidate.id === runId);
                  if (!latest) {
                    throw new Error('Run not found');
                  }
                  return latest;
                }),
                {
                  loading: 'Refreshing run metadata…',
                  success: (updated) => {
                    return `Run status: ${updated.status}`;
                  },
                  error: 'Unable to refresh run metadata'
                }
              );
            }}
          >
            <RefreshCcw className="mr-2 h-4 w-4" />
            Refresh
          </Button>
          <Button
            variant="destructive"
            size="sm"
            className="gap-2"
            onClick={handleStop}
            disabled={!canStop}
            title={!canStop ? 'Run is already complete or unavailable' : undefined}
          >
            <Octagon className="h-4 w-4" />
            Stop run
          </Button>
        </div>
      </div>

      <section className="rounded-xl border border-border bg-card p-6">
        {isLoading ? (
          <div className="flex items-center gap-3 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading run metadata…
          </div>
        ) : run ? (
          <dl className="grid gap-4 sm:grid-cols-2">
            <div>
              <dt className="text-xs uppercase tracking-wide text-muted-foreground">Name</dt>
              <dd className="text-sm text-foreground">{run.name}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-muted-foreground">Status</dt>
              <dd className="text-sm text-foreground">{run.status}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-muted-foreground">Created</dt>
              <dd className="text-sm text-foreground">{new Date(run.createdAt).toLocaleString()}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-muted-foreground">Latest update</dt>
              <dd className="text-sm text-foreground">
                {latestStatus ? JSON.stringify(latestStatus) : 'Streaming events'}
              </dd>
            </div>
          </dl>
        ) : (
          <div className="text-sm text-muted-foreground">Run not found or has been archived.</div>
        )}
      </section>

      <section className="rounded-xl border border-border bg-card">
        <header className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-6 py-4">
          <div>
            <p className="text-sm font-semibold text-foreground">Live events</p>
            <p className="text-xs text-muted-foreground">Newest events appear first. Streaming up to 200 entries.</p>
          </div>
          <div className="flex items-center gap-3 text-xs text-muted-foreground">
            <Radio className="h-3.5 w-3.5 text-green-500" />
            Connected
          </div>
        </header>
        <ol className="max-h-[480px] space-y-3 overflow-y-auto px-6 py-4 text-sm">
          {events.length === 0 ? (
            <li className="flex items-center gap-2 text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              Waiting for events…
            </li>
          ) : (
            events.map((event, index) => (
              <li key={`${event.type}-${event.timestamp}-${index}`} className="rounded-lg border border-border bg-background p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-medium text-foreground">{event.type}</span>
                  <span className="text-xs text-muted-foreground">{new Date(event.timestamp).toLocaleString()}</span>
                </div>
                {event.payload === undefined ? null : (
                  <pre className="mt-3 max-h-60 overflow-auto rounded-md bg-muted p-3 text-xs text-muted-foreground">
                    {JSON.stringify(event.payload, null, 2)}
                  </pre>
                )}
              </li>
            ))
          )}
        </ol>
      </section>

      <section className="grid gap-4 md:grid-cols-3">
        <div className="rounded-xl border border-border bg-card p-4">
          <div className="flex items-center gap-2 text-xs uppercase tracking-wide text-muted-foreground">
            <Timer className="h-4 w-4" />
            Duration estimate
          </div>
          <p className="mt-2 text-2xl font-semibold text-foreground">Live</p>
          <p className="text-xs text-muted-foreground">
            Run duration is calculated on completion. Monitor rate limits to project completion time.
          </p>
        </div>
        <div className="rounded-xl border border-border bg-card p-4">
          <div className="flex items-center gap-2 text-xs uppercase tracking-wide text-muted-foreground">
            <Zap className="h-4 w-4" />
            Throughput
          </div>
          <p className="mt-2 text-sm text-muted-foreground">
            Rate metrics become available after the first plugin emits telemetry.
          </p>
        </div>
        <div className="rounded-xl border border-border bg-card p-4">
          <div className="flex items-center gap-2 text-xs uppercase tracking-wide text-muted-foreground">
            <Radio className="h-4 w-4" />
            Stream status
          </div>
          <p className="mt-2 text-sm text-muted-foreground">Connection is managed automatically while this page remains open.</p>
        </div>
      </section>
    </div>
  );
}

export const Route = createFileRoute('/runs/$runId')({
  component: RunDetailRoute
});

export default RunDetailRoute;
