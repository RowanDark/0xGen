import { createFileRoute } from '@tanstack/react-router';
import { useEffect, useState } from 'react';
import { Play } from 'lucide-react';

import { Button } from '../components/ui/button';
import { listRuns, startRun, streamEvents, type Run, type RunEvent, type StreamHandle } from '../lib/ipc';
import { toast } from 'sonner';

function RunsRoute() {
  const [runs, setRuns] = useState<Run[]>([]);
  const [events, setEvents] = useState<Record<string, RunEvent[]>>({});

  useEffect(() => {
    listRuns()
      .then(setRuns)
      .catch((error) => {
        console.error('Failed to load runs', error);
        toast.error('Unable to fetch runs from the Glyph API');
      });
  }, []);

  const [isLaunching, setIsLaunching] = useState(false);

  useEffect(() => {
    if (runs.length === 0) {
      return;
    }

    const run = runs[0];
    let cancelled = false;
    let handle: StreamHandle | undefined;

    streamEvents(run.id, (event) => {
      if (cancelled) {
        return;
      }

      setEvents((prev) => ({
        ...prev,
        [run.id]: [...(prev[run.id] ?? []), event]
      }));
    })
      .then((value) => {
        if (cancelled) {
          void value.close();
          return;
        }
        handle = value;
      })
      .catch((error) => {
        console.error('Failed to start event stream', error);
        toast.error('Unable to stream run events');
      });

    return () => {
      cancelled = true;
      if (handle) {
        handle.close().catch((error) => {
          console.warn('Failed to close stream', error);
        });
      }
    };
  }, [runs]);

  return (
    <div className="mx-auto flex w-full max-w-4xl flex-col gap-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-semibold tracking-tight">Runs</h1>
          <p className="text-muted-foreground">Review the status of ongoing investigations.</p>
        </div>
        <Button
          className="gap-2"
          disabled={isLaunching}
          onClick={async () => {
            try {
              setIsLaunching(true);
              const response = await startRun({ name: 'New Glyph run' });
              toast.success(`Run ${response.id} started`);
              const latestRuns = await listRuns();
              setRuns(latestRuns);
            } catch (error) {
              console.error('Failed to start run', error);
              toast.error('Unable to start run');
            } finally {
              setIsLaunching(false);
            }
          }}
        >
          <Play className="h-4 w-4" />
          {isLaunching ? 'Starting…' : 'Start run'}
        </Button>
      </div>
      <div className="rounded-lg border border-border bg-card">
        <table className="w-full table-auto">
          <thead className="border-b border-border text-left text-sm uppercase text-muted-foreground">
            <tr>
              <th className="px-4 py-3 font-medium">Name</th>
              <th className="px-4 py-3 font-medium">Status</th>
              <th className="px-4 py-3 font-medium">Created</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border text-sm">
            {runs.map((run) => (
              <tr key={run.id}>
                <td className="px-4 py-3 font-medium">{run.name}</td>
                <td className="px-4 py-3">
                  <span className="rounded-full bg-secondary px-3 py-1 text-xs font-semibold uppercase text-secondary-foreground">
                    {run.status}
                  </span>
                </td>
                <td className="px-4 py-3 text-muted-foreground">{run.createdAt}</td>
              </tr>
            ))}
            {runs.length === 0 && (
              <tr>
                <td colSpan={3} className="px-4 py-12 text-center text-muted-foreground">
                  No runs available.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {runs.length > 0 && (
        <section className="rounded-lg border border-border bg-card">
          <header className="border-b border-border px-4 py-3">
            <h2 className="text-lg font-medium">Live events</h2>
            <p className="text-sm text-muted-foreground">
              Streaming the latest updates for run {runs[0].name}.
            </p>
          </header>
          <ul className="max-h-64 space-y-3 overflow-y-auto px-4 py-4 text-sm">
            {(events[runs[0].id] ?? []).map((event, index) => (
              <li key={`${event.type}-${index}`} className="rounded-md border border-border bg-background p-3">
                <p className="font-medium">{event.type}</p>
                <p className="text-xs text-muted-foreground">{event.timestamp}</p>
                {event.payload && (
                  <pre className="mt-2 max-h-32 overflow-auto rounded bg-muted p-2 text-xs text-muted-foreground">
                    {JSON.stringify(event.payload, null, 2)}
                  </pre>
                )}
              </li>
            ))}
            {(events[runs[0].id] ?? []).length === 0 && (
              <li className="rounded-md border border-dashed border-border bg-background p-4 text-center text-muted-foreground">
                Waiting for events…
              </li>
            )}
          </ul>
        </section>
      )}
    </div>
  );
}

export const Route = createFileRoute('/runs')({
  component: RunsRoute
});

export default RunsRoute;
