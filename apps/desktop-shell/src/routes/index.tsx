import { createFileRoute, Link } from '@tanstack/react-router';
import { useEffect, useState } from 'react';
import { AlertTriangle, Play } from 'lucide-react';

import { Button } from '../components/ui/button';
import { listRuns, startRun, type Run } from '../lib/ipc';
import { toast } from 'sonner';

function DashboardRoute() {
  const [runs, setRuns] = useState<Run[]>([]);
  const [isLaunching, setIsLaunching] = useState(false);

  useEffect(() => {
    let cancelled = false;
    listRuns()
      .then((data) => {
        if (!cancelled) {
          setRuns(data.slice(0, 5));
        }
      })
      .catch((error) => {
        console.error('Failed to load runs', error);
        toast.error('Unable to load recent runs');
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="mx-auto flex w-full max-w-4xl flex-col gap-6 p-6">
      <section className="flex flex-col gap-2">
        <h1 className="text-3xl font-semibold tracking-tight">Welcome back</h1>
        <p className="text-muted-foreground">
          Launch investigations, monitor live events, and manage Glyph runs in one place.
        </p>
        <div className="flex gap-2">
          <Button
            className="gap-2"
            disabled={isLaunching}
            onClick={async () => {
              try {
                setIsLaunching(true);
                const response = await startRun({ name: 'New Glyph run' });
                toast.success(`Run ${response.id} started`);
              } catch (error) {
                console.error('Failed to start run', error);
                toast.error('Unable to start run');
              } finally {
                setIsLaunching(false);
              }
            }}
          >
            <Play className="h-4 w-4" />
            {isLaunching ? 'Starting…' : 'Start new run'}
          </Button>
          <Button variant="outline" asChild>
            <Link to="/runs">View all runs</Link>
          </Button>
        </div>
      </section>
      <section className="rounded-lg border border-border bg-card">
        <header className="flex items-center justify-between border-b border-border px-4 py-3">
          <h2 className="text-lg font-medium">Recent runs</h2>
          <Button variant="link" asChild>
            <Link to="/runs">View all</Link>
          </Button>
        </header>
        <ul className="divide-y divide-border">
          {runs.length === 0 ? (
            <li className="flex flex-col items-center justify-center gap-2 px-6 py-10 text-center text-muted-foreground">
              <AlertTriangle className="h-6 w-6" />
              <span>No runs available. Launch one to get started.</span>
            </li>
          ) : (
            runs.map((run) => (
              <li key={run.id} className="flex items-center justify-between px-6 py-4">
                <div>
                  <p className="font-medium">{run.name}</p>
                  <p className="text-sm text-muted-foreground">Started {run.createdAt}</p>
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
