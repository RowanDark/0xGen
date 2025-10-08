import { invoke } from '@tauri-apps/api/tauri';
import { listen, type Event } from '@tauri-apps/api/event';
import { z } from 'zod';

const RunSchema = z.object({
  id: z.string(),
  name: z.string(),
  status: z.string(),
  createdAt: z.preprocess((value) => {
    if (typeof value === 'number') {
      return new Date(value * 1000).toISOString();
    }
    return value;
  }, z.string())
});

const StartRunResponseSchema = z.object({
  id: z.string()
});

export type Run = z.infer<typeof RunSchema>;

export async function listRuns(): Promise<Run[]> {
  const runs = await invoke('list_runs');
  return z.array(RunSchema).parse(runs);
}

export async function startRun(payload: { name: string; template?: string }) {
  const response = await invoke('start_run', payload);
  return StartRunResponseSchema.parse(response);
}

export type RunEvent = {
  type: string;
  timestamp: string;
  payload?: unknown;
};

export type StreamHandle = {
  close: () => Promise<void>;
};

export async function streamEvents(runId: string, onEvent: (event: RunEvent) => void) {
  const eventName = `runs:${runId}:events`;
  const unlisten = await listen(eventName, (event: Event<RunEvent>) => {
    if (event.payload) {
      onEvent(event.payload);
    }
  });

  await invoke('stream_events', { run_id: runId });

  return {
    close: async () => {
      await invoke('stop_stream', { run_id: runId });
      unlisten();
    }
  } satisfies StreamHandle;
}
