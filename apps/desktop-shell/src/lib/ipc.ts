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

const DashboardMetricsSchema = z.object({
  failures: z.number(),
  queueDepth: z.number(),
  avgLatencyMs: z.number(),
  casesFound: z.number()
});

const timestampSchema = z.preprocess((value) => {
  if (typeof value === 'number') {
    return new Date(value * 1000).toISOString();
  }
  return value;
}, z.string());

const FlowEventSchema = z.object({
  id: z.string(),
  sequence: z.number().int(),
  timestamp: timestampSchema,
  type: z.string(),
  sanitized: z.string().optional(),
  sanitizedBase64: z.string().optional(),
  raw: z.string().optional(),
  rawBase64: z.string().optional(),
  rawBodySize: z.number().int().optional(),
  rawBodyCaptured: z.number().int().optional(),
  sanitizedRedacted: z.boolean().optional(),
  scope: z.string().optional(),
  tags: z.array(z.string()).optional(),
  pluginTags: z.array(z.string()).optional(),
  metadata: z.unknown().optional()
});

const FlowPageSchema = z.object({
  items: z.array(FlowEventSchema),
  nextCursor: z.string().optional().nullable()
});

const ResendFlowResponseSchema = z.object({
  flowId: z.string(),
  metadata: z.unknown().optional()
});

export type Run = z.infer<typeof RunSchema>;
export type DashboardMetrics = z.infer<typeof DashboardMetricsSchema>;
export type FlowEvent = z.infer<typeof FlowEventSchema>;
export type FlowPage = z.infer<typeof FlowPageSchema>;

export type FlowFilters = {
  search?: string;
  methods?: string[];
  statuses?: number[];
  domains?: string[];
  scope?: string[];
  tags?: string[];
  pluginTags?: string[];
};

export type RunEvent = {
  type: string;
  timestamp: string;
  payload?: unknown;
};

export type StreamHandle = {
  close: () => Promise<void>;
};

export type FlowStreamHandle = {
  close: () => Promise<void>;
};

export async function listRuns(): Promise<Run[]> {
  const runs = await invoke('list_runs');
  return z.array(RunSchema).parse(runs);
}

export async function startRun(payload: { name: string; template?: string }) {
  const response = await invoke('start_run', payload);
  return StartRunResponseSchema.parse(response);
}

export async function fetchMetrics(): Promise<DashboardMetrics> {
  const metrics = await invoke('fetch_metrics');
  return DashboardMetricsSchema.parse(metrics);
}

export async function listFlows(payload: {
  cursor?: string;
  limit?: number;
  filters?: FlowFilters;
} = {}): Promise<FlowPage> {
  const response = await invoke('list_flows', payload);
  return FlowPageSchema.parse(response);
}

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

export async function streamFlowEvents(
  streamId: string,
  onEvent: (event: FlowEvent) => void,
  options: { filters?: FlowFilters } = {}
): Promise<FlowStreamHandle> {
  const eventName = `flows:${streamId}:events`;
  const unlisten = await listen(eventName, (event: Event<unknown>) => {
    if (!event.payload) {
      return;
    }
    try {
      const parsed = FlowEventSchema.parse(event.payload);
      onEvent(parsed);
    } catch (error) {
      console.warn('Failed to parse flow event payload', error);
    }
  });

  await invoke('stream_flows', { stream_id: streamId, filters: options.filters });

  return {
    close: async () => {
      await invoke('stop_flow_stream', { stream_id: streamId });
      unlisten();
    }
  } satisfies FlowStreamHandle;
}

export async function resendFlow(flowId: string, message: string) {
  const response = await invoke('resend_flow', { flow_id: flowId, message });
  return ResendFlowResponseSchema.parse(response);
}
