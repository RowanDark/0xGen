import { invoke } from '@tauri-apps/api/core';
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

const StopRunResponseSchema = z.object({
  id: z.string().optional(),
  status: z.string().optional()
});

export type StartRunPayload = {
  name: string;
  template?: string;
  targets: string[];
  targetNotes?: string;
  scopePolicy: string;
  plugins: string[];
  limits: {
    concurrency: number;
    maxRps: number;
    maxFindings: number;
    safeMode: boolean;
  };
  auth: {
    strategy: string;
    apiKey?: string;
    username?: string;
    password?: string;
    oauthClientId?: string;
    oauthClientSecret?: string;
  };
  schedule: {
    mode: 'now' | 'later';
    startAt?: string;
    timezone?: string;
  };
};

const LatencyBucketSchema = z.object({
  upperBoundMs: z.number(),
  count: z.number()
});

const PluginErrorSchema = z.object({
  plugin: z.string(),
  errors: z.number()
});

const DashboardMetricsSchema = z.object({
  failures: z.number(),
  queueDepth: z.number(),
  avgLatencyMs: z.number(),
  casesFound: z.number(),
  eventsTotal: z.number(),
  queueDrops: z.number(),
  latencyBuckets: z.array(LatencyBucketSchema).optional().default([]),
  pluginErrors: z.array(PluginErrorSchema).optional().default([])
});

const ManifestDnsRecordSchema = z.object({
  host: z.string(),
  addresses: z.array(z.string()).optional().default([])
});

const ManifestTlsRecordSchema = z.object({
  host: z.string(),
  ja3: z.string().optional(),
  ja3Hash: z.string().optional(),
  negotiatedAlpn: z.string().optional(),
  offeredAlpn: z.array(z.string()).optional().default([])
});

const ManifestRobotsRecordSchema = z.object({
  host: z.string(),
  bodyFile: z.string().optional()
});

const ManifestRateLimitSchema = z.object({
  host: z.string(),
  policy: z.string()
});

const ManifestCookieSchema = z.object({
  domain: z.string(),
  name: z.string(),
  value: z.string()
});

const ManifestResponseSchema = z.object({
  requestUrl: z.string(),
  method: z.string(),
  status: z.number().int(),
  headers: z.record(z.array(z.string())).optional().default({}),
  bodyFile: z.string().optional()
});

const ManifestRunnerSchema = z.object({
  '0xgenctlVersion': z.string().optional(),
  '0xgendVersion': z.string().optional(),
  goVersion: z.string().optional(),
  os: z.string().optional(),
  arch: z.string().optional()
});

const ManifestPluginSchema = z.object({
  name: z.string(),
  version: z.string(),
  manifestPath: z.string(),
  signature: z.string(),
  sha256: z.string()
});

const ManifestSchema = z.object({
  version: z.string(),
  createdAt: z.string(),
  seeds: z.record(z.number()).optional().default({}),
  dns: z.array(ManifestDnsRecordSchema).optional().default([]),
  tls: z.array(ManifestTlsRecordSchema).optional().default([]),
  robots: z.array(ManifestRobotsRecordSchema).optional().default([]),
  rateLimits: z.array(ManifestRateLimitSchema).optional().default([]),
  cookies: z.array(ManifestCookieSchema).optional().default([]),
  responses: z.array(ManifestResponseSchema).optional().default([]),
  flowsFile: z.string().optional(),
  runner: ManifestRunnerSchema,
  plugins: z.array(ManifestPluginSchema).optional().default([]),
  findingsFile: z.string(),
  casesFile: z.string(),
  caseTimestamp: z.string()
});

const CaseEvidenceSchema = z.object({
  plugin: z.string(),
  type: z.string(),
  message: z.string(),
  evidence: z.string().optional(),
  metadata: z.record(z.string()).optional().default({})
});

const CaseProofSchema = z.object({
  summary: z.string().optional(),
  steps: z.array(z.string()).optional().default([])
});

const CaseRiskSchema = z.object({
  severity: z.string(),
  score: z.number(),
  rationale: z.string().optional()
});

const CaseSourceSchema = z.object({
  id: z.string(),
  plugin: z.string(),
  type: z.string(),
  severity: z.string(),
  target: z.string().optional()
});

const CaseChainStepSchema = z.object({
  stage: z.number().int(),
  from: z.string(),
  to: z.string(),
  description: z.string(),
  plugin: z.string(),
  type: z.string(),
  findingId: z.string(),
  severity: z.string(),
  weakLink: z.boolean().optional()
});

const CaseGraphSchema = z.object({
  dot: z.string(),
  mermaid: z.string(),
  summary: z.string().optional(),
  attackPath: z.array(CaseChainStepSchema).optional().default([])
});

const CaseSchema = z.object({
  version: z.string(),
  id: z.string(),
  asset: z.object({
    kind: z.string(),
    identifier: z.string(),
    details: z.string().optional()
  }),
  vector: z.object({
    kind: z.string(),
    value: z.string().optional()
  }),
  summary: z.string(),
  evidence: z.array(CaseEvidenceSchema).optional().default([]),
  proof: CaseProofSchema,
  risk: CaseRiskSchema,
  confidence: z.number(),
  confidenceLog: z.string().optional(),
  sources: z.array(CaseSourceSchema).optional().default([]),
  generatedAt: z.string(),
  labels: z.record(z.string()).optional().default({}),
  graph: CaseGraphSchema
});

const OpenArtifactResponseSchema = z.object({
  manifest: ManifestSchema,
  metrics: DashboardMetricsSchema,
  caseCount: z.number().int().nonnegative(),
  flowCount: z.number().int().nonnegative()
});

const ArtifactStatusSchema = z.object({
  loaded: z.boolean(),
  manifest: ManifestSchema.optional(),
  metrics: DashboardMetricsSchema.optional(),
  caseCount: z.number().int().nonnegative(),
  flowCount: z.number().int().nonnegative()
});

const timestampSchema = z.preprocess((value) => {
  if (typeof value === 'number') {
    return new Date(value * 1000).toISOString();
  }
  return value;
}, z.string());

const CaseSnapshotSummarySchema = z.object({
  id: z.string(),
  hash: z.string(),
  capturedAt: timestampSchema,
  caseTimestamp: timestampSchema,
  caseCount: z.number().int().nonnegative(),
  label: z.string()
});

const CaseSnapshotSchema = CaseSnapshotSummarySchema.extend({
  cases: z.array(CaseSchema)
});

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

const AuditRecordSchema = z
  .object({
    entryId: z.string().optional(),
    signature: z.string().optional(),
    recordedAt: z.string().optional(),
    actor: z.string().optional(),
    action: z.string().optional(),
    decision: z.string().optional()
  })
  .passthrough();

const ResendFlowMetadataSchema = z
  .object({
    parentFlowId: z.string().optional(),
    sourceFlowId: z.string().optional(),
    originalFlowId: z.string().optional(),
    childFlowId: z.string().optional(),
    cloneReason: z.string().optional(),
    audit: z.union([AuditRecordSchema, z.array(AuditRecordSchema)]).optional(),
    auditEntry: AuditRecordSchema.optional(),
    auditTrail: z.array(AuditRecordSchema).optional(),
    clones: z.array(z.string()).optional()
  })
  .passthrough();

const ResendFlowResponseSchema = z.object({
  flowId: z.string(),
  metadata: z.union([ResendFlowMetadataSchema, z.null()]).optional()
});

export type ResendFlowMetadata = z.infer<typeof ResendFlowMetadataSchema> | null | undefined;
export type ResendFlowResponse = z.infer<typeof ResendFlowResponseSchema>;

const RegistryCompatibilitySchema = z.object({
  status: z.string(),
  notes: z.string().optional()
});

const RegistryPluginSchema = z
  .object({
    id: z.string(),
    name: z.string(),
    version: z.string(),
    author: z.string(),
    language: z.string(),
    summary: z.string(),
    capabilities: z.array(z.string()),
    categories: z.array(z.string()).optional().default([]),
    last_updated: z.string().optional(),
    signature_sha256: z.string().optional(),
    links: z.record(z.string()),
    oxg_compat: z.record(RegistryCompatibilitySchema).optional().default({})
  })
  .transform((value) => ({
    id: value.id,
    name: value.name,
    version: value.version,
    author: value.author,
    language: value.language,
    summary: value.summary,
    capabilities: value.capabilities,
    categories: value.categories,
    lastUpdated: value.last_updated ?? null,
    signatureSha256: value.signature_sha256 ?? null,
    links: value.links,
    compatibility: value.oxg_compat
  }));

const InstalledPluginSchema = z
  .object({
    id: z.string(),
    name: z.string(),
    version: z.string(),
    capabilities: z.array(z.string()),
    path: z.string(),
    manifest_path: z.string(),
    artifact_path: z.string(),
    artifact_sha256: z.string().optional(),
    updated_at: z.string().optional()
  })
  .transform((value) => ({
    id: value.id,
    name: value.name,
    version: value.version,
    capabilities: value.capabilities,
    path: value.path,
    manifestPath: value.manifest_path,
    artifactPath: value.artifact_path,
    artifactSha256: value.artifact_sha256 ?? null,
    updatedAt: value.updated_at ?? null
  }));

const PluginStatusSchema = z
  .object({
    id: z.string(),
    installed: z.string().optional(),
    latest: z.string(),
    compatible: z.boolean().optional(),
    compatibility: z.string().optional(),
    update_available: z.boolean().optional()
  })
  .transform((value) => ({
    id: value.id,
    installed: value.installed ?? null,
    latest: value.latest,
    compatible: value.compatible ?? true,
    compatibility: value.compatibility ?? null,
    updateAvailable: value.update_available ?? false
  }));

const PluginRegistrySchema = z
  .object({
    schema_version: z.string(),
    generated_at: z.string(),
    oxg_versions: z.array(z.string()).optional().default([]),
    plugins: z.array(RegistryPluginSchema),
    installed: z.array(InstalledPluginSchema).optional().default([]),
    status: z.array(PluginStatusSchema).optional().default([]),
    daemon_version: z.string().optional()
  })
  .transform((value) => ({
    schemaVersion: value.schema_version,
    generatedAt: value.generated_at,
    oxgVersions: value.oxg_versions,
    plugins: value.plugins,
    installed: value.installed,
    status: value.status,
    daemonVersion: value.daemon_version ?? 'dev'
  }));

const ScopeRuleSchema = z.object({
  type: z.string(),
  value: z.string(),
  notes: z.string().optional()
});

const ScopePolicyDocumentSchema = z.object({
  policy: z.string(),
  source: z.string().optional(),
  updatedAt: z.string().optional()
});

const ScopeValidationMessageSchema = z.object({
  message: z.string(),
  line: z.number().int().optional(),
  column: z.number().int().optional(),
  path: z.string().optional()
});

const ScopeValidationResultSchema = z.object({
  valid: z.boolean(),
  errors: z.array(ScopeValidationMessageSchema),
  warnings: z.array(ScopeValidationMessageSchema).optional().default([])
});

const ScopeApplyResponseSchema = z.object({
  policy: z.string(),
  appliedAt: z.string(),
  warnings: z.array(ScopeValidationMessageSchema).optional().default([])
});

const ScopeParseSuggestionSchema = z.object({
  policy: z.string(),
  summary: z.string().optional(),
  notes: z.string().optional(),
  rationale: z.array(z.string()).optional(),
  rules: z
    .object({
      allow: z.array(ScopeRuleSchema).optional().default([]),
      deny: z.array(ScopeRuleSchema).optional().default([])
    })
    .optional()
});

const ScopeParseResponseSchema = z.object({
  suggestions: z.array(ScopeParseSuggestionSchema)
});

const ScopeDryRunDecisionSchema = z.object({
  url: z.string(),
  allowed: z.boolean(),
  reason: z.string().optional(),
  matchedRule: ScopeRuleSchema.optional()
});

const ScopeDryRunResponseSchema = z.object({
  results: z.array(ScopeDryRunDecisionSchema)
});

export type Run = z.infer<typeof RunSchema>;
export type LatencyBucket = z.infer<typeof LatencyBucketSchema>;
export type PluginErrorTotal = z.infer<typeof PluginErrorSchema>;
export type DashboardMetrics = z.infer<typeof DashboardMetricsSchema>;
export type FlowEvent = z.infer<typeof FlowEventSchema>;
export type FlowPage = z.infer<typeof FlowPageSchema>;
export type ScopePolicyDocument = z.infer<typeof ScopePolicyDocumentSchema>;
export type ScopeValidationMessage = z.infer<typeof ScopeValidationMessageSchema>;
export type ScopeValidationResult = z.infer<typeof ScopeValidationResultSchema>;
export type ScopeApplyResponse = z.infer<typeof ScopeApplyResponseSchema>;
export type ScopeParseSuggestion = z.infer<typeof ScopeParseSuggestionSchema>;
export type ScopeParseResponse = z.infer<typeof ScopeParseResponseSchema>;
export type ScopeDryRunDecision = z.infer<typeof ScopeDryRunDecisionSchema>;
export type ScopeDryRunResponse = z.infer<typeof ScopeDryRunResponseSchema>;
export type Manifest = z.infer<typeof ManifestSchema>;
export type CaseRecord = z.infer<typeof CaseSchema>;
export type OpenArtifactResponse = z.infer<typeof OpenArtifactResponseSchema>;
export type ArtifactStatus = z.infer<typeof ArtifactStatusSchema>;

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

export async function startRun(payload: StartRunPayload) {
  const response = await invoke('start_run', { payload });
  return StartRunResponseSchema.parse(response);
}

export async function stopRun(id: string) {
  const response = await invoke('stop_run', { id });
  if (!response) {
    return;
  }
  try {
    StopRunResponseSchema.parse(response);
  } catch (error) {
    console.warn('Unexpected stop_run response', error);
  }
}

export async function openArtifact(path: string): Promise<OpenArtifactResponse> {
  const response = await invoke('open_artifact', { path });
  return OpenArtifactResponseSchema.parse(response);
}

export async function getArtifactStatus(): Promise<ArtifactStatus> {
  const status = await invoke('artifact_status');
  return ArtifactStatusSchema.parse(status);
}

export async function fetchArtifactCases(): Promise<CaseRecord[]> {
  const cases = await invoke('list_cases');
  return z.array(CaseSchema).parse(cases);
}

export type CaseSnapshotSummary = z.infer<typeof CaseSnapshotSummarySchema>;
export type CaseSnapshot = z.infer<typeof CaseSnapshotSchema>;

export async function captureCaseSnapshot(): Promise<CaseSnapshotSummary> {
  const snapshot = await invoke('capture_case_snapshot');
  return CaseSnapshotSummarySchema.parse(snapshot);
}

export async function listCaseSnapshots(): Promise<CaseSnapshotSummary[]> {
  const snapshots = await invoke('list_case_snapshots');
  return z.array(CaseSnapshotSummarySchema).parse(snapshots);
}

export async function loadCaseSnapshot(id: string): Promise<CaseSnapshot> {
  const snapshot = await invoke('load_case_snapshot', { id });
  return CaseSnapshotSchema.parse(snapshot);
}

export async function deleteCaseSnapshot(id: string): Promise<void> {
  await invoke('delete_case_snapshot', { id });
}

export async function fetchMetrics(): Promise<DashboardMetrics> {
  const metrics = await invoke('fetch_metrics');
  return DashboardMetricsSchema.parse(metrics);
}

export type RegistryPlugin = z.infer<typeof RegistryPluginSchema>;
export type InstalledPluginSummary = z.infer<typeof InstalledPluginSchema>;
export type PluginStatus = z.infer<typeof PluginStatusSchema>;
export type PluginRegistry = z.infer<typeof PluginRegistrySchema>;

export async function fetchPluginRegistryData(): Promise<PluginRegistry> {
  const payload = await invoke('fetch_plugin_registry');
  return PluginRegistrySchema.parse(payload);
}

export async function installMarketplacePlugin(
  id: string,
  options: { force?: boolean } = {}
): Promise<InstalledPluginSummary> {
  const response = await invoke('install_plugin', {
    id,
    force: options.force ?? false
  });
  return InstalledPluginSchema.parse(response);
}

export async function removeMarketplacePlugin(id: string): Promise<void> {
  await invoke('remove_plugin', { id });
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
  const isTauri =
    typeof window !== 'undefined' &&
    Boolean((window as typeof window & { __TAURI_IPC__?: unknown }).__TAURI_IPC__);

  if (typeof window !== 'undefined' && !isTauri) {
    try {
      const base = import.meta.env.VITE_API_BASE_URL ?? window.location.origin;
      const url = new URL('/api/flows/stream', base);
      url.searchParams.set('streamId', streamId);
      if (options.filters) {
        url.searchParams.set('filters', JSON.stringify(options.filters));
      }

      const eventSource = new EventSource(url.toString(), { withCredentials: true });

      const handleMessage = (event: MessageEvent<string>) => {
        if (!event.data) {
          return;
        }
        try {
          const parsed = FlowEventSchema.parse(JSON.parse(event.data));
          onEvent(parsed);
        } catch (error) {
          console.warn('Failed to parse flow event payload from SSE', error);
        }
      };

      eventSource.addEventListener('message', handleMessage);
      eventSource.addEventListener('error', (error) => {
        console.warn('Flow SSE stream error', error);
      });

      return {
        close: async () => {
          eventSource.removeEventListener('message', handleMessage);
          eventSource.close();
        }
      } satisfies FlowStreamHandle;
    } catch (error) {
      console.warn('Falling back to native flow stream', error);
    }
  }

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

export async function fetchScopePolicy(): Promise<ScopePolicyDocument> {
  const response = await invoke('fetch_scope_policy');
  return ScopePolicyDocumentSchema.parse(response);
}

export async function validateScopePolicy(policy: string): Promise<ScopeValidationResult> {
  const response = await invoke('validate_scope_policy', { policy });
  return ScopeValidationResultSchema.parse(response);
}

export async function applyScopePolicy(policy: string): Promise<ScopeApplyResponse> {
  const response = await invoke('apply_scope_policy', { policy });
  return ScopeApplyResponseSchema.parse(response);
}

export async function parseScopeText(text: string): Promise<ScopeParseResponse> {
  const response = await invoke('parse_scope_text', { text });
  return ScopeParseResponseSchema.parse(response);
}

export async function dryRunScopePolicy(payload: {
  policy?: string;
  urls: string[];
}): Promise<ScopeDryRunResponse> {
  const response = await invoke('dry_run_scope_policy', payload);
  return ScopeDryRunResponseSchema.parse(response);
}

// Cipher API

const CipherPipelineOpSchema = z.object({
  name: z.string(),
  parameters: z.record(z.unknown()).optional()
});

const CipherOperationResultSchema = z.object({
  output: z.string().optional(),
  error: z.string().optional()
});

const CipherPipelineResultSchema = z.object({
  output: z.string().optional(),
  error: z.string().optional()
});

const CipherDetectionSchema = z.object({
  encoding: z.string(),
  confidence: z.number(),
  reasoning: z.string(),
  operation: z.string()
});

const CipherDetectResultSchema = z.object({
  detections: z.array(CipherDetectionSchema)
});

const CipherSmartDecodeResultSchema = z.object({
  output: z.string().optional(),
  pipeline: z.array(z.string()),
  confidence: z.number(),
  error: z.string().optional()
});

const CipherOperationInfoSchema = z.object({
  name: z.string(),
  type: z.string(),
  description: z.string(),
  reversible: z.boolean()
});

const CipherPipelineDataSchema = z.object({
  operations: z.array(CipherPipelineOpSchema),
  reversible: z.boolean().optional()
});

const CipherRecipeSchema = z.object({
  name: z.string(),
  description: z.string(),
  tags: z.array(z.string()),
  pipeline: CipherPipelineDataSchema,
  created_at: z.string().optional(),
  updated_at: z.string().optional()
}).transform((value) => ({
  name: value.name,
  description: value.description,
  tags: value.tags,
  pipeline: value.pipeline,
  createdAt: value.created_at ?? null,
  updatedAt: value.updated_at ?? null
}));

export type CipherPipelineOp = z.infer<typeof CipherPipelineOpSchema>;
export type CipherOperationResult = z.infer<typeof CipherOperationResultSchema>;
export type CipherPipelineResult = z.infer<typeof CipherPipelineResultSchema>;
export type CipherDetection = z.infer<typeof CipherDetectionSchema>;
export type CipherDetectResult = z.infer<typeof CipherDetectResultSchema>;
export type CipherSmartDecodeResult = z.infer<typeof CipherSmartDecodeResultSchema>;
export type CipherOperationInfo = z.infer<typeof CipherOperationInfoSchema>;
export type CipherRecipe = z.infer<typeof CipherRecipeSchema>;

export async function cipherExecute(
  operation: string,
  input: string,
  config?: Record<string, unknown>
): Promise<CipherOperationResult> {
  const response = await invoke('cipher_execute', { operation, input, config });
  return CipherOperationResultSchema.parse(response);
}

export async function cipherPipeline(
  input: string,
  operations: CipherPipelineOp[]
): Promise<CipherPipelineResult> {
  const response = await invoke('cipher_pipeline', { input, operations });
  return CipherPipelineResultSchema.parse(response);
}

export async function cipherDetect(input: string): Promise<CipherDetectResult> {
  const response = await invoke('cipher_detect', { input });
  return CipherDetectResultSchema.parse(response);
}

export async function cipherSmartDecode(input: string): Promise<CipherSmartDecodeResult> {
  const response = await invoke('cipher_smart_decode', { input });
  return CipherSmartDecodeResultSchema.parse(response);
}

export async function cipherListOperations(): Promise<CipherOperationInfo[]> {
  const response = await invoke('cipher_list_operations');
  return z.array(CipherOperationInfoSchema).parse(response);
}

export async function cipherSaveRecipe(
  name: string,
  description: string,
  tags: string[],
  operations: CipherPipelineOp[]
): Promise<void> {
  await invoke('cipher_save_recipe', { name, description, tags, operations });
}

export async function cipherListRecipes(): Promise<CipherRecipe[]> {
  const response = await invoke('cipher_list_recipes');
  return z.array(CipherRecipeSchema).parse(response);
}

export async function cipherLoadRecipe(name: string): Promise<CipherRecipe> {
  const response = await invoke('cipher_load_recipe', { name });
  return CipherRecipeSchema.parse(response);
}

export async function cipherDeleteRecipe(name: string): Promise<void> {
  await invoke('cipher_delete_recipe', { name });
}

// Entropy API

const TokenExtractorSchema = z.object({
  pattern: z.string(),
  location: z.string(),
  name: z.string()
});

const CaptureStatusSchema = z.enum(['active', 'paused', 'stopped']);

const StopReasonSchema = z.enum(['manual', 'target_reached', 'timeout', 'pattern_detected', 'error']);

const CaptureSessionSchema = z.object({
  id: z.number().int(),
  name: z.string(),
  extractor: TokenExtractorSchema,
  startedAt: timestampSchema,
  completedAt: timestampSchema.optional().nullable(),
  pausedAt: timestampSchema.optional().nullable(),
  tokenCount: z.number().int(),
  status: CaptureStatusSchema,
  targetCount: z.number().int().optional(),
  timeout: z.number().optional(),
  stopReason: StopReasonSchema.optional().nullable(),
  lastAnalyzedAt: timestampSchema.optional().nullable(),
  lastAnalysisCount: z.number().int(),
  analysisInterval: z.number().int()
});

const TestResultSchema = z.object({
  pValue: z.number(),
  passed: z.boolean(),
  confidence: z.number(),
  description: z.string()
});

const PatternSchema = z.object({
  type: z.string(),
  confidence: z.number(),
  description: z.string(),
  evidence: z.string()
});

const PRNGSignatureSchema = z.object({
  name: z.string(),
  weakness: z.string(),
  exploitHint: z.string(),
  confidence: z.number()
});

const RiskLevelSchema = z.enum(['low', 'medium', 'high', 'critical']);

const EntropyAnalysisSchema = z.object({
  captureSessionId: z.number().int(),
  tokenCount: z.number().int(),
  tokenLength: z.number().int(),
  characterSet: z.array(z.string()),
  chiSquared: TestResultSchema,
  runs: TestResultSchema,
  serialCorrelation: TestResultSchema,
  spectral: TestResultSchema,
  shannonEntropy: z.number(),
  collisionRate: z.number(),
  bitDistribution: z.array(z.number()),
  detectedPRNG: PRNGSignatureSchema.optional().nullable(),
  detectedPatterns: z.array(PatternSchema),
  recommendations: z.array(z.string()),
  randomnessScore: z.number(),
  risk: RiskLevelSchema,
  confidenceLevel: z.number(),
  reliabilityScore: z.number(),
  tokensNeeded: z.number().int(),
  sampleQuality: z.string()
});

const IncrementalStatsSchema = z.object({
  tokenCount: z.number().int(),
  charFrequency: z.record(z.number()),
  totalChars: z.number().int(),
  collisionCount: z.number().int(),
  currentEntropy: z.number(),
  minSampleSize: z.number().int(),
  confidenceLevel: z.number(),
  tokensNeeded: z.number().int(),
  reliabilityScore: z.number(),
  lastUpdated: timestampSchema
});

export type TokenExtractor = z.infer<typeof TokenExtractorSchema>;
export type CaptureStatus = z.infer<typeof CaptureStatusSchema>;
export type StopReason = z.infer<typeof StopReasonSchema>;
export type CaptureSession = z.infer<typeof CaptureSessionSchema>;
export type TestResult = z.infer<typeof TestResultSchema>;
export type Pattern = z.infer<typeof PatternSchema>;
export type PRNGSignature = z.infer<typeof PRNGSignatureSchema>;
export type RiskLevel = z.infer<typeof RiskLevelSchema>;
export type EntropyAnalysis = z.infer<typeof EntropyAnalysisSchema>;
export type IncrementalStats = z.infer<typeof IncrementalStatsSchema>;

export type StartEntropySessionPayload = {
  name: string;
  extractor: TokenExtractor;
  targetCount?: number;
  timeoutSeconds?: number;
};

export async function listEntropySessions(): Promise<CaptureSession[]> {
  const sessions = await invoke('list_entropy_sessions');
  return z.array(CaptureSessionSchema).parse(sessions);
}

export async function getEntropySession(id: number): Promise<CaptureSession> {
  const session = await invoke('get_entropy_session', { id });
  return CaptureSessionSchema.parse(session);
}

export async function startEntropySession(payload: StartEntropySessionPayload): Promise<CaptureSession> {
  const session = await invoke('start_entropy_session', { payload });
  return CaptureSessionSchema.parse(session);
}

export async function pauseEntropySession(id: number): Promise<void> {
  await invoke('pause_entropy_session', { id });
}

export async function resumeEntropySession(id: number): Promise<void> {
  await invoke('resume_entropy_session', { id });
}

export async function stopEntropySession(id: number): Promise<void> {
  await invoke('stop_entropy_session', { id });
}

export async function getEntropyAnalysis(sessionId: number): Promise<EntropyAnalysis | null> {
  const analysis = await invoke('get_entropy_analysis', { sessionId });
  if (!analysis) return null;
  return EntropyAnalysisSchema.parse(analysis);
}

export async function getIncrementalStats(sessionId: number): Promise<IncrementalStats | null> {
  const stats = await invoke('get_incremental_stats', { sessionId });
  if (!stats) return null;
  return IncrementalStatsSchema.parse(stats);
}

export async function exportEntropySession(sessionId: number, format: 'csv' | 'json'): Promise<string> {
  const result = await invoke('export_entropy_session', { sessionId, format });
  return z.string().parse(result);
}

const TokenSampleSchema = z.object({
  id: z.number().int(),
  captureSessionId: z.number().int(),
  tokenValue: z.string(),
  tokenLength: z.number().int(),
  capturedAt: timestampSchema,
  sourceRequestId: z.string().optional()
});

export type TokenSample = z.infer<typeof TokenSampleSchema>;

export async function getTokenSamples(sessionId: number, limit?: number): Promise<TokenSample[]> {
  const samples = await invoke('get_token_samples', { sessionId, limit });
  return z.array(TokenSampleSchema).parse(samples);
}

export type CompareSessionsPayload = {
  sessionIds: number[];
  baselineId?: number;
};

const SessionComparisonSchema = z.object({
  sessionId: z.number().int(),
  sessionName: z.string(),
  analysis: EntropyAnalysisSchema.nullable(),
  stats: IncrementalStatsSchema.nullable(),
  deltaFromBaseline: z
    .object({
      randomnessScoreDelta: z.number(),
      entropyDelta: z.number(),
      collisionRateDelta: z.number()
    })
    .nullable()
    .optional()
});

export type SessionComparison = z.infer<typeof SessionComparisonSchema>;

export async function compareSessions(sessionIds: number[]): Promise<SessionComparison[]> {
  const comparisons = await invoke('compare_entropy_sessions', { sessionIds });
  return z.array(SessionComparisonSchema).parse(comparisons);
}

export async function exportEntropyReport(
  sessionId: number,
  format: 'html' | 'markdown' | 'pdf'
): Promise<string> {
  const result = await invoke('export_entropy_report', { sessionId, format });
  return z.string().parse(result);
}

// Rewrite API

const RewriteScopeSchema = z.object({
  direction: z.string(),
  methods: z.array(z.string()).optional().default([]),
  urlPattern: z.string()
});

const RewriteConditionSchema = z.object({
  type: z.string(),
  location: z.string(),
  name: z.string(),
  operator: z.string(),
  value: z.string(),
  caseSensitive: z.boolean()
});

const RewriteActionSchema = z.object({
  type: z.string(),
  location: z.string(),
  name: z.string(),
  value: z.string()
});

const RewriteRuleSchema = z.object({
  id: z.number().int().optional(),
  name: z.string(),
  description: z.string(),
  enabled: z.boolean(),
  priority: z.number().int(),
  scope: RewriteScopeSchema,
  conditions: z.array(RewriteConditionSchema).optional().default([]),
  actions: z.array(RewriteActionSchema).optional().default([]),
  createdAt: timestampSchema.optional(),
  modifiedAt: timestampSchema.optional(),
  version: z.number().int().optional()
});

const RewriteTestRequestInputSchema = z.object({
  method: z.string(),
  url: z.string(),
  headers: z.record(z.string()),
  body: z.string()
});

const RewriteTestResponseInputSchema = z.object({
  statusCode: z.number().int(),
  headers: z.record(z.string()),
  body: z.string()
});

const RewriteHeaderDiffSchema = z.object({
  name: z.string(),
  oldValue: z.string(),
  newValue: z.string(),
  action: z.string()
});

const RewriteDiffResultSchema = z.object({
  headerChanges: z.array(RewriteHeaderDiffSchema),
  bodyChanged: z.boolean(),
  bodyDiff: z.string(),
  urlChanged: z.boolean(),
  urlDiff: z.string(),
  statusChanged: z.boolean(),
  oldStatus: z.number().int(),
  newStatus: z.number().int()
});

const RewriteActionResultSchema = z.object({
  actionType: z.string(),
  location: z.string(),
  name: z.string(),
  oldValue: z.string(),
  newValue: z.string(),
  success: z.boolean(),
  error: z.string().optional()
});

const RewriteExecutionStepSchema = z.object({
  ruleId: z.number().int(),
  ruleName: z.string(),
  priority: z.number().int(),
  matched: z.boolean(),
  matchReason: z.string(),
  actionsApplied: z.array(RewriteActionResultSchema),
  variables: z.record(z.string()),
  duration: z.number(),
  errors: z.array(z.string())
});

const RewriteExecutionLogSchema = z.object({
  steps: z.array(RewriteExecutionStepSchema),
  totalDuration: z.number(),
  rulesExecuted: z.number().int(),
  rulesMatched: z.number().int(),
  actionsApplied: z.number().int(),
  variables: z.record(z.string()),
  errors: z.array(z.string())
});

const RewriteValidationErrorSchema = z.object({
  ruleId: z.number().int(),
  ruleName: z.string(),
  severity: z.string(),
  type: z.string(),
  message: z.string(),
  suggestion: z.string(),
  location: z.string()
});

const RewriteSandboxResultSchema = z.object({
  success: z.boolean(),
  originalInput: z.unknown(),
  modifiedInput: z.unknown(),
  executionLog: RewriteExecutionLogSchema,
  diff: RewriteDiffResultSchema,
  warnings: z.array(RewriteValidationErrorSchema),
  duration: z.number()
});

const RewriteTestCaseSchema = z.object({
  id: z.number().int().optional(),
  name: z.string(),
  description: z.string(),
  type: z.string(),
  input: z.unknown(),
  expectedOutput: z.unknown().optional(),
  ruleIds: z.array(z.number().int()),
  tags: z.array(z.string()).optional().default([]),
  createdAt: timestampSchema.optional(),
  modifiedAt: timestampSchema.optional()
});

const RewriteTestResultSchema = z.object({
  testCaseId: z.number().int(),
  testCaseName: z.string(),
  passed: z.boolean(),
  failures: z.array(z.string()),
  sandboxResult: RewriteSandboxResultSchema.nullable(),
  duration: z.number()
});

const RewriteMetricsSchema = z.object({
  totalRequests: z.number().int(),
  totalResponses: z.number().int(),
  rulesApplied: z.number().int(),
  averageLatency: z.number(),
  slowRules: z.record(z.number())
});

export type RewriteScope = z.infer<typeof RewriteScopeSchema>;
export type RewriteCondition = z.infer<typeof RewriteConditionSchema>;
export type RewriteAction = z.infer<typeof RewriteActionSchema>;
export type RewriteRule = z.infer<typeof RewriteRuleSchema>;
export type RewriteTestRequestInput = z.infer<typeof RewriteTestRequestInputSchema>;
export type RewriteTestResponseInput = z.infer<typeof RewriteTestResponseInputSchema>;
export type RewriteHeaderDiff = z.infer<typeof RewriteHeaderDiffSchema>;
export type RewriteDiffResult = z.infer<typeof RewriteDiffResultSchema>;
export type RewriteActionResult = z.infer<typeof RewriteActionResultSchema>;
export type RewriteExecutionStep = z.infer<typeof RewriteExecutionStepSchema>;
export type RewriteExecutionLog = z.infer<typeof RewriteExecutionLogSchema>;
export type RewriteValidationError = z.infer<typeof RewriteValidationErrorSchema>;
export type RewriteSandboxResult = z.infer<typeof RewriteSandboxResultSchema>;
export type RewriteTestCase = z.infer<typeof RewriteTestCaseSchema>;
export type RewriteTestResult = z.infer<typeof RewriteTestResultSchema>;
export type RewriteMetrics = z.infer<typeof RewriteMetricsSchema>;

export async function listRewriteRules(): Promise<RewriteRule[]> {
  const response = await invoke('list_rewrite_rules');
  const data = z.object({ rules: z.array(RewriteRuleSchema) }).parse(response);
  return data.rules;
}

export async function createRewriteRule(rule: Omit<RewriteRule, 'id'>): Promise<RewriteRule> {
  const response = await invoke('create_rewrite_rule', { rule });
  const data = z.object({ rule: RewriteRuleSchema }).parse(response);
  return data.rule;
}

export async function getRewriteRule(id: number): Promise<RewriteRule> {
  const response = await invoke('get_rewrite_rule', { id });
  const data = z.object({ rule: RewriteRuleSchema }).parse(response);
  return data.rule;
}

export async function updateRewriteRule(id: number, rule: Omit<RewriteRule, 'id'>): Promise<RewriteRule> {
  const response = await invoke('update_rewrite_rule', { id, rule });
  const data = z.object({ rule: RewriteRuleSchema }).parse(response);
  return data.rule;
}

export async function deleteRewriteRule(id: number): Promise<void> {
  await invoke('delete_rewrite_rule', { id });
}

export async function importRewriteRules(rules: RewriteRule[]): Promise<number> {
  const response = await invoke('import_rewrite_rules', { rules });
  const data = z.object({ imported: z.number().int() }).parse(response);
  return data.imported;
}

export async function exportRewriteRules(): Promise<RewriteRule[]> {
  const response = await invoke('export_rewrite_rules');
  const data = z.object({ rules: z.array(RewriteRuleSchema) }).parse(response);
  return data.rules;
}

export async function testRewriteRequest(
  input: RewriteTestRequestInput,
  ruleIds: number[]
): Promise<RewriteSandboxResult> {
  const response = await invoke('test_rewrite_request', { input, ruleIds });
  return RewriteSandboxResultSchema.parse(response);
}

export async function testRewriteResponse(
  input: RewriteTestResponseInput,
  ruleIds: number[]
): Promise<RewriteSandboxResult> {
  const response = await invoke('test_rewrite_response', { input, ruleIds });
  return RewriteSandboxResultSchema.parse(response);
}

export async function listRewriteTestCases(): Promise<RewriteTestCase[]> {
  const response = await invoke('list_rewrite_test_cases');
  const data = z.object({ test_cases: z.array(RewriteTestCaseSchema) }).parse(response);
  return data.test_cases;
}

export async function createRewriteTestCase(testCase: Omit<RewriteTestCase, 'id'>): Promise<RewriteTestCase> {
  const response = await invoke('create_rewrite_test_case', { testCase });
  const data = z.object({ test_case: RewriteTestCaseSchema }).parse(response);
  return data.test_case;
}

export async function getRewriteTestCase(id: number): Promise<RewriteTestCase> {
  const response = await invoke('get_rewrite_test_case', { id });
  const data = z.object({ test_case: RewriteTestCaseSchema }).parse(response);
  return data.test_case;
}

export async function deleteRewriteTestCase(id: number): Promise<void> {
  await invoke('delete_rewrite_test_case', { id });
}

export async function runRewriteTestCase(id: number): Promise<RewriteTestResult> {
  const response = await invoke('run_rewrite_test_case', { id });
  return RewriteTestResultSchema.parse(response);
}

export async function runAllRewriteTestCases(): Promise<RewriteTestResult[]> {
  const response = await invoke('run_all_rewrite_test_cases');
  const data = z.object({ results: z.array(RewriteTestResultSchema) }).parse(response);
  return data.results;
}

export async function fetchRewriteMetrics(): Promise<RewriteMetrics> {
  const response = await invoke('fetch_rewrite_metrics');
  return RewriteMetricsSchema.parse(response);
}
