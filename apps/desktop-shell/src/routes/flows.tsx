import { DiffEditor } from '@monaco-editor/react';
import { createFileRoute } from '@tanstack/react-router';
import { useVirtualizer } from '@tanstack/react-virtual';
import {
  AlertTriangle,
  FileSignature,
  Filter,
  GitBranch,
  Link,
  RefreshCw,
  Search,
  Send,
  Shield,
  ShieldAlert,
  Timer
} from 'lucide-react';
import {
  Dispatch,
  SetStateAction,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  useTransition
} from 'react';
import { toast } from 'sonner';

import { Button } from '../components/ui/button';
import { RedactionNotice } from '../components/redaction-notice';
import {
  FlowEvent,
  FlowStreamHandle,
  ResendFlowMetadata,
  listFlows,
  resendFlow,
  streamFlowEvents
} from '../lib/ipc';
import { useArtifact } from '../providers/artifact-provider';
import { useCommandCenter } from '../providers/command-center';
import { cn, isRedactedValue } from '../lib/utils';
import { useDebouncedValue } from '../lib/use-debounced-value';

type HttpHeader = {
  name: string;
  value: string;
};

type ParsedHttpMessage = {
  startLine: string;
  headers: HttpHeader[];
  body: string;
  prettyBody?: string;
  format: 'json' | 'form' | 'text';
  contentType?: string;
  isBinary: boolean;
  isTruncated: boolean;
  size: number;
};

type FlowMessage = {
  timestamp: string;
  raw: string;
  parsed: ParsedHttpMessage | null;
  sanitizedRedacted?: boolean;
  rawBodySize?: number;
  rawBodyCaptured?: number;
};

type FlowAuditRecord = {
  entryId: string;
  signature: string;
  recordedAt?: string;
  actor?: string;
  action?: string;
  decision?: string;
};

type FlowEntry = {
  id: string;
  flowId: string;
  method?: string;
  path?: string;
  host?: string;
  url?: string;
  domain?: string;
  statusCode?: number;
  statusText?: string;
  tags: string[];
  pluginTags: string[];
  scope: string;
  updatedAt: string;
  request?: FlowMessage;
  response?: FlowMessage;
  requestSize?: number;
  responseSize?: number;
  requestBinary?: boolean;
  responseBinary?: boolean;
  requestTruncated?: boolean;
  responseTruncated?: boolean;
  requestRedacted?: boolean;
  responseRedacted?: boolean;
  durationMs?: number;
  searchText: string;
  parentFlowId?: string;
  childFlowIds: string[];
  cloneReason?: string;
  auditTrail: FlowAuditRecord[];
};

const ITEM_HEIGHT = 136;
const STREAM_ID = 'timeline';
const LARGE_BODY_THRESHOLD = 64 * 1024;
const MAX_FLOW_QUEUE = 1000;
const FLUSH_BATCH_SIZE = 250;
const MAX_FLOW_ENTRIES = 50000;

function decodeBase64(value: string | undefined | null): string {
  if (!value) {
    return '';
  }
  try {
    if (typeof globalThis.atob === 'function') {
      return globalThis.atob(value);
    }
  } catch {
    return value;
  }
  return value;
}

function normaliseScope(raw?: string | null): string {
  if (!raw) {
    return 'in-scope';
  }
  const value = raw.toLowerCase();
  if (value.includes('out')) {
    return 'out-of-scope';
  }
  return 'in-scope';
}

type FlowMetadataInfo = {
  parentFlowId?: string;
  childFlowIds: string[];
  cloneReason?: string;
  auditTrail: FlowAuditRecord[];
};

function extractString(value: unknown): string | undefined {
  if (typeof value === 'string') {
    return value;
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value.toString();
  }
  return undefined;
}

function toAuditRecord(value: unknown): FlowAuditRecord | null {
  if (!value || typeof value !== 'object') {
    return null;
  }
  const record = value as Record<string, unknown>;
  const entryId =
    extractString(record.entryId) ||
    extractString(record.id) ||
    extractString(record.auditId) ||
    extractString(record.referenceId);
  const signature =
    extractString(record.signature) ||
    extractString(record.signatureHex) ||
    extractString(record.signatureBase64) ||
    extractString(record.hash);
  if (!entryId || !signature) {
    return null;
  }
  const recordedAt =
    extractString(record.recordedAt) ||
    extractString(record.timestamp) ||
    extractString(record.createdAt) ||
    extractString(record.generatedAt);
  const actor = extractString(record.actor) || extractString(record.user) || extractString(record.issuedBy);
  const action =
    extractString(record.action) || extractString(record.eventType) || extractString(record.operation);
  const decision = extractString(record.decision) || extractString(record.outcome);

  return {
    entryId,
    signature,
    recordedAt,
    actor,
    action,
    decision
  } satisfies FlowAuditRecord;
}

function mergeAuditRecords(base: FlowAuditRecord[], incoming: FlowAuditRecord[]): FlowAuditRecord[] {
  const map = new Map<string, FlowAuditRecord>();

  for (const item of base) {
    map.set(item.entryId, item);
  }

  for (const next of incoming) {
    const existing = map.get(next.entryId);
    if (!existing) {
      map.set(next.entryId, next);
      continue;
    }
    map.set(next.entryId, {
      entryId: existing.entryId,
      signature: next.signature || existing.signature,
      recordedAt: next.recordedAt ?? existing.recordedAt,
      actor: next.actor ?? existing.actor,
      action: next.action ?? existing.action,
      decision: next.decision ?? existing.decision
    });
  }

  return Array.from(map.values()).sort((a, b) => {
    const aTime = a.recordedAt ? Date.parse(a.recordedAt) : 0;
    const bTime = b.recordedAt ? Date.parse(b.recordedAt) : 0;
    return bTime - aTime;
  });
}

function parseFlowMetadata(metadata: unknown): FlowMetadataInfo {
  if (!metadata || typeof metadata !== 'object') {
    return { childFlowIds: [], auditTrail: [] };
  }

  const record = metadata as Record<string, unknown>;
  const parentFlowId =
    extractString(record.parentFlowId) ||
    extractString(record.sourceFlowId) ||
    extractString(record.originalFlowId) ||
    extractString(record.resendOf) ||
    extractString(record.cloneOf) ||
    extractString(record.parentId);

  const childFlowIds: string[] = [];
  const singleChild =
    extractString(record.childFlowId) ||
    extractString(record.cloneFlowId) ||
    extractString(record.cloneId) ||
    extractString(record.childId);
  if (singleChild) {
    childFlowIds.push(singleChild);
  }

  const clones = record.clones;
  if (Array.isArray(clones)) {
    for (const value of clones) {
      const id = extractString(value);
      if (id) {
        childFlowIds.push(id);
      }
    }
  }

  const cloneReason =
    extractString(record.cloneReason) || extractString(record.reason) || extractString(record.actionReason);

  const auditTrail: FlowAuditRecord[] = [];
  const auditSources = [record.audit, record.auditEntry, record.auditTrail, record.auditLog];
  for (const source of auditSources) {
    if (!source) {
      continue;
    }
    if (Array.isArray(source)) {
      for (const item of source) {
        const parsed = toAuditRecord(item);
        if (parsed) {
          auditTrail.push(parsed);
        }
      }
    } else {
      const parsed = toAuditRecord(source);
      if (parsed) {
        auditTrail.push(parsed);
      }
    }
  }

  return {
    parentFlowId: parentFlowId || undefined,
    childFlowIds: Array.from(new Set(childFlowIds)),
    cloneReason: cloneReason || undefined,
    auditTrail: auditTrail.length > 0 ? mergeAuditRecords([], auditTrail) : []
  } satisfies FlowMetadataInfo;
}

function splitRawHttpMessage(raw: string) {
  const normalised = raw.replace(/\r\n/g, '\n');
  const separatorIndex = normalised.indexOf('\n\n');
  if (separatorIndex === -1) {
    return { headers: normalised, body: '' };
  }
  return {
    headers: normalised.slice(0, separatorIndex),
    body: normalised.slice(separatorIndex + 2)
  };
}

function buildHeaderSource(message: ParsedHttpMessage | null, fallback: string): string {
  if (message) {
    const headerLines = message.headers.map((header) => `${header.name}: ${header.value}`);
    return [message.startLine, ...headerLines].join('\n');
  }
  return splitRawHttpMessage(fallback).headers;
}

type BodySource = {
  text: string;
  language: string;
  isBinary: boolean;
};

function buildBodySource(message: ParsedHttpMessage | null, fallback: string): BodySource {
  if (message) {
    let language = 'plaintext';
    if (message.format === 'json') {
      language = 'json';
    }
    return {
      text: message.prettyBody ?? message.body ?? '',
      language,
      isBinary: message.isBinary
    };
  }
  const raw = splitRawHttpMessage(fallback).body;
  return {
    text: raw,
    language: 'plaintext',
    isBinary: /[\x00-\x08\x0B\x0C\x0E-\x1F]/.test(raw)
  };
}

function parseHttpMessage(raw: string): ParsedHttpMessage | null {
  if (!raw) {
    return null;
  }
  const normalised = raw.replace(/\r\n/g, '\n');
  const lines = normalised.split('\n');
  if (lines.length === 0) {
    return null;
  }
  const startLine = lines[0] ?? '';
  let separatorIndex = lines.indexOf('');
  if (separatorIndex === -1) {
    separatorIndex = lines.length;
  }
  const headerLines = lines.slice(1, separatorIndex);
  const bodyLines = lines.slice(separatorIndex + 1);
  const headers: HttpHeader[] = headerLines
    .map((line) => {
      const [name, ...rest] = line.split(':');
      const value = rest.join(':').trim();
      const trimmedName = name.trim();
      if (!trimmedName) {
        return null;
      }
      return { name: trimmedName, value };
    })
    .filter((header): header is HttpHeader => Boolean(header));
  const body = bodyLines.join('\n');
  const isBinary = /[\x00-\x08\x0B\x0C\x0E-\x1F]/.test(body);
  const contentLengthHeader = headers.find(
    (header) => header.name.toLowerCase() === 'content-length'
  );
  const size = (() => {
    if (!contentLengthHeader) {
      return body.length;
    }
    const parsed = Number.parseInt(contentLengthHeader.value, 10);
    if (Number.isNaN(parsed) || parsed < 0) {
      return body.length;
    }
    return parsed;
  })();
  const contentType = headers.find(
    (header) => header.name.toLowerCase() === 'content-type'
  )?.value;
  const isTruncated = headers.some((header) => {
    const key = header.name.toLowerCase();
    return (
      key === 'x-0xgen-body-redacted' ||
      key === 'x-0xgen-raw-body-truncated' ||
      key === 'x-0xgen-body-truncated'
    );
  });

  let prettyBody: string | undefined;
  let format: ParsedHttpMessage['format'] = 'text';

  if (!isBinary && body.trim()) {
    const lowerType = contentType?.toLowerCase() ?? '';
    if (lowerType.includes('json')) {
      try {
        prettyBody = JSON.stringify(JSON.parse(body), null, 2);
        format = 'json';
      } catch {
        prettyBody = undefined;
      }
    } else if (lowerType.includes('x-www-form-urlencoded')) {
      try {
        const params = new URLSearchParams(body);
        const entries: string[] = [];
        params.forEach((value, key) => {
          entries.push(`${key}=${value}`);
        });
        prettyBody = entries.join('\n');
        format = 'form';
      } catch {
        prettyBody = undefined;
      }
    }
  }

  return {
    startLine,
    headers,
    body,
    prettyBody,
    format,
    contentType,
    isBinary,
    isTruncated,
    size
  };
}

function extractRequestSummary(startLine: string, headers: HttpHeader[]) {
  const parts = startLine.trim().split(/\s+/);
  const method = parts[0]?.toUpperCase();
  let target = parts[1] ?? '';
  let host = headers.find((header) => header.name.toLowerCase() === 'host')?.value;

  if (target.startsWith('http://') || target.startsWith('https://')) {
    try {
      const url = new URL(target);
      host = url.host;
      target = url.pathname + url.search;
    } catch {
      // ignore parsing errors
    }
  } else if (target && !target.startsWith('/')) {
    target = `/${target}`;
  }

  const url = host ? `https://${host}${target || ''}` : undefined;

  return {
    method,
    path: target || undefined,
    host: host || undefined,
    url
  };
}

function extractResponseSummary(startLine: string) {
  const match = startLine.match(/^\S+\s+(\d{3})(?:\s+(.*))?$/);
  if (!match) {
    return { statusCode: undefined, statusText: undefined };
  }
  const statusCode = Number.parseInt(match[1], 10);
  const statusText = match[2]?.trim();
  return {
    statusCode: Number.isNaN(statusCode) ? undefined : statusCode,
    statusText: statusText && statusText.length > 0 ? statusText : undefined
  };
}

function computeDuration(start?: string, end?: string): number | undefined {
  if (!start || !end) {
    return undefined;
  }
  const startMs = new Date(start).getTime();
  const endMs = new Date(end).getTime();
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs)) {
    return undefined;
  }
  return Math.max(0, endMs - startMs);
}

function formatDuration(durationMs?: number) {
  if (!Number.isFinite(durationMs)) {
    return '—';
  }
  if (!durationMs || durationMs < 1) {
    return '<1 ms';
  }
  if (durationMs < 1000) {
    return `${Math.round(durationMs)} ms`;
  }
  if (durationMs < 60_000) {
    return `${(durationMs / 1000).toFixed(1)} s`;
  }
  return `${Math.round(durationMs / 1000)} s`;
}

function formatBytes(size?: number) {
  if (!Number.isFinite(size) || size === undefined) {
    return '—';
  }
  const units = ['B', 'KB', 'MB', 'GB'];
  let value = size;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  const display =
    value >= 10 || Math.abs(value - Math.round(value)) < 0.05
      ? Math.round(value).toString()
      : value.toFixed(1);
  return `${display} ${units[unitIndex]}`;
}

function formatTimestamp(timestamp: string) {
  const date = new Date(timestamp);
  if (!Number.isFinite(date.getTime())) {
    return '—';
  }
  return date.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
}

function buildSearchIndex(entry: FlowEntry): string {
  const parts: string[] = [];
  if (entry.method) {
    parts.push(entry.method);
  }
  if (entry.host) {
    parts.push(entry.host);
  }
  if (entry.path) {
    parts.push(entry.path);
  }
  if (entry.statusCode) {
    parts.push(entry.statusCode.toString());
  }
  if (entry.statusText) {
    parts.push(entry.statusText);
  }
  if (entry.tags.length > 0) {
    parts.push(entry.tags.join(' '));
  }
  if (entry.pluginTags.length > 0) {
    parts.push(entry.pluginTags.join(' '));
  }
  if (entry.request?.parsed?.body) {
    parts.push(entry.request.parsed.body);
  }
  if (entry.response?.parsed?.body) {
    parts.push(entry.response.parsed.body);
  }
  return parts.join(' ').toLowerCase();
}

function getMethodTone(method?: string) {
  switch ((method ?? '').toUpperCase()) {
    case 'GET':
      return 'bg-blue-500/10 text-blue-500';
    case 'POST':
      return 'bg-emerald-500/10 text-emerald-500';
    case 'PUT':
      return 'bg-amber-500/10 text-amber-500';
    case 'DELETE':
      return 'bg-red-500/10 text-red-500';
    case 'PATCH':
      return 'bg-purple-500/10 text-purple-500';
    default:
      return 'bg-muted text-muted-foreground';
  }
}

function getStatusTone(status?: number) {
  if (status === undefined) {
    return 'bg-muted text-muted-foreground';
  }
  if (status >= 500) {
    return 'bg-red-500/10 text-red-500';
  }
  if (status >= 400) {
    return 'bg-amber-500/10 text-amber-500';
  }
  if (status >= 300) {
    return 'bg-blue-500/10 text-blue-500';
  }
  if (status >= 200) {
    return 'bg-emerald-500/10 text-emerald-500';
  }
  return 'bg-muted text-muted-foreground';
}

function integrateFlowEvent(existing: FlowEntry | undefined, event: FlowEvent): FlowEntry {
  const baseId = event.id.replace(/:(request|response)$/i, '');
  const normalizedType = event.type.toUpperCase();
  const direction: 'request' | 'response' | 'unknown' = normalizedType.includes('REQUEST')
    ? 'request'
    : normalizedType.includes('RESPONSE')
      ? 'response'
      : 'unknown';

  const sanitized = event.sanitized ?? decodeBase64(event.sanitizedBase64);
  const raw = event.raw ?? decodeBase64(event.rawBase64);
  const messageText = sanitized || raw || '';
  const parsed = parseHttpMessage(messageText);

  const entry: FlowEntry = existing
    ? {
        ...existing,
        tags: [...existing.tags],
        pluginTags: [...existing.pluginTags],
        childFlowIds: [...existing.childFlowIds],
        auditTrail: [...existing.auditTrail],
        request: existing.request
          ? { ...existing.request, parsed: existing.request.parsed }
          : undefined,
        response: existing.response
          ? { ...existing.response, parsed: existing.response.parsed }
          : undefined
      }
    : {
        id: baseId,
        flowId: baseId,
        tags: [],
        pluginTags: [],
        scope: 'in-scope',
        updatedAt: event.timestamp,
        searchText: '',
        childFlowIds: [],
        auditTrail: []
      };

  const normalisedScope = normaliseScope(event.scope);
  entry.scope = normalisedScope;
  entry.updatedAt = event.timestamp;

  const tagSet = new Set(entry.tags);
  for (const tag of event.tags ?? []) {
    const trimmed = tag.trim();
    if (trimmed) {
      tagSet.add(trimmed);
    }
  }
  entry.tags = Array.from(tagSet).sort();

  const pluginTagSet = new Set(entry.pluginTags);
  for (const tag of event.pluginTags ?? []) {
    const trimmed = tag.trim();
    if (trimmed) {
      pluginTagSet.add(trimmed);
    }
  }
  entry.pluginTags = Array.from(pluginTagSet).sort();

  if (direction === 'request') {
    const summary = parsed ? extractRequestSummary(parsed.startLine, parsed.headers) : undefined;
    entry.method = summary?.method ?? entry.method;
    entry.path = summary?.path ?? entry.path;
    entry.host = summary?.host ?? entry.host;
    entry.url = summary?.url ?? entry.url;
    entry.domain = entry.host ? entry.host.toLowerCase().replace(/:\d+$/, '') : entry.domain;
    const rawBodySize = event.rawBodySize ?? entry.request?.rawBodySize;
    const rawBodyCaptured = event.rawBodyCaptured ?? entry.request?.rawBodyCaptured;
    const rawTruncated =
      typeof rawBodySize === 'number' &&
      typeof rawBodyCaptured === 'number' &&
      rawBodyCaptured >= 0 &&
      rawBodyCaptured < rawBodySize;

    entry.request = {
      timestamp: event.timestamp,
      raw: messageText,
      parsed,
      sanitizedRedacted: event.sanitizedRedacted ?? entry.request?.sanitizedRedacted,
      rawBodySize,
      rawBodyCaptured
    };
    entry.requestSize = parsed?.size ?? rawBodySize ?? entry.requestSize;
    entry.requestBinary = parsed?.isBinary ?? entry.requestBinary;
    entry.requestTruncated = Boolean(parsed?.isTruncated || rawTruncated);
    entry.requestRedacted = event.sanitizedRedacted ?? entry.requestRedacted;
  } else if (direction === 'response') {
    const summary = parsed ? extractResponseSummary(parsed.startLine) : undefined;
    entry.statusCode = summary?.statusCode ?? entry.statusCode;
    entry.statusText = summary?.statusText ?? entry.statusText;
    const rawBodySize = event.rawBodySize ?? entry.response?.rawBodySize;
    const rawBodyCaptured = event.rawBodyCaptured ?? entry.response?.rawBodyCaptured;
    const rawTruncated =
      typeof rawBodySize === 'number' &&
      typeof rawBodyCaptured === 'number' &&
      rawBodyCaptured >= 0 &&
      rawBodyCaptured < rawBodySize;

    entry.response = {
      timestamp: event.timestamp,
      raw: messageText,
      parsed,
      sanitizedRedacted: event.sanitizedRedacted ?? entry.response?.sanitizedRedacted,
      rawBodySize,
      rawBodyCaptured
    };
    entry.responseSize = parsed?.size ?? rawBodySize ?? entry.responseSize;
    entry.responseBinary = parsed?.isBinary ?? entry.responseBinary;
    entry.responseTruncated = Boolean(parsed?.isTruncated || rawTruncated);
    entry.responseRedacted = event.sanitizedRedacted ?? entry.responseRedacted;
  }

  const metadataInfo = parseFlowMetadata(event.metadata);
  if (metadataInfo.parentFlowId) {
    entry.parentFlowId = metadataInfo.parentFlowId;
  }
  if (metadataInfo.cloneReason) {
    entry.cloneReason = metadataInfo.cloneReason;
  }
  if (metadataInfo.childFlowIds.length > 0) {
    const existingChildren = new Set(entry.childFlowIds);
    for (const id of metadataInfo.childFlowIds) {
      existingChildren.add(id);
    }
    entry.childFlowIds = Array.from(existingChildren);
  }
  if (metadataInfo.auditTrail.length > 0) {
    entry.auditTrail = mergeAuditRecords(entry.auditTrail, metadataInfo.auditTrail);
  }

  entry.durationMs = computeDuration(entry.request?.timestamp, entry.response?.timestamp);
  entry.searchText = buildSearchIndex(entry);

  return entry;
}

function FlowListItem({
  flow,
  selected,
  onSelect
}: {
  flow: FlowEntry;
  selected: boolean;
  onSelect: () => void;
}) {
  const methodTone = getMethodTone(flow.method);
  const statusTone = getStatusTone(flow.statusCode);
  const statusLabel = flow.statusCode
    ? `${flow.statusCode}${flow.statusText ? ` ${flow.statusText}` : ''}`
    : 'Pending';
  return (
    <button
      type="button"
      onClick={onSelect}
      data-flow-id={flow.id}
      className={cn(
        'flex w-full flex-col justify-between rounded-lg border p-3 text-left transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2',
        selected
          ? 'border-primary bg-primary/10 shadow'
          : 'border-transparent hover:border-border hover:bg-muted/40'
      )}
      style={{ height: ITEM_HEIGHT - 12 }}
    >
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span>{formatTimestamp(flow.updatedAt)}</span>
        <span className="flex items-center gap-1">
          <Timer className="h-3 w-3" />
          {formatDuration(flow.durationMs)}
        </span>
      </div>
      <div className="mt-2 flex items-center gap-2">
        <span
          className={cn(
            'rounded-md px-2 py-0.5 text-xs font-semibold uppercase tracking-wide',
            methodTone
          )}
        >
          {flow.method ?? '—'}
        </span>
        <span className="truncate text-sm font-medium text-foreground">
          {flow.path ?? flow.url ?? flow.id}
        </span>
      </div>
      <div className="mt-2 flex items-center justify-between text-xs text-muted-foreground">
        <span className="truncate">{flow.host ?? 'Unknown host'}</span>
        <span
          className={cn(
            'rounded-full px-2 py-0.5 text-xs font-semibold uppercase',
            statusTone
          )}
        >
          {statusLabel}
        </span>
      </div>
      <div className="mt-3 flex items-center justify-between text-xs text-muted-foreground">
        <div className="flex items-center gap-3">
          <span>Req {formatBytes(flow.requestSize)}</span>
          <span>Res {formatBytes(flow.responseSize)}</span>
        </div>
        <div className="flex items-center gap-3">
          {(flow.requestTruncated || flow.responseTruncated) && (
            <span className="flex items-center gap-1 text-amber-500">
              <AlertTriangle className="h-3 w-3" /> Truncated
            </span>
          )}
          {(flow.requestRedacted || flow.responseRedacted) && (
            <span className="flex items-center gap-1 text-sky-500">
              <Shield className="h-3 w-3" /> Redacted
            </span>
          )}
        </div>
      </div>
    </button>
  );
}

function HttpMessageViewer({ message }: { message?: FlowMessage }) {
  const [mode, setMode] = useState<'pretty' | 'raw'>('pretty');
  const parsed = message?.parsed ?? null;
  const prettyAvailable = Boolean(parsed?.prettyBody && parsed.prettyBody !== parsed.body);

  useEffect(() => {
    if (prettyAvailable) {
      setMode('pretty');
    } else {
      setMode('raw');
    }
  }, [message?.raw, prettyAvailable]);

  if (!message) {
    return (
      <div className="mt-3 rounded-md border border-dashed border-border p-4 text-sm text-muted-foreground">
        Awaiting message…
      </div>
    );
  }

  const activeMode = mode === 'pretty' && prettyAvailable ? 'pretty' : 'raw';
  const body =
    activeMode === 'pretty'
      ? parsed?.prettyBody ?? parsed?.body ?? message.raw
      : parsed?.body ?? message.raw;
  const headerRedacted = parsed?.headers?.some((header) => isRedactedValue(header.value)) ?? false;
  const redacted =
    Boolean(message?.sanitizedRedacted) ||
    headerRedacted ||
    isRedactedValue(parsed?.body) ||
    isRedactedValue(parsed?.prettyBody) ||
    isRedactedValue(message?.raw);

  return (
    <div className="mt-3 space-y-3 rounded-md border border-border bg-card p-4">
      {redacted && (
        <RedactionNotice
          capability="CAP_FLOW_INSPECT_RAW"
          className="mb-2"
          message="Payload redacted by policy"
        />
      )}
      {parsed ? (
        <div className="space-y-2">
          <div className="font-mono text-sm text-primary">{parsed.startLine}</div>
          <div className="space-y-1 text-xs text-muted-foreground">
            {parsed.headers.map((header) => (
              <div key={`${header.name}:${header.value}`} className="flex gap-2">
                <span className="font-semibold text-foreground">{header.name}:</span>
                <span>{header.value}</span>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="text-sm text-muted-foreground">Message metadata unavailable.</div>
      )}
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={() => setMode('pretty')}
          className={cn(
            'rounded-md px-2 py-1 text-xs font-medium transition',
            activeMode === 'pretty'
              ? 'bg-primary text-primary-foreground'
              : 'bg-muted text-muted-foreground hover:bg-muted/80',
            !prettyAvailable && 'opacity-60'
          )}
          disabled={!prettyAvailable}
        >
          Pretty
        </button>
        <button
          type="button"
          onClick={() => setMode('raw')}
          className={cn(
            'rounded-md px-2 py-1 text-xs font-medium transition',
            activeMode === 'raw'
              ? 'bg-primary text-primary-foreground'
              : 'bg-muted text-muted-foreground hover:bg-muted/80'
          )}
        >
          Raw
        </button>
      </div>
      <pre className="max-h-80 overflow-auto rounded bg-muted px-3 py-2 text-xs font-mono leading-relaxed text-foreground">
        {body || '∅'}
      </pre>
    </div>
  );
}

function HttpDiffViewer({
  original,
  updated,
  originalParsed,
  updatedParsed
}: {
  original: string;
  updated: string;
  originalParsed: ParsedHttpMessage | null;
  updatedParsed: ParsedHttpMessage | null;
}) {
  const headerOriginal = useMemo(() => buildHeaderSource(originalParsed, original), [originalParsed, original]);
  const headerUpdated = useMemo(() => buildHeaderSource(updatedParsed, updated), [updatedParsed, updated]);
  const originalBody = useMemo(() => buildBodySource(originalParsed, original), [originalParsed, original]);
  const updatedBody = useMemo(() => buildBodySource(updatedParsed, updated), [updatedParsed, updated]);

  const bodyLanguage = useMemo(() => {
    if (originalBody.language === updatedBody.language) {
      return originalBody.language;
    }
    if (updatedBody.language !== 'plaintext') {
      return updatedBody.language;
    }
    return originalBody.language;
  }, [originalBody.language, updatedBody.language]);

  const isBinary = originalBody.isBinary || updatedBody.isBinary;

  const diffOptions = useMemo(
    () => ({
      readOnly: true,
      renderSideBySide: true,
      minimap: { enabled: false },
      scrollBeyondLastLine: false,
      renderIndicators: true,
      glyphMargin: false,
      automaticLayout: true,
      enableSplitViewResizing: false
    }),
    []
  );

  return (
    <div className="space-y-4">
      <div>
        <div className="mb-2 flex items-center justify-between text-xs font-semibold uppercase text-muted-foreground">
          <span>Request line &amp; headers</span>
        </div>
        <div className="overflow-hidden rounded-md border border-border">
          <DiffEditor
            original={headerOriginal}
            modified={headerUpdated}
            language="plaintext"
            options={diffOptions}
            height="220px"
          />
        </div>
      </div>
      <div>
        <div className="mb-2 flex items-center justify-between text-xs font-semibold uppercase text-muted-foreground">
          <span>Body</span>
          <span className="text-muted-foreground">
            {bodyLanguage === 'json' ? 'JSON' : 'Text'}
          </span>
        </div>
        {isBinary ? (
          <div className="rounded-md border border-border bg-card p-3 text-xs text-muted-foreground">
            Binary payload detected. Diff unavailable.
          </div>
        ) : (
          <div className="overflow-hidden rounded-md border border-border">
            <DiffEditor
              original={originalBody.text}
              modified={updatedBody.text}
              language={bodyLanguage || 'plaintext'}
              options={diffOptions}
              height="260px"
            />
          </div>
        )}
      </div>
    </div>
  );
}

function FilterGroup({
  title,
  options,
  selected,
  onToggle,
  emptyLabel
}: {
  title: string;
  options: string[];
  selected: string[];
  onToggle: (value: string) => void;
  emptyLabel?: string;
}) {
  if (options.length === 0) {
    return null;
  }
  return (
    <div>
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase text-muted-foreground">{title}</span>
        {selected.length > 0 && (
          <span className="text-xs text-primary">{selected.length}</span>
        )}
      </div>
      <div className="mt-2 space-y-1">
        {options.map((option) => {
          const id = `${title}-${option}`;
          const checked = selected.includes(option);
          return (
            <label
              key={option}
              htmlFor={id}
              className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1 text-sm hover:bg-muted/40"
            >
              <input
                id={id}
                type="checkbox"
                className="h-3 w-3 rounded border-border text-primary focus-visible:outline-none focus-visible:ring-0"
                checked={checked}
                onChange={() => onToggle(option)}
              />
              <span className="truncate">{option || emptyLabel || 'Unknown'}</span>
            </label>
          );
        })}
      </div>
    </div>
  );
}

function NumberFilterGroup({
  title,
  options,
  selected,
  onToggle
}: {
  title: string;
  options: number[];
  selected: number[];
  onToggle: (value: number) => void;
}) {
  if (options.length === 0) {
    return null;
  }
  return (
    <div>
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase text-muted-foreground">{title}</span>
        {selected.length > 0 && (
          <span className="text-xs text-primary">{selected.length}</span>
        )}
      </div>
      <div className="mt-2 space-y-1">
        {options.map((option) => {
          const id = `${title}-${option}`;
          const checked = selected.includes(option);
          return (
            <label
              key={option}
              htmlFor={id}
              className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1 text-sm hover:bg-muted/40"
            >
              <input
                id={id}
                type="checkbox"
                className="h-3 w-3 rounded border-border text-primary focus-visible:outline-none focus-visible:ring-0"
                checked={checked}
                onChange={() => onToggle(option)}
              />
              <span>{option}</span>
            </label>
          );
        })}
      </div>
    </div>
  );
}

function FlowsRouteComponent() {
  const [flowMap, setFlowMap] = useState<Map<string, FlowEntry>>(() => new Map());
  const [, startTransition] = useTransition();
  const flowsList = useMemo(() => {
    return Array.from(flowMap.values()).sort((a, b) => {
      const aTime = new Date(a.updatedAt).getTime();
      const bTime = new Date(b.updatedAt).getTime();
      return bTime - aTime;
    });
  }, [flowMap]);
  const [searchInput, setSearchInput] = useState('');
  const searchTerm = useDebouncedValue(searchInput, 200);
  const [methodFilter, setMethodFilter] = useState<string[]>([]);
  const [statusFilter, setStatusFilter] = useState<number[]>([]);
  const [domainFilter, setDomainFilter] = useState<string[]>([]);
  const [scopeFilter, setScopeFilter] = useState<string[]>([]);
  const [tagFilter, setTagFilter] = useState<string[]>([]);
  const [pluginTagFilter, setPluginTagFilter] = useState<string[]>([]);
  const [selectedFlowId, setSelectedFlowId] = useState<string | null>(null);
  const [initialLoading, setInitialLoading] = useState(true);
  const [cursor, setCursor] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [editingFlow, setEditingFlow] = useState<FlowEntry | null>(null);
  const [editDraft, setEditDraft] = useState('');
  const [editConfirmed, setEditConfirmed] = useState(false);
  const [showDiff, setShowDiff] = useState(true);
  const [isSubmittingEdit, setIsSubmittingEdit] = useState(false);
  const filterSearchRef = useRef<HTMLInputElement | null>(null);
  const listRef = useRef<HTMLDivElement | null>(null);
  const detailPanelRef = useRef<HTMLDivElement | null>(null);
  const eventQueueRef = useRef<FlowEvent[]>([]);
  const flushTimeoutRef = useRef<number | null>(null);
  const statsAnimationFrameRef = useRef<number | null>(null);
  const streamStatsRef = useRef({ queued: 0, dropped: 0 });
  const [streamStats, setStreamStats] = useState(streamStatsRef.current);
  const { status } = useArtifact();
  const { registerCommand } = useCommandCenter();
  const offlineMode = Boolean(status?.loaded);
  const artifactKey = `${status?.manifest?.flowsFile ?? ''}:${status?.flowCount ?? 0}`;
  const editingEnabled = !offlineMode;

  const scheduleStreamStatsUpdate = useCallback(() => {
    if (typeof window === 'undefined') {
      return;
    }
    if (statsAnimationFrameRef.current !== null) {
      return;
    }
    statsAnimationFrameRef.current = window.requestAnimationFrame(() => {
      statsAnimationFrameRef.current = null;
      startTransition(() => {
        setStreamStats({ ...streamStatsRef.current });
      });
    });
  }, [startTransition]);

  const updateQueuedLength = useCallback(
    (value: number) => {
      if (streamStatsRef.current.queued === value) {
        return;
      }
      streamStatsRef.current.queued = value;
      scheduleStreamStatsUpdate();
    },
    [scheduleStreamStatsUpdate]
  );

  const incrementDropped = useCallback(
    (value: number) => {
      if (value <= 0) {
        return;
      }
      streamStatsRef.current.dropped += value;
      scheduleStreamStatsUpdate();
    },
    [scheduleStreamStatsUpdate]
  );

  useEffect(() => {
    const cleanups = [
      registerCommand({
        id: 'flows.focusFilters',
        title: 'Focus flow filters',
        description: 'Jump to the filter search field',
        group: 'Flows',
        shortcut: 'alt+1',
        run: () => {
          if (filterSearchRef.current) {
            filterSearchRef.current.focus();
            filterSearchRef.current.select?.();
          }
        },
        allowInInput: true
      }),
      registerCommand({
        id: 'flows.focusList',
        title: 'Focus flow list',
        description: 'Move focus to the flow timeline',
        group: 'Flows',
        shortcut: 'alt+2',
        run: () => {
          const container = listRef.current;
          if (!container) {
            return;
          }
          const selector = selectedFlowId ? `[data-flow-id="${selectedFlowId}"]` : '[data-flow-id]';
          const target = container.querySelector<HTMLButtonElement>(selector);
          if (target) {
            target.focus();
          } else {
            container.focus();
          }
        },
        allowInInput: true
      }),
      registerCommand({
        id: 'flows.focusDetails',
        title: 'Focus flow details',
        description: 'Jump to the detailed view of the selected flow',
        group: 'Flows',
        shortcut: 'alt+3',
        run: () => {
          detailPanelRef.current?.focus();
        },
        allowInInput: true
      })
    ];

    return () => {
      for (const cleanup of cleanups) {
        cleanup();
      }
    };
  }, [registerCommand, selectedFlowId]);

  useEffect(() => {
    setFlowMap(new Map());
    setCursor(null);
    setHasMore(false);
    streamStatsRef.current = { queued: 0, dropped: 0 };
    setStreamStats(streamStatsRef.current);
    setSearchInput('');
  }, [artifactKey]);

  const applyBatch = useCallback(
    (items: FlowEvent[]) => {
      setFlowMap((previous) => {
        const next = new Map(previous);
        for (const item of items) {
          const flowId = item.id.replace(/:(request|response)$/i, '');
          const existing = next.get(flowId);
          const updated = integrateFlowEvent(existing, item);
          next.set(flowId, updated);

          if (updated.parentFlowId) {
            const parent = next.get(updated.parentFlowId);
            if (parent) {
              const cloneSet = new Set(parent.childFlowIds);
              cloneSet.add(updated.id);
              const mergedAudit =
                updated.auditTrail.length > 0
                  ? mergeAuditRecords(parent.auditTrail, updated.auditTrail)
                  : parent.auditTrail;
              next.set(updated.parentFlowId, {
                ...parent,
                childFlowIds: Array.from(cloneSet),
                auditTrail: mergedAudit
              });
            }
          }

          if (updated.childFlowIds.length > 0) {
            for (const childId of updated.childFlowIds) {
              const child = next.get(childId);
              if (!child) {
                continue;
              }
              const mergedAudit =
                updated.auditTrail.length > 0
                  ? mergeAuditRecords(child.auditTrail, updated.auditTrail)
                  : child.auditTrail;
              next.set(childId, {
                ...child,
                parentFlowId: child.parentFlowId ?? updated.id,
                auditTrail: mergedAudit
              });
            }
          }
        }

        if (next.size > MAX_FLOW_ENTRIES) {
          const overflow = next.size - MAX_FLOW_ENTRIES;
          const entries = Array.from(next.entries()).sort((a, b) => {
            const aTime = new Date(a[1].updatedAt).getTime();
            const bTime = new Date(b[1].updatedAt).getTime();
            return aTime - bTime;
          });
          for (let index = 0; index < overflow; index += 1) {
            const [key] = entries[index];
            next.delete(key);
          }
          incrementDropped(overflow);
        }

        return next;
      });
    },
    [incrementDropped]
  );

  const commitBatch = useCallback(
    (items: FlowEvent[]) => {
      if (items.length === 0) {
        return;
      }
      startTransition(() => {
        applyBatch(items);
      });
    },
    [applyBatch, startTransition]
  );

  const flushPendingEvents = useCallback(() => {
    if (eventQueueRef.current.length === 0) {
      return;
    }
    const batch = eventQueueRef.current.splice(0, eventQueueRef.current.length);
    updateQueuedLength(eventQueueRef.current.length);
    commitBatch(batch);
  }, [commitBatch, updateQueuedLength]);

  const scheduleFlush = useCallback(() => {
    if (flushTimeoutRef.current !== null) {
      return;
    }
    flushTimeoutRef.current = window.setTimeout(() => {
      flushTimeoutRef.current = null;
      flushPendingEvents();
    }, 16);
  }, [flushPendingEvents]);

  useEffect(() => {
    let cancelled = false;
    setInitialLoading(true);
    listFlows({ limit: 200 })
      .then((page) => {
        if (cancelled) {
          return;
        }
        commitBatch(page.items);
        setCursor(page.nextCursor ?? null);
        setHasMore(Boolean(page.nextCursor));
      })
      .catch((error) => {
        console.error('Failed to load flows', error);
        toast.error('Unable to load captured flows');
      })
      .finally(() => {
        if (!cancelled) {
          setInitialLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [commitBatch, artifactKey]);

  useEffect(() => {
    if (offlineMode) {
      return;
    }

    let cancelled = false;
    let handle: FlowStreamHandle | undefined;

    streamFlowEvents(
      STREAM_ID,
      (event) => {
        if (!cancelled) {
          const queue = eventQueueRef.current;
          if (queue.length >= MAX_FLOW_QUEUE) {
            queue.shift();
            incrementDropped(1);
          }
          queue.push(event);
          updateQueuedLength(queue.length);
          if (queue.length >= FLUSH_BATCH_SIZE) {
            flushPendingEvents();
          } else {
            scheduleFlush();
          }
        }
      }
    )
      .then((value) => {
        if (cancelled) {
          void value.close();
          return;
        }
        handle = value;
      })
      .catch((error) => {
        console.error('Failed to stream flow events', error);
        toast.error('Unable to subscribe to live flow updates');
      });

    return () => {
      cancelled = true;
      if (handle) {
        handle
          .close()
          .catch((error) => console.warn('Failed to close flow stream', error));
      }
      if (flushTimeoutRef.current !== null) {
        window.clearTimeout(flushTimeoutRef.current);
        flushTimeoutRef.current = null;
      }
      if (statsAnimationFrameRef.current !== null && typeof window !== 'undefined') {
        window.cancelAnimationFrame(statsAnimationFrameRef.current);
        statsAnimationFrameRef.current = null;
      }
      eventQueueRef.current = [];
      updateQueuedLength(0);
    };
  }, [
    flushPendingEvents,
    scheduleFlush,
    offlineMode,
    incrementDropped,
    updateQueuedLength
  ]);

  const methodOptions = useMemo(() => {
    return Array.from(
      new Set(
        flowsList
          .map((flow) => flow.method)
          .filter((value): value is string => Boolean(value))
      )
    ).sort();
  }, [flowsList]);

  const statusOptions = useMemo(() => {
    return Array.from(
      new Set(
        flowsList
          .map((flow) => flow.statusCode)
          .filter((value): value is number => typeof value === 'number')
      )
    ).sort((a, b) => a - b);
  }, [flowsList]);

  const domainOptions = useMemo(() => {
    return Array.from(
      new Set(
        flowsList
          .map((flow) => flow.domain ?? flow.host)
          .filter((value): value is string => Boolean(value))
      )
    ).sort();
  }, [flowsList]);

  const scopeOptions = useMemo(() => {
    return Array.from(new Set(flowsList.map((flow) => flow.scope))).sort();
  }, [flowsList]);

  const tagOptions = useMemo(() => {
    const all = new Set<string>();
    for (const flow of flowsList) {
      for (const tag of flow.tags) {
        all.add(tag);
      }
    }
    return Array.from(all).sort();
  }, [flowsList]);

  const pluginTagOptions = useMemo(() => {
    const all = new Set<string>();
    for (const flow of flowsList) {
      for (const tag of flow.pluginTags) {
        all.add(tag);
      }
    }
    return Array.from(all).sort();
  }, [flowsList]);

  const filteredFlows = useMemo(() => {
    const term = searchTerm.trim().toLowerCase();
    return flowsList.filter((flow) => {
      if (term && !flow.searchText.includes(term)) {
        return false;
      }
      if (methodFilter.length > 0) {
        if (!flow.method || !methodFilter.includes(flow.method)) {
          return false;
        }
      }
      if (statusFilter.length > 0) {
        if (!flow.statusCode || !statusFilter.includes(flow.statusCode)) {
          return false;
        }
      }
      if (domainFilter.length > 0) {
        const domain = flow.domain ?? flow.host ?? '';
        if (!domain || !domainFilter.includes(domain)) {
          return false;
        }
      }
      if (scopeFilter.length > 0 && !scopeFilter.includes(flow.scope)) {
        return false;
      }
      if (tagFilter.length > 0) {
        if (!flow.tags.some((tag) => tagFilter.includes(tag))) {
          return false;
        }
      }
      if (pluginTagFilter.length > 0) {
        if (!flow.pluginTags.some((tag) => pluginTagFilter.includes(tag))) {
          return false;
        }
      }
      return true;
    });
  }, [
    flowsList,
    searchTerm,
    methodFilter,
    statusFilter,
    domainFilter,
    scopeFilter,
    tagFilter,
    pluginTagFilter
  ]);

  useEffect(() => {
    if (filteredFlows.length === 0) {
      return;
    }
    if (!selectedFlowId || !filteredFlows.some((flow) => flow.id === selectedFlowId)) {
      setSelectedFlowId(filteredFlows[0].id);
    }
  }, [filteredFlows, selectedFlowId]);

  const selectedFlow = useMemo(() => {
    if (!selectedFlowId) {
      return null;
    }
    return flowsList.find((flow) => flow.id === selectedFlowId) ?? null;
  }, [flowsList, selectedFlowId]);

  const timelineVirtualizer = useVirtualizer({
    count: filteredFlows.length,
    getScrollElement: () => listRef.current,
    estimateSize: () => ITEM_HEIGHT,
    overscan: 12
  });
  const virtualFlows = timelineVirtualizer.getVirtualItems();

  const editAnalysis = useMemo(() => {
    if (!editingFlow) {
      return {
        originalParsed: null,
        updatedParsed: null as ParsedHttpMessage | null,
        originalSummary: undefined as ReturnType<typeof extractRequestSummary> | undefined,
        updatedSummary: undefined as ReturnType<typeof extractRequestSummary> | undefined,
        guardErrors: [] as string[],
        guardWarnings: [] as string[]
      };
    }

    const originalRaw = editingFlow.request?.raw ?? '';
    const originalParsed = editingFlow.request?.parsed ?? parseHttpMessage(originalRaw);
    const updatedParsed = parseHttpMessage(editDraft);
    const originalSummary = originalParsed
      ? extractRequestSummary(originalParsed.startLine, originalParsed.headers)
      : undefined;
    const updatedSummary = updatedParsed
      ? extractRequestSummary(updatedParsed.startLine, updatedParsed.headers)
      : undefined;

    const guardErrors: string[] = [];
    const guardWarnings: string[] = [];

    if (editingFlow.scope === 'out-of-scope') {
      guardErrors.push('Scope policy denies resending out-of-scope requests.');
    }

    if (isRedactedValue(editDraft)) {
      guardErrors.push('Request contains redacted placeholders. Remove or replace them before resending.');
    }

    const originalMethod = originalSummary?.method;
    const updatedMethod = updatedSummary?.method;

    if (originalMethod || updatedMethod) {
      if (!originalMethod && updatedMethod) {
        guardWarnings.push(`HTTP method added (${updatedMethod}).`);
      } else if (originalMethod && !updatedMethod) {
        guardWarnings.push('HTTP method removed from the request line.');
      } else if (originalMethod && updatedMethod && originalMethod !== updatedMethod) {
        guardWarnings.push(`HTTP method changed from ${originalMethod} to ${updatedMethod}.`);
      }
    }

    const originalHost = originalSummary?.host?.toLowerCase();
    const updatedHost = updatedSummary?.host?.toLowerCase();

    if (originalHost || updatedHost) {
      if (!originalHost && updatedHost) {
        guardWarnings.push(`Host header added (${updatedSummary?.host}).`);
      } else if (originalHost && !updatedHost) {
        guardWarnings.push('Host header removed from the request.');
      } else if (originalHost && updatedHost && originalHost !== updatedHost) {
        guardWarnings.push(`Host header changed from ${originalSummary?.host} to ${updatedSummary?.host}.`);
      }
    }

    return {
      originalParsed: originalParsed ?? null,
      updatedParsed,
      originalSummary,
      updatedSummary,
      guardErrors,
      guardWarnings
    };
  }, [editDraft, editingFlow]);

  const hasGuardErrors = editAnalysis.guardErrors.length > 0;

  const clearFilters = () => {
    startTransition(() => {
      setMethodFilter([]);
      setStatusFilter([]);
      setDomainFilter([]);
      setScopeFilter([]);
      setTagFilter([]);
      setPluginTagFilter([]);
    });
    setSearchInput('');
  };

  const toggleFilter = useCallback(
    <Value,>(value: Value, setter: Dispatch<SetStateAction<Value[]>>) => {
      startTransition(() => {
        setter((previous) => {
          const exists = previous.includes(value);
          if (exists) {
            return previous.filter((item) => item !== value);
          }
          return [...previous, value];
        });
      });
    },
    [startTransition]
  );

  const loadMore = async () => {
    if (!cursor) {
      return;
    }
    try {
      setIsLoadingMore(true);
      const page = await listFlows({ cursor, limit: 200 });
      commitBatch(page.items);
      setCursor(page.nextCursor ?? null);
      setHasMore(Boolean(page.nextCursor));
    } catch (error) {
      console.error('Failed to load additional flows', error);
      toast.error('Unable to load additional flows');
    } finally {
      setIsLoadingMore(false);
    }
  };

  const beginEdit = (flow: FlowEntry) => {
    if (!editingEnabled) {
      toast.info('Editing is disabled while viewing replay artifacts');
      return;
    }
    if (!flow.request) {
      toast.error('Original request payload unavailable for editing');
      return;
    }
    if (flow.requestRedacted) {
      toast.info('Request payload redacted by policy. CAP_FLOW_INSPECT_RAW reveals raw content.');
      return;
    }
    setEditingFlow(flow);
    setEditDraft(flow.request.raw);
    setEditConfirmed(false);
    setShowDiff(true);
  };

  const submitEdit = async () => {
    if (!editingEnabled) {
      toast.info('Editing is disabled while viewing replay artifacts');
      return;
    }
    if (!editingFlow) {
      return;
    }
    if (!editConfirmed) {
      return;
    }
    if (hasGuardErrors) {
      toast.error(editAnalysis.guardErrors[0] ?? 'Request blocked by guardrails');
      return;
    }
    try {
      setIsSubmittingEdit(true);
      const response = await resendFlow(editingFlow.id, editDraft);
      const metadata = parseFlowMetadata(response.metadata as ResendFlowMetadata);
      const parentId = metadata.parentFlowId ?? editingFlow.id;

      setFlowMap((previous) => {
        const next = new Map(previous);
        const parent = next.get(parentId);
        if (parent) {
          const cloneSet = new Set(parent.childFlowIds);
          cloneSet.add(response.flowId);
          const updatedParent: FlowEntry = {
            ...parent,
            childFlowIds: Array.from(cloneSet)
          };
          if (metadata.cloneReason) {
            updatedParent.cloneReason = metadata.cloneReason;
          }
          if (metadata.auditTrail.length > 0) {
            updatedParent.auditTrail = mergeAuditRecords(parent.auditTrail, metadata.auditTrail);
          }
          next.set(parentId, updatedParent);
        }

        const existingChild = next.get(response.flowId);
        const childEntry: FlowEntry = existingChild
          ? { ...existingChild }
          : {
              id: response.flowId,
              flowId: response.flowId,
              tags: [],
              pluginTags: [],
              scope: parent?.scope ?? 'in-scope',
              updatedAt: new Date().toISOString(),
              searchText: '',
              childFlowIds: [],
              auditTrail: []
            };
        childEntry.parentFlowId = parentId;
        if (metadata.cloneReason) {
          childEntry.cloneReason = metadata.cloneReason;
        }
        if (metadata.childFlowIds.length > 0) {
          const set = new Set(childEntry.childFlowIds);
          for (const id of metadata.childFlowIds) {
            set.add(id);
          }
          childEntry.childFlowIds = Array.from(set);
        }
        if (metadata.auditTrail.length > 0) {
          childEntry.auditTrail = mergeAuditRecords(childEntry.auditTrail, metadata.auditTrail);
        }
        next.set(response.flowId, childEntry);

        return next;
      });

      setSelectedFlowId(response.flowId);
      toast.success('Modified request dispatched');
      setEditingFlow(null);
      setEditDraft('');
      setEditConfirmed(false);
    } catch (error) {
      console.error('Failed to resend flow', error);
      toast.error('Unable to resend modified request');
    } finally {
      setIsSubmittingEdit(false);
    }
  };

  return (
    <div className="flex h-full min-h-0">
      <aside className="w-72 border-r border-border bg-card px-4 py-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold uppercase text-muted-foreground">Filters</h2>
          <Button variant="ghost" size="sm" onClick={clearFilters} className="h-auto px-2 py-1 text-xs">
            Clear
          </Button>
        </div>
        <div className="mt-4 space-y-4">
          <div>
            <label className="text-xs font-semibold uppercase text-muted-foreground" htmlFor="flow-search">
              Search
            </label>
            <div className="relative mt-2">
              <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
              <input
                id="flow-search"
                type="search"
                ref={filterSearchRef}
                value={searchInput}
                onChange={(event) => setSearchInput(event.target.value)}
                placeholder="Method, URL, body…"
                className="w-full rounded-md border border-border bg-background py-2 pl-9 pr-3 text-sm text-foreground placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
              />
            </div>
          </div>
          <FilterGroup
            title="Methods"
            options={methodOptions}
            selected={methodFilter}
            onToggle={(value) => toggleFilter(value, setMethodFilter)}
          />
          <NumberFilterGroup
            title="Status"
            options={statusOptions}
            selected={statusFilter}
            onToggle={(value) => toggleFilter(value, setStatusFilter)}
          />
          <FilterGroup
            title="Domains"
            options={domainOptions}
            selected={domainFilter}
            onToggle={(value) => toggleFilter(value, setDomainFilter)}
            emptyLabel="Unknown domain"
          />
          <FilterGroup
            title="Scope"
            options={scopeOptions}
            selected={scopeFilter}
            onToggle={(value) => toggleFilter(value, setScopeFilter)}
          />
          <FilterGroup
            title="Tags"
            options={tagOptions}
            selected={tagFilter}
            onToggle={(value) => toggleFilter(value, setTagFilter)}
          />
          <FilterGroup
            title="Plugin tags"
            options={pluginTagOptions}
            selected={pluginTagFilter}
            onToggle={(value) => toggleFilter(value, setPluginTagFilter)}
          />
        </div>
      </aside>
      <section className="flex min-h-0 flex-1">
        <div className="flex w-[420px] min-w-[320px] flex-col border-r border-border">
          <div className="border-b border-border px-4 py-3">
            <h1 className="text-lg font-semibold text-foreground">Flow timeline</h1>
            <p className="text-sm text-muted-foreground">
              Real-time intercepted requests and responses with live updates.
            </p>
            <div className="mt-2 flex items-center justify-between text-xs text-muted-foreground">
              <span>Queued {streamStats.queued.toLocaleString()}</span>
              <span
                className={cn(
                  'flex items-center gap-1',
                  streamStats.dropped > 0 ? 'text-amber-600' : undefined
                )}
              >
                {streamStats.dropped > 0 && <AlertTriangle className="h-3 w-3" />}
                Dropped {streamStats.dropped.toLocaleString()}
              </span>
            </div>
          </div>
          <div
            ref={listRef}
            className="flex-1 overflow-y-auto px-3 py-2"
            role="region"
            aria-label="Flow timeline"
            tabIndex={-1}
          >
            {initialLoading && filteredFlows.length === 0 ? (
              <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
                <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> Loading flows…
              </div>
            ) : filteredFlows.length === 0 ? (
              <div className="flex h-full items-center justify-center px-4 text-center text-sm text-muted-foreground">
                No flows match the current filters.
              </div>
            ) : (
              <div
                style={{ height: `${timelineVirtualizer.getTotalSize()}px`, position: 'relative' }}
              >
                {virtualFlows.map((virtualFlow) => {
                  const flow = filteredFlows[virtualFlow.index];
                  if (!flow) {
                    return null;
                  }
                  return (
                    <div
                      key={virtualFlow.key}
                      data-index={virtualFlow.index}
                      ref={timelineVirtualizer.measureElement}
                      className="pb-2"
                      style={{
                        position: 'absolute',
                        top: 0,
                        left: 0,
                        right: 0,
                        transform: `translateY(${virtualFlow.start}px)`
                      }}
                    >
                      <FlowListItem
                        flow={flow}
                        selected={flow.id === selectedFlowId}
                        onSelect={() => setSelectedFlowId(flow.id)}
                      />
                    </div>
                  );
                })}
              </div>
            )}
          </div>
          {hasMore && (
            <div className="border-t border-border p-3">
              <Button
                variant="outline"
                className="w-full"
                onClick={loadMore}
                disabled={isLoadingMore || !cursor}
              >
                <RefreshCw className={cn('mr-2 h-4 w-4', isLoadingMore && 'animate-spin')} />
                {isLoadingMore ? 'Loading…' : 'Load more'}
              </Button>
            </div>
          )}
        </div>
        <div
          ref={detailPanelRef}
          className="flex min-w-0 flex-1 flex-col"
          tabIndex={-1}
          role="region"
          aria-label="Flow details"
        >
          {selectedFlow ? (
            <div className="flex min-h-0 flex-1 flex-col">
              <div className="border-b border-border px-6 py-4">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-3">
                      <span
                        className={cn(
                          'rounded-md px-2 py-0.5 text-xs font-semibold uppercase tracking-wide',
                          getMethodTone(selectedFlow.method)
                        )}
                      >
                        {selectedFlow.method ?? '—'}
                      </span>
                      <h2 className="truncate text-xl font-semibold text-foreground">
                        {selectedFlow.path ?? selectedFlow.url ?? selectedFlow.id}
                      </h2>
                    </div>
                    <div className="mt-2 flex flex-wrap items-center gap-3 text-sm text-muted-foreground">
                      <span>{selectedFlow.host ?? 'Unknown host'}</span>
                      <span className={cn(
                        'rounded-full px-2 py-0.5 text-xs font-semibold uppercase',
                        getStatusTone(selectedFlow.statusCode)
                      )}>
                        {selectedFlow.statusCode
                          ? `${selectedFlow.statusCode}${
                              selectedFlow.statusText ? ` ${selectedFlow.statusText}` : ''
                            }`
                          : 'Awaiting response'}
                      </span>
                      <span className={cn(
                        'rounded-full px-2 py-0.5 text-xs font-semibold uppercase',
                        selectedFlow.scope === 'out-of-scope'
                          ? 'bg-amber-500/10 text-amber-500'
                          : 'bg-emerald-500/10 text-emerald-500'
                      )}>
                        {selectedFlow.scope.replace('-', ' ')}
                      </span>
                      <span className="flex items-center gap-1">
                        <Timer className="h-4 w-4" /> {formatDuration(selectedFlow.durationMs)}
                      </span>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2 text-xs text-muted-foreground">
                      {selectedFlow.tags.map((tag) => (
                        <span key={tag} className="rounded-full bg-muted px-2 py-0.5">
                          #{tag}
                        </span>
                      ))}
                      {selectedFlow.pluginTags.map((tag) => (
                        <span key={`plugin-${tag}`} className="rounded-full bg-muted/60 px-2 py-0.5">
                          Plugin:{' '}
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div className="flex flex-col items-end gap-3">
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={isLoadingMore}
                      onClick={() => {
                        setInitialLoading(true);
                        listFlows({ limit: 200 })
                          .then((page) => {
                            setFlowMap(() => {
                              const map = new Map<string, FlowEntry>();
                              for (const item of page.items) {
                                const flowId = item.id.replace(/:(request|response)$/i, '');
                                const existing = map.get(flowId);
                                const updated = integrateFlowEvent(existing, item);
                                map.set(flowId, updated);
                              }
                              return map;
                            });
                            setCursor(page.nextCursor ?? null);
                            setHasMore(Boolean(page.nextCursor));
                          })
                          .catch((error) => {
                            console.error('Failed to refresh flows', error);
                            toast.error('Unable to refresh flows');
                          })
                          .finally(() => setInitialLoading(false));
                      }}
                    >
                      <RefreshCw className="mr-2 h-4 w-4" /> Refresh
                    </Button>
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => beginEdit(selectedFlow)}
                      disabled={!selectedFlow.request || !editingEnabled || selectedFlow.requestRedacted}
                      title={
                        !editingEnabled
                          ? 'Editing is disabled for replay artifacts'
                          : selectedFlow.requestRedacted
                            ? 'Request payload redacted by policy (requires CAP_FLOW_INSPECT_RAW)'
                            : undefined
                      }
                    >
                      <Send className="mr-2 h-4 w-4" /> Edit & resend
                    </Button>
                  </div>
              </div>
            </div>
            <div className="flex-1 overflow-y-auto px-6 py-6">
              {(selectedFlow.parentFlowId ||
                selectedFlow.childFlowIds.length > 0 ||
                selectedFlow.auditTrail.length > 0) && (
                <div className="mb-6 space-y-4 rounded-md border border-border bg-muted/30 p-4 text-xs">
                  {selectedFlow.parentFlowId && (
                    <div className="flex flex-wrap items-center justify-between gap-2 text-sm text-foreground">
                      <div className="flex items-center gap-2">
                        <Link className="h-4 w-4 text-muted-foreground" />
                        <span className="truncate">
                          Resent from{' '}
                          <button
                            type="button"
                            className="font-mono underline-offset-2 hover:underline"
                            onClick={() => setSelectedFlowId(selectedFlow.parentFlowId!)}
                          >
                            {selectedFlow.parentFlowId}
                          </button>
                        </span>
                      </div>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setSelectedFlowId(selectedFlow.parentFlowId!)}
                        className="h-7 px-2 text-xs"
                      >
                        View parent
                      </Button>
                    </div>
                  )}
                  {selectedFlow.childFlowIds.length > 0 && (
                    <div className="space-y-2">
                      <div className="flex items-center gap-2 text-sm font-semibold text-foreground">
                        <GitBranch className="h-4 w-4 text-muted-foreground" /> Resent copies
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {selectedFlow.childFlowIds.map((childId) => (
                          <Button
                            key={childId}
                            variant="outline"
                            size="sm"
                            className="h-7 px-2 text-xs font-mono"
                            onClick={() => setSelectedFlowId(childId)}
                          >
                            {childId}
                          </Button>
                        ))}
                      </div>
                    </div>
                  )}
                  {selectedFlow.cloneReason && (
                    <div className="flex items-start gap-2 text-muted-foreground">
                      <Send className="mt-0.5 h-3 w-3" />
                      <span>{selectedFlow.cloneReason}</span>
                    </div>
                  )}
                  {selectedFlow.auditTrail.length > 0 && (
                    <div className="space-y-2">
                      <div className="flex items-center gap-2 text-sm font-semibold text-foreground">
                        <FileSignature className="h-4 w-4 text-muted-foreground" /> Audit trail
                      </div>
                      <ul className="space-y-2">
                        {selectedFlow.auditTrail.map((audit) => (
                          <li key={audit.entryId} className="rounded-md bg-background/80 p-3">
                            <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-foreground">
                              <span className="font-mono">{audit.entryId}</span>
                              {audit.recordedAt && (
                                <span className="text-muted-foreground">
                                  {new Date(audit.recordedAt).toLocaleString()}
                                </span>
                              )}
                            </div>
                            <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">
                              sig {audit.signature}
                            </div>
                            <div className="mt-1 flex flex-wrap gap-3 text-[11px] text-muted-foreground">
                              {audit.actor && <span>Actor: {audit.actor}</span>}
                              {audit.action && <span>Action: {audit.action}</span>}
                              {audit.decision && <span>Decision: {audit.decision}</span>}
                            </div>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}
              <section>
                <header className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-semibold uppercase text-muted-foreground">Request</h3>
                    <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                        <span>Size {formatBytes(selectedFlow.requestSize)}</span>
                        {selectedFlow.requestSize && selectedFlow.requestSize > LARGE_BODY_THRESHOLD && (
                          <span className="flex items-center gap-1 text-orange-500">
                            <Filter className="h-3 w-3" /> Large payload
                          </span>
                        )}
                        {selectedFlow.requestTruncated && (
                          <span className="flex items-center gap-1 text-amber-500">
                            <AlertTriangle className="h-3 w-3" /> Truncated
                          </span>
                        )}
                        {selectedFlow.requestRedacted && (
                          <span className="flex items-center gap-1 text-sky-500">
                            <Shield className="h-3 w-3" /> Sanitized
                          </span>
                        )}
                        {selectedFlow.requestBinary && (
                          <span className="flex items-center gap-1 text-purple-500">
                            Binary
                          </span>
                        )}
                      </div>
                    </div>
                  </header>
                  <HttpMessageViewer message={selectedFlow.request} />
                </section>
                <section className="mt-8">
                  <header className="flex items-center justify-between">
                    <div>
                      <h3 className="text-sm font-semibold uppercase text-muted-foreground">Response</h3>
                      <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                        <span>Size {formatBytes(selectedFlow.responseSize)}</span>
                        {selectedFlow.responseSize &&
                          selectedFlow.responseSize > LARGE_BODY_THRESHOLD && (
                            <span className="flex items-center gap-1 text-orange-500">
                              <Filter className="h-3 w-3" /> Large payload
                            </span>
                          )}
                        {selectedFlow.responseTruncated && (
                          <span className="flex items-center gap-1 text-amber-500">
                            <AlertTriangle className="h-3 w-3" /> Truncated
                          </span>
                        )}
                        {selectedFlow.responseRedacted && (
                          <span className="flex items-center gap-1 text-sky-500">
                            <Shield className="h-3 w-3" /> Sanitized
                          </span>
                        )}
                        {selectedFlow.responseBinary && (
                          <span className="flex items-center gap-1 text-purple-500">
                            Binary
                          </span>
                        )}
                      </div>
                    </div>
                  </header>
                  <HttpMessageViewer message={selectedFlow.response} />
                </section>
              </div>
            </div>
          ) : (
            <div className="flex flex-1 items-center justify-center p-6 text-sm text-muted-foreground">
              Select a flow from the timeline to inspect the intercepted request and response.
            </div>
          )}
        </div>
      </section>
      {editingFlow && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
          <div className="w-full max-w-3xl rounded-lg border border-border bg-background shadow-xl">
            <div className="flex items-start justify-between border-b border-border px-6 py-4">
              <div>
                <h2 className="text-lg font-semibold text-foreground">Modify request &amp; resend</h2>
                <p className="text-sm text-muted-foreground">
                  Editing sanitized requests can expose sensitive data. Review changes carefully before dispatching.
                </p>
              </div>
              <Button variant="ghost" size="sm" onClick={() => setEditingFlow(null)}>
                Close
              </Button>
            </div>
            <div className="space-y-4 px-6 py-6">
              <div>
                <label className="text-xs font-semibold uppercase text-muted-foreground" htmlFor="edit-draft">
                  Request payload
                </label>
                <textarea
                  id="edit-draft"
                  value={editDraft}
                  onChange={(event) => setEditDraft(event.target.value)}
                  className="mt-2 h-64 w-full rounded-md border border-border bg-card p-3 font-mono text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-destructive"
                />
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <input
                    id="confirm-send"
                    type="checkbox"
                    className="h-3 w-3 rounded border-border text-destructive focus-visible:outline-none focus-visible:ring-0"
                    checked={editConfirmed}
                    onChange={(event) => setEditConfirmed(event.target.checked)}
                  />
                  <label htmlFor="confirm-send" className="cursor-pointer">
                    I understand this will send a modified request to the upstream service.
                  </label>
                </div>
                <div className="flex items-center gap-2">
                  <Button variant="ghost" onClick={() => setShowDiff((value) => !value)} size="sm">
                    {showDiff ? 'Hide diff' : 'Show diff'}
                  </Button>
                </div>
              </div>
              <div className="rounded-md border border-border bg-muted/30 p-4 text-xs">
                <div className="flex items-center gap-2 text-sm font-semibold text-foreground">
                  <ShieldAlert
                    className={cn('h-4 w-4', hasGuardErrors ? 'text-destructive' : 'text-emerald-500')}
                  />
                  Pre-send guardrails
                </div>
                {hasGuardErrors || editAnalysis.guardWarnings.length > 0 ? (
                  <div className="mt-2 space-y-2">
                    {editAnalysis.guardErrors.map((message, index) => (
                      <div key={`guard-error-${index}`} className="flex items-start gap-2 text-destructive">
                        <ShieldAlert className="mt-0.5 h-3 w-3" />
                        <span>{message}</span>
                      </div>
                    ))}
                    {editAnalysis.guardWarnings.map((message, index) => (
                      <div key={`guard-warning-${index}`} className="flex items-start gap-2 text-amber-500">
                        <AlertTriangle className="mt-0.5 h-3 w-3" />
                        <span>{message}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="mt-2 text-muted-foreground">No policy violations detected.</p>
                )}
              </div>
              {showDiff && (
                <HttpDiffViewer
                  original={editingFlow.request?.raw ?? ''}
                  updated={editDraft}
                  originalParsed={editAnalysis.originalParsed}
                  updatedParsed={editAnalysis.updatedParsed}
                />
              )}
              <div className="flex items-center justify-end gap-3">
                <Button variant="ghost" onClick={() => setEditingFlow(null)}>
                  Cancel
                </Button>
                <Button
                  variant="destructive"
                  onClick={submitEdit}
                  disabled={
                    !editConfirmed ||
                    isSubmittingEdit ||
                    !editingFlow.request ||
                    editDraft.trim().length === 0 ||
                    !editingEnabled ||
                    hasGuardErrors
                  }
                >
                  {isSubmittingEdit ? 'Sending…' : 'Resend modified request'}
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export const Route = createFileRoute('/flows')({
  component: FlowsRouteComponent
});

export default FlowsRouteComponent;
