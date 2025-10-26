import type { CaseRecord, CaseSnapshot, CaseSnapshotSummary } from './ipc';

export type CaseSeverity = 'critical' | 'high' | 'medium' | 'low' | 'informational';

export type KeyChange = {
  key: string;
  before?: string;
  after?: string;
  change: 'added' | 'removed' | 'changed';
};

export type EvidenceDiff = {
  key: string;
  plugin: string;
  type: string;
  change: 'added' | 'removed' | 'changed' | 'unchanged';
  before?: CaseRecord['evidence'][number];
  after?: CaseRecord['evidence'][number];
  bodyText?: {
    before: string;
    after: string;
    changed: boolean;
  };
  bodyMetadata: KeyChange[];
  headers: KeyChange[];
  metadata: KeyChange[];
};

export type CaseChange = {
  id: string;
  titleBefore: string;
  titleAfter: string;
  severityBefore: string;
  severityAfter: string;
  before: CaseRecord;
  after: CaseRecord;
  summaryChanged: boolean;
  confidenceChanged: boolean;
  riskChanged: boolean;
  labelsChanged: KeyChange[];
  evidenceDiff: EvidenceDiff[];
  changedFields: string[];
};

export type CaseDiffSummary = {
  baseline: CaseSnapshotSummary;
  target: CaseSnapshotSummary;
  added: CaseRecord[];
  removed: CaseRecord[];
  changed: CaseChange[];
};

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableStringify(entry)).join(',')}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .map(([key, val]) => [key, stableStringify(val)] as const)
    .sort(([a], [b]) => a.localeCompare(b));
  return `{${entries.map(([key, val]) => `${JSON.stringify(key)}:${val}`).join(',')}}`;
}

function casesEqual(a: CaseRecord, b: CaseRecord): boolean {
  return stableStringify(a) === stableStringify(b);
}

function diffLabels(
  before: Record<string, string> | undefined,
  after: Record<string, string> | undefined
): KeyChange[] {
  const left = before ?? {};
  const right = after ?? {};
  const changes: KeyChange[] = [];

  for (const [key, value] of Object.entries(right)) {
    if (!(key in left)) {
      changes.push({ key, after: value, change: 'added' });
    } else if (left[key] !== value) {
      changes.push({ key, before: left[key], after: value, change: 'changed' });
    }
  }

  for (const [key, value] of Object.entries(left)) {
    if (!(key in right)) {
      changes.push({ key, before: value, change: 'removed' });
    }
  }

  return changes;
}

function classifyKeyChange(change: KeyChange) {
  const lowered = change.key.toLowerCase();
  if (lowered.includes('header')) {
    return 'header' as const;
  }
  if (lowered.includes('body')) {
    return 'body' as const;
  }
  return 'metadata' as const;
}

function diffEvidenceItem(
  before: CaseRecord['evidence'][number] | undefined,
  after: CaseRecord['evidence'][number] | undefined,
  key: string
): EvidenceDiff {
  if (before && !after) {
    return {
      key,
      plugin: before.plugin,
      type: before.type,
      change: 'removed',
      before,
      bodyMetadata: [],
      headers: [],
      metadata: []
    };
  }
  if (after && !before) {
    return {
      key,
      plugin: after.plugin,
      type: after.type,
      change: 'added',
      after,
      bodyMetadata: [],
      headers: [],
      metadata: []
    };
  }
  if (!before || !after) {
    throw new Error('diffEvidenceItem called with invalid arguments');
  }

  const metadataChanges = diffLabels(before.metadata, after.metadata);
  const bodyMetadata: KeyChange[] = [];
  const headers: KeyChange[] = [];
  const metadata: KeyChange[] = [];

  for (const change of metadataChanges) {
    const category = classifyKeyChange(change);
    if (category === 'header') {
      headers.push(change);
    } else if (category === 'body') {
      bodyMetadata.push(change);
    } else {
      metadata.push(change);
    }
  }

  const bodyBefore = before.evidence ?? '';
  const bodyAfter = after.evidence ?? '';
  const bodyChanged = bodyBefore !== bodyAfter;

  return {
    key,
    plugin: after.plugin,
    type: after.type,
    change: metadataChanges.length > 0 || bodyChanged || before.message !== after.message ? 'changed' : 'unchanged',
    before,
    after,
    bodyText: bodyChanged
      ? {
          before: bodyBefore,
          after: bodyAfter,
          changed: true
        }
      : undefined,
    bodyMetadata,
    headers,
    metadata
  };
}

function matchEvidence(list: CaseRecord['evidence']): Map<string, CaseRecord['evidence'][number]> {
  const counts = new Map<string, number>();
  const map = new Map<string, CaseRecord['evidence'][number]>();
  list.forEach((item) => {
    const baseKey = `${item.plugin}|${item.type}`;
    const index = (counts.get(baseKey) ?? 0) + 1;
    counts.set(baseKey, index);
    map.set(`${baseKey}#${index}`, item);
  });
  return map;
}

function computeEvidenceDiff(
  before: CaseRecord['evidence'] | undefined,
  after: CaseRecord['evidence'] | undefined
): EvidenceDiff[] {
  const leftMap = matchEvidence(before ?? []);
  const leftCounts = new Map<string, number>();
  (before ?? []).forEach((item) => {
    const key = `${item.plugin}|${item.type}`;
    leftCounts.set(key, (leftCounts.get(key) ?? 0) + 1);
  });

  const rightCounts = new Map<string, number>();
  const changes: EvidenceDiff[] = [];
  (after ?? []).forEach((item) => {
    const baseKey = `${item.plugin}|${item.type}`;
    const index = (rightCounts.get(baseKey) ?? 0) + 1;
    rightCounts.set(baseKey, index);
    const composite = `${baseKey}#${index}`;
    const previous = leftMap.get(composite);
    changes.push(diffEvidenceItem(previous, item, composite));
    if (previous) {
      leftMap.delete(composite);
    }
  });

  for (const [key, remaining] of leftMap.entries()) {
    changes.push(diffEvidenceItem(remaining, undefined, key));
  }

  return changes.filter((entry) => entry.change !== 'unchanged');
}

function mapSeverity(value: string | undefined): CaseSeverity {
  const normalized = value?.trim().toLowerCase();
  switch (normalized) {
    case 'critical':
    case 'crit':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
    case 'med':
      return 'medium';
    case 'low':
      return 'low';
    default:
      return 'informational';
  }
}

export function severityToSarifLevel(severity: CaseSeverity): 'error' | 'warning' | 'note' {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    default:
      return 'note';
  }
}

export function computeCaseDiff(baseline: CaseSnapshot, target: CaseSnapshot): CaseDiffSummary {
  const baselineMap = new Map(baseline.cases.map((item) => [item.id, item] as const));
  const targetMap = new Map(target.cases.map((item) => [item.id, item] as const));

  const added: CaseRecord[] = [];
  const removed: CaseRecord[] = [];
  const changed: CaseChange[] = [];

  for (const [id, before] of baselineMap.entries()) {
    const current = targetMap.get(id);
    if (!current) {
      removed.push(before);
      continue;
    }
    if (casesEqual(before, current)) {
      continue;
    }

    const summaryChanged = before.summary !== current.summary;
    const confidenceChanged = before.confidence !== current.confidence;
    const riskChanged =
      before.risk?.severity !== current.risk?.severity || before.risk?.score !== current.risk?.score;
    const labelsChanged = diffLabels(before.labels, current.labels);
    const evidenceDiff = computeEvidenceDiff(before.evidence, current.evidence);

    const changedFields: string[] = [];
    if (summaryChanged) changedFields.push('summary');
    if (confidenceChanged) changedFields.push('confidence');
    if (riskChanged) changedFields.push('risk');
    if (labelsChanged.length > 0) changedFields.push('labels');
    if (evidenceDiff.length > 0) changedFields.push('evidence');

    changed.push({
      id,
      titleBefore: before.summary,
      titleAfter: current.summary,
      severityBefore: before.risk?.severity ?? 'informational',
      severityAfter: current.risk?.severity ?? 'informational',
      before,
      after: current,
      summaryChanged,
      confidenceChanged,
      riskChanged,
      labelsChanged,
      evidenceDiff,
      changedFields
    });
  }

  for (const [id, current] of targetMap.entries()) {
    if (!baselineMap.has(id)) {
      added.push(current);
    }
  }

  const { cases: _baselineCases, ...baselineSummary } = baseline;
  const { cases: _targetCases, ...targetSummary } = target;

  return {
    baseline: baselineSummary,
    target: targetSummary,
    added,
    removed,
    changed
  };
}

function simplifyCase(caseRecord: CaseRecord) {
  return {
    id: caseRecord.id,
    summary: caseRecord.summary,
    severity: caseRecord.risk?.severity ?? 'informational',
    asset: caseRecord.asset,
    confidence: caseRecord.confidence,
    labels: caseRecord.labels,
    evidence: caseRecord.evidence
  };
}

export function buildCaseDiffJson(diff: CaseDiffSummary) {
  return {
    baseline: diff.baseline,
    target: diff.target,
    summary: {
      added: diff.added.length,
      removed: diff.removed.length,
      changed: diff.changed.length
    },
    added: diff.added.map(simplifyCase),
    removed: diff.removed.map(simplifyCase),
    changed: diff.changed.map((entry) => ({
      id: entry.id,
      changedFields: entry.changedFields,
      before: simplifyCase(entry.before),
      after: simplifyCase(entry.after),
      evidenceDiff: entry.evidenceDiff.map((item) => ({
        plugin: item.plugin,
        type: item.type,
        change: item.change,
        bodyText: item.bodyText,
        bodyMetadata: item.bodyMetadata,
        headers: item.headers,
        metadata: item.metadata
      }))
    }))
  };
}

export function buildCaseDiffSarif(diff: CaseDiffSummary) {
  const results = [
    ...diff.added.map((entry) => ({
      ruleId: entry.id,
      level: severityToSarifLevel(mapSeverity(entry.risk?.severity)),
      message: { text: `New case detected: ${entry.summary}` },
      properties: {
        changeType: 'added',
        asset: entry.asset?.identifier ?? entry.asset?.details ?? 'unknown'
      }
    })),
    ...diff.removed.map((entry) => ({
      ruleId: entry.id,
      level: 'note' as const,
      message: { text: `Case resolved: ${entry.summary}` },
      properties: {
        changeType: 'removed',
        asset: entry.asset?.identifier ?? entry.asset?.details ?? 'unknown'
      }
    })),
    ...diff.changed.map((entry) => ({
      ruleId: entry.id,
      level: severityToSarifLevel(mapSeverity(entry.after.risk?.severity ?? entry.before.risk?.severity)),
      message: {
        text:
          entry.changedFields.length === 0
            ? 'Case updated'
            : `Case updated (${entry.changedFields.join(', ')})`
      },
      properties: {
        changeType: 'changed',
        changedFields: entry.changedFields
      }
    }))
  ];

  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: '0xgen Case Diff Viewer',
            informationUri: 'https://0xgen.sh'
          }
        },
        results
      }
    ]
  } as const;
}
